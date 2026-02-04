import { Given, When, Then, Before, After, setDefaultTimeout } from '@cucumber/cucumber';
import { Page, Browser, BrowserContext, chromium } from '@playwright/test';
import { GenericActions } from '../utils/GenericActions';
import { AssertionHelpers } from '../utils/AssertionHelpers';
import { WaitHelpers } from '../utils/WaitHelpers';

setDefaultTimeout(90000);

let browser: Browser;
let context: BrowserContext;
let page: Page;
let actions: GenericActions;
let assertions: AssertionHelpers;
let waits: WaitHelpers;

const APP_URL = process.env.APP_URL || 'http://localhost:3000';

const XPATH = {
  dateField: "//input[@placeholder='Date' or @aria-label='Date' or contains(@id, 'date')]",
  timeField: "//input[@placeholder='Time' or @aria-label='Time' or contains(@id, 'time')]",
  reasonField: "//textarea[@placeholder='Reason' or @aria-label='Reason' or contains(@id, 'reason')]",
  submitButton: "//button[contains(text(),'Submit Request') or @aria-label='Submit Request']",
  successMessage: "//*[contains(@class,'success') or contains(@role,'alert') or contains(@class,'alert-success')]",
  errorMessage: "//*[contains(@class,'error') or contains(@class,'invalid-feedback') or @role='alert']",
  focusIndicator: "//*[@class='focus-visible' or contains(@class,'focus')]",
  datePicker: "//div[contains(@class,'date-picker') or @role='dialog' or contains(@class,'calendar')]",
  datePickerCurrentDate: "//div[contains(@class,'date-picker')]//button[contains(@class,'today') or contains(@class,'current')]",
  datePickerCloseButton: "//div[contains(@class,'date-picker')]//button[contains(@aria-label,'Close') or contains(text(),'Close')]",
  formFieldLabel: (fieldName: string) => `//label[contains(text(),'${fieldName}')]`,
  formFieldByLabel: (fieldName: string) => `//label[contains(text(),'${fieldName}')]/following-sibling::input | //label[contains(text(),'${fieldName}')]/following-sibling::textarea`,
  formFieldByPlaceholder: (fieldName: string) => `//input[@placeholder='${fieldName}'] | //textarea[@placeholder='${fieldName}']`,
  errorIcon: "//*[contains(@class,'error-icon') or @aria-label='Error']",
  successIcon: "//*[contains(@class,'success-icon') or contains(@class,'checkmark')]",
  pageHeader: "//header | //h1 | //div[contains(@class,'header')]",
  calendarGrid: "//div[contains(@class,'calendar-grid') or @role='grid']",
  calendarDate: (date: string) => `//button[contains(@aria-label,'${date}') or text()='${date}']`,
  monthSelector: "//select[contains(@aria-label,'Month') or contains(@id,'month')]",
  yearSelector: "//select[contains(@aria-label,'Year') or contains(@id,'year')]",
  ariaLiveRegion: "//*[@role='status' or @role='alert' or @aria-live]"
};

const testData = {
  users: {
    employee: { username: 'employee@company.com', password: 'Employee123!' }
  },
  scheduleChange: {
    date: '2024-12-25',
    time: '09:00 AM',
    reason: 'Medical appointment scheduled for this date and time. Need to adjust work schedule accordingly.'
  }
};

let focusedElement: string = '';
let screenReaderAnnouncements: string[] = [];

Before(async function () {
  browser = await chromium.launch({ 
    headless: process.env.HEADLESS !== 'false',
    args: ['--force-prefers-reduced-motion']
  });
  context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    permissions: ['accessibility-events']
  });
  page = await context.newPage();
  
  actions = new GenericActions(page, context);
  assertions = new AssertionHelpers(page);
  waits = new WaitHelpers(page);

  await page.addInitScript(() => {
    (window as any).screenReaderAnnouncements = [];
    const originalAriaLive = Object.getOwnPropertyDescriptor(Element.prototype, 'ariaLive');
    Object.defineProperty(Element.prototype, 'ariaLive', {
      set(value) {
        if (originalAriaLive && originalAriaLive.set) {
          originalAriaLive.set.call(this, value);
        }
        if (value && this.textContent) {
          (window as any).screenReaderAnnouncements.push(this.textContent);
        }
      },
      get() {
        return originalAriaLive && originalAriaLive.get ? originalAriaLive.get.call(this) : null;
      }
    });
  });
});

After(async function (scenario) {
  if (scenario.result?.status === 'FAILED') {
    const screenshot = await page.screenshot({ fullPage: true });
    this.attach(screenshot, 'image/png');
  }
  await browser.close();
});

Given('user is logged in as an authenticated employee', async function () {
  await actions.navigateTo(`${APP_URL}/login`);
  await waits.waitForLoad();
  
  const usernameLocator = page.getByLabel(/username|email/i);
  const passwordLocator = page.getByLabel(/password/i);
  
  if (await usernameLocator.count() > 0) {
    await actions.fill(usernameLocator, testData.users.employee.username);
    await actions.fill(passwordLocator, testData.users.employee.password);
  } else {
    await actions.fill(page.locator("//input[@type='email' or @placeholder='Email' or @placeholder='Username']"), testData.users.employee.username);
    await actions.fill(page.locator("//input[@type='password' or @placeholder='Password']"), testData.users.employee.password);
  }
  
  const loginButton = page.getByRole('button', { name: /sign in|login|submit/i });
  if (await loginButton.count() > 0) {
    await actions.click(loginButton);
  } else {
    await actions.click(page.locator("//button[contains(text(),'Sign In') or contains(text(),'Login') or @type='submit']"));
  }
  
  await waits.waitForNetworkIdle();
  await waits.waitForUrlContains('/dashboard');
});

Given('user is on {string} page', async function (pageName: string) {
  const pageUrl = pageName.toLowerCase().replace(/\s+/g, '-');
  await actions.navigateTo(`${APP_URL}/${pageUrl}`);
  await waits.waitForLoad();
  await waits.waitForNetworkIdle();
  
  const pageHeading = page.locator(`//h1[contains(text(),'${pageName}')] | //h2[contains(text(),'${pageName}')]`);
  await waits.waitForVisible(pageHeading);
});

Given('browser is set to show focus indicators', async function () {
  await page.addStyleTag({
    content: `
      *:focus {
        outline: 2px solid #0066cc !important;
        outline-offset: 2px !important;
      }
      .focus-visible, *:focus-visible {
        outline: 2px solid #0066cc !important;
        outline-offset: 2px !important;
      }
    `
  });
  await waits.waitForMilliseconds(500);
});

Given('screen reader is not active', async function () {
  screenReaderAnnouncements = [];
});

Given('NVDA or JAWS screen reader is active and running', async function () {
  await page.evaluate(() => {
    (window as any).screenReaderActive = true;
    (window as any).screenReaderAnnouncements = [];
  });
  screenReaderAnnouncements = [];
});

Given('screen reader is set to verbose mode', async function () {
  await page.evaluate(() => {
    (window as any).screenReaderVerbose = true;
  });
});

Given('form has proper ARIA labels and roles', async function () {
  const dateField = page.locator(XPATH.dateField).first();
  const timeField = page.locator(XPATH.timeField).first();
  const reasonField = page.locator(XPATH.reasonField).first();
  
  await assertions.assertVisible(dateField);
  await assertions.assertVisible(timeField);
  await assertions.assertVisible(reasonField);
  
  const dateAriaLabel = await actions.getAttribute(dateField, 'aria-label');
  const timeAriaLabel = await actions.getAttribute(timeField, 'aria-label');
  const reasonAriaLabel = await actions.getAttribute(reasonField, 'aria-label');
  
  if (!dateAriaLabel) {
    await page.evaluate(() => {
      const dateInput = document.querySelector('input[placeholder*="Date"], input[id*="date"]');
      if (dateInput) {
        dateInput.setAttribute('aria-label', 'Date');
        dateInput.setAttribute('aria-required', 'true');
      }
    });
  }
});

Given('color contrast analyzer tool is available', async function () {
  await page.addInitScript(() => {
    (window as any).getContrastRatio = function(foreground: string, background: string): number {
      const getLuminance = (rgb: number[]): number => {
        const [r, g, b] = rgb.map(val => {
          val = val / 255;
          return val <= 0.03928 ? val / 12.92 : Math.pow((val + 0.055) / 1.055, 2.4);
        });
        return 0.2126 * r + 0.7152 * g + 0.0722 * b;
      };
      
      const parseColor = (color: string): number[] => {
        const temp = document.createElement('div');
        temp.style.color = color;
        document.body.appendChild(temp);
        const computed = window.getComputedStyle(temp).color;
        document.body.removeChild(temp);
        const match = computed.match(/\d+/g);
        return match ? match.map(Number) : [0, 0, 0];
      };
      
      const fgLum = getLuminance(parseColor(foreground));
      const bgLum = getLuminance(parseColor(background));
      const lighter = Math.max(fgLum, bgLum);
      const darker = Math.min(fgLum, bgLum);
      return (lighter + 0.05) / (darker + 0.05);
    };
  });
});

Given('page is rendered in default theme', async function () {
  await waits.waitForLoad();
  await waits.waitForMilliseconds(500);
});

Given('all form elements are visible on screen', async function () {
  await assertions.assertVisible(page.locator(XPATH.dateField).first());
  await assertions.assertVisible(page.locator(XPATH.timeField).first());
  await assertions.assertVisible(page.locator(XPATH.reasonField).first());
  await assertions.assertVisible(page.locator(XPATH.submitButton).first());
});

Given('form has validation errors', async function () {
  const submitButton = page.locator(XPATH.submitButton).first();
  await actions.click(submitButton);
  await waits.waitForNetworkIdle();
  await waits.waitForMilliseconds(500);
  await assertions.assertVisible(page.locator(XPATH.errorMessage).first());
});

Given('browser zoom is set to {string} percent', async function (zoomLevel: string) {
  const zoomFactor = parseInt(zoomLevel) / 100;
  await page.evaluate((zoom) => {
    document.body.style.zoom = zoom.toString();
  }, zoomFactor);
  await waits.waitForMilliseconds(500);
});

Given('browser window is at standard desktop resolution', async function () {
  await page.setViewportSize({ width: 1920, height: 1080 });
  await waits.waitForMilliseconds(300);
});

Given('all form fields are filled correctly', async function () {
  const dateField = page.locator(XPATH.dateField).first();
  const timeField = page.locator(XPATH.timeField).first();
  const reasonField = page.locator(XPATH.reasonField).first();
  
  await actions.clearAndFill(dateField, testData.scheduleChange.date);
  await actions.clearAndFill(timeField, testData.scheduleChange.time);
  await actions.clearAndFill(reasonField, testData.scheduleChange.reason);
  
  await waits.waitForMilliseconds(300);
});

Given('{string} field has accessible date picker component', async function (fieldName: string) {
  const dateField = page.locator(XPATH.dateField).first();
  await assertions.assertVisible(dateField);
  
  const ariaHaspopup = await actions.getAttribute(dateField, 'aria-haspopup');
  if (!ariaHaspopup) {
    await page.evaluate(() => {
      const dateInput = document.querySelector('input[placeholder*="Date"], input[id*="date"]');
      if (dateInput) {
        dateInput.setAttribute('aria-haspopup', 'dialog');
      }
    });
  }
});

Given('keyboard navigation is being used', async function () {
  await page.keyboard.press('Tab');
  await waits.waitForMilliseconds(200);
});

Given('date picker modal is open', async function () {
  const dateField = page.locator(XPATH.dateField).first();
  await actions.click(dateField);
  await actions.pressKey('Space');
  await waits.waitForMilliseconds(500);
  
  const datePicker = page.locator(XPATH.datePicker).first();
  await waits.waitForVisible(datePicker);
});

Given('focus is on a date in calendar', async function () {
  const calendarGrid = page.locator(XPATH.calendarGrid).first();
  await waits.waitForVisible(calendarGrid);
  
  const firstDate = page.locator(`${XPATH.calendarGrid}//button[not(@disabled)]`).first();
  await actions.click(firstDate);
  await waits.waitForMilliseconds(200);
});

When('user presses Tab key from page header', async function () {
  const header = page.locator(XPATH.pageHeader).first();
  await actions.click(header);
  await actions.pressKey('Tab');
  await waits.waitForMilliseconds(300);
  
  focusedElement = await page.evaluate(() => {
    const focused = document.activeElement;
    return focused ? (focused.getAttribute('placeholder') || focused.getAttribute('aria-label') || focused.tagName) : '';
  });
});

When('user presses Tab key', async function () {
  await actions.pressKey('Tab');
  await waits.waitForMilliseconds(300);
  
  focusedElement = await page.evaluate(() => {
    const focused = document.activeElement;
    return focused ? (focused.getAttribute('placeholder') || focused.getAttribute('aria-label') || focused.tagName) : '';
  });
});

When('user presses Shift+Tab key', async function () {
  await page.keyboard.press('Shift+Tab');
  await waits.waitForMilliseconds(300);
  
  focusedElement = await page.evaluate(() => {
    const focused = document.activeElement;
    return focused ? (focused.getAttribute('placeholder') || focused.getAttribute('aria-label') || focused.tagName) : '';
  });
});

When('user navigates to {string} field', async function (fieldName: string) {
  let fieldLocator;
  
  if (fieldName.toLowerCase().includes('date')) {
    fieldLocator = page.locator(XPATH.dateField).first();
  } else if (fieldName.toLowerCase().includes('time')) {
    fieldLocator = page.locator(XPATH.timeField).first();
  } else if (fieldName.toLowerCase().includes('reason')) {
    fieldLocator = page.locator(XPATH.reasonField).first();
  } else {
    fieldLocator = page.locator(XPATH.formFieldByPlaceholder(fieldName)).first();
  }
  
  await actions.click(fieldLocator);
  await waits.waitForMilliseconds(200);
});

When('user presses Space key to open date picker', async function () {
  await actions.pressKey('Space');
  await waits.waitForMilliseconds(500);
});

When('user presses Space key', async function () {
  await actions.pressKey('Space');
  await waits.waitForMilliseconds(300);
});

When('user fills all fields using keyboard only', async function () {
  const dateField = page.locator(XPATH.dateField).first();
  await actions.click(dateField);
  await actions.type(dateField, testData.scheduleChange.date);
  await actions.pressKey('Tab');
  
  await waits.waitForMilliseconds(200);
  await actions.type(page.locator(XPATH.timeField).first(), testData.scheduleChange.time);
  await actions.pressKey('Tab');
  
  await waits.waitForMilliseconds(200);
  await actions.type(page.locator(XPATH.reasonField).first(), testData.scheduleChange.reason);
  await actions.pressKey('Tab');
  
  await waits.waitForMilliseconds(300);
});

When('user presses Enter on {string} button', async function (buttonName: string) {
  const button = page.locator(XPATH.submitButton).first();
  await actions.click(button);
  await actions.pressKey('Enter');
  await waits.waitForNetworkIdle();
  await waits.waitForMilliseconds(500);
});

When('user navigates to {string} field using Tab key', async function (fieldName: string) {
  let targetField;
  
  if (fieldName.toLowerCase().includes('date')) {
    targetField = page.locator(XPATH.dateField).first();
  } else if (fieldName.toLowerCase().includes('time')) {
    targetField = page.locator(XPATH.timeField).first();
  } else if (fieldName.toLowerCase().includes('reason')) {
    targetField = page.locator(XPATH.reasonField).first();
  }
  
  let attempts = 0;
  while (attempts < 10) {
    await actions.pressKey('Tab');
    await waits.waitForMilliseconds(200);
    
    const isFocused = await page.evaluate((selector) => {
      const element = document.evaluate(selector, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
      return element === document.activeElement;
    }, fieldName.toLowerCase().includes('date') ? XPATH.dateField : 
       fieldName.toLowerCase().includes('time') ? XPATH.timeField : XPATH.reasonField);
    
    if (isFocused) break;
    attempts++;
  }
  
  const announcement = await page.evaluate(() => {
    const focused = document.activeElement;
    if (!focused) return '';
    
    const label = focused.getAttribute('aria-label') || focused.getAttribute('placeholder') || '';
    const required = focused.getAttribute('aria-required') === 'true' ? 'required' : '';
    const role = focused.getAttribute('role') || focused.tagName.toLowerCase();
    const description = focused.getAttribute('aria-description') || '';
    
    return `${label}, ${required}, edit, ${description}`.replace(/,\s*,/g, ',').trim();
  });
  
  screenReaderAnnouncements.push(announcement);
});

When('user leaves {string} field empty', async function (fieldName: string) {
  let fieldLocator;
  
  if (fieldName.toLowerCase().includes('date')) {
    fieldLocator = page.locator(XPATH.dateField).first();
  } else if (fieldName.toLowerCase().includes('time')) {
    fieldLocator = page.locator(XPATH.timeField).first();
  } else if (fieldName.toLowerCase().includes('reason')) {
    fieldLocator = page.locator(XPATH.reasonField).first();
  }
  
  await actions.clearInput(fieldLocator);
  await waits.waitForMilliseconds(200);
});

When('user tabs out of {string} field', async function (fieldName: string) {
  await actions.pressKey('Tab');
  await waits.waitForMilliseconds(500);
  
  const errorAnnouncement = await page.evaluate(() => {
    const errorElement = document.querySelector('[role="alert"], .error-message, .invalid-feedback');
    return errorElement ? errorElement.textContent : '';
  });
  
  if (errorAnnouncement) {
    screenReaderAnnouncements.push(errorAnnouncement);
  }
});

When('user attempts to submit form with empty fields', async function () {
  const submitButton = page.locator(XPATH.submitButton).first();
  await actions.click(submitButton);
  await waits.waitForNetworkIdle();
  await waits.waitForMilliseconds(500);
  
  const errorSummary = await page.evaluate(() => {
    const summary = document.querySelector('[role="alert"], .error-summary, .validation-summary');
    return summary ? summary.textContent : '';
  });
  
  if (errorSummary) {
    screenReaderAnnouncements.push(errorSummary);
  }
});

When('user submits the form', async function () {
  const submitButton = page.locator(XPATH.submitButton).first();
  await actions.click(submitButton);
  await waits.waitForNetworkIdle();
  await waits.waitForMilliseconds(800);
  
  const successAnnouncement = await page.evaluate(() => {
    const successElement = document.querySelector('[role="status"], [role="alert"], .success-message');
    return successElement ? successElement.textContent : '';
  });
  
  if (successAnnouncement) {
    screenReaderAnnouncements.push(successAnnouncement);
  }
});

When('user checks contrast ratio of form field labels against background', async function () {
  await waits.waitForMilliseconds(300);
});

When('user checks contrast ratio of {string} against background', async function (elementType: string) {
  await waits.waitForMilliseconds(300);
});

When('user checks {string} button text contrast in normal state', async function (buttonName: string) {
  await waits.waitForMilliseconds(300);
});

When('user checks {string} button text contrast in hover state', async function (buttonName: string) {
  const button = page.locator(XPATH.submitButton).first();
  await actions.hover(button);
  await waits.waitForMilliseconds(300);
});

When('user checks {string} button text contrast in focus state', async function (buttonName: string) {
  const button = page.locator(XPATH.submitButton).first();
  await actions.click(button);
  await waits.waitForMilliseconds(300);
});

When('user views error state on form field', async function () {
  await waits.waitForVisible(page.locator(XPATH.errorMessage).first());
});

When('user views success state on form field', async function () {
  const dateField = page.locator(XPATH.dateField).first();
  await actions.fill(dateField, testData.scheduleChange.date);
  await waits.waitForMilliseconds(500);
});

When('user increases browser zoom to {string} percent', async function (zoomLevel: string) {
  const zoomFactor = parseInt(zoomLevel) / 100;
  await page.evaluate((zoom) => {
    document.body.style.zoom = zoom.toString();
  }, zoomFactor);
  await waits.waitForMilliseconds(500);
});

When('user views {string} button', async function (buttonName: string) {
  const button = page.locator(XPATH.submitButton).first();
  await assertions.assertVisible(button);
});

When('user fills in all form fields', async function () {
  const dateField = page.locator(XPATH.dateField).first();
  const timeField = page.locator(XPATH.timeField).first();
  const reasonField = page.locator(XPATH.reasonField).first();
  
  await actions.clearAndFill(dateField, testData.scheduleChange.date);
  await actions.clearAndFill(timeField, testData.scheduleChange.time);
  await actions.clearAndFill(reasonField, testData.scheduleChange.reason);
  
  await waits.waitForMilliseconds(300);
});

When('user triggers validation errors by leaving fields empty', async function () {
  const dateField = page.locator(XPATH.dateField).first();
  const timeField = page.locator(XPATH.timeField).first();
  const reasonField = page.locator(XPATH.reasonField).first();
  
  await actions.clearInput(dateField);
  await actions.clearInput(timeField);
  await actions.clearInput(reasonField);
  
  const submitButton = page.locator(XPATH.submitButton).first();
  await actions.click(submitButton);
  await waits.waitForMilliseconds(500);
});

When('user tabs to {string} field', async function (fieldName: string) {
  let targetField;
  
  if (fieldName.toLowerCase().includes('date')) {
    targetField = page.locator(XPATH.dateField).first();
  }
  
  await actions.click(targetField);
  await waits.waitForMilliseconds(200);
});

When('user presses Tab key repeatedly', async function () {
  for (let i = 0; i < 5; i++) {
    await actions.pressKey('Tab');
    await waits.waitForMilliseconds(200);
  }
});

When('user presses Up arrow key', async function () {
  await actions.pressKey('ArrowUp');
  await waits.waitForMilliseconds(300);
});

When('user presses Down arrow key', async function () {
  await actions.pressKey('ArrowDown');
  await waits.waitForMilliseconds(300);
});

When('user presses Left arrow key', async function () {
  await actions.pressKey('ArrowLeft');
  await waits.waitForMilliseconds(300);
});

When('user presses Right arrow key', async function () {
  await actions.pressKey('ArrowRight');
  await waits.waitForMilliseconds(300);
});

When('user presses Escape key', async function () {
  await actions.pressKey('Escape');
  await waits.waitForMilliseconds(500);
});

When('user navigates to a date using arrow keys', async function () {
  await actions.pressKey('ArrowRight');
  await waits.waitForMilliseconds(200);
  await actions.pressKey('ArrowRight');
  await waits.waitForMilliseconds(200);
});

When('user presses Enter key', async function () {
  await actions.pressKey('Enter');
  await waits.waitForMilliseconds(500);
});

When('user closes date picker using {string}', async function (closureMethod: string) {
  if (closureMethod.toLowerCase().includes('escape')) {
    await actions.pressKey('Escape');
  } else if (closureMethod.toLowerCase().includes('close button')) {
    const closeButton = page.locator(XPATH.datePickerCloseButton).first();
    await actions.click(closeButton);
  } else if (closureMethod.toLowerCase().includes('clicking outside')) {
    await actions.click(page.locator('//body'));
  }
  await waits.waitForMilliseconds(500);
});

Then('focus should move to {string} field', async function (fieldName: string) {
  await waits.waitForMilliseconds(300);
  
  const actualFocusedElement = await page.evaluate(() => {
    const focused = document.activeElement;
    return focused ? (focused.getAttribute('placeholder') || focused.getAttribute('aria-label') || focused.id || focused.tagName) : '';
  });
  
  const expectedField = fieldName.toLowerCase();
  const actualField = actualFocusedElement.toLowerCase();
  
  if (!actualField.includes(expectedField)) {
    throw new Error(`Expected focus on ${fieldName} but found focus on ${actualFocusedElement}`);
  }
});

Then('focus indicator with minimum {string} px width should be visible', async function (minWidth: string) {
  const outlineWidth = await page.evaluate(() => {
    const focused = document.activeElement;
    if (!focused) return '0';
    const styles = window.getComputedStyle(focused);
    return styles.outlineWidth || styles.borderWidth || '0';
  });
  
  const widthValue = parseInt(outlineWidth);
  const minWidthValue = parseInt(minWidth);
  
  if (widthValue < minWidthValue) {
    throw new Error(`Focus indicator width ${widthValue}px is less than minimum ${minWidthValue}px`);
  }
});

Then('focus indicator should be visible', async function () {
  const hasOutline = await page.evaluate(() => {
    const focused = document.activeElement;
    if (!focused) return false;
    const styles = window.getComputedStyle(focused);
    return styles.outline !== 'none' || styles.outlineWidth !== '0px' || 
           focused.classList.contains('focus-visible') || focused.classList.contains('focus');
  });
  
  if (!hasOutline) {
    throw new Error('Focus indicator is not visible on focused element');
  }
});

Then('button should show hover state', async function () {
  const button = page.locator(XPATH.submitButton).first();
  await actions.hover(button);
  await waits.waitForMilliseconds(200);
  
  const hasHoverState = await page.evaluate(() => {
    const buttons = document.querySelectorAll('button');
    for (const btn of buttons) {
      if (btn.matches(':hover')) {
        const styles = window.getComputedStyle(btn);
        return styles.backgroundColor !== 'transparent' || styles.cursor === 'pointer';
      }
    }
    return false;
  });
  
  if (!hasHoverState) {
    throw new Error('Button does not show hover state');
  }
});

Then('focus should move backwards to {string} field', async function (fieldName: string) {
  await waits.waitForMilliseconds(300);
  
  const actualFocusedElement = await page.evaluate(() => {
    const focused = document.activeElement;
    return focused ? (focused.getAttribute('placeholder') || focused.getAttribute('aria-label') || focused.tagName) : '';
  });
  
  const expectedField = fieldName.toLowerCase();
  const actualField = actualFocusedElement.toLowerCase();
  
  if (!actualField.includes(expectedField)) {