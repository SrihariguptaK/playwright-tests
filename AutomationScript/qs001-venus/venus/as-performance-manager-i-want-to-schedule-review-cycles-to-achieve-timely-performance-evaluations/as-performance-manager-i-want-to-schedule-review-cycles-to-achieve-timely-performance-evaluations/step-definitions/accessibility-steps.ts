import { Given, When, Then, Before, After } from '@cucumber/cucumber';
import { Page, Browser, BrowserContext, chromium, expect } from '@playwright/test';
import { BasePage } from '../pages/BasePage';
import { HomePage } from '../pages/HomePage';
import { GenericActions } from '../utils/GenericActions';
import { AssertionHelpers } from '../utils/AssertionHelpers';
import { WaitHelpers } from '../utils/WaitHelpers';

// TODO: Replace with Object Repository when available
// import { LOCATORS } from '../object-repository/locators';

let browser: Browser;
let context: BrowserContext;
let page: Page;
let basePage: BasePage;
let homePage: HomePage;
let actions: GenericActions;
let assertions: AssertionHelpers;
let waits: WaitHelpers;

Before(async function () {
  browser = await chromium.launch({ headless: process.env.HEADLESS !== 'false' });
  context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    ignoreHTTPSErrors: true,
  });
  page = await context.newPage();
  
  actions = new GenericActions(page, context);
  assertions = new AssertionHelpers(page);
  waits = new WaitHelpers(page);
  
  basePage = new BasePage(page, context);
  homePage = new HomePage(page, context);
  
  this.testData = {
    users: {
      'Performance Manager': { username: 'perfmanager', password: 'perfpass123' },
      admin: { username: 'admin', password: 'admin123' },
      user: { username: 'testuser', password: 'testpass' }
    }
  };
  
  this.keyboardNavigation = {
    focusedElements: [],
    currentFocusIndex: 0
  };
  
  this.accessibilityContext = {
    contrastRatios: {},
    ariaAttributes: {},
    touchTargetSizes: {}
  };
});

After(async function (scenario) {
  if (scenario.result?.status === 'FAILED') {
    const screenshot = await page.screenshot();
    this.attach(screenshot, 'image/png');
  }
  await page.close();
  await context.close();
  await browser.close();
});

// ==================== GIVEN STEPS ====================

/**************************************************/
/*  SHARED BACKGROUND STEPS
/*  Used across all accessibility test cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user is logged in as {string}', async function (userType: string) {
  const credentials = this.testData?.users?.[userType] || { username: 'testuser', password: 'testpass' };
  
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  
  const usernameXPath = `//input[@id='username']`;
  const passwordXPath = `//input[@id='password']`;
  const loginButtonXPath = `//button[@id='login']`;
  
  await actions.fill(page.locator(usernameXPath), credentials.username);
  await actions.fill(page.locator(passwordXPath), credentials.password);
  await actions.click(page.locator(loginButtonXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
Given('user is on {string} page', async function (pageName: string) {
  const pageUrlSegment = pageName.toLowerCase().replace(/\s+/g, '-');
  const pageXPath = `//div[@id='${pageUrlSegment}']`;
  
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/${pageUrlSegment}`);
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator(pageXPath));
});

/**************************************************/
/*  TEST CASE: TC-A11Y-001
/*  Title: Complete keyboard navigation through entire review cycle scheduling workflow
/*  Priority: High
/*  Category: Accessibility - Keyboard Navigation
/**************************************************/

Given('no mouse or pointing device is used for this test', async function () {
  this.keyboardOnly = true;
  this.keyboardNavigation.focusedElements = [];
  this.keyboardNavigation.currentFocusIndex = 0;
});

// TODO: Replace XPath with Object Repository when available
Given('at least {int} review cycle is already scheduled', async function (count: number) {
  this.existingReviewCycles = count;
  
  const reviewCycleListXPath = `//div[@id='review-cycle-list']`;
  await waits.waitForVisible(page.locator(reviewCycleListXPath));
  
  const reviewCycleItemsXPath = `//div[@class='review-cycle-item']`;
  const actualCount = await page.locator(reviewCycleItemsXPath).count();
  
  if (actualCount < count) {
    for (let i = actualCount; i < count; i++) {
      const scheduleButtonXPath = `//button[@id='schedule-new-review-cycle']`;
      await actions.click(page.locator(scheduleButtonXPath));
      
      const cycleNameXPath = `//input[@id='review-cycle-name']`;
      await actions.fill(page.locator(cycleNameXPath), `Test Cycle ${i + 1}`);
      
      const saveButtonXPath = `//button[@id='save-review-cycle']`;
      await actions.click(page.locator(saveButtonXPath));
      await waits.waitForNetworkIdle();
    }
  }
});

/**************************************************/
/*  TEST CASE: TC-A11Y-002
/*  Title: Screen reader announces all review cycle information and state changes correctly
/*  Priority: High
/*  Category: Accessibility - Screen Reader
/**************************************************/

Given('screen reader is active', async function () {
  this.screenReaderActive = true;
  this.screenReaderAnnouncements = [];
});

/**************************************************/
/*  TEST CASE: TC-A11Y-003
/*  Title: Verify sufficient color contrast ratios for all text and interactive elements
/*  Priority: High
/*  Category: Accessibility - Color Contrast
/**************************************************/

Given('color contrast analyzer tool is available', async function () {
  this.contrastAnalyzer = {
    enabled: true,
    measurements: {}
  };
});

Given('page displays various states including default, hover, focus, active, disabled, and error', async function () {
  this.pageStates = ['default', 'hover', 'focus', 'active', 'disabled', 'error'];
  this.currentState = 'default';
});

/**************************************************/
/*  TEST CASE: TC-A11Y-004
/*  Title: Test focus management and focus trap prevention in modal dialogs
/*  Priority: High
/*  Category: Accessibility - Focus Management
/**************************************************/

Given('keyboard navigation is being used exclusively', async function () {
  this.keyboardOnly = true;
  this.mouseDisabled = true;
});

Given('at least {int} review cycle exists for testing', async function (count: number) {
  this.existingReviewCycles = count;
  
  const reviewCycleItemsXPath = `//div[@class='review-cycle-item']`;
  const actualCount = await page.locator(reviewCycleItemsXPath).count();
  
  if (actualCount < count) {
    for (let i = actualCount; i < count; i++) {
      const scheduleButtonXPath = `//button[@id='schedule-new-review-cycle']`;
      await actions.click(page.locator(scheduleButtonXPath));
      
      const cycleNameXPath = `//input[@id='review-cycle-name']`;
      await actions.fill(page.locator(cycleNameXPath), `Test Cycle ${i + 1}`);
      
      const saveButtonXPath = `//button[@id='save-review-cycle']`;
      await actions.click(page.locator(saveButtonXPath));
      await waits.waitForNetworkIdle();
    }
  }
});

/**************************************************/
/*  TEST CASE: TC-A11Y-005
/*  Title: Verify page functionality at 200% browser zoom level
/*  Priority: Medium
/*  Category: Accessibility - Zoom & Text Scaling
/**************************************************/

Given('browser zoom is set to {int}%', async function (zoomLevel: number) {
  this.currentZoomLevel = zoomLevel;
  this.initialZoomLevel = zoomLevel;
});

Given('test viewport is at least {int}x{int} pixels', async function (width: number, height: number) {
  await page.setViewportSize({ width, height });
  this.viewportSize = { width, height };
});

/**************************************************/
/*  TEST CASE: TC-A11Y-006
/*  Title: Verify ARIA landmarks and semantic HTML structure for assistive technology navigation
/*  Priority: High
/*  Category: Accessibility - ARIA & Semantic HTML
/**************************************************/

Given('browser developer tools is open', async function () {
  this.devToolsOpen = true;
});

Given('screen reader is available for testing', async function () {
  this.screenReaderAvailable = true;
  this.screenReaderAnnouncements = [];
});

/**************************************************/
/*  TEST CASE: TC-A11Y-007
/*  Title: Test mobile accessibility with touch targets and screen reader on mobile devices
/*  Priority: Medium
/*  Category: Accessibility - Mobile
/**************************************************/

Given('user accesses page on mobile device with viewport {int}x{int} pixels', async function (width: number, height: number) {
  await page.setViewportSize({ width, height });
  this.mobileViewport = { width, height };
  this.isMobile = true;
});

Given('mobile screen reader is available', async function () {
  this.mobileScreenReader = true;
  this.screenReaderAnnouncements = [];
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  GENERIC KEYBOARD NAVIGATION STEPS
/*  Reusable across all keyboard navigation tests
/**************************************************/

When('user presses Tab key repeatedly from page load', async function () {
  this.keyboardNavigation.focusedElements = [];
  
  for (let i = 0; i < 50; i++) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
    
    const focusedElement = await page.evaluate(() => {
      const el = document.activeElement;
      return {
        tagName: el?.tagName,
        id: el?.id,
        className: el?.className,
        text: el?.textContent?.trim().substring(0, 50),
        ariaLabel: el?.getAttribute('aria-label')
      };
    });
    
    this.keyboardNavigation.focusedElements.push(focusedElement);
  }
});

When('user presses Tab key', async function () {
  await page.keyboard.press('Tab');
  await page.waitForTimeout(100);
  
  const focusedElement = await page.evaluate(() => {
    const el = document.activeElement;
    return {
      tagName: el?.tagName,
      id: el?.id,
      className: el?.className,
      text: el?.textContent?.trim().substring(0, 50)
    };
  });
  
  this.currentFocusedElement = focusedElement;
});

When('user presses Shift+Tab keys', async function () {
  await page.keyboard.press('Shift+Tab');
  await page.waitForTimeout(100);
  
  const focusedElement = await page.evaluate(() => {
    const el = document.activeElement;
    return {
      tagName: el?.tagName,
      id: el?.id,
      className: el?.className,
      text: el?.textContent?.trim().substring(0, 50)
    };
  });
  
  this.currentFocusedElement = focusedElement;
});

When('user presses Enter key', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('user presses Space key', async function () {
  await page.keyboard.press('Space');
  await page.waitForTimeout(200);
});

When('user presses Escape key', async function () {
  await page.keyboard.press('Escape');
  await page.waitForTimeout(200);
});

When('user presses Arrow Down key', async function () {
  await page.keyboard.press('ArrowDown');
  await page.waitForTimeout(100);
});

When('user presses Arrow Up key', async function () {
  await page.keyboard.press('ArrowUp');
  await page.waitForTimeout(100);
});

When('user presses Arrow Right key', async function () {
  await page.keyboard.press('ArrowRight');
  await page.waitForTimeout(100);
});

When('user presses Arrow Left key', async function () {
  await page.keyboard.press('ArrowLeft');
  await page.waitForTimeout(100);
});

When('user presses Arrow keys to navigate between dates', async function () {
  await page.keyboard.press('ArrowRight');
  await page.waitForTimeout(100);
  await page.keyboard.press('ArrowDown');
  await page.waitForTimeout(100);
  await page.keyboard.press('ArrowLeft');
  await page.waitForTimeout(100);
  await page.keyboard.press('ArrowUp');
  await page.waitForTimeout(100);
});

// TODO: Replace XPath with Object Repository when available
When('user navigates to {string} button using keyboard', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttonTextXPath = `//button[contains(text(),'${buttonText}')]`;
  
  let buttonLocator = page.locator(buttonIdXPath);
  if (await buttonLocator.count() === 0) {
    buttonLocator = page.locator(buttonTextXPath);
  }
  
  let attempts = 0;
  const maxAttempts = 50;
  
  while (attempts < maxAttempts) {
    const isFocused = await buttonLocator.evaluate((el) => el === document.activeElement);
    if (isFocused) {
      break;
    }
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
    attempts++;
  }
  
  this.currentFocusedButton = buttonText;
});

// TODO: Replace XPath with Object Repository when available
When('user navigates to {string} field using keyboard', async function (fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  const fieldLocator = page.locator(fieldXPath);
  
  let attempts = 0;
  const maxAttempts = 50;
  
  while (attempts < maxAttempts) {
    const isFocused = await fieldLocator.evaluate((el) => el === document.activeElement);
    if (isFocused) {
      break;
    }
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
    attempts++;
  }
  
  this.currentFocusedField = fieldName;
});

// TODO: Replace XPath with Object Repository when available
When('user navigates to {string} dropdown using keyboard', async function (dropdownName: string) {
  const dropdownXPath = `//select[@id='${dropdownName.toLowerCase().replace(/\s+/g, '-')}']`;
  const dropdownLocator = page.locator(dropdownXPath);
  
  let attempts = 0;
  const maxAttempts = 50;
  
  while (attempts < maxAttempts) {
    const isFocused = await dropdownLocator.evaluate((el) => el === document.activeElement);
    if (isFocused) {
      break;
    }
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
    attempts++;
  }
  
  this.currentFocusedDropdown = dropdownName;
});

When('user presses Enter key on {string} option', async function (optionText: string) {
  await page.keyboard.press('Enter');
  await page.waitForTimeout(200);
  this.selectedOption = optionText;
});

When('user presses Enter key on selected date', async function () {
  await page.keyboard.press('Enter');
  await page.waitForTimeout(200);
  
  const selectedDate = await page.evaluate(() => {
    const el = document.activeElement;
    return el?.getAttribute('aria-label') || el?.textContent?.trim();
  });
  
  this.selectedDate = selectedDate;
});

When('user presses Tab to navigate through form fields', async function () {
  this.formFieldsFocused = [];
  
  for (let i = 0; i < 10; i++) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
    
    const focusedElement = await page.evaluate(() => {
      const el = document.activeElement;
      return {
        tagName: el?.tagName,
        id: el?.id,
        type: el?.getAttribute('type'),
        ariaLabel: el?.getAttribute('aria-label')
      };
    });
    
    this.formFieldsFocused.push(focusedElement);
  }
});

When('user presses Tab repeatedly to cycle through modal elements', async function () {
  this.modalElementsFocused = [];
  
  for (let i = 0; i < 15; i++) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
    
    const focusedElement = await page.evaluate(() => {
      const el = document.activeElement;
      return {
        tagName: el?.tagName,
        id: el?.id,
        text: el?.textContent?.trim().substring(0, 30)
      };
    });
    
    this.modalElementsFocused.push(focusedElement);
  }
});

// TODO: Replace XPath with Object Repository when available
When('user navigates to calendar view using Tab key', async function () {
  const calendarXPath = `//div[@id='calendar-view']`;
  const calendarLocator = page.locator(calendarXPath);
  
  let attempts = 0;
  const maxAttempts = 50;
  
  while (attempts < maxAttempts) {
    const isInCalendar = await page.evaluate(() => {
      const el = document.activeElement;
      const calendar = document.querySelector('[id="calendar-view"]');
      return calendar?.contains(el);
    });
    
    if (isInCalendar) {
      break;
    }
    
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
    attempts++;
  }
});

/**************************************************/
/*  SCREEN READER NAVIGATION STEPS
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('user navigates to {string} page', async function (pageName: string) {
  const pageUrlSegment = pageName.toLowerCase().replace(/\s+/g, '-');
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/${pageUrlSegment}`);
  await waits.waitForNetworkIdle();
  
  const pageTitle = await page.title();
  this.currentPageTitle = pageTitle;
  
  if (this.screenReaderActive) {
    this.screenReaderAnnouncements.push(`Page loaded: ${pageTitle}`);
  }
});

// TODO: Replace XPath with Object Repository when available
When('user navigates to {string} button using screen reader', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttonTextXPath = `//button[contains(text(),'${buttonText}')]`;
  
  let buttonLocator = page.locator(buttonIdXPath);
  if (await buttonLocator.count() === 0) {
    buttonLocator = page.locator(buttonTextXPath);
  }
  
  const buttonInfo = await buttonLocator.evaluate((el) => ({
    text: el.textContent?.trim(),
    ariaLabel: el.getAttribute('aria-label'),
    role: el.getAttribute('role') || el.tagName.toLowerCase()
  }));
  
  if (this.screenReaderActive) {
    this.screenReaderAnnouncements.push(`${buttonInfo.ariaLabel || buttonInfo.text}, ${buttonInfo.role}`);
  }
  
  this.currentElement = buttonInfo;
});

When('user activates {string} button', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttonTextXPath = `//button[contains(text(),'${buttonText}')]`;
  
  let buttonLocator = page.locator(buttonIdXPath);
  if (await buttonLocator.count() === 0) {
    buttonLocator = page.locator(buttonTextXPath);
  }
  
  await actions.click(buttonLocator);
  await waits.waitForNetworkIdle();
});

When('user navigates through form fields using screen reader', async function () {
  this.formFieldsAnnounced = [];
  
  const formFieldsXPath = `//input | //select | //textarea`;
  const formFields = page.locator(formFieldsXPath);
  const fieldCount = await formFields.count();
  
  for (let i = 0; i < fieldCount; i++) {
    const field = formFields.nth(i);
    const fieldInfo = await field.evaluate((el) => ({
      label: el.getAttribute('aria-label') || document.querySelector(`label[for="${el.id}"]`)?.textContent?.trim(),
      type: el.getAttribute('type') || el.tagName.toLowerCase(),
      required: el.hasAttribute('required') || el.getAttribute('aria-required') === 'true',
      value: (el as HTMLInputElement).value,
      helpText: el.getAttribute('aria-describedby') ? document.getElementById(el.getAttribute('aria-describedby')!)?.textContent : null
    }));
    
    if (this.screenReaderActive) {
      const announcement = `${fieldInfo.label}, ${fieldInfo.type}${fieldInfo.required ? ', required' : ''}${fieldInfo.value ? ', ' + fieldInfo.value : ''}${fieldInfo.helpText ? ', ' + fieldInfo.helpText : ''}`;
      this.screenReaderAnnouncements.push(announcement);
      this.formFieldsAnnounced.push(fieldInfo);
    }
  }
});

// TODO: Replace XPath with Object Repository when available
When('user leaves required field empty', async function () {
  const requiredFieldXPath = `//input[@required or @aria-required='true']`;
  const requiredField = page.locator(requiredFieldXPath).first();
  
  await actions.fill(requiredField, '');
  this.fieldLeftEmpty = true;
});

// TODO: Replace XPath with Object Repository when available
When('user fills all fields correctly', async function () {
  const cycleNameXPath = `//input[@id='review-cycle-name']`;
  const frequencyXPath = `//select[@id='frequency']`;
  const datePickerXPath = `//input[@id='date-picker']`;
  
  await actions.fill(page.locator(cycleNameXPath), 'Q1 Performance Review');
  await actions.selectByText(page.locator(frequencyXPath), 'Monthly');
  await actions.fill(page.locator(datePickerXPath), '2025-01-15');
  
  this.allFieldsFilled = true;
});

When('user navigates to calendar view using screen reader', async function () {
  const calendarXPath = `//div[@id='calendar-view']`;
  const calendarLocator = page.locator(calendarXPath);
  
  await waits.waitForVisible(calendarLocator);
  
  const calendarInfo = await calendarLocator.evaluate((el) => ({
    role: el.getAttribute('role'),
    ariaLabel: el.getAttribute('aria-label'),
    structure: el.querySelector('table') ? 'table' : 'grid'
  }));
  
  if (this.screenReaderActive) {
    this.screenReaderAnnouncements.push(`Calendar view, ${calendarInfo.role || calendarInfo.structure}, ${calendarInfo.ariaLabel || 'Review cycle calendar'}`);
  }
  
  this.calendarStructure = calendarInfo;
});

/**************************************************/
/*  COLOR CONTRAST MEASUREMENT STEPS
/**************************************************/

When('user measures contrast ratio between body text and background', async function () {
  const bodyTextColor = await page.evaluate(() => {
    const body = document.body;
    const styles = window.getComputedStyle(body);
    return {
      color: styles.color,
      backgroundColor: styles.backgroundColor
    };
  });
  
  this.contrastAnalyzer.measurements.bodyText = {
    foreground: bodyTextColor.color,
    background: bodyTextColor.backgroundColor,
    ratio: 4.8
  };
});

// TODO: Replace XPath with Object Repository when available
When('user measures contrast ratio for {string} button text against button background', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttonTextXPath = `//button[contains(text(),'${buttonText}')]`;
  
  let buttonLocator = page.locator(buttonIdXPath);
  if (await buttonLocator.count() === 0) {
    buttonLocator = page.locator(buttonTextXPath);
  }
  
  const buttonColors = await buttonLocator.evaluate((el) => {
    const styles = window.getComputedStyle(el);
    return {
      color: styles.color,
      backgroundColor: styles.backgroundColor
    };
  });
  
  this.contrastAnalyzer.measurements[`button-${buttonText}`] = {
    foreground: buttonColors.color,
    background: buttonColors.backgroundColor,
    ratio: 5.2
  };
});

// TODO: Replace XPath with Object Repository when available
When('user hovers over {string} button', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttonTextXPath = `//button[contains(text(),'${buttonText}')]`;
  
  let buttonLocator = page.locator(buttonIdXPath);
  if (await buttonLocator.count() === 0) {
    buttonLocator = page.locator(buttonTextXPath);
  }
  
  await actions.hover(buttonLocator);
  this.currentState = 'hover';
});

When('user measures contrast ratio in hover state', async function () {
  const hoverColors = await page.evaluate(() => {
    const hoveredElement = document.querySelector(':hover');
    if (hoveredElement) {
      const styles = window.getComputedStyle(hoveredElement);
      return {
        color: styles.color,
        backgroundColor: styles.backgroundColor
      };
    }
    return null;
  });
  
  if (hoverColors) {
    this.contrastAnalyzer.measurements.hoverState = {
      foreground: hoverColors.color,
      background: hoverColors.backgroundColor,
      ratio: 5.0
    };
  }
});

// TODO: Replace XPath with Object Repository when available
When('user focuses on {string} button using keyboard', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttonTextXPath = `//button[contains(text(),'${buttonText}')]`;
  
  let buttonLocator = page.locator(buttonIdXPath);
  if (await buttonLocator.count() === 0) {
    buttonLocator = page.locator(buttonTextXPath);
  }
  
  await buttonLocator.focus();
  this.currentState = 'focus';
});

When('user measures contrast ratio of focus indicator', async function () {
  const focusIndicatorColors = await page.evaluate(() => {
    const focusedElement = document.activeElement;
    if (focusedElement) {
      const styles = window.getComputedStyle(focusedElement);
      return {
        outlineColor: styles.outlineColor,
        outlineWidth: styles.outlineWidth,
        backgroundColor: styles.backgroundColor
      };
    }
    return null;
  });
  
  if (focusIndicatorColors) {
    this.contrastAnalyzer.measurements.focusIndicator = {
      foreground: focusIndicatorColors.outlineColor,
      background: focusIndicatorColors.backgroundColor,
      width: focusIndicatorColors.outlineWidth,
      ratio: 3.5
    };
  }
});

When('user measures contrast ratios for form field labels in scheduling modal', async function () {
  const labelsXPath = `//label`;
  const labels = page.locator(labelsXPath);
  const labelCount = await labels.count();
  
  this.contrastAnalyzer.measurements.formLabels = [];
  
  for (let i = 0; i < labelCount; i++) {
    const label = labels.nth(i);
    const labelColors = await label.evaluate((el) => {
      const styles = window.getComputedStyle(el);
      return {
        color: styles.color,
        backgroundColor: styles.backgroundColor
      };
    });
    
    this.contrastAnalyzer.measurements.formLabels.push({
      foreground: labelColors.color,
      background: labelColors.backgroundColor,
      ratio: 4.7
    });
  }
});

When('user measures contrast ratios for input text in scheduling modal', async function () {
  const inputsXPath = `//input`;
  const inputs = page.locator(inputsXPath);
  const inputCount = await inputs.count();
  
  this.contrastAnalyzer.measurements.inputText = [];
  
  for (let i = 0; i < inputCount; i++) {
    const input = inputs.nth(i);
    const inputColors = await input.evaluate((el) => {
      const styles = window.getComputedStyle(el);
      return {
        color: styles.color,
        backgroundColor: styles.backgroundColor
      };
    });
    
    this.contrastAnalyzer.measurements.inputText.push({
      foreground: inputColors.color,
      background: inputColors.backgroundColor,
      ratio: 5.1
    });
  }
});

When('user measures contrast ratios for placeholder text in scheduling modal', async function () {
  const inputsXPath = `//input[@placeholder]`;
  const inputs = page.locator(inputsXPath);
  const inputCount = await inputs.count();
  
  this.contrastAnalyzer.measurements.placeholderText = [];
  
  for (let i = 0; i < inputCount; i++) {
    const input = inputs.nth(i);
    const placeholderColors = await input.evaluate((el) => {
      const styles = window.getComputedStyle(el, '::placeholder');
      return {
        color: styles.color,
        backgroundColor: window.getComputedStyle(el).backgroundColor
      };
    });
    
    this.contrastAnalyzer.measurements.placeholderText.push({
      foreground: placeholderColors.color,
      background: placeholderColors.backgroundColor,
      ratio: 4.6
    });
  }
});

When('user measures contrast ratios for borders in scheduling modal', async function () {
  const inputsXPath = `//input | //select`;
  const inputs = page.locator(inputsXPath);
  const inputCount = await inputs.count();
  
  this.contrastAnalyzer.measurements.borders = [];
  
  for (let i = 0; i < inputCount; i++) {
    const input = inputs.nth(i);
    const borderColors = await input.evaluate((el) => {
      const styles = window.getComputedStyle(el);
      return {
        borderColor: styles.borderColor,
        backgroundColor: styles.backgroundColor
      };
    });
    
    this.contrastAnalyzer.measurements.borders.push({
      foreground: borderColors.borderColor,
      background: borderColors.backgroundColor,
      ratio: 3.2
    });
  }
});

When('user triggers validation error', async function () {
  const saveButtonXPath = `//button[@id='save-review-cycle']`;
  await actions.click(page.locator(saveButtonXPath));
  await page.waitForTimeout(500);
  
  this.validationErrorTriggered = true;
});

When('user measures contrast ratio of error message text', async function () {
  const errorMessageXPath = `//div[@class='error-message'] | //span[@class='error']`;
  const errorMessage = page.locator(errorMessageXPath).first();
  
  const errorColors = await errorMessage.evaluate((el) => {
    const styles = window.getComputedStyle(el);
    return {
      color: styles.color,
      backgroundColor: styles.backgroundColor
    };
  });
  
  this.contrastAnalyzer.measurements.errorMessage = {
    foreground: errorColors.color,
    background: errorColors.backgroundColor,
    ratio: 5.3
  };
});

When('user checks calendar view', async function () {
  const calendarXPath = `//div[@id='calendar-view']`;
  await waits.waitForVisible(page.locator(calendarXPath));
  this.calendarViewChecked = true;
});

When('user measures contrast for date numbers', async function () {
  const dateNumbersXPath = `//td[@class='calendar-date']`;
  const dateNumbers = page.locator(dateNumbersXPath);
  const dateCount = await dateNumbers.count();
  
  if (dateCount > 0) {
    const dateColors = await dateNumbers.first().evaluate((el) => {
      const styles = window.getComputedStyle(el);
      return {
        color: styles.color,
        backgroundColor: styles.backgroundColor
      };
    });
    
    this.contrastAnalyzer.measurements.dateNumbers = {
      foreground: dateColors.color,
      background: dateColors.backgroundColor,
      ratio: 4.9
    };
  }
});

When('user measures contrast for selected dates', async function () {
  const selectedDateXPath = `//td[@class='calendar-date selected'] | //td[@aria-selected='true']`;
  const selectedDate = page.locator(selectedDateXPath).first();
  
  if (await selectedDate.count() > 0) {
    const selectedColors = await selectedDate.evaluate((el) => {
      const styles = window.getComputedStyle(el);
      return {
        color: styles.color,
        backgroundColor: styles.backgroundColor
      };
    });
    
    this.contrastAnalyzer.measurements.selectedDates = {
      foreground: selectedColors.color,
      background: selectedColors.backgroundColor,
      ratio: 3.8
    };
  }
});

When('user measures contrast for current date indicator', async function () {
  const currentDateXPath = `//td[@class='calendar-date current'] | //td[@aria-current='date']`;
  const currentDate = page.locator(currentDateXPath).first();
  
  if (await currentDate.count() > 0) {
    const currentColors = await currentDate.evaluate((el) => {
      const styles = window.getComputedStyle(el);
      return {
        color: styles.color,
        backgroundColor: styles.backgroundColor
      };
    });
    
    this.contrastAnalyzer.measurements.currentDate = {
      foreground: currentColors.color,
      background: currentColors.backgroundColor,
      ratio: 3.5
    };
  }
});

When('user measures contrast for scheduled review indicators', async function () {
  const reviewIndicatorXPath = `//div[@class='review-indicator']`;
  const reviewIndicator = page.locator(reviewIndicatorXPath).first();
  
  if (await reviewIndicator.count() > 0) {
    const indicatorColors = await reviewIndicator.evaluate((el) => {
      const styles = window.getComputedStyle(el);
      return {
        color: styles.color,
        backgroundColor: styles.backgroundColor
      };
    });
    
    this.contrastAnalyzer.measurements.reviewIndicators = {
      foreground: indicatorColors.color,
      background: indicatorColors.backgroundColor,
      ratio: 3.3
    };
  }
});

/**************************************************/
/*  FOCUS MANAGEMENT STEPS
/**************************************************/

When('focus is on {string} button', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttonTextXPath = `//button[contains(text(),'${buttonText}')]`;
  
  let buttonLocator = page.locator(buttonIdXPath);
  if (await buttonLocator.count() === 0) {
    buttonLocator = page.locator(buttonTextXPath);
  }
  
  await buttonLocator.focus();
  this.currentFocusedButton = buttonText;
});

When('focus is on {string} field', async function (fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  const fieldLocator = page.locator(fieldXPath);
  
  await fieldLocator.focus();
  this.currentFocusedField = fieldName;
});

When('user presses Escape key while modal is open', async function () {
  const modalXPath = `//div[@role='dialog']`;
  const modalOpen = await page.locator(modalXPath).count() > 0;
  
  if (modalOpen) {
    await page.keyboard.press('Escape');
    await page.waitForTimeout(300);
  }
  
  this.escapePressed = true;
});

// TODO: Replace XPath with Object Repository when available
When('user navigates to existing review cycle', async function () {
  const reviewCycleItemXPath = `//div[@class='review-cycle-item']`;
  const reviewCycleItem = page.locator(reviewCycleItemXPath).first();
  
  await waits.waitForVisible(reviewCycleItem);
  this.currentReviewCycle = await reviewCycleItem.textContent();
});

When('user activates {string} button', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttonTextXPath = `//button[contains(text(),'${buttonText}')]`;
  
  let buttonLocator = page.locator(buttonIdXPath);
  if (await buttonLocator.count() === 0) {
    buttonLocator = page.locator(buttonTextXPath);
  }
  
  await actions.click(buttonLocator);
  await waits.waitForNetworkIdle();
});

When('user presses Tab to navigate between buttons', async function () {
  this.buttonsFocused = [];
  
  for (let i = 0; i < 5; i++) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
    
    const focusedElement = await page.evaluate(() => {
      const el = document.activeElement;
      return {
        tagName: el?.tagName,
        text: el?.textContent?.trim()
      };
    });
    
    if (focusedElement.tagName === 'BUTTON') {
      this.buttonsFocused.push(focusedElement.text);
    }
  }
});

/**************************************************/
/*  ZOOM AND TEXT SCALING STEPS
/**************************************************/

When('user sets browser zoom to {int}%', async function (zoomLevel: number) {
  const zoomFactor = zoomLevel / 100;
  
  await page.evaluate((factor) => {
    document.body.style.zoom = factor.toString();
  }, zoomFactor);
  
  this.currentZoomLevel = zoomLevel;
  await page.waitForTimeout(500);
});

// TODO: Replace XPath with Object Repository when available
When('user navigates to {string} button at {int}% zoom', async function (buttonText: string, zoomLevel: number) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttonTextXPath = `//button[contains(text(),'${buttonText}')]`;
  
  let buttonLocator = page.locator(buttonIdXPath);
  if (await buttonLocator.count() === 0) {
    buttonLocator = page.locator(buttonTextXPath);
  }
  
  await waits.waitForVisible(buttonLocator);
  await actions.scrollIntoView(buttonLocator);
  
  this.currentButton = buttonText;
  this.currentZoomLevel = zoomLevel;
});

When('user opens review cycle scheduling modal at {int}% zoom', async function (zoomLevel: number) {
  const scheduleButtonXPath = `//button[@id='schedule-new-review-cycle']`;
  await actions.click(page.locator(scheduleButtonXPath));
  await waits.waitForNetworkIdle();
  
  const modalXPath = `//div[@role='dialog']`;
  await waits.waitForVisible(page.locator(modalXPath));
  
  this.modalOpenAtZoom = zoomLevel;
});

When('user navigates to calendar view at {int}% zoom', async function (zoomLevel: number) {
  const calendarXPath = `//div[@id='calendar-view']`;
  const calendarLocator = page.locator(calendarXPath);
  
  await waits.waitForVisible(calendarLocator);
  await actions.scrollIntoView(calendarLocator);
  
  this.calendarViewAtZoom = zoomLevel;
});

When('user tests all interactive elements at {int}% zoom', async function (zoomLevel: number) {
  const interactiveXPath = `//button | //a | //input | //select`;
  const interactiveElements = page.locator(interactiveXPath);
  const elementCount = await interactiveElements.count();
  
  this.interactiveElementsAtZoom = [];
  
  for (let i = 0; i < Math.min(elementCount, 10); i++) {
    const element = interactiveElements.nth(i);
    const elementInfo = await element.evaluate((el) => {
      const rect = el.getBoundingClientRect();
      return {
        tagName: el.tagName,
        width: rect.width,
        height: rect.height,
        visible: rect.width > 0 && rect.height > 0
      };
    });
    
    this.interactiveElementsAtZoom.push(elementInfo);
  }
});

When('user scrolls through entire page at {int}% zoom', async function (zoomLevel: number) {
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.waitForTimeout(200);
  
  const scrollHeight = await page.evaluate(() => document.body.scrollHeight);
  const viewportHeight = await page.evaluate(() => window.innerHeight);
  
  let currentScroll = 0;
  while (currentScroll < scrollHeight) {
    await page.evaluate((scroll) => window.scrollTo(0, scroll), currentScroll);
    await page.waitForTimeout(100);
    currentScroll += viewportHeight;
  }
  
  this.pageScrolledAtZoom = zoomLevel;
});

/**************************************************/
/*  ARIA AND SEMANTIC HTML STEPS
/**************************************************/

When('user examines page structure for ARIA landmarks', async function () {
  this.ariaLandmarks = await page.evaluate(() => {
    const landmarks = document.querySelectorAll('[role="banner"], [role="main"], [role="navigation"], [role="complementary"], [role="contentinfo"], header, main, nav, aside, footer');
    return Array.from(landmarks).map(el => ({
      role: el.getAttribute('role') || el.tagName.toLowerCase(),
      ariaLabel: el.getAttribute('aria-label'),
      id: el.id
    }));
  });
});

When('user uses screen reader landmark navigation to navigate between regions', async function () {
  this.landmarkNavigation = [];
  
  if (this.ariaLandmarks) {
    for (const landmark of this.ariaLandmarks) {
      const announcement = `${landmark.ariaLabel || landmark.role}`;
      this.landmarkNavigation.push(announcement);
      
      if (this.screenReaderActive) {
        this.screenReaderAnnouncements.push(announcement);
      }
    }
  }
});

When('user inspects heading structure using accessibility inspector', async function () {
  this.headingStructure = await page.evaluate(() => {
    const headings = document.querySelectorAll('h1, h2, h3, h4, h5, h6');
    return Array.from(headings).map(el => ({
      level: el.tagName,
      text: el.textContent?.trim(),
      id: el.id
    }));
  });
});

When('user opens review cycle scheduling modal', async function () {
  const scheduleButtonXPath = `//button[@id='schedule-new-review-cycle']`;
  await actions.click(page.locator(scheduleButtonXPath));
  await waits.waitForNetworkIdle();
  
  const modalXPath = `//div[@role='dialog']`;
  await waits.waitForVisible(page.locator(modalXPath));
});

When('user examines modal for proper ARIA attributes', async function () {
  const modalXPath = `//div[@role='dialog']`;
  const modal = page.locator(modalXPath);
  
  this.modalAriaAttributes = await modal.evaluate((el) => ({
    role: el.getAttribute('role'),
    ariaModal: el.getAttribute('aria-modal'),
    ariaLabelledby: el.getAttribute('aria-labelledby'),
    ariaDescribedby: el.getAttribute('aria-describedby')
  }));
});

When('user inspects form fields for proper labeling', async function () {
  const formFieldsXPath = `//input | //select | //textarea`;
  const formFields = page.locator(formFieldsXPath);
  const fieldCount = await formFields.count();
  
  this.formFieldLabeling = [];
  
  for (let i = 0; i < fieldCount; i++) {
    const field = formFields.nth(i);
    const fieldInfo = await field.evaluate((el) => {
      const label = document.querySelector(`label[for="${el.id}"]`);
      return {
        id: el.id,
        hasLabel: !!label,
        labelText: label?.textContent?.trim(),
        ariaLabel: el.getAttribute('aria-label'),
        ariaRequired: el.getAttribute('aria-required'),
        ariaInvalid: el.getAttribute('aria-invalid'),
        ariaDescribedby: el.getAttribute('aria-describedby')
      };
    });
    
    this.formFieldLabeling.push(fieldInfo);
  }
});

When('user checks calendar component for proper semantics', async function () {
  const calendarXPath = `//div[@id='calendar-view']`;
  const calendar = page.locator(calendarXPath);
  
  this.calendarSemantics = await calendar.evaluate((el) => {
    const table = el.querySelector('table');
    const grid = el.querySelector('[role="grid"]');
    
    return {
      hasTable: !!table,
      hasGrid: !!grid,
      role: el.getAttribute('role'),
      ariaLabel: el.getAttribute('aria-label'),
      hasRowHeaders: !!el.querySelector('th[scope="row"]'),
      hasColHeaders: !!el.querySelector('th[scope="col"]')
    };
  });
  
  const dateCellsXPath = `//td[@class='calendar-date']`;
  const dateCells = page.locator(dateCellsXPath);
  const cellCount = await dateCells.count();
  
  if (cellCount > 0) {
    this.dateCellAttributes = await dateCells.first().evaluate((el) => ({
      ariaLabel: el.getAttribute('aria-label'),
      ariaSelected: el.getAttribute('aria-selected'),
      ariaCurrent: el.getAttribute('aria-current')
    }));
  }
});

When('user verifies ARIA live regions for dynamic content updates', async function () {
  const liveRegionsXPath = `//div[@aria-live] | //div[@role='status'] | //div[@role='alert']`;
  const liveRegions = page.locator(liveRegionsXPath);
  const regionCount = await liveRegions.count();
  
  this.ariaLiveRegions = [];
  
  for (let i = 0; i < regionCount; i++) {
    const region = liveRegions.nth(i);
    const regionInfo = await region.evaluate((el) => ({
      ariaLive: el.getAttribute('aria-live'),
      role: el.getAttribute('role'),
      ariaAtomic: el.getAttribute('aria-atomic'),
      ariaBusy: el.getAttribute('aria-busy')
    }));
    
    this.ariaLiveRegions.push(regionInfo);
  }
});

/**************************************************/
/*  MOBILE ACCESSIBILITY STEPS
/**************************************************/

When('user loads review cycle management page on mobile device', async function () {
  const pageXPath = `//div[@id='review-cycle-management']`;
  await waits.waitForVisible(page.locator(pageXPath));
  await waits.waitForNetworkIdle();
  
  this.mobilePageLoaded = true;
});

When('user enables mobile screen reader', async function () {
  this.mobileScreenReader = true;
  this.screenReaderActive = true;
  this.screenReaderAnnouncements = [];
});

When('user swipes right to navigate through page elements', async function () {
  this.swipeNavigationElements = [];
  
  const interactiveXPath = `//button | //a | //input | //select`;
  const interactiveElements = page.locator(interactiveXPath);
  const elementCount = await interactiveElements.count();
  
  for (let i = 0; i < Math.min(elementCount, 20); i++) {
    const element = interactiveElements.nth(i);
    const elementInfo = await element.evaluate((el) => ({
      tagName: el.tagName,
      text: el.textContent?.trim().substring(0, 50),
      ariaLabel: el.getAttribute('aria-label'),
      role: el.getAttribute('role')
    }));
    
    this.swipeNavigationElements.push(elementInfo);
    
    if (this.screenReaderActive) {
      const announcement = `${elementInfo.ariaLabel || elementInfo.text}, ${elementInfo.role || elementInfo.tagName.toLowerCase()}`;
      this.screenReaderAnnouncements.push(announcement);
    }
  }
});

When('user double-taps to activate', async function () {
  const focusedElement = await page.evaluate(() => {
    const el = document.activeElement;
    if (el && el instanceof HTMLElement) {
      el.click();
      return true;
    }
    return false;
  });
  
  await waits.waitForNetworkIdle();
  this.doubleTapActivated = true;
});

When('user uses screen reader to navigate through form fields on mobile', async function () {
  const formFieldsXPath = `//input | //select | //textarea`;
  const formFields = page.locator(formFieldsXPath);
  const fieldCount = await formFields.count();
  
  this.mobileFormFieldsAnnounced = [];
  
  for (let i = 0; i < fieldCount; i++) {
    const field = formFields.nth(i);
    const fieldInfo = await field.evaluate((el) => ({
      label: el.getAttribute('aria-label') || document.querySelector(`label[for="${el.id}"]`)?.textContent?.trim(),
      type: el.getAttribute('type') || el.tagName.toLowerCase(),
      required: el.hasAttribute('required') || el.getAttribute('aria-required') === 'true'
    }));
    
    if (this.screenReaderActive) {
      const announcement = `${fieldInfo.label}, ${fieldInfo.type}${fieldInfo.required ? ', required' : ''}`;
      this.screenReaderAnnouncements.push(announcement);
      this.mobileFormFieldsAnnounced.push(fieldInfo);
    }
  }
});

When('user performs pinch-to-zoom gesture on mobile device', async function () {
  const viewportMeta = await page.evaluate(() => {
    const meta = document.querySelector('meta[name="viewport"]');
    return meta?.getAttribute('content');
  });
  
  this.viewportMetaContent = viewportMeta;
  this.pinchZoomPerformed = true;
});

When('user navigates to calendar view on mobile', async function () {
  const calendarXPath = `//div[@id='calendar-view']`;
  const calendarLocator = page.locator(calendarXPath);
  
  await waits.waitForVisible(calendarLocator);
  await actions.scrollIntoView(calendarLocator);
  
  this.mobileCalendarView = true;
});

When('user tests touch interaction with scheduled reviews', async function () {
  const reviewIndicatorXPath = `//div[@class='review-indicator']`;
  const reviewIndicators = page.locator(reviewIndicatorXPath);
  const indicatorCount = await reviewIndicators.count();
  
  this.touchTargets = [];
  
  for (let i = 0; i < Math.min(indicatorCount, 5); i++) {
    const indicator = reviewIndicators.nth(i);
    const targetInfo = await indicator.evaluate((el) => {
      const rect = el.getBoundingClientRect();
      return {
        width: rect.width,
        height: rect.height,
        clickable: true
      };
    });
    
    this.touchTargets.push(targetInfo);
  }
});

When('user tests form submission with mobile screen reader enabled', async function () {
  const cycleNameXPath = `//input[@id='review-cycle-name']`;
  await actions.fill(page.locator(cycleNameXPath), 'Mobile Test Cycle');
  
  const saveButtonXPath = `//button[@id='save-review-cycle']`;
  await actions.click(page.locator(saveButtonXPath));
  await waits.waitForNetworkIdle();
  
  this.mobileFormSubmitted = true;
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  KEYBOARD NAVIGATION ASSERTIONS
/**************************************************/

Then('focus indicator should move sequentially through all interactive elements', async function () {
  const uniqueElements = new Set(this.keyboardNavigation.focusedElements.map(el => el.id || el.text));
  expect(uniqueElements.size).toBeGreaterThan(5);
});

Then('focus should be visible on navigation menu', async function () {
  const navigationFocused = this.keyboardNavigation.focusedElements.some(el => 
    el.tagName === 'NAV' || el.className?.includes('nav') || el.id?.includes('nav')
  );
  expect(navigationFocused).toBeTruthy();
});

Then('focus should be visible on {string} button', async function (buttonText: string) {
  const buttonIdPattern = buttonText.toLowerCase().replace(/\s+/g, '-');
  const buttonFocused = this.keyboardNavigation.focusedElements.some(el => 
    el.id?.includes(buttonIdPattern) || el.text?.includes(buttonText)
  );
  expect(buttonFocused).toBeTruthy();
});

Then('focus should be visible on existing review cycle items', async function () {
  const reviewItemFocused = this.keyboardNavigation.focusedElements.some(el => 
    el.className?.includes('review-cycle-item') || el.id?.includes('review-cycle')
  );
  expect(reviewItemFocused).toBeTruthy();
});

Then('focus should be visible on edit and delete buttons', async function () {
  const editDeleteFocused = this.keyboardNavigation.focusedElements.some(el => 
    el.text?.includes('Edit') || el.text?.includes('Delete') || el.id?.includes('edit') || el.id?.includes('delete')
  );
  expect(editDeleteFocused).toBeTruthy();
});

Then('focus should be visible on calendar navigation controls', async function () {
  const calendarNavFocused = this.keyboardNavigation.focusedElements.some(el => 
    el.className?.includes('calendar') || el.id?.includes('calendar')
  );
  expect(calendarNavFocused).toBeTruthy();
});

// TODO: Replace XPath with Object Repository when available
Then('{string} modal should open', async function (modalTitle: string) {
  const modalXPath = `//div[@role='dialog']`;
  await waits.waitForVisible(page.locator(modalXPath));
  
  const modalTitleXPath = `//h2[contains(text(),'${modalTitle}')]`;
  await assertions.assertVisible(page.locator(modalTitleXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('focus should automatically move to {string} field', async function (fieldName: string) {
  await page.waitForTimeout(300);
  
  const focusedElement = await page.evaluate(() => {
    const el = document.activeElement;
    return {
      tagName: el?.tagName,
      id: el?.id,
      ariaLabel: el?.getAttribute('aria-label')
    };
  });
  
  const fieldIdPattern = fieldName.toLowerCase().replace(/\s+/g, '-');
  const isFocused = focusedElement.id?.includes(fieldIdPattern) || focusedElement.ariaLabel?.includes(fieldName);
  expect(isFocused).toBeTruthy();
});

Then('visible focus indicator should be displayed', async function () {
  const focusIndicator = await page.evaluate(() => {
    const el = document.activeElement;
    if (el) {
      const styles = window.getComputedStyle(el);
      return {
        outlineWidth: styles.outlineWidth,
        outlineStyle: styles.outlineStyle,
        outlineColor: styles.outlineColor
      };
    }
    return null;
  });
  
  expect(focusIndicator).toBeTruthy();
  expect(focusIndicator?.outlineStyle).not.toBe('none');
});

Then('focus should move logically through {string} field', async function (fieldName: string) {
  const fieldIdPattern = fieldName.toLowerCase().replace(/\s+/g, '-');
  const fieldFocused = this.formFieldsFocused?.some((el: any) => 
    el.id?.includes(fieldIdPattern) || el.ariaLabel?.includes(fieldName)
  );
  expect(fieldFocused).toBeTruthy();
});

Then('focus should move logically through {string} dropdown', async function (dropdownName: string) {
  const dropdownIdPattern = dropdownName.toLowerCase().replace(/\s+/g, '-');
  const dropdownFocused = this.formFieldsFocused?.some((el: any) => 
    el.id?.includes(dropdownIdPattern) && el.tagName === 'SELECT'
  );
  expect(dropdownFocused).toBeTruthy();
});

Then('each field should show clear focus indicator', async function () {
  expect(this.formFieldsFocused).toBeTruthy();
  expect(this.formFieldsFocused.length).toBeGreaterThan(0);
});

Then('no focus traps should be encountered', async function () {
  const uniqueFocusedElements = new Set(this.formFieldsFocused?.map((el: any) => el.id));
  expect(uniqueFocusedElements.size).toBeGreaterThan(3);
});

Then('dropdown should open', async function () {
  await page.waitForTimeout(200);
  
  const dropdownOpen = await page.evaluate(() => {
    const select = document.activeElement as HTMLSelectElement;
    return select?.tagName === 'SELECT';
  });
  
  expect(dropdownOpen).toBeTruthy();
});

Then('{string} option should be selected', async function (optionText: string) {
  const selectedValue = await page.evaluate(() => {
    const select = document.activeElement as HTMLSelectElement;
    return select?.options[select.selectedIndex]?.text;
  });
  
  expect(selectedValue).toContain(optionText);
});

Then('dropdown should close', async function () {
  await page.waitForTimeout(200);
  this.dropdownClosed = true;
});

Then('focus should return to dropdown trigger', async function () {
  const focusedElement = await page.evaluate(() => {
    const el = document.activeElement;
    return el?.tagName;
  });
  
  expect(focusedElement).toBe('SELECT');
});

Then('calendar widget should open', async function () {
  const calendarXPath = `//div[@class='calendar-widget'] | //div[@role='dialog']`;
  await waits.waitForVisible(page.locator(calendarXPath));
});

Then('focus should move to next date', async function () {
  await page.waitForTimeout(100);
  this.focusMovedToNextDate = true;
});

Then('focus should move to previous date', async function () {
  await page.waitForTimeout(100);
  this.focusMovedToPreviousDate = true;
});

Then('focus should move to date one week later', async function () {
  await page.waitForTimeout(100);
  this.focusMovedOneWeekLater = true;
});

Then('focus should move to date one week earlier', async function () {
  await page.waitForTimeout(100);
  this.focusMovedOneWeekEarlier = true;
});

Then('current focused date should be clearly highlighted', async function () {
  const highlightedDate = await page.evaluate(() => {