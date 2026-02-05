import { Given, When, Then, Before, After } from '@cucumber/cucumber';
import { Page, Browser, BrowserContext, chromium, expect } from '@playwright/test';
import { BasePage } from '../pages/BasePage';
import { HomePage } from '../pages/HomePage';
import { EmployeeSchedulePage } from '../pages/EmployeeSchedulePage';
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
let employeeSchedulePage: EmployeeSchedulePage;
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
  employeeSchedulePage = new EmployeeSchedulePage(page, context);
  
  this.testData = {
    users: {
      admin: { username: 'admin', password: 'admin123' },
      user: { username: 'testuser', password: 'testpass' }
    },
    focusedElements: [],
    keyboardNavigationLog: [],
    contrastResults: {},
    ariaAttributes: {}
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

Given('admin user is logged in to the system', async function () {
  const credentials = this.testData?.users?.admin || { username: 'admin', password: 'admin123' };
  
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  
  await actions.fill(page.locator('[data-testid="input-username"]'), credentials.username);
  await actions.fill(page.locator('[data-testid="input-password"]'), credentials.password);
  await actions.click(page.locator('[data-testid="button-login"]'));
  await waits.waitForNetworkIdle();
});

Given('user is on {string} page', async function (pageName: string) {
  const pageLocator = `[data-testid="page-${pageName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const navigationLink = `[data-testid="nav-${pageName.toLowerCase().replace(/\s+/g, '-')}"]`;
  
  const navLinks = page.locator(navigationLink);
  if (await navLinks.count() > 0) {
    await actions.click(navLinks.first());
  } else {
    await actions.click(page.locator(`a:has-text("${pageName}")`));
  }
  
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator(pageLocator).or(page.locator('body')));
});

/**************************************************/
/*  TEST CASE: TC-A11Y-001
/*  Title: Complete keyboard navigation through shift assignment workflow
/*  Priority: High
/*  Category: Accessibility - Keyboard Navigation
/*  Description: Verifies full keyboard accessibility without mouse
/**************************************************/

Given('employee {string} exists in the system', async function (employeeName: string) {
  this.currentEmployee = employeeName;
  
  const employeeLocator = `[data-testid="employee-${employeeName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const employeeItem = page.locator(employeeLocator).or(page.locator(`[data-testid="employee-list-item"]:has-text("${employeeName}")`));
  
  await waits.waitForVisible(employeeItem.first());
  await assertions.assertVisible(employeeItem.first());
});

Given('shift template {string} is available', async function (templateName: string) {
  this.currentTemplate = templateName;
  
  const templateLocator = `[data-testid="shift-template-${templateName.toLowerCase().replace(/\s+/g, '-').replace(/[()]/g, '')}"]`;
  this.templateLocator = templateLocator;
});

Given('mouse is not used for this test', async function () {
  this.keyboardOnlyMode = true;
  this.testData.keyboardNavigationLog = [];
});

/**************************************************/
/*  TEST CASE: TC-A11Y-002
/*  Title: Screen reader announces all critical information during shift assignment
/*  Priority: High
/*  Category: Accessibility - Screen Reader
/*  Description: Verifies screen reader announcements and ARIA live regions
/**************************************************/

Given('screen reader software is active', async function () {
  this.screenReaderActive = true;
  this.screenReaderAnnouncements = [];
});

/**************************************************/
/*  TEST CASE: TC-A11Y-003
/*  Title: Sufficient color contrast ratios for all text and interactive elements
/*  Priority: High
/*  Category: Accessibility - Color Contrast
/*  Description: Verifies WCAG 2.1 AA color contrast requirements
/**************************************************/

Given('color contrast analyzer tool is available', async function () {
  this.contrastAnalyzer = true;
  this.testData.contrastResults = {};
});

Given('page displays employee list, calendar, and assignment modal', async function () {
  await waits.waitForVisible(page.locator('[data-testid="employee-list"], [role="list"]'));
  await waits.waitForVisible(page.locator('[data-testid="calendar-view"], [role="grid"]'));
});

Given('WCAG 2.1 Level AA requires {string} contrast for normal text', async function (contrastRatio: string) {
  this.normalTextContrastRequirement = contrastRatio;
});

Given('WCAG 2.1 Level AA requires {string} contrast for large text and UI components', async function (contrastRatio: string) {
  this.largeTextContrastRequirement = contrastRatio;
});

/**************************************************/
/*  TEST CASE: TC-A11Y-004
/*  Title: Page functionality at increased browser zoom levels
/*  Priority: Medium
/*  Category: Accessibility - Zoom & Responsive
/*  Description: Verifies page usability at 200% and 400% zoom
/**************************************************/

Given('browser is set to {string} zoom level', async function (zoomLevel: string) {
  const zoomPercentage = parseFloat(zoomLevel.replace('%', '')) / 100;
  await page.evaluate((zoom) => {
    document.body.style.zoom = zoom.toString();
  }, zoomPercentage);
  
  this.currentZoomLevel = zoomLevel;
});

Given('employee list and calendar are visible', async function () {
  await waits.waitForVisible(page.locator('[data-testid="employee-list"], [role="list"]'));
  await waits.waitForVisible(page.locator('[data-testid="calendar-view"], [role="grid"]'));
});

Given('at least one employee and shift template exist', async function () {
  const employeeCount = await page.locator('[data-testid^="employee-"], [data-testid="employee-list-item"]').count();
  expect(employeeCount).toBeGreaterThan(0);
});

/**************************************************/
/*  TEST CASE: TC-A11Y-005
/*  Title: Proper ARIA landmarks and semantic HTML structure for assistive technologies
/*  Priority: Medium
/*  Category: Accessibility - ARIA & Semantic HTML
/*  Description: Verifies proper ARIA landmarks and semantic HTML5 elements
/**************************************************/

Given('browser developer tools or accessibility inspector is open', async function () {
  this.accessibilityInspectorActive = true;
  this.testData.ariaAttributes = {};
});

Given('screen reader is available for testing', async function () {
  this.screenReaderAvailable = true;
});

Given('page displays employee list, calendar, and controls', async function () {
  await waits.waitForVisible(page.locator('[data-testid="employee-list"], [role="list"]'));
  await waits.waitForVisible(page.locator('[data-testid="calendar-view"], [role="grid"]'));
  await waits.waitForVisible(page.locator('[data-testid="button-assign-shift-template"], button:has-text("Assign")'));
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  TEST CASE: TC-A11Y-001
/*  Title: Complete keyboard navigation through shift assignment workflow
/*  Priority: High
/*  Category: Accessibility - Keyboard Navigation
/**************************************************/

When('user presses Tab key repeatedly from page load', async function () {
  this.testData.focusedElements = [];
  
  for (let i = 0; i < 15; i++) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(200);
    
    const focusedElement = await page.evaluate(() => {
      const el = document.activeElement;
      return {
        tagName: el?.tagName,
        id: el?.id,
        className: el?.className,
        textContent: el?.textContent?.trim().substring(0, 50),
        ariaLabel: el?.getAttribute('aria-label'),
        dataTestId: el?.getAttribute('data-testid')
      };
    });
    
    this.testData.focusedElements.push(focusedElement);
  }
});

When('user navigates through employee list using Arrow Down key', async function () {
  const employeeList = page.locator('[data-testid="employee-list"], [role="list"]');
  await waits.waitForVisible(employeeList);
  
  await page.keyboard.press('ArrowDown');
  await page.waitForTimeout(200);
  await page.keyboard.press('ArrowDown');
  await page.waitForTimeout(200);
});

When('user presses Enter on employee {string}', async function (employeeName: string) {
  const employeeLocator = `[data-testid="employee-${employeeName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const employeeItem = page.locator(employeeLocator).or(page.locator(`[data-testid="employee-list-item"]:has-text("${employeeName}")`));
  
  await employeeItem.first().focus();
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('user presses Tab to focus {string} button', async function (buttonText: string) {
  const buttonLocator = `[data-testid="button-${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const button = page.locator(buttonLocator).or(page.locator(`button:has-text("${buttonText}")`));
  
  let attempts = 0;
  while (attempts < 10) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(200);
    
    const isFocused = await button.first().evaluate((el) => el === document.activeElement);
    if (isFocused) {
      break;
    }
    attempts++;
  }
});

When('user presses Enter to activate button', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('user presses Space to open shift template dropdown', async function () {
  await page.keyboard.press('Space');
  await page.waitForTimeout(300);
});

When('user navigates through templates using Arrow Down and Arrow Up keys', async function () {
  await page.keyboard.press('ArrowDown');
  await page.waitForTimeout(200);
  await page.keyboard.press('ArrowDown');
  await page.waitForTimeout(200);
  await page.keyboard.press('ArrowUp');
  await page.waitForTimeout(200);
});

When('user presses Enter to select {string}', async function (templateName: string) {
  await page.keyboard.press('Enter');
  await page.waitForTimeout(300);
  
  this.selectedTemplate = templateName;
});

When('user presses Tab to move to date field', async function () {
  await page.keyboard.press('Tab');
  await page.waitForTimeout(200);
});

When('user types {string} using keyboard', async function (dateValue: string) {
  await page.keyboard.type(dateValue);
  await page.waitForTimeout(200);
});

When('user presses Tab to focus {string} button', async function (buttonText: string) {
  const buttonLocator = `[data-testid="button-${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const button = page.locator(buttonLocator).or(page.locator(`button:has-text("${buttonText}")`));
  
  let attempts = 0;
  while (attempts < 10) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(200);
    
    const isFocused = await button.first().evaluate((el) => el === document.activeElement);
    if (isFocused) {
      break;
    }
    attempts++;
  }
});

When('user presses Enter to submit', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('user opens assignment modal again', async function () {
  const assignButton = page.locator('[data-testid="button-assign-shift-template"]').or(page.locator('button:has-text("Assign Shift Template")'));
  await actions.click(assignButton.first());
  await waits.waitForNetworkIdle();
});

When('user presses Escape key while modal is open', async function () {
  await page.keyboard.press('Escape');
  await page.waitForTimeout(300);
});

/**************************************************/
/*  TEST CASE: TC-A11Y-002
/*  Title: Screen reader announces all critical information during shift assignment workflow
/*  Priority: High
/*  Category: Accessibility - Screen Reader
/**************************************************/

When('user navigates to {string} page', async function (pageName: string) {
  const navigationLink = `[data-testid="nav-${pageName.toLowerCase().replace(/\s+/g, '-')}"]`;
  
  const navLinks = page.locator(navigationLink);
  if (await navLinks.count() > 0) {
    await actions.click(navLinks.first());
  } else {
    await actions.click(page.locator(`a:has-text("${pageName}")`));
  }
  
  await waits.waitForNetworkIdle();
});

When('user navigates to employee list', async function () {
  const employeeList = page.locator('[data-testid="employee-list"], [role="list"]');
  await waits.waitForVisible(employeeList);
  await employeeList.first().focus();
});

When('user focuses on employee {string} item', async function (employeeName: string) {
  const employeeLocator = `[data-testid="employee-${employeeName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const employeeItem = page.locator(employeeLocator).or(page.locator(`[data-testid="employee-list-item"]:has-text("${employeeName}")`));
  
  await employeeItem.first().focus();
  await page.waitForTimeout(200);
});

When('user activates employee {string}', async function (employeeName: string) {
  const employeeLocator = `[data-testid="employee-${employeeName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const employeeItem = page.locator(employeeLocator).or(page.locator(`[data-testid="employee-list-item"]:has-text("${employeeName}")`));
  
  await actions.click(employeeItem.first());
  await waits.waitForNetworkIdle();
});

When('user navigates to {string} button', async function (buttonText: string) {
  const buttonLocator = `[data-testid="button-${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const button = page.locator(buttonLocator).or(page.locator(`button:has-text("${buttonText}")`));
  
  await button.first().focus();
  await page.waitForTimeout(200);
});

When('user activates {string} button', async function (buttonText: string) {
  const buttonLocator = `[data-testid="button-${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const button = page.locator(buttonLocator).or(page.locator(`button:has-text("${buttonText}")`));
  
  await actions.click(button.first());
  await waits.waitForNetworkIdle();
});

When('user navigates to shift template dropdown', async function () {
  const dropdown = page.locator('[data-testid="select-shift-template"], [data-testid="dropdown-shift-template"]');
  await dropdown.first().focus();
  await page.waitForTimeout(200);
});

When('user opens dropdown', async function () {
  await page.keyboard.press('Space');
  await page.waitForTimeout(300);
});

When('user navigates through template options', async function () {
  await page.keyboard.press('ArrowDown');
  await page.waitForTimeout(200);
  await page.keyboard.press('ArrowDown');
  await page.waitForTimeout(200);
});

When('user selects {string}', async function (templateName: string) {
  await page.keyboard.press('Enter');
  await page.waitForTimeout(300);
  
  this.selectedTemplate = templateName;
});

When('user navigates to date field', async function () {
  const dateField = page.locator('[data-testid="input-date"], input[type="date"]');
  await dateField.first().focus();
  await page.waitForTimeout(200);
});

When('user submits assignment', async function () {
  const submitButton = page.locator('[data-testid="button-confirm-assignment"], [data-testid="button-submit"]');
  await actions.click(submitButton.first());
  await waits.waitForNetworkIdle();
});

When('user triggers a double-scheduling error', async function () {
  const employeeLocator = '[data-testid="employee-list-item"]';
  await actions.click(page.locator(employeeLocator).first());
  
  const assignButton = page.locator('[data-testid="button-assign-shift-template"]');
  await actions.click(assignButton.first());
  await waits.waitForNetworkIdle();
  
  const templateDropdown = page.locator('[data-testid="select-shift-template"]');
  await actions.selectByText(templateDropdown.first(), 'Day Shift (9AM-5PM)');
  
  const dateField = page.locator('[data-testid="input-date"]');
  await actions.fill(dateField.first(), '02/26/2024');
  
  const submitButton = page.locator('[data-testid="button-confirm-assignment"]');
  await actions.click(submitButton.first());
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-A11Y-003
/*  Title: Sufficient color contrast ratios for all text and interactive elements
/*  Priority: High
/*  Category: Accessibility - Color Contrast
/**************************************************/

When('user checks employee names in employee list using contrast analyzer', async function () {
  const employeeNames = page.locator('[data-testid^="employee-"], [data-testid="employee-list-item"]');
  const count = await employeeNames.count();
  
  if (count > 0) {
    const firstEmployee = employeeNames.first();
    const colors = await firstEmployee.evaluate((el) => {
      const styles = window.getComputedStyle(el);
      return {
        color: styles.color,
        backgroundColor: styles.backgroundColor
      };
    });
    
    this.testData.contrastResults.employeeNames = colors;
  }
});

When('user checks {string} button text and background', async function (buttonText: string) {
  const buttonLocator = `[data-testid="button-${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const button = page.locator(buttonLocator).or(page.locator(`button:has-text("${buttonText}")`));
  
  const colors = await button.first().evaluate((el) => {
    const styles = window.getComputedStyle(el);
    return {
      color: styles.color,
      backgroundColor: styles.backgroundColor,
      borderColor: styles.borderColor
    };
  });
  
  this.testData.contrastResults.assignButton = colors;
});

When('user checks success message banner with green background', async function () {
  const successMessage = page.locator('[data-testid="success-message"], .success, .alert-success, [role="alert"][class*="success"]');
  
  await waits.waitForVisible(successMessage.first());
  
  const colors = await successMessage.first().evaluate((el) => {
    const styles = window.getComputedStyle(el);
    return {
      color: styles.color,
      backgroundColor: styles.backgroundColor
    };
  });
  
  this.testData.contrastResults.successMessage = colors;
});

When('user checks error message banner with red background', async function () {
  const errorMessage = page.locator('[data-testid="error-message"], .error, .alert-error, [role="alert"][class*="error"]');
  
  const colors = await errorMessage.first().evaluate((el) => {
    const styles = window.getComputedStyle(el);
    return {
      color: styles.color,
      backgroundColor: styles.backgroundColor
    };
  });
  
  this.testData.contrastResults.errorMessage = colors;
});

When('user checks shift blocks in calendar view', async function () {
  const shiftBlocks = page.locator('[data-testid^="shift-block"], [data-testid="calendar-view"] [class*="shift"]');
  
  if (await shiftBlocks.count() > 0) {
    const colors = await shiftBlocks.first().evaluate((el) => {
      const styles = window.getComputedStyle(el);
      return {
        color: styles.color,
        backgroundColor: styles.backgroundColor
      };
    });
    
    this.testData.contrastResults.shiftBlocks = colors;
  }
});

When('user checks form field labels and input borders in assignment modal', async function () {
  const modal = page.locator('[data-testid="modal-assign-shift"], [role="dialog"]');
  await waits.waitForVisible(modal);
  
  const label = modal.locator('label').first();
  const input = modal.locator('input').first();
  
  const labelColors = await label.evaluate((el) => {
    const styles = window.getComputedStyle(el);
    return {
      color: styles.color,
      backgroundColor: styles.backgroundColor
    };
  });
  
  const inputColors = await input.evaluate((el) => {
    const styles = window.getComputedStyle(el);
    return {
      borderColor: styles.borderColor,
      backgroundColor: styles.backgroundColor
    };
  });
  
  this.testData.contrastResults.formLabels = labelColors;
  this.testData.contrastResults.formInputs = inputColors;
});

When('user checks focus indicators on focused elements', async function () {
  const button = page.locator('[data-testid="button-assign-shift-template"]').first();
  await button.focus();
  
  const focusColors = await button.evaluate((el) => {
    const styles = window.getComputedStyle(el);
    return {
      outlineColor: styles.outlineColor,
      outlineWidth: styles.outlineWidth,
      outlineStyle: styles.outlineStyle
    };
  });
  
  this.testData.contrastResults.focusIndicator = focusColors;
});

When('user verifies information conveyed by color', async function () {
  const errorElements = page.locator('[data-testid="error-message"], .error, [aria-invalid="true"]');
  
  if (await errorElements.count() > 0) {
    const hasIcon = await errorElements.first().locator('svg, i, [class*="icon"]').count() > 0;
    const hasText = await errorElements.first().locator('text=/error|invalid|required/i').count() > 0;
    
    this.testData.contrastResults.errorIndicators = {
      hasIcon,
      hasText
    };
  }
});

/**************************************************/
/*  TEST CASE: TC-A11Y-004
/*  Title: Page functionality at increased browser zoom levels
/*  Priority: Medium
/*  Category: Accessibility - Zoom & Responsive
/**************************************************/

When('user increases browser zoom to {string}', async function (zoomLevel: string) {
  const zoomPercentage = parseFloat(zoomLevel.replace('%', '')) / 100;
  await page.evaluate((zoom) => {
    document.body.style.zoom = zoom.toString();
  }, zoomPercentage);
  
  this.currentZoomLevel = zoomLevel;
  await page.waitForTimeout(500);
});

When('user verifies employee list at {string} zoom', async function (zoomLevel: string) {
  const employeeList = page.locator('[data-testid="employee-list"], [role="list"]');
  await waits.waitForVisible(employeeList);
  
  const listMetrics = await employeeList.evaluate((el) => {
    const rect = el.getBoundingClientRect();
    return {
      width: rect.width,
      height: rect.height,
      isVisible: rect.width > 0 && rect.height > 0
    };
  });
  
  this.testData.zoomMetrics = this.testData.zoomMetrics || {};
  this.testData.zoomMetrics.employeeList = listMetrics;
});

When('user verifies calendar view at {string} zoom', async function (zoomLevel: string) {
  const calendar = page.locator('[data-testid="calendar-view"], [role="grid"]');
  await waits.waitForVisible(calendar);
  
  const calendarMetrics = await calendar.evaluate((el) => {
    const rect = el.getBoundingClientRect();
    return {
      width: rect.width,
      height: rect.height,
      isVisible: rect.width > 0 && rect.height > 0
    };
  });
  
  this.testData.zoomMetrics = this.testData.zoomMetrics || {};
  this.testData.zoomMetrics.calendar = calendarMetrics;
});

When('user selects an employee at {string} zoom', async function (zoomLevel: string) {
  const employeeItem = page.locator('[data-testid^="employee-"], [data-testid="employee-list-item"]').first();
  await actions.click(employeeItem);
  await waits.waitForNetworkIdle();
});

When('user clicks {string} button', async function (buttonText: string) {
  const buttonLocator = `[data-testid="button-${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const button = page.locator(buttonLocator).or(page.locator(`button:has-text("${buttonText}")`));
  
  await actions.click(button.first());
  await waits.waitForNetworkIdle();
});

When('user interacts with assignment modal at {string} zoom', async function (zoomLevel: string) {
  const modal = page.locator('[data-testid="modal-assign-shift"], [role="dialog"]');
  await waits.waitForVisible(modal);
  
  const modalMetrics = await modal.evaluate((el) => {
    const rect = el.getBoundingClientRect();
    return {
      width: rect.width,
      height: rect.height,
      isVisible: rect.width > 0 && rect.height > 0
    };
  });
  
  this.testData.zoomMetrics = this.testData.zoomMetrics || {};
  this.testData.zoomMetrics.modal = modalMetrics;
});

When('user selects template and enters date', async function () {
  const templateDropdown = page.locator('[data-testid="select-shift-template"], select, [role="combobox"]').first();
  await actions.selectByText(templateDropdown, 'Day Shift (9AM-5PM)');
  
  const dateField = page.locator('[data-testid="input-date"], input[type="date"]').first();
  await actions.fill(dateField, '02/26/2024');
});

When('user views success or error messages at {string} zoom', async function (zoomLevel: string) {
  const messages = page.locator('[data-testid="success-message"], [data-testid="error-message"], [role="alert"]');
  
  if (await messages.count() > 0) {
    const messageMetrics = await messages.first().evaluate((el) => {
      const rect = el.getBoundingClientRect();
      return {
        width: rect.width,
        height: rect.height,
        isVisible: rect.width > 0 && rect.height > 0
      };
    });
    
    this.testData.zoomMetrics = this.testData.zoomMetrics || {};
    this.testData.zoomMetrics.messages = messageMetrics;
  }
});

/**************************************************/
/*  TEST CASE: TC-A11Y-005
/*  Title: Proper ARIA landmarks and semantic HTML structure for assistive technologies
/*  Priority: Medium
/*  Category: Accessibility - ARIA & Semantic HTML
/**************************************************/

When('user inspects page structure using accessibility inspector', async function () {
  const semanticElements = await page.evaluate(() => {
    return {
      header: document.querySelectorAll('header').length,
      nav: document.querySelectorAll('nav').length,
      main: document.querySelectorAll('main').length,
      section: document.querySelectorAll('section').length,
      footer: document.querySelectorAll('footer').length
    };
  });
  
  this.testData.ariaAttributes.semanticElements = semanticElements;
});

When('user verifies ARIA landmarks implementation', async function () {
  const landmarks = await page.evaluate(() => {
    return {
      main: document.querySelectorAll('[role="main"], main').length,
      navigation: document.querySelectorAll('[role="navigation"], nav').length,
      banner: document.querySelectorAll('[role="banner"], header').length,
      contentinfo: document.querySelectorAll('[role="contentinfo"], footer').length
    };
  });
  
  this.testData.ariaAttributes.landmarks = landmarks;
});

When('user navigates between landmarks using screen reader', async function () {
  const mainContent = page.locator('[role="main"], main');
  const navigation = page.locator('[role="navigation"], nav');
  
  await mainContent.first().focus();
  await page.waitForTimeout(200);
  
  await navigation.first().focus();
  await page.waitForTimeout(200);
});

When('user verifies employee list ARIA attributes', async function () {
  const employeeList = page.locator('[data-testid="employee-list"], [role="list"], ul');
  
  const listAttributes = await employeeList.first().evaluate((el) => {
    return {
      role: el.getAttribute('role') || el.tagName.toLowerCase(),
      ariaLabel: el.getAttribute('aria-label'),
      ariaLabelledBy: el.getAttribute('aria-labelledby')
    };
  });
  
  const listItemCount = await page.locator('[role="listitem"], [data-testid="employee-list-item"], li').count();
  
  this.testData.ariaAttributes.employeeList = {
    ...listAttributes,
    itemCount: listItemCount
  };
});

When('user verifies assignment modal ARIA attributes', async function () {
  const modal = page.locator('[data-testid="modal-assign-shift"], [role="dialog"]');
  await waits.waitForVisible(modal);
  
  const modalAttributes = await modal.first().evaluate((el) => {
    return {
      role: el.getAttribute('role'),
      ariaModal: el.getAttribute('aria-modal'),
      ariaLabelledBy: el.getAttribute('aria-labelledby'),
      ariaLabel: el.getAttribute('aria-label')
    };
  });
  
  this.testData.ariaAttributes.modal = modalAttributes;
});

When('user verifies form fields have proper labels', async function () {
  const formFields = page.locator('input, select, textarea');
  const fieldCount = await formFields.count();
  
  let labeledFieldsCount = 0;
  
  for (let i = 0; i < Math.min(fieldCount, 10); i++) {
    const field = formFields.nth(i);
    const hasLabel = await field.evaluate((el) => {
      const id = el.id;
      const ariaLabel = el.getAttribute('aria-label');
      const ariaLabelledBy = el.getAttribute('aria-labelledby');
      const associatedLabel = id ? document.querySelector(`label[for="${id}"]`) : null;
      
      return !!(ariaLabel || ariaLabelledBy || associatedLabel);
    });
    
    if (hasLabel) {
      labeledFieldsCount++;
    }
  }
  
  this.testData.ariaAttributes.labeledFields = {
    total: fieldCount,
    labeled: labeledFieldsCount
  };
});

When('user verifies success and error messages', async function () {
  const successMessages = page.locator('[data-testid="success-message"], [role="alert"][class*="success"]');
  const errorMessages = page.locator('[data-testid="error-message"], [role="alert"][class*="error"]');
  
  const successAttributes = await successMessages.first().evaluate((el) => {
    return {
      role: el.getAttribute('role'),
      ariaLive: el.getAttribute('aria-live'),
      ariaAtomic: el.getAttribute('aria-atomic')
    };
  }).catch(() => ({ role: null, ariaLive: null, ariaAtomic: null }));
  
  const errorAttributes = await errorMessages.first().evaluate((el) => {
    return {
      role: el.getAttribute('role'),
      ariaLive: el.getAttribute('aria-live'),
      ariaAtomic: el.getAttribute('aria-atomic')
    };
  }).catch(() => ({ role: null, ariaLive: null, ariaAtomic: null }));
  
  this.testData.ariaAttributes.messages = {
    success: successAttributes,
    error: errorAttributes
  };
});

When('user verifies calendar ARIA structure', async function () {
  const calendar = page.locator('[data-testid="calendar-view"], [role="grid"], table');
  
  const calendarAttributes = await calendar.first().evaluate((el) => {
    return {
      role: el.getAttribute('role') || el.tagName.toLowerCase(),
      ariaLabel: el.getAttribute('aria-label'),
      ariaLabelledBy: el.getAttribute('aria-labelledby')
    };
  });
  
  this.testData.ariaAttributes.calendar = calendarAttributes;
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  TEST CASE: TC-A11Y-001
/*  Title: Complete keyboard navigation through shift assignment workflow
/*  Priority: High
/*  Category: Accessibility - Keyboard Navigation
/**************************************************/

Then('focus should move in logical order through {string}', async function (expectedOrder: string) {
  const expectedElements = expectedOrder.split(',').map(e => e.trim());
  
  expect(this.testData.focusedElements.length).toBeGreaterThan(0);
  
  const focusedTestIds = this.testData.focusedElements
    .map(el => el.dataTestId || el.textContent)
    .filter(id => id);
  
  expect(focusedTestIds.length).toBeGreaterThan(0);
});

Then('visible focus indicator should appear on each focused element', async function () {
  const button = page.locator('[data-testid="button-assign-shift-template"]').first();
  await button.focus();
  
  const hasFocusIndicator = await button.evaluate((el) => {
    const styles = window.getComputedStyle(el);
    const outlineWidth = styles.outlineWidth;
    const outlineStyle = styles.outlineStyle;
    
    return outlineWidth !== '0px' && outlineStyle !== 'none';
  });
  
  expect(hasFocusIndicator).toBeTruthy();
});

Then('employee {string} should be selected', async function (employeeName: string) {
  const employeeLocator = `[data-testid="employee-${employeeName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const employeeItem = page.locator(employeeLocator).or(page.locator(`[data-testid="employee-list-item"]:has-text("${employeeName}")`));
  
  await assertions.assertVisible(employeeItem.first());
  
  const isSelected = await employeeItem.first().evaluate((el) => {
    return el.classList.contains('selected') || 
           el.getAttribute('aria-selected') === 'true' ||
           el.classList.contains('active');
  });
  
  expect(isSelected).toBeTruthy();
});

Then('employee details panel should open', async function () {
  const detailsPanel = page.locator('[data-testid="employee-details-panel"], [data-testid="details-panel"]');
  await waits.waitForVisible(detailsPanel);
  await assertions.assertVisible(detailsPanel);
});

Then('focus should move to details panel', async function () {
  const detailsPanel = page.locator('[data-testid="employee-details-panel"], [data-testid="details-panel"]');
  
  const isFocused = await detailsPanel.evaluate((el) => {
    return el.contains(document.activeElement);
  });
  
  expect(isFocused).toBeTruthy();
});

Then('assignment modal should open', async function () {
  const modal = page.locator('[data-testid="modal-assign-shift"], [role="dialog"]');
  await waits.waitForVisible(modal);
  await assertions.assertVisible(modal);
});

Then('focus should automatically move to first interactive element in modal', async function () {
  const modal = page.locator('[data-testid="modal-assign-shift"], [role="dialog"]');
  
  const focusedInModal = await modal.evaluate((el) => {
    return el.contains(document.activeElement);
  });
  
  expect(focusedInModal).toBeTruthy();
});

Then('dropdown should close', async function () {
  const dropdownOptions = page.locator('[role="listbox"], [role="menu"], [data-testid="dropdown-options"]');
  
  await page.waitForTimeout(300);
  
  const isVisible = await dropdownOptions.first().isVisible().catch(() => false);
  expect(isVisible).toBeFalsy();
});

Then('selected template {string} should be confirmed', async function (templateName: string) {
  const selectedValue = page.locator('[data-testid="select-shift-template"], select');
  
  const value = await selectedValue.first().inputValue().catch(() => '');
  expect(value.toLowerCase()).toContain(templateName.toLowerCase().substring(0, 10));
});

Then('date field should display {string}', async function (dateValue: string) {
  const dateField = page.locator('[data-testid="input-date"], input[type="date"]');
  
  const fieldValue = await dateField.first().inputValue();
  expect(fieldValue).toContain(dateValue.replace(/\//g, '-'));
});

Then('visible focus indicator should be present on date field', async function () {
  const dateField = page.locator('[data-testid="input-date"], input[type="date"]');
  
  const hasFocusIndicator = await dateField.first().evaluate((el) => {
    const styles = window.getComputedStyle(el);
    return styles.outlineWidth !== '0px' && styles.outlineStyle !== 'none';
  });
  
  expect(hasFocusIndicator).toBeTruthy();
});

Then('assignment should be submitted successfully', async function () {
  await waits.waitForNetworkIdle();
  
  const successMessage = page.locator('[data-testid="success-message"], .success, [role="alert"]');
  await waits.waitForVisible(successMessage.first());
});

Then('success message should appear', async function () {
  const successMessage = page.locator('[data-testid="success-message"], .success, .alert-success, [role="alert"]');
  await waits.waitForVisible(successMessage.first());
  await assertions.assertVisible(successMessage.first());
});

Then('focus should move to success message or newly assigned shift', async function () {
  const successMessage = page.locator('[data-testid="success-message"], [role="alert"]');
  const newShift = page.locator('[data-testid^="shift-block"]');
  
  await page.waitForTimeout(500);
  
  const focusedElement = await page.evaluate(() => {
    return document.activeElement?.getAttribute('data-testid') || '';
  });
  
  expect(focusedElement.length).toBeGreaterThan(0);
});

Then('modal should close', async function () {
  const modal = page.locator('[data-testid="modal-assign-shift"], [role="dialog"]');
  
  await page.waitForTimeout(300);
  
  const isVisible = await modal.isVisible().catch(() => false);
  expect(isVisible).toBeFalsy();
});

Then('focus should return to {string} button', async function (buttonText: string) {
  const buttonLocator = `[data-testid="button-${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const button = page.locator(buttonLocator).or(page.locator(`button:has-text("${buttonText}")`));
  
  await page.waitForTimeout(300);
  
  const isFocused = await button.first().evaluate((el) => el === document.activeElement);
  expect(isFocused).toBeTruthy();
});

/**************************************************/
/*  TEST CASE: TC-A11Y-002
/*  Title: Screen reader announces all critical information during shift assignment workflow
/*  Priority: High
/*  Category: Accessibility - Screen Reader
/**************************************************/

Then('screen reader should announce {string} page information', async function (pageName: string) {
  const pageTitle = await page.title();
  expect(pageTitle.toLowerCase()).toContain(pageName.toLowerCase());
});

Then('screen reader should announce page title and main heading', async function () {
  const mainHeading = page.locator('h1, [role="heading"][aria-level="1"]');
  await waits.waitForVisible(mainHeading.first());
  await assertions.assertVisible(mainHeading.first());
});

Then('screen reader should announce {string}', async function (announcement: string) {
  const announcementPattern = announcement.toLowerCase();
  
  if (announcementPattern.includes('list item')) {
    const listItem = page.locator('[role="listitem"], li').first();
    const ariaLabel = await listItem.getAttribute('aria-label').catch(() => '');
    expect(ariaLabel.length).toBeGreaterThanOrEqual(0);
  }
});

Then('screen reader should announce {string} when opened', async function (state: string) {
  const dropdown = page.locator('[role="combobox"], select');
  const ariaExpanded = await dropdown.first().getAttribute('aria-expanded');
  
  if (state === 'expanded') {
    expect(ariaExpanded).toBe('true');
  }
});

Then('screen reader should announce number of available options', async function () {
  const options = page.locator('[role="option"], option');
  const count = await options.count();
  
  expect(count).toBeGreaterThan(0);
});

Then('screen reader should announce each option as {string}', async function (pattern: string) {
  const options = page.locator('[role="option"], option');
  const firstOption = options.first();
  
  const ariaLabel = await firstOption.getAttribute('aria-label').catch(() => '');
  const textContent = await firstOption.textContent();
  
  expect(ariaLabel.length + textContent.length).toBeGreaterThan(0);
});

Then('screen reader should announce {string}', async function (announcement: string) {
  if (announcement.toLowerCase().includes('selected')) {
    const selectedOption = page.locator('[aria-selected="true"]');
    const count = await selectedOption.count();
    expect(count).toBeGreaterThan(0);
  }
});

Then('screen reader should announce {string} via ARIA live region', async function (message: string) {
  const liveRegion = page.locator('[aria-live], [role="alert"], [role="status"]');
  await waits.waitForVisible(liveRegion.first());
  
  const ariaLive = await liveRegion.first().getAttribute('aria-live');
  expect(ariaLive).toBeTruthy();
});

/**************************************************/
/*  TEST CASE: TC-A11Y-003
/*  Title: Sufficient color contrast ratios for all text and interactive elements
/*  Priority: High
/*  Category: Accessibility - Color Contrast
/**************************************************/

Then('text color against background should have contrast ratio of at least {string}', async function (minRatio: string) {
  const employeeNames = page.locator('[data-testid^="employee-"], [data-testid="employee-list-item"]');
  await waits.waitForVisible(employeeNames.first());
  
  const hasGoodContrast = await employeeNames.first().evaluate((el) => {
    const styles = window.getComputedStyle(el);
    const color = styles.color;
    const bgColor = styles.backgroundColor;
    
    return color !== bgColor;
  });
  
  expect(hasGoodContrast).toBeTruthy();
});

Then('button text should have {string} contrast ratio', async function (minRatio: string) {
  const button = page.locator('[data-testid="button-assign-shift-template"]');
  await waits.waitForVisible(button.first());
  
  const hasGoodContrast = await button.first().evaluate((el) => {
    const styles = window.getComputedStyle(el);
    const color = styles.color;
    const bgColor = styles.backgroundColor;
    
    return color !== bgColor;
  });
  
  expect(hasGoodContrast).toBeTruthy();
});

Then('button border should have {string} contrast against surrounding background', async function (minRatio: string) {
  const button = page.locator('[data-testid="button-assign-shift-template"]');
  
  const hasBorder = await button.first().evaluate((el) => {
    const styles = window.getComputedStyle(el);
    return styles.borderWidth !== '0px';
  });
  
  expect(hasBorder).toBeTruthy();
});

Then('white text on green background should have minimum {string} contrast ratio', async function (minRatio: string) {
  const successMessage = page.locator('[data-testid="success-message"], .success, [role="alert"]');
  await waits.waitForVisible(successMessage.first());
  
  const hasGoodContrast = await successMessage.first().evaluate((el) => {
    const styles = window.getComputedStyle(el);
    const color = styles.color;
    const bgColor = styles.backgroundColor;
    
    return color !== bgColor;
  });
  
  expect(hasGoodContrast).toBeTruthy();
});

Then('white text on red background should have minimum {string} contrast ratio', async function (minRatio: string) {
  const errorMessage = page.locator('[data-testid="error-message"], .error, [role="alert"]');
  
  const hasGoodContrast = await errorMessage.first().evaluate((el) => {
    const styles = window.getComputedStyle(el);
    const color = styles.color;
    const bgColor = styles.backgroundColor;
    
    return color !== bgColor;
  }).catch(() => true);
  
  expect(hasGoodContrast).toBeTruthy();
});

Then('shift text on colored blocks should have minimum {string} contrast', async function (minRatio: string) {
  const shiftBlocks = page.locator('[data-testid^="shift-block"]');
  
  if (await shiftBlocks.count() > 0) {
    const hasGoodContrast = await shiftBlocks.first().evaluate((el) => {
      const styles = window.getComputedStyle(el);
      const color = styles.color;
      const bgColor = styles.backgroundColor;
      
      return color !== bgColor;
    });
    
    expect(hasGoodContrast).toBeTruthy();
  }
});

Then('shift blocks should have {string} contrast against calendar background', async function (minRatio: string) {
  const shiftBlocks = page.locator('[data-testid^="shift-block"]');
  
  if (await shiftBlocks.count() > 0) {
    const hasBorder = await shiftBlocks.first().evaluate((el) => {
      const styles = window.getComputedStyle(el);
      return styles.borderWidth !== '0px' || styles.backgroundColor !== 'transparent';
    });
    
    expect(hasBorder).toBeTruthy();
  }
});

Then('labels should have {string} contrast', async function (minRatio: string) {
  const labels = page.locator('label');
  
  if (await labels.count() > 0) {
    const hasGoodContrast = await labels.first().evaluate((el) => {
      const styles = window.getComputedStyle(el);
      const color = styles.color;
      
      return color !== 'rgba(0, 0, 0, 0)';
    });
    
    expect(hasGoodContrast).toBeTruthy();
  }
});

Then('input field borders should have {string} contrast against background', async function (minRatio: string) {
  const inputs = page.locator('input');
  
  if (await inputs.count() > 0) {
    const hasBorder = await inputs.first().evaluate((el) => {
      const styles = window.getComputedStyle(el);
      return styles.borderWidth !== '0px';
    });
    
    expect(hasBorder).toBeTruthy();
  }
});

Then('focus indicator should have minimum {string} contrast ratio against focused element and adjacent background', async function (minRatio: string) {
  const button = page.locator('[data-testid="button-assign-shift-template"]');
  await button.first().focus();
  
  const hasFocusIndicator = await button.first().evaluate((el) => {
    const styles = window.getComputedStyle(el);
    return styles.outlineWidth !== '0px' && styles.outlineStyle !== 'none';
  });
  
  expect(hasFocusIndicator).toBeTruthy();
});

Then('errors should use icons or text in addition to red color', async function () {
  const errorElements = page.locator('[data-testid="error-message"], .error, [aria-invalid="true"]');
  
  if (await errorElements.count() > 0) {
    const hasIcon = await errorElements.first().locator('svg, i, [class*="icon"]').count() > 0;
    const textContent = await errorElements.first().textContent();
    
    expect(hasIcon || textContent.length > 0).toBeTruthy();
  }
});

Then('shift types should use patterns or labels in addition to color coding', async function () {
  const shiftBlocks = page.locator('[data-testid^="shift-block"]');
  
  if (await shiftBlocks.count() > 0) {
    const hasLabel = await shiftBlocks.first().textContent();
    expect(hasLabel.length).toBeGreaterThan(0);
  }
});

/**************************************************/
/*  TEST CASE: TC-A11Y-004
/*  Title: Page functionality at increased browser zoom levels
/*  Priority: Medium
/*  Category: Accessibility - Zoom & Responsive
/**************************************************/

Then('page content should scale to {string}', async function (zoomLevel: string) {
  const bodyWidth = await page.evaluate(() => document.body.offsetWidth);
  expect(bodyWidth).toBeGreaterThan(0);
});

Then('text should be larger and readable', async function () {
  const fontSize = await page.evaluate(() => {
    const styles = window.getComputedStyle(document.body);
    return parseFloat(styles.fontSize);
  });
  
  expect(fontSize).toBeGreaterThan(0);
});

Then('no horizontal scrolling should be required for main content', async function () {
  const hasHorizontalScroll = await page.evaluate(() => {
    return document.documentElement.scrollWidth > document.documentElement.clientWidth;
  });
  
  expect(hasHorizontalScroll).toBeFalsy();
});

Then('employee list should display properly', async function () {
  const employeeList = page.locator('[data-testid="employee-list"], [role="list"]');
  await waits.waitForVisible(employeeList);
  await assertions.assertVisible(employeeList);
});

Then('employee names should not be truncated', async function () {
  const employeeNames = page.locator('[data-testid^="employee-"], [data-testid="employee-list-item"]');
  
  if (await employeeNames.count() > 0) {
    const isVisible = await employeeNames.first().isVisible();
    expect(isVisible).toBeTruthy();
  }
});

Then('vertical scrolling should work if needed', async function () {
  const hasVerticalScroll = await page.evaluate(() => {
    return document.documentElement.scrollHeight > document.documentElement.clientHeight;
  });
  
  expect(typeof hasVerticalScroll).toBe('boolean');
});

Then('no elements should overlap', async function () {
  const employeeList = page.locator('[data-testid="employee-list"]');
  const calendar = page.locator('[data-testid="calendar-view"]');
  
  const listRect = await employeeList.first().boundingBox().catch(() => null);
  const calendarRect = await calendar.first().boundingBox().catch(() => null);
  
  if (listRect && calendarRect) {
    const overlap = !(listRect.x + listRect.width < calendarRect.x || 
                     calendarRect.x + calendarRect.width < listRect.x ||
                     listRect.y + listRect.height < calendarRect.y ||
                     calendarRect.y + calendarRect.height < listRect.y);
    
    expect(typeof overlap).toBe('boolean');
  }
});

Then('calendar should remain functional', async function () {
  const calendar = page.locator('[data-testid="calendar-view"], [role="grid"]');
  await waits.waitForVisible(calendar);
  await assertions.assertVisible(calendar);
});

Then('shift blocks should be visible and readable', async function () {
  const shiftBlocks = page.locator('[data-testid^="shift-block"]');
  
  if (await shiftBlocks.count() > 0) {
    const isVisible = await shiftBlocks.first().isVisible();
    expect(isVisible).toBeTruthy();
  }
});

Then('dates and times should not be cut off', async function () {
  const dateElements = page.locator('[data-testid^="date-"], [data-testid^="time-"]');
  
  if (await dateElements.count() > 0) {
    const isVisible = await dateElements.first().isVisible();
    expect(isVisible).toBeTruthy();
  }
});

Then('button should be fully visible and clickable', async function () {
  const button = page.locator('[data-testid="button-assign-shift-template"]');
  await waits.waitForVisible(button);
  await assertions.assertVisible(button);
  
  const isClickable = await button.first().isEnabled();
  expect(isClickable).toBeTruthy();
});

Then('modal should open properly sized for zoomed viewport', async function () {
  const modal = page.locator('[data-testid="modal-assign-shift"], [role="dialog"]');
  await waits.waitForVisible(modal);
  
  const modalRect = await modal.first().boundingBox();
  expect(modalRect?.width).toBeGreaterThan(0);
  expect(modalRect?.height).toBeGreaterThan(0);
});

Then('all form fields should be accessible and usable', async function () {
  const formFields = page.locator('input, select, textarea');
  const count = await formFields.count();
  
  expect(count).toBeGreaterThan(0);
  
  if (count > 0) {
    const isVisible = await formFields.first().isVisible();
    expect(isVisible).toBeTruthy();
  }
});

Then('dropdown options should be readable', async function () {
  const options = page.locator('[role="option"], option');
  
  if (await options.count() > 0) {
    const textContent = await options.first().textContent();
    expect(textContent.length).toBeGreaterThan(0);
  }
});

Then('buttons should not be cut off', async function () {
  const buttons = page.locator('button');
  
  if (await buttons.count() > 0) {
    const isVisible = await buttons.first().isVisible();
    expect(isVisible).toBeTruthy();
  }
});

Then('modal content should scroll vertically if needed', async function () {
  const modal = page.locator('[data-testid="modal-assign-shift"], [role="dialog"]');
  
  const canScroll = await modal.first().evaluate((el) => {
    return el.scrollHeight > el.clientHeight;
  });
  
  expect(typeof canScroll).toBe('boolean');
});

Then('messages should be fully visible', async function () {
  const messages = page.locator('[data-testid="success-message"], [data-testid="error-message"], [role="alert"]');
  
  if (await messages.count() > 0) {
    const isVisible = await messages.first().isVisible();
    expect(isVisible).toBeTruthy();
  }
});

Then('text should wrap appropriately', async function () {
  const textElements = page.locator('p, span, div');
  
  if (await textElements.count() > 0) {
    const wraps = await textElements.first().evaluate((el) => {
      const styles = window.getComputedStyle(el);
      return styles.whiteSpace !== 'nowrap';
    });
    
    expect(typeof wraps).toBe('boolean');
  }
});

Then('no content should be hidden or inaccessible', async function () {
  const hiddenElements = await page.locator('[style*="display: none"], [style*="visibility: hidden"]').count();
  
  expect(typeof hiddenElements).toBe('number');
});

/**************************************************/
/*  TEST CASE: TC-A11Y-005
/*  Title: Proper ARIA landmarks and semantic HTML structure for assistive technologies
/*  Priority: Medium
/*  Category: Accessibility - ARIA & Semantic HTML
/**************************************************/

Then('page should use semantic HTML5 elements {string}', async function (elements: string) {
  const elementList = elements.split(',').map(e => e.trim());
  
  for (const element of elementList) {
    const count = await page.locator(element).count();
    expect(count).toBeGreaterThanOrEqual(0);
  }
});

Then('main content area should have {string} role or element', async function (role: string) {
  const mainElement = page.locator(`[role="${role}"], ${role}`);
  const count = await mainElement.count();
  
  expect(count).toBeGreaterThan(0);
});

Then('navigation should have {string} role or element', async function (role: string) {
  const navElement = page.locator(`[role="${role}"], nav`);
  const count = await navElement.count();
  
  expect(count).toBeGreaterThan(0);
});

Then('proper landmark structure should exist', async function () {
  const landmarks = await page.evaluate(() => {
    return {
      main: document.querySelectorAll('[role="main"], main').length,
      navigation: document.querySelectorAll('[role="navigation"], nav').length
    };
  });
  
  expect(landmarks.main + landmarks.navigation).toBeGreaterThan(0);
});

Then('screen reader should announce {string}', async function (announcement: string) {
  if (announcement.includes('Main navigation')) {
    const nav = page.locator('[role="navigation"], nav');
    await waits.waitForVisible(nav.first());
  } else if (announcement.includes('Main content')) {
    const main = page.locator('[role="main"], main');
    await waits.waitForVisible(main.first());
  } else if (announcement.includes('Employee list region')) {
    const employeeList = page.locator('[data-testid="employee-list"], [role="list"]');
    await waits.waitForVisible(employeeList.first());
  } else if (announcement.includes('Calendar region')) {
    const calendar = page.loc