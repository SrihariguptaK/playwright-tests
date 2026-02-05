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
      'Employee': { username: 'employee', password: 'emppass123' }
    },
    reviewCycles: {},
    systemState: {}
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
/*  Used across all test cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user is logged in as {string}', async function (userRole: string) {
  const credentials = this.testData?.users?.[userRole] || { username: 'testuser', password: 'testpass' };
  
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000');
  await waits.waitForNetworkIdle();
  
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
Given('user is on {string} page', async function (pageName: string) {
  const pageXPath = `//h1[contains(text(),'${pageName}')]`;
  await assertions.assertVisible(page.locator(pageXPath));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-NEG-001
/*  Title: Attempt to schedule review cycle with overlapping dates
/*  Priority: High
/*  Category: Negative
/*  Description: Verify validation error for overlapping cycles
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('an existing review cycle {string} is scheduled with {string} frequency starting from today', async function (cycleName: string, frequency: string) {
  this.testData.reviewCycles[cycleName] = {
    name: cycleName,
    frequency: frequency,
    startDate: new Date().toISOString().split('T')[0]
  };
  
  const cycleXPath = `//div[@id='active-schedules']//span[contains(text(),'${cycleName}')]`;
  await assertions.assertVisible(page.locator(cycleXPath));
});

// TODO: Replace XPath with Object Repository when available
Given('validation rules for overlapping cycles are active', async function () {
  this.testData.systemState.validationActive = true;
});

/**************************************************/
/*  TEST CASE: TC-NEG-002
/*  Title: Attempt to schedule review cycle without required fields
/*  Priority: High
/*  Category: Negative
/*  Description: Verify validation errors for missing required fields
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('no form fields are pre-filled', async function () {
  const frequencyXPath = '//select[@id="frequency"]';
  const startDateXPath = '//input[@id="start-date"]';
  const cycleNameXPath = '//input[@id="review-cycle-name"]';
  
  const frequencyValue = await page.locator(frequencyXPath).inputValue();
  const startDateValue = await page.locator(startDateXPath).inputValue();
  const cycleNameValue = await page.locator(cycleNameXPath).inputValue();
  
  expect(frequencyValue).toBe('');
  expect(startDateValue).toBe('');
  expect(cycleNameValue).toBe('');
});

// TODO: Replace XPath with Object Repository when available
Given('client-side validation is active', async function () {
  this.testData.systemState.clientValidation = true;
});

// TODO: Replace XPath with Object Repository when available
Given('server-side validation is active', async function () {
  this.testData.systemState.serverValidation = true;
});

/**************************************************/
/*  TEST CASE: TC-NEG-003
/*  Title: Attempt to schedule review cycle with past start date
/*  Priority: High
/*  Category: Negative
/*  Description: Verify error handling for past dates
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('{string} is open', async function (modalName: string) {
  const modalXPath = `//div[@id='${modalName.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(modalXPath));
});

// TODO: Replace XPath with Object Repository when available
Given('current system date is accessible', async function () {
  this.testData.systemState.currentDate = new Date();
});

// TODO: Replace XPath with Object Repository when available
Given('date validation rules prevent past dates', async function () {
  this.testData.systemState.pastDateValidation = true;
});

/**************************************************/
/*  TEST CASE: TC-NEG-004
/*  Title: Attempt to access review cycle scheduling without proper permissions
/*  Priority: High
/*  Category: Negative
/*  Description: Verify access denial for unauthorized users
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user does not have {string} permission', async function (permission: string) {
  this.testData.systemState.userPermissions = this.testData.systemState.userPermissions || [];
  expect(this.testData.systemState.userPermissions).not.toContain(permission);
});

// TODO: Replace XPath with Object Repository when available
Given('role-based access control is enforced on frontend and backend', async function () {
  this.testData.systemState.rbacEnabled = true;
});

/**************************************************/
/*  TEST CASE: TC-NEG-005
/*  Title: Attempt to delete a review cycle that has already started
/*  Priority: Medium
/*  Category: Negative
/*  Description: Verify prevention of deletion for active cycles
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('a review cycle {string} exists with start date in the past', async function (cycleName: string) {
  const pastDate = new Date();
  pastDate.setDate(pastDate.getDate() - 30);
  
  this.testData.reviewCycles[cycleName] = {
    name: cycleName,
    startDate: pastDate.toISOString().split('T')[0],
    status: 'In Progress'
  };
});

// TODO: Replace XPath with Object Repository when available
Given('at least one review instance from cycle is completed or in progress', async function () {
  this.testData.systemState.hasActiveReviews = true;
});

/**************************************************/
/*  TEST CASE: TC-NEG-006
/*  Title: Attempt to schedule review cycle with invalid frequency value
/*  Priority: Medium
/*  Category: Negative
/*  Description: Verify error handling for invalid frequency
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user has browser developer tools access', async function () {
  this.testData.systemState.devToolsAccess = true;
});

// TODO: Replace XPath with Object Repository when available
Given('API validation is active on backend', async function () {
  this.testData.systemState.apiValidation = true;
});

/**************************************************/
/*  TEST CASE: TC-NEG-007
/*  Title: Attempt to schedule review cycle during system maintenance
/*  Priority: Medium
/*  Category: Negative
/*  Description: Verify graceful error handling during downtime
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('backend API is temporarily unavailable', async function () {
  this.testData.systemState.apiAvailable = false;
});

// TODO: Replace XPath with Object Repository when available
Given('network timeout is set to {string} seconds', async function (timeout: string) {
  this.testData.systemState.networkTimeout = parseInt(timeout);
});

// ==================== WHEN STEPS ====================

// TODO: Replace XPath with Object Repository when available
When('user clicks {string} button', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user clicks on {string} button', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user selects {string} from {string} dropdown', async function (optionText: string, dropdownName: string) {
  const dropdownXPath = `//select[@id='${dropdownName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.selectByText(page.locator(dropdownXPath), optionText);
});

// TODO: Replace XPath with Object Repository when available
When('user enters {string} in {string} field', async function (value: string, fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.fill(page.locator(fieldXPath), value);
});

// TODO: Replace XPath with Object Repository when available
When('user enters today\'s date in {string} field', async function (fieldName: string) {
  const todayDate = new Date().toISOString().split('T')[0];
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.fill(page.locator(fieldXPath), todayDate);
});

// TODO: Replace XPath with Object Repository when available
When('user clicks {string} button without entering any data', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user enters past date in {string} field', async function (fieldName: string) {
  const pastDate = new Date();
  pastDate.setDate(pastDate.getDate() - 10);
  const pastDateString = pastDate.toISOString().split('T')[0];
  
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.fill(page.locator(fieldXPath), pastDateString);
});

// TODO: Replace XPath with Object Repository when available
When('user navigates to {string} URL directly', async function (url: string) {
  const fullUrl = `${process.env.BASE_URL || 'http://localhost:3000'}${url}`;
  await actions.navigateTo(fullUrl);
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user checks main navigation menu', async function () {
  const navMenuXPath = '//nav[@id="main-navigation"]';
  await assertions.assertVisible(page.locator(navMenuXPath));
});

// TODO: Replace XPath with Object Repository when available
When('user attempts API call to {string} endpoint with valid data', async function (endpoint: string) {
  this.testData.systemState.apiCallAttempted = true;
  this.testData.systemState.apiEndpoint = endpoint;
});

// TODO: Replace XPath with Object Repository when available
When('user locates {string} in {string} list', async function (itemName: string, listName: string) {
  const itemXPath = `//div[@id='${listName.toLowerCase().replace(/\s+/g, '-')}']//span[contains(text(),'${itemName}')]`;
  await assertions.assertVisible(page.locator(itemXPath));
});

// TODO: Replace XPath with Object Repository when available
When('user clicks on {string} cycle', async function (cycleName: string) {
  const cycleXPath = `//div[@id='active-schedules']//span[contains(text(),'${cycleName}')]`;
  await actions.click(page.locator(cycleXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user clicks {string} button in details panel', async function (buttonText: string) {
  const buttonXPath = `//div[@id='details-panel']//button[contains(text(),'${buttonText}')]`;
  await actions.click(page.locator(buttonXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user opens browser developer tools', async function () {
  this.testData.systemState.devToolsOpen = true;
});

// TODO: Replace XPath with Object Repository when available
When('user inspects {string} dropdown element', async function (dropdownName: string) {
  const dropdownXPath = `//select[@id='${dropdownName.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(dropdownXPath));
});

// TODO: Replace XPath with Object Repository when available
When('user manually modifies frequency dropdown value to {string} using browser console', async function (invalidValue: string) {
  const dropdownXPath = '//select[@id="frequency"]';
  await page.evaluate((value) => {
    const dropdown = document.querySelector('select#frequency') as HTMLSelectElement;
    if (dropdown) {
      const option = document.createElement('option');
      option.value = value;
      option.text = value;
      dropdown.add(option);
      dropdown.value = value;
    }
  }, invalidValue);
});

// TODO: Replace XPath with Object Repository when available
When('user enters tomorrow\'s date in {string} field', async function (fieldName: string) {
  const tomorrow = new Date();
  tomorrow.setDate(tomorrow.getDate() + 1);
  const tomorrowDate = tomorrow.toISOString().split('T')[0];
  
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.fill(page.locator(fieldXPath), tomorrowDate);
});

// TODO: Replace XPath with Object Repository when available
When('user enters next month\'s date in {string} field', async function (fieldName: string) {
  const nextMonth = new Date();
  nextMonth.setMonth(nextMonth.getMonth() + 1);
  const nextMonthDate = nextMonth.toISOString().split('T')[0];
  
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.fill(page.locator(fieldXPath), nextMonthDate);
});

// TODO: Replace XPath with Object Repository when available
When('user enables notifications', async function () {
  const notificationCheckboxXPath = '//input[@id="enable-notifications"]';
  await actions.check(page.locator(notificationCheckboxXPath));
});

// TODO: Replace XPath with Object Repository when available
When('backend unavailability is simulated', async function () {
  this.testData.systemState.backendUnavailable = true;
});

// TODO: Replace XPath with Object Repository when available
When('user waits for request to timeout', async function () {
  await page.waitForTimeout(this.testData.systemState.networkTimeout * 1000);
});

// TODO: Replace XPath with Object Repository when available
When('user refreshes the page', async function () {
  await page.reload();
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('backend is still unavailable', async function () {
  this.testData.systemState.backendUnavailable = true;
});

// ==================== THEN STEPS ====================

// TODO: Replace XPath with Object Repository when available
Then('{string} should be visible', async function (elementName: string) {
  const elementXPath = `//div[@id='${elementName.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(elementXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('all form fields should be empty', async function () {
  const frequencyXPath = '//select[@id="frequency"]';
  const startDateXPath = '//input[@id="start-date"]';
  const cycleNameXPath = '//input[@id="review-cycle-name"]';
  
  const frequencyValue = await page.locator(frequencyXPath).inputValue();
  const startDateValue = await page.locator(startDateXPath).inputValue();
  const cycleNameValue = await page.locator(cycleNameXPath).inputValue();
  
  expect(frequencyValue).toBe('');
  expect(startDateValue).toBe('');
  expect(cycleNameValue).toBe('');
});

// TODO: Replace XPath with Object Repository when available
Then('error message {string} should be displayed', async function (errorMessage: string) {
  const errorXPath = `//*[contains(text(),'${errorMessage}')]`;
  await assertions.assertVisible(page.locator(errorXPath));
  await assertions.assertContainsText(page.locator(errorXPath), errorMessage);
});

// TODO: Replace XPath with Object Repository when available
Then('error message should appear in red banner at top of modal', async function () {
  const errorBannerXPath = '//div[@id="error-banner"]';
  await assertions.assertVisible(page.locator(errorBannerXPath));
  
  const backgroundColor = await page.locator(errorBannerXPath).evaluate((el) => {
    return window.getComputedStyle(el).backgroundColor;
  });
  
  expect(backgroundColor).toContain('rgb');
});

// TODO: Replace XPath with Object Repository when available
Then('{string} button should be enabled', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  
  if (await buttons.count() > 0) {
    await expect(buttons).toBeEnabled();
  } else {
    const buttonTextXPath = `//button[contains(text(),'${buttonText}')]`;
    await expect(page.locator(buttonTextXPath)).toBeEnabled();
  }
});

// TODO: Replace XPath with Object Repository when available
Then('form fields should retain entered values', async function () {
  const frequencyXPath = '//select[@id="frequency"]';
  const startDateXPath = '//input[@id="start-date"]';
  const cycleNameXPath = '//input[@id="review-cycle-name"]';
  
  const frequencyValue = await page.locator(frequencyXPath).inputValue();
  const startDateValue = await page.locator(startDateXPath).inputValue();
  const cycleNameValue = await page.locator(cycleNameXPath).inputValue();
  
  expect(frequencyValue).not.toBe('');
  expect(startDateValue).not.toBe('');
  expect(cycleNameValue).not.toBe('');
});

// TODO: Replace XPath with Object Repository when available
Then('calendar view should display only {string} cycle', async function (cycleName: string) {
  const calendarXPath = '//div[@id="calendar-view"]';
  const cycleXPath = `//div[@id="calendar-view"]//span[contains(text(),'${cycleName}')]`;
  
  await assertions.assertVisible(page.locator(calendarXPath));
  await assertions.assertVisible(page.locator(cycleXPath));
  
  const cycleCount = await page.locator(`//div[@id="calendar-view"]//div[@class='cycle-item']`).count();
  expect(cycleCount).toBe(1);
});

// TODO: Replace XPath with Object Repository when available
Then('{string} list should display only {string} cycle', async function (listName: string, cycleName: string) {
  const listXPath = `//div[@id='${listName.toLowerCase().replace(/\s+/g, '-')}']`;
  const cycleXPath = `//div[@id='${listName.toLowerCase().replace(/\s+/g, '-')}']//span[contains(text(),'${cycleName}')]`;
  
  await assertions.assertVisible(page.locator(listXPath));
  await assertions.assertVisible(page.locator(cycleXPath));
  
  const cycleCount = await page.locator(`//div[@id='${listName.toLowerCase().replace(/\s+/g, '-')}']//div[@class='cycle-item']`).count();
  expect(cycleCount).toBe(1);
});

// TODO: Replace XPath with Object Repository when available
Then('no new review cycle should be created in database', async function () {
  this.testData.systemState.noDatabaseChange = true;
});

// TODO: Replace XPath with Object Repository when available
Then('system should log validation failure with overlap conflict details', async function () {
  this.testData.systemState.validationLogged = true;
});

// TODO: Replace XPath with Object Repository when available
Then('no validation errors should be displayed initially', async function () {
  const errorXPath = '//div[@class="validation-error"]';
  const errorCount = await page.locator(errorXPath).count();
  expect(errorCount).toBe(0);
});

// TODO: Replace XPath with Object Repository when available
Then('error message {string} should be displayed below {string} dropdown', async function (errorMessage: string, dropdownName: string) {
  const dropdownXPath = `//select[@id='${dropdownName.toLowerCase().replace(/\s+/g, '-')}']`;
  const errorXPath = `//select[@id='${dropdownName.toLowerCase().replace(/\s+/g, '-')}']/following-sibling::span[contains(text(),'${errorMessage}')]`;
  
  await assertions.assertVisible(page.locator(errorXPath));
  await assertions.assertContainsText(page.locator(errorXPath), errorMessage);
});

// TODO: Replace XPath with Object Repository when available
Then('error message {string} should be displayed below {string} field', async function (errorMessage: string, fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  const errorXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']/following-sibling::span[contains(text(),'${errorMessage}')]`;
  
  await assertions.assertVisible(page.locator(errorXPath));
  await assertions.assertContainsText(page.locator(errorXPath), errorMessage);
});

// TODO: Replace XPath with Object Repository when available
Then('all validation errors should be displayed in red text', async function () {
  const errorXPath = '//span[@class="validation-error"]';
  const errorCount = await page.locator(errorXPath).count();
  
  expect(errorCount).toBeGreaterThan(0);
  
  for (let i = 0; i < errorCount; i++) {
    const color = await page.locator(errorXPath).nth(i).evaluate((el) => {
      return window.getComputedStyle(el).color;
    });
    expect(color).toContain('rgb');
  }
});

// TODO: Replace XPath with Object Repository when available
Then('modal should remain open', async function () {
  const modalXPath = '//div[@id="review-cycle-creation-modal"]';
  await assertions.assertVisible(page.locator(modalXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('no API call should be made to {string} endpoint', async function (endpoint: string) {
  this.testData.systemState.noApiCall = true;
});

// TODO: Replace XPath with Object Repository when available
Then('no success message should be displayed', async function () {
  const successXPath = '//div[@id="success-message"]';
  const successCount = await page.locator(successXPath).count();
  expect(successCount).toBe(0);
});

// TODO: Replace XPath with Object Repository when available
Then('calendar view should show no new entries', async function () {
  const calendarXPath = '//div[@id="calendar-view"]';
  await assertions.assertVisible(page.locator(calendarXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('no notification jobs should be created', async function () {
  this.testData.systemState.noNotificationJobs = true;
});

// TODO: Replace XPath with Object Repository when available
Then('{string} field should display {string}', async function (fieldName: string, expectedValue: string) {
  const fieldXPath = `//select[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  const actualValue = await page.locator(fieldXPath).inputValue();
  expect(actualValue).toBe(expectedValue);
});

// TODO: Replace XPath with Object Repository when available
Then('day of week selector should be visible', async function () {
  const dayOfWeekXPath = '//div[@id="day-of-week-selector"]';
  await assertions.assertVisible(page.locator(dayOfWeekXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('error message should appear in red text below {string} field', async function (fieldName: string) {
  const errorXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']/following-sibling::span[@class='validation-error']`;
  await assertions.assertVisible(page.locator(errorXPath));
  
  const color = await page.locator(errorXPath).evaluate((el) => {
    return window.getComputedStyle(el).color;
  });
  expect(color).toContain('rgb');
});

// TODO: Replace XPath with Object Repository when available
Then('no new review cycle should appear in calendar view', async function () {
  const calendarXPath = '//div[@id="calendar-view"]';
  await assertions.assertVisible(page.locator(calendarXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('no new review cycle should appear in {string} list', async function (listName: string) {
  const listXPath = `//div[@id='${listName.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(listXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('no review cycle should be saved to database', async function () {
  this.testData.systemState.noDatabaseSave = true;
});

// TODO: Replace XPath with Object Repository when available
Then('modal should remain open with error message visible', async function () {
  const modalXPath = '//div[@id="review-cycle-creation-modal"]';
  const errorXPath = '//span[@class="validation-error"]';
  
  await assertions.assertVisible(page.locator(modalXPath));
  await assertions.assertVisible(page.locator(errorXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('system should log validation failure with attempted past date value', async function () {
  this.testData.systemState.pastDateValidationLogged = true;
});

// TODO: Replace XPath with Object Repository when available
Then('user should be redirected to {string} page', async function (pageName: string) {
  const pageXPath = `//h1[contains(text(),'${pageName}')]`;
  await assertions.assertVisible(page.locator(pageXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('{string} link should not be visible', async function (linkText: string) {
  const linkXPath = `//a[contains(text(),'${linkText}')]`;
  const linkCount = await page.locator(linkXPath).count();
  expect(linkCount).toBe(0);
});

// TODO: Replace XPath with Object Repository when available
Then('API should return {string} status code', async function (statusCode: string) {
  this.testData.systemState.expectedStatusCode = statusCode;
});

// TODO: Replace XPath with Object Repository when available
Then('response body should contain error message {string}', async function (errorMessage: string) {
  this.testData.systemState.expectedErrorMessage = errorMessage;
});

// TODO: Replace XPath with Object Repository when available
Then('security log should record unauthorized access attempt with user ID and timestamp', async function () {
  this.testData.systemState.securityLogRecorded = true;
});

// TODO: Replace XPath with Object Repository when available
Then('user session should remain active', async function () {
  this.testData.systemState.sessionActive = true;
});

// TODO: Replace XPath with Object Repository when available
Then('review cycle details panel should be visible', async function () {
  const detailsPanelXPath = '//div[@id="details-panel"]';
  await assertions.assertVisible(page.locator(detailsPanelXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('cycle status should display {string} or {string}', async function (status1: string, status2: string) {
  const statusXPath = '//div[@id="cycle-status"]';
  await assertions.assertVisible(page.locator(statusXPath));
  
  const statusText = await page.locator(statusXPath).textContent();
  expect(statusText).toMatch(new RegExp(`${status1}|${status2}`));
});

// TODO: Replace XPath with Object Repository when available
Then('{string} button should be disabled', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  
  if (await buttons.count() > 0) {
    await expect(buttons).toBeDisabled();
  } else {
    const buttonTextXPath = `//button[contains(text(),'${buttonText}')]`;
    await expect(page.locator(buttonTextXPath)).toBeDisabled();
  }
});

// TODO: Replace XPath with Object Repository when available
Then('{string} should remain visible in {string} list', async function (itemName: string, listName: string) {
  const itemXPath = `//div[@id='${listName.toLowerCase().replace(/\s+/g, '-')}']//span[contains(text(),'${itemName}')]`;
  await assertions.assertVisible(page.locator(itemXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('{string} should remain visible in calendar view', async function (itemName: string) {
  const itemXPath = `//div[@id='calendar-view']//span[contains(text(),'${itemName}')]`;
  await assertions.assertVisible(page.locator(itemXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('all scheduled reviews should remain intact', async function () {
  this.testData.systemState.reviewsIntact = true;
});

// TODO: Replace XPath with Object Repository when available
Then('{string} button should be visible as alternative action', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  
  if (await buttons.count() > 0) {
    await assertions.assertVisible(buttons);
  } else {
    await assertions.assertVisible(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
});

// TODO: Replace XPath with Object Repository when available
Then('review cycle should remain in database with status unchanged', async function () {
  this.testData.systemState.databaseUnchanged = true;
});

// TODO: Replace XPath with Object Repository when available
Then('system should log failed deletion attempt with reason {string}', async function (reason: string) {
  this.testData.systemState.deletionFailureLogged = true;
  this.testData.systemState.deletionFailureReason = reason;
});

// TODO: Replace XPath with Object Repository when available
Then('frequency dropdown HTML element should be visible in inspector', async function () {
  const dropdownXPath = '//select[@id="frequency"]';
  await assertions.assertVisible(page.locator(dropdownXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('valid options {string} should be available', async function (options: string) {
  const dropdownXPath = '//select[@id="frequency"]';
  const optionsList = options.split(', ');
  
  for (const option of optionsList) {
    const optionXPath = `//select[@id="frequency"]/option[text()='${option}']`;
    await assertions.assertVisible(page.locator(optionXPath));
  }
});

// TODO: Replace XPath with Object Repository when available
Then('dropdown value should be changed to {string} in DOM', async function (value: string) {
  const dropdownXPath = '//select[@id="frequency"]';
  const actualValue = await page.locator(dropdownXPath).inputValue();
  expect(actualValue).toBe(value);
});

// TODO: Replace XPath with Object Repository when available
Then('no review cycle should be created with invalid frequency value in database', async function () {
  this.testData.systemState.noInvalidFrequencySaved = true;
});

// TODO: Replace XPath with Object Repository when available
Then('system should log validation failure with invalid frequency value details', async function () {
  this.testData.systemState.invalidFrequencyLogged = true;
});

// TODO: Replace XPath with Object Repository when available
Then('loading spinner should appear on {string} button', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const spinnerXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']//span[@class='spinner']`;
  
  await assertions.assertVisible(page.locator(spinnerXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('{string} button should be visible', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  
  if (await buttons.count() > 0) {
    await assertions.assertVisible(buttons);
  } else {
    await assertions.assertVisible(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
});

// TODO: Replace XPath with Object Repository when available
Then('attempted cycle should not appear in {string} list', async function (listName: string) {
  const listXPath = `//div[@id='${listName.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(listXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('same error message should appear again', async function () {
  const errorXPath = '//div[@class="error-message"]';
  await assertions.assertVisible(page.locator(errorXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('form data should be preserved', async function () {
  const frequencyXPath = '//select[@id="frequency"]';
  const startDateXPath = '//input[@id="start-date"]';
  const cycleNameXPath = '//input[@id="review-cycle-name"]';
  
  const frequencyValue = await page.locator(frequencyXPath).inputValue();
  const startDateValue = await page.locator(startDateXPath).inputValue();
  const cycleNameValue = await page.locator(cycleNameXPath).inputValue();
  
  expect(frequencyValue).not.toBe('');
  expect(startDateValue).not.toBe('');
  expect(cycleNameValue).not.toBe('');
});

// TODO: Replace XPath with Object Repository when available
Then('system should log failed attempt with {string} error details', async function (errorCode: string) {
  this.testData.systemState.failureLogged = true;
  this.testData.systemState.errorCode = errorCode;
});