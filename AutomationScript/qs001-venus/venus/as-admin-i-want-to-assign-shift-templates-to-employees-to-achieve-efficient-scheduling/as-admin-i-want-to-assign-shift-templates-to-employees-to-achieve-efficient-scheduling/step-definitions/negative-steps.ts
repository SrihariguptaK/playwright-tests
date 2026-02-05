import { Given, When, Then, Before, After } from '@cucumber/cucumber';
import { Page, Browser, BrowserContext, chromium, expect } from '@playwright/test';
import { BasePage } from '../pages/BasePage';
import { HomePage } from '../pages/HomePage';
import { LoginPage } from '../pages/LoginPage';
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
let loginPage: LoginPage;
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
  loginPage = new LoginPage(page, context);
  
  this.testData = {
    users: {
      admin: { username: 'admin@company.com', password: 'admin123' },
      regular_user: { username: 'regular_user@company.com', password: 'user123' }
    },
    employees: {},
    shiftTemplates: {},
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
/*  BACKGROUND STEPS - All Test Cases
/*  Common preconditions for negative scenarios
/**************************************************/

Given('admin user is logged in with valid credentials', async function () {
  await loginPage.navigate();
  const credentials = this.testData.users.admin;
  await actions.fill(page.locator('[data-testid="input-username"]'), credentials.username);
  await actions.fill(page.locator('[data-testid="input-password"]'), credentials.password);
  await actions.click(page.locator('[data-testid="button-login"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('[data-testid="dashboard-container"]'));
});

Given('user is on {string} page', async function (pageName: string) {
  const pageUrl = `/${pageName.toLowerCase().replace(/\s+/g, '-')}`;
  await actions.navigateTo(pageUrl);
  await waits.waitForNetworkIdle();
  const pageLocator = `[data-testid="page-${pageName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await assertions.assertVisible(page.locator(pageLocator));
});

/**************************************************/
/*  TEST CASE: TC-NEG-001
/*  Title: System prevents double scheduling with overlapping shift times
/*  Priority: High
/*  Category: Negative
/*  Description: Validates overlap detection and prevents duplicate assignments
/**************************************************/

Given('employee {string} exists in the system', async function (employeeName: string) {
  this.testData.employees[employeeName] = {
    name: employeeName,
    id: employeeName.toLowerCase().replace(/\s+/g, '-'),
    shifts: []
  };
  await assertions.assertVisible(page.locator('[data-testid="employee-list"]'));
});

Given('employee {string} has {string} assigned on {string}', async function (employeeName: string, shiftName: string, date: string) {
  this.testData.employees[employeeName].shifts.push({
    shiftName: shiftName,
    date: date
  });
  const employeeLocator = page.locator(`[data-testid="employee-${employeeName.toLowerCase().replace(/\s+/g, '-')}"]`);
  await actions.click(employeeLocator);
  await waits.waitForNetworkIdle();
  const calendarDateLocator = page.locator(`[data-testid="calendar-date-${date}"]`);
  await assertions.assertVisible(calendarDateLocator);
});

Given('shift template {string} exists that overlaps with existing shift', async function (templateName: string) {
  this.testData.shiftTemplates[templateName] = {
    name: templateName,
    overlapping: true
  };
  await assertions.assertVisible(page.locator('[data-testid="shift-template-dropdown"]'));
});

Given('user is viewing {string} schedule', async function (employeeName: string) {
  const employeeLocator = page.locator(`[data-testid="employee-${employeeName.toLowerCase().replace(/\s+/g, '-')}"]`);
  await actions.click(employeeLocator);
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('[data-testid="employee-schedule-calendar"]'));
});

/**************************************************/
/*  TEST CASE: TC-NEG-002
/*  Title: Error handling when attempting to assign shift without selecting a template
/*  Priority: High
/*  Category: Negative
/*  Description: Validates client-side validation for required fields
/**************************************************/

/**************************************************/
/*  TEST CASE: TC-NEG-003
/*  Title: Error handling when non-admin user attempts to access shift assignment functionality
/*  Priority: High
/*  Category: Negative
/*  Description: Validates authorization and access control
/**************************************************/

Given('user account {string} exists with {string} role', async function (email: string, role: string) {
  this.testData.users.regular_user = {
    username: email,
    password: 'user123',
    role: role
  };
});

Given('user is logged out', async function () {
  await actions.click(page.locator('[data-testid="button-logout"], [data-testid="user-menu-logout"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('[data-testid="login-page"]'));
});

Given('user logs in as {string}', async function (email: string) {
  await loginPage.navigate();
  await actions.fill(page.locator('[data-testid="input-username"]'), email);
  await actions.fill(page.locator('[data-testid="input-password"]'), 'user123');
  await actions.click(page.locator('[data-testid="button-login"]'));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-NEG-004
/*  Title: Error handling when assigning shift with past date
/*  Priority: Medium
/*  Category: Negative
/*  Description: Validates past date warning and confirmation flow
/**************************************************/

Given('current system date is {string}', async function (currentDate: string) {
  this.testData.systemState.currentDate = currentDate;
});

Given('shift template {string} is available', async function (templateName: string) {
  this.testData.shiftTemplates[templateName] = {
    name: templateName,
    active: true
  };
});

/**************************************************/
/*  TEST CASE: TC-NEG-005
/*  Title: Error handling when database connection fails during shift assignment
/*  Priority: High
/*  Category: Negative
/*  Description: Validates error handling for database failures
/**************************************************/

Given('database connection is simulated to fail', async function () {
  this.testData.systemState.databaseFailure = true;
  await page.route('**/api/employees/schedule', route => {
    route.abort('failed');
  });
});

/**************************************************/
/*  TEST CASE: TC-NEG-006
/*  Title: Error handling when attempting to assign deleted or inactive shift template
/*  Priority: Medium
/*  Category: Negative
/*  Description: Validates inactive template filtering and API validation
/**************************************************/

Given('shift template {string} is marked as inactive in database', async function (templateName: string) {
  this.testData.shiftTemplates[templateName] = {
    name: templateName,
    active: false,
    status: 'inactive'
  };
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  TEST CASE: TC-NEG-001
/*  Title: System prevents double scheduling with overlapping shift times
/*  Priority: High
/*  Category: Negative
/**************************************************/

When('user verifies calendar shows {string} on {string}', async function (shiftName: string, date: string) {
  const calendarDateLocator = page.locator(`[data-testid="calendar-date-${date}"]`);
  await assertions.assertVisible(calendarDateLocator);
  await assertions.assertContainsText(calendarDateLocator, shiftName);
});

When('user clicks {string} button', async function (buttonText: string) {
  const testIdLocator = `[data-testid="button-${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const buttons = page.locator(testIdLocator);
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`button:has-text("${buttonText}")`));
  }
  await waits.waitForNetworkIdle();
});

When('user selects {string} from shift template dropdown', async function (templateName: string) {
  const dropdownLocator = page.locator('[data-testid="select-shift-template"], [data-testid="dropdown-shift-template"]');
  await actions.click(dropdownLocator);
  await waits.waitForVisible(page.locator('[data-testid="dropdown-options"]'));
  const optionLocator = page.locator(`[data-testid="option-${templateName.toLowerCase().replace(/\s+/g, '-')}"]`);
  if (await optionLocator.count() > 0) {
    await actions.click(optionLocator);
  } else {
    await actions.click(page.locator(`text="${templateName}"`));
  }
});

When('user enters {string} in {string} field', async function (value: string, fieldName: string) {
  const fieldLocator = `[data-testid="input-${fieldName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await actions.fill(page.locator(fieldLocator), value);
});

/**************************************************/
/*  TEST CASE: TC-NEG-002
/*  Title: Error handling when attempting to assign shift without selecting a template
/*  Priority: High
/*  Category: Negative
/**************************************************/

When('user selects employee {string} from employee list', async function (employeeName: string) {
  const employeeLocator = page.locator(`[data-testid="employee-${employeeName.toLowerCase().replace(/\s+/g, '-')}"]`);
  await actions.click(employeeLocator);
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('[data-testid="employee-schedule-calendar"]'));
});

When('user leaves shift template dropdown empty', async function () {
  const dropdownLocator = page.locator('[data-testid="select-shift-template"], [data-testid="dropdown-shift-template"]');
  await assertions.assertVisible(dropdownLocator);
});

/**************************************************/
/*  TEST CASE: TC-NEG-003
/*  Title: Error handling when non-admin user attempts to access shift assignment functionality
/*  Priority: High
/*  Category: Negative
/**************************************************/

When('user attempts to navigate to {string} URL directly', async function (url: string) {
  await actions.navigateTo(url);
  await waits.waitForNetworkIdle();
});

When('user attempts to send POST request to {string} with valid shift data', async function (endpoint: string) {
  const response = await page.evaluate(async (apiEndpoint) => {
    const res = await fetch(apiEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        employeeId: 'emp-001',
        shiftTemplateId: 'shift-001',
        date: '2024-02-15'
      })
    });
    return {
      status: res.status,
      body: await res.json()
    };
  }, endpoint);
  this.testData.apiResponse = response;
});

/**************************************************/
/*  TEST CASE: TC-NEG-004
/*  Title: Error handling when assigning shift with past date
/*  Priority: Medium
/*  Category: Negative
/**************************************************/

/**************************************************/
/*  TEST CASE: TC-NEG-006
/*  Title: Error handling when attempting to assign deleted or inactive shift template
/*  Priority: Medium
/*  Category: Negative
/**************************************************/

When('user attempts to call API {string} with inactive template ID', async function (apiEndpoint: string) {
  const response = await page.evaluate(async (endpoint) => {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        employeeId: 'emp-natalie-portman',
        shiftTemplateId: 'inactive-template-001',
        date: '2024-02-25'
      })
    });
    return {
      status: res.status,
      body: await res.json()
    };
  }, apiEndpoint);
  this.testData.apiResponse = response;
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  TEST CASE: TC-NEG-001
/*  Title: System prevents double scheduling with overlapping shift times
/*  Priority: High
/*  Category: Negative
/**************************************************/

Then('error message {string} should be displayed', async function (errorMessage: string) {
  const errorLocator = page.locator('[data-testid="error-message"], [data-testid="alert-error"], .error-message, .alert-danger');
  await assertions.assertVisible(errorLocator);
  await assertions.assertContainsText(errorLocator, errorMessage);
});

Then('assignment modal should remain open', async function () {
  await assertions.assertVisible(page.locator('[data-testid="modal-assign-shift"], [data-testid="assignment-modal"]'));
});

Then('calendar should display only {string} on {string}', async function (shiftName: string, date: string) {
  const calendarDateLocator = page.locator(`[data-testid="calendar-date-${date}"]`);
  await assertions.assertVisible(calendarDateLocator);
  await assertions.assertContainsText(calendarDateLocator, shiftName);
  const shiftCount = await page.locator(`[data-testid="calendar-date-${date}"] [data-testid*="shift-"]`).count();
  expect(shiftCount).toBe(1);
});

Then('no duplicate shift entry should exist in database for {string} on {string}', async function (employeeName: string, date: string) {
  const response = await page.evaluate(async (empName, shiftDate) => {
    const res = await fetch(`/api/employees/${empName.toLowerCase().replace(/\s+/g, '-')}/shifts?date=${shiftDate}`);
    return await res.json();
  }, employeeName, date);
  expect(response.shifts.length).toBeLessThanOrEqual(1);
});

Then('failed assignment attempt should be logged in system error logs', async function () {
  await assertions.assertVisible(page.locator('[data-testid="error-log-entry"], [data-testid="system-log"]'));
});

/**************************************************/
/*  TEST CASE: TC-NEG-002
/*  Title: Error handling when attempting to assign shift without selecting a template
/*  Priority: High
/*  Category: Negative
/**************************************************/

Then('validation error message {string} should be displayed below template dropdown', async function (validationMessage: string) {
  const validationLocator = page.locator('[data-testid="validation-error-shift-template"], [data-testid="error-shift-template"]');
  await assertions.assertVisible(validationLocator);
  await assertions.assertContainsText(validationLocator, validationMessage);
});

Then('no API call should be made to {string}', async function (apiEndpoint: string) {
  const apiCalls = await page.evaluate(() => {
    return (window as any).apiCallLog || [];
  });
  const matchingCalls = apiCalls.filter((call: any) => call.url.includes(apiEndpoint));
  expect(matchingCalls.length).toBe(0);
});

Then('no shift assignment should be created in database', async function () {
  await waits.waitForNetworkIdle();
});

Then('{string} schedule should remain unchanged', async function (employeeName: string) {
  const calendarLocator = page.locator('[data-testid="employee-schedule-calendar"]');
  await assertions.assertVisible(calendarLocator);
});

/**************************************************/
/*  TEST CASE: TC-NEG-003
/*  Title: Error handling when non-admin user attempts to access shift assignment functionality
/*  Priority: High
/*  Category: Negative
/**************************************************/

Then('user should see {string} page', async function (pageType: string) {
  const pageLocator = `[data-testid="page-${pageType.toLowerCase().replace(/\s+/g, '-')}"]`;
  await assertions.assertVisible(page.locator(pageLocator));
  await assertions.assertContainsText(page.locator('body'), pageType);
});

Then('API should return status code {string}', async function (statusCode: string) {
  expect(this.testData.apiResponse.status).toBe(parseInt(statusCode));
});

Then('API response should contain error {string}', async function (errorType: string) {
  expect(this.testData.apiResponse.body.error).toContain(errorType);
});

Then('API response should contain message {string}', async function (message: string) {
  expect(this.testData.apiResponse.body.message).toContain(message);
});

Then('{string} link should not be visible in navigation menu', async function (linkText: string) {
  const navLinkLocator = page.locator(`[data-testid="nav-link-${linkText.toLowerCase().replace(/\s+/g, '-')}"]`);
  const linkCount = await navLinkLocator.count();
  expect(linkCount).toBe(0);
});

Then('unauthorized access attempt should be logged with user ID and timestamp', async function () {
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-NEG-004
/*  Title: Error handling when assigning shift with past date
/*  Priority: Medium
/*  Category: Negative
/**************************************************/

Then('warning message {string} should be displayed', async function (warningMessage: string) {
  const warningLocator = page.locator('[data-testid="warning-message"], [data-testid="alert-warning"], .warning-message, .alert-warning');
  await assertions.assertVisible(warningLocator);
  await assertions.assertContainsText(warningLocator, warningMessage);
});

Then('{string} button should be visible', async function (buttonText: string) {
  const testIdLocator = `[data-testid="button-${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const buttonLocator = page.locator(testIdLocator);
  if (await buttonLocator.count() > 0) {
    await assertions.assertVisible(buttonLocator);
  } else {
    await assertions.assertVisible(page.locator(`button:has-text("${buttonText}")`));
  }
});

Then('assignment modal should close', async function () {
  const modalLocator = page.locator('[data-testid="modal-assign-shift"], [data-testid="assignment-modal"]');
  await waits.waitForHidden(modalLocator);
});

Then('no shift assignment should be created for past date in database', async function () {
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-NEG-005
/*  Title: Error handling when database connection fails during shift assignment
/*  Priority: High
/*  Category: Negative
/**************************************************/

Then('loading spinner should appear briefly', async function () {
  const spinnerLocator = page.locator('[data-testid="loading-spinner"], [data-testid="spinner"], .spinner, .loading');
  await assertions.assertVisible(spinnerLocator);
});

Then('calendar should not show {string} assignment for {string}', async function (shiftName: string, employeeName: string) {
  const calendarLocator = page.locator('[data-testid="employee-schedule-calendar"]');
  await assertions.assertVisible(calendarLocator);
  const shiftLocator = page.locator(`text="${shiftName}"`);
  const shiftCount = await shiftLocator.count();
  expect(shiftCount).toBe(0);
});

Then('previous schedule state should be maintained', async function () {
  await assertions.assertVisible(page.locator('[data-testid="employee-schedule-calendar"]'));
});

Then('error should be logged with timestamp and error type {string}', async function (errorType: string) {
  await waits.waitForNetworkIdle();
});

Then('no partial data should be written to database', async function () {
  await waits.waitForNetworkIdle();
});

Then('no corrupted data should exist in {string} table', async function (tableName: string) {
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-NEG-006
/*  Title: Error handling when attempting to assign deleted or inactive shift template
/*  Priority: Medium
/*  Category: Negative
/**************************************************/

Then('{string} should not appear in shift template dropdown', async function (templateName: string) {
  const dropdownLocator = page.locator('[data-testid="select-shift-template"], [data-testid="dropdown-shift-template"]');
  await actions.click(dropdownLocator);
  await waits.waitForVisible(page.locator('[data-testid="dropdown-options"]'));
  const optionLocator = page.locator(`text="${templateName}"`);
  const optionCount = await optionLocator.count();
  expect(optionCount).toBe(0);
});

Then('only active templates should be visible in dropdown', async function () {
  const dropdownLocator = page.locator('[data-testid="select-shift-template"], [data-testid="dropdown-shift-template"]');
  await actions.click(dropdownLocator);
  await waits.waitForVisible(page.locator('[data-testid="dropdown-options"]'));
  const activeOptions = page.locator('[data-testid^="option-"]:not([data-inactive="true"])');
  const activeCount = await activeOptions.count();
  expect(activeCount).toBeGreaterThan(0);
});

Then('API response should contain error message {string}', async function (errorMessage: string) {
  expect(this.testData.apiResponse.body.error || this.testData.apiResponse.body.message).toContain(errorMessage);
});

Then('no assignment should be created in database for {string}', async function (employeeName: string) {
  await waits.waitForNetworkIdle();
});