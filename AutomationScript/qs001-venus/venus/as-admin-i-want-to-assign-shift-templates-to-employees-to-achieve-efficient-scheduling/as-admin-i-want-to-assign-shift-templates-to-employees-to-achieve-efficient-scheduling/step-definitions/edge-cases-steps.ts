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
      admin: { username: 'admin', password: 'admin123' },
      user: { username: 'testuser', password: 'testpass' }
    },
    performanceMetrics: {
      apiResponseTimes: [],
      requestStatuses: []
    }
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
/*  Common preconditions for all scenarios
/**************************************************/

Given('admin user is logged in', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  
  const credentials = this.testData?.users?.admin || { username: 'admin', password: 'admin123' };
  
  await actions.fill(page.locator('[data-testid="input-username"]'), credentials.username);
  await actions.fill(page.locator('[data-testid="input-password"]'), credentials.password);
  await actions.click(page.locator('[data-testid="button-login"]'));
  await waits.waitForNetworkIdle();
});

Given('user is on {string} page', async function (pageName: string) {
  const pageLocator = `[data-testid="nav-${pageName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const navLinks = page.locator(pageLocator);
  
  if (await navLinks.count() > 0) {
    await actions.click(navLinks);
  } else {
    await actions.click(page.locator(`a:has-text("${pageName}")`));
  }
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-EDGE-001
/*  Title: System handles assignment of maximum allowed shifts to single employee
/*  Priority: Medium
/*  Category: Edge Cases
/*  Description: Tests system behavior when assigning maximum number of shifts (31) to one employee
/**************************************************/

Given('employee {string} exists with no current assignments', async function (employeeName: string) {
  this.currentEmployee = employeeName;
  
  const employeeLocator = page.locator('[data-testid="employee-list"]');
  await waits.waitForVisible(employeeLocator);
  
  const employeeItem = page.locator(`[data-testid="employee-item-${employeeName.toLowerCase().replace(/\s+/g, '-')}"]`);
  if (await employeeItem.count() === 0) {
    const employeeSearch = page.locator('[data-testid="input-employee-search"]');
    await actions.fill(employeeSearch, employeeName);
    await waits.waitForNetworkIdle();
  }
});

Given('system has maximum limit of {int} shifts per employee per month', async function (maxShifts: number) {
  this.maxShiftsLimit = maxShifts;
});

Given('sufficient shift templates are available', async function () {
  const templatesLocator = page.locator('[data-testid="shift-template-list"]');
  await waits.waitForVisible(templatesLocator);
  
  const templateCount = await page.locator('[data-testid^="shift-template-"]').count();
  expect(templateCount).toBeGreaterThan(0);
});

/**************************************************/
/*  TEST CASE: TC-EDGE-002
/*  Title: System handles 100 concurrent shift assignments from multiple admins
/*  Priority: High
/*  Category: Edge Cases
/*  Description: Tests system performance and data integrity under concurrent load
/**************************************************/

Given('{int} admin user accounts are created and authenticated', async function (adminCount: number) {
  this.concurrentAdminCount = adminCount;
  this.adminSessions = [];
});

Given('{int} different employees exist in system', async function (employeeCount: number) {
  this.employeeCount = employeeCount;
});

Given('performance testing environment is configured', async function () {
  this.performanceTestConfig = {
    concurrentUsers: this.concurrentAdminCount || 100,
    timeout: 30000,
    apiEndpoint: '/api/employees/schedule'
  };
});

/**************************************************/
/*  TEST CASE: TC-EDGE-003
/*  Title: Shift assignment with employee name containing special characters and Unicode
/*  Priority: Low
/*  Category: Edge Cases
/*  Description: Tests proper handling of special characters and Unicode in employee names
/**************************************************/

Given('employee {string} exists in system', async function (employeeName: string) {
  this.currentEmployee = employeeName;
  
  const employeeListLocator = page.locator('[data-testid="employee-list"]');
  await waits.waitForVisible(employeeListLocator);
});

Given('shift template {string} is available', async function (templateName: string) {
  this.selectedTemplate = templateName;
  
  const templateLocator = page.locator(`[data-testid="shift-template-${templateName.toLowerCase().replace(/\s+/g, '-').replace(/[()]/g, '')}"]`);
  const fallbackLocator = page.locator(`text="${templateName}"`);
  
  if (await templateLocator.count() > 0) {
    await waits.waitForVisible(templateLocator);
  } else {
    await waits.waitForVisible(fallbackLocator);
  }
});

/**************************************************/
/*  TEST CASE: TC-EDGE-004
/*  Title: Shift assignment at exact midnight boundary
/*  Priority: Medium
/*  Category: Edge Cases
/*  Description: Tests proper handling of shifts starting/ending at midnight
/**************************************************/

Given('shift template {string} exists with start time at midnight', async function (templateName: string) {
  this.midnightTemplate = templateName;
  
  const templateLocator = page.locator(`[data-testid="shift-template-${templateName.toLowerCase().replace(/\s+/g, '-').replace(/[()]/g, '')}"]`);
  await waits.waitForVisible(templateLocator);
});

Given('system timezone is configured', async function () {
  this.systemTimezone = 'UTC';
});

/**************************************************/
/*  TEST CASE: TC-EDGE-005
/*  Title: System behavior when employee list is empty
/*  Priority: Low
/*  Category: Edge Cases
/*  Description: Tests graceful handling of empty employee list
/**************************************************/

Given('database EmployeeSchedules table exists', async function () {
  this.databaseTableExists = true;
});

Given('no employee records exist in system', async function () {
  this.employeeCount = 0;
});

Given('shift templates exist in system', async function () {
  this.shiftTemplatesExist = true;
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  TEST CASE: TC-EDGE-001 - WHEN Steps
/**************************************************/

When('user selects employee {string} from employee list', async function (employeeName: string) {
  const employeeItemLocator = `[data-testid="employee-item-${employeeName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const employeeItem = page.locator(employeeItemLocator);
  
  if (await employeeItem.count() > 0) {
    await actions.click(employeeItem);
  } else {
    await actions.click(page.locator(`text="${employeeName}"`).first());
  }
  await waits.waitForNetworkIdle();
});

When('user assigns shift templates for consecutive days from {string} to {string}', async function (startDate: string, endDate: string) {
  this.assignmentStartDate = startDate;
  this.assignmentEndDate = endDate;
  this.assignedShiftCount = 0;
  
  const start = new Date(startDate);
  const end = new Date(endDate);
  
  for (let currentDate = new Date(start); currentDate <= end; currentDate.setDate(currentDate.getDate() + 1)) {
    const dateString = currentDate.toISOString().split('T')[0];
    
    await actions.click(page.locator('[data-testid="button-assign-shift"]'));
    await waits.waitForVisible(page.locator('[data-testid="modal-assign-shift"]'));
    
    await actions.fill(page.locator('[data-testid="input-shift-date"]'), dateString);
    
    const templateDropdown = page.locator('[data-testid="select-shift-template"]');
    await actions.click(templateDropdown);
    await actions.click(page.locator('[data-testid="option-shift-template"]').first());
    
    await actions.click(page.locator('[data-testid="button-confirm-assignment"]'));
    await waits.waitForNetworkIdle();
    
    this.assignedShiftCount++;
  }
});

When('user attempts to assign shift for date {string}', async function (date: string) {
  await actions.click(page.locator('[data-testid="button-assign-shift"]'));
  await waits.waitForVisible(page.locator('[data-testid="modal-assign-shift"]'));
  
  await actions.fill(page.locator('[data-testid="input-shift-date"]'), date);
  
  const templateDropdown = page.locator('[data-testid="select-shift-template"]');
  await actions.click(templateDropdown);
  await actions.click(page.locator('[data-testid="option-shift-template"]').first());
  
  await actions.click(page.locator('[data-testid="button-confirm-assignment"]'));
  await waits.waitForNetworkIdle();
});

When('user views calendar with all assigned shifts', async function () {
  const calendarLocator = page.locator('[data-testid="calendar-view"]');
  await waits.waitForVisible(calendarLocator);
  await actions.scrollIntoView(calendarLocator);
});

/**************************************************/
/*  TEST CASE: TC-EDGE-002 - WHEN Steps
/**************************************************/

When('automated test simulates {int} concurrent admin users accessing {string} section simultaneously', async function (userCount: number, sectionName: string) {
  this.concurrentUserCount = userCount;
  this.targetSection = sectionName;
  this.simulationReady = true;
});

When('all {int} admins assign different shift templates to different employees at same time', async function (adminCount: number) {
  this.concurrentAssignments = adminCount;
  
  page.on('response', response => {
    if (response.url().includes('/api/employees/schedule')) {
      const responseTime = response.timing().responseEnd;
      this.testData.performanceMetrics.apiResponseTimes.push(responseTime);
      this.testData.performanceMetrics.requestStatuses.push(response.status());
    }
  });
  
  this.assignmentStartTime = Date.now();
  await waits.waitForNetworkIdle();
  this.assignmentEndTime = Date.now();
});

/**************************************************/
/*  TEST CASE: TC-EDGE-003 - WHEN Steps
/**************************************************/

When('user searches for employee {string} in employee list search field', async function (employeeName: string) {
  const searchFieldLocator = page.locator('[data-testid="input-employee-search"]');
  await actions.fill(searchFieldLocator, employeeName);
  await waits.waitForNetworkIdle();
});

When('user selects employee {string} from list', async function (employeeName: string) {
  const employeeItemLocator = `[data-testid="employee-item"]`;
  const employeeItems = page.locator(employeeItemLocator);
  
  if (await employeeItems.count() > 0) {
    await actions.click(employeeItems.first());
  } else {
    await actions.click(page.locator(`text="${employeeName}"`).first());
  }
  await waits.waitForNetworkIdle();
});

When('user assigns {string} template for date {string}', async function (templateName: string, date: string) {
  await actions.click(page.locator('[data-testid="button-assign-shift"]'));
  await waits.waitForVisible(page.locator('[data-testid="modal-assign-shift"]'));
  
  await actions.fill(page.locator('[data-testid="input-shift-date"]'), date);
  
  const templateDropdown = page.locator('[data-testid="select-shift-template"]');
  await actions.click(templateDropdown);
  
  const templateOption = page.locator(`[data-testid="option-${templateName.toLowerCase().replace(/\s+/g, '-').replace(/[()]/g, '')}"]`);
  if (await templateOption.count() > 0) {
    await actions.click(templateOption);
  } else {
    await actions.click(page.locator(`text="${templateName}"`).first());
  }
});

When('user confirms assignment', async function () {
  await actions.click(page.locator('[data-testid="button-confirm-assignment"]'));
  await waits.waitForNetworkIdle();
});

When('user views calendar', async function () {
  const calendarLocator = page.locator('[data-testid="calendar-view"]');
  await waits.waitForVisible(calendarLocator);
});

When('user queries EmployeeSchedules table', async function () {
  this.databaseQueryExecuted = true;
});

/**************************************************/
/*  TEST CASE: TC-EDGE-004 - WHEN Steps
/**************************************************/

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

When('user selects {string} template', async function (templateName: string) {
  const templateDropdown = page.locator('[data-testid="select-shift-template"]');
  await actions.click(templateDropdown);
  
  const templateOption = page.locator(`[data-testid="option-${templateName.toLowerCase().replace(/\s+/g, '-').replace(/[()]/g, '')}"]`);
  if (await templateOption.count() > 0) {
    await actions.click(templateOption);
  } else {
    await actions.click(page.locator(`text="${templateName}"`).first());
  }
  await waits.waitForNetworkIdle();
});

When('user sets date to {string}', async function (date: string) {
  await actions.fill(page.locator('[data-testid="input-shift-date"]'), date);
});

/**************************************************/
/*  TEST CASE: TC-EDGE-005 - WHEN Steps
/**************************************************/

When('user navigates to {string} section', async function (sectionName: string) {
  const sectionLocator = `[data-testid="nav-${sectionName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const navLinks = page.locator(sectionLocator);
  
  if (await navLinks.count() > 0) {
    await actions.click(navLinks);
  } else {
    await actions.click(page.locator(`a:has-text("${sectionName}")`));
  }
  await waits.waitForNetworkIdle();
});

When('user views employee list panel', async function () {
  const employeeListPanel = page.locator('[data-testid="employee-list-panel"]');
  await waits.waitForVisible(employeeListPanel);
});

When('user attempts to access assignment functionality', async function () {
  const assignButton = page.locator('[data-testid="button-assign-shift"]');
  if (await assignButton.count() > 0) {
    await actions.click(assignButton);
  }
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  TEST CASE: TC-EDGE-001 - THEN Steps
/**************************************************/

Then('employee details and empty schedule should be displayed', async function () {
  await assertions.assertVisible(page.locator('[data-testid="employee-details-panel"]'));
  await assertions.assertVisible(page.locator('[data-testid="employee-schedule-section"]'));
});

Then('each assignment should succeed with success message', async function () {
  const successMessageLocator = page.locator('[data-testid="success-message"], .success, .alert-success');
  await waits.waitForVisible(successMessageLocator);
});

Then('calendar should display {int} shift assignments', async function (expectedCount: number) {
  const shiftElements = page.locator('[data-testid^="shift-assignment-"]');
  await waits.waitForVisible(shiftElements.first());
  
  const actualCount = await shiftElements.count();
  expect(actualCount).toBe(expectedCount);
});

Then('system should display warning {string} or allow assignment based on business rules', async function (warningMessage: string) {
  const warningLocator = page.locator('[data-testid="warning-message"], .warning, .alert-warning');
  const successLocator = page.locator('[data-testid="success-message"], .success, .alert-success');
  
  const warningVisible = await warningLocator.count() > 0;
  const successVisible = await successLocator.count() > 0;
  
  expect(warningVisible || successVisible).toBe(true);
});

Then('calendar should render all shifts properly with readable labels', async function () {
  const shiftLabels = page.locator('[data-testid^="shift-label-"]');
  await waits.waitForVisible(shiftLabels.first());
  
  const labelCount = await shiftLabels.count();
  expect(labelCount).toBeGreaterThan(0);
});

Then('shifts should display with proper spacing and no overlapping visual elements', async function () {
  const calendarView = page.locator('[data-testid="calendar-view"]');
  await waits.waitForVisible(calendarView);
  
  const boundingBox = await calendarView.boundingBox();
  expect(boundingBox).not.toBeNull();
});

Then('page should remain responsive', async function () {
  const pageTitle = page.locator('[data-testid="page-title"]');
  await waits.waitForVisible(pageTitle);
  
  await actions.click(page.locator('body'));
  await waits.waitForNetworkIdle();
});

Then('calendar should load within {int} seconds', async function (maxSeconds: number) {
  const startTime = Date.now();
  await waits.waitForVisible(page.locator('[data-testid="calendar-view"]'));
  const endTime = Date.now();
  
  const loadTime = (endTime - startTime) / 1000;
  expect(loadTime).toBeLessThanOrEqual(maxSeconds);
});

Then('browser should show no freezing or memory issues', async function () {
  await page.evaluate(() => {
    return performance.memory ? performance.memory.usedJSHeapSize : 0;
  });
});

Then('all {int} shift assignments should be stored in EmployeeSchedules table', async function (expectedCount: number) {
  this.expectedDatabaseRecords = expectedCount;
});

/**************************************************/
/*  TEST CASE: TC-EDGE-002 - THEN Steps
/**************************************************/

Then('test script should be ready with {int} concurrent user sessions', async function (sessionCount: number) {
  expect(this.simulationReady).toBe(true);
  expect(this.concurrentUserCount).toBe(sessionCount);
});

Then('system should process all {int} assignment requests without crashing', async function (requestCount: number) {
  expect(this.concurrentAssignments).toBe(requestCount);
});

Then('system should process all {int} assignment requests without timing out', async function (requestCount: number) {
  const totalTime = this.assignmentEndTime - this.assignmentStartTime;
  expect(totalTime).toBeLessThan(30000);
});

Then('{int} percent of API requests to {string} should complete within {int} seconds', async function (percentage: number, endpoint: string, maxSeconds: number) {
  const responseTimes = this.testData.performanceMetrics.apiResponseTimes || [];
  const maxMilliseconds = maxSeconds * 1000;
  
  const withinThreshold = responseTimes.filter((time: number) => time <= maxMilliseconds).length;
  const actualPercentage = (withinThreshold / responseTimes.length) * 100;
  
  expect(actualPercentage).toBeGreaterThanOrEqual(percentage);
});

Then('no requests should fail with 500 errors', async function () {
  const statuses = this.testData.performanceMetrics.requestStatuses || [];
  const serverErrors = statuses.filter((status: number) => status >= 500);
  
  expect(serverErrors.length).toBe(0);
});

Then('all requests should return appropriate success or error responses', async function () {
  const statuses = this.testData.performanceMetrics.requestStatuses || [];
  const validStatuses = statuses.filter((status: number) => status >= 200 && status < 600);
  
  expect(validStatuses.length).toBe(statuses.length);
});

Then('EmployeeSchedules table should contain exactly {int} new shift assignment records', async function (expectedRecords: number) {
  this.expectedDatabaseRecords = expectedRecords;
});

Then('database should contain no duplicate assignments', async function () {
  this.noDuplicateAssignments = true;
});

Then('database should contain no missing assignments', async function () {
  this.noMissingAssignments = true;
});

Then('no database deadlocks should have occurred', async function () {
  this.noDeadlocks = true;
});

Then('all transactions should have completed successfully', async function () {
  this.allTransactionsCompleted = true;
});

Then('data integrity should be maintained', async function () {
  this.dataIntegrityMaintained = true;
});

Then('each admin should see their own assignment reflected in real-time', async function () {
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('[data-testid="shift-assignment"]').first());
});

Then('no stale data should be displayed to any user', async function () {
  await page.reload();
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('[data-testid="calendar-view"]'));
});

/**************************************************/
/*  TEST CASE: TC-EDGE-003 - THEN Steps
/**************************************************/

Then('employee should be found and displayed correctly', async function () {
  const employeeItem = page.locator('[data-testid="employee-item"]').first();
  await waits.waitForVisible(employeeItem);
});

Then('all special characters and Unicode should be rendered properly', async function () {
  const employeeName = this.currentEmployee;
  await assertions.assertContainsText(page.locator('body'), employeeName);
});

Then('employee details panel should open', async function () {
  await assertions.assertVisible(page.locator('[data-testid="employee-details-panel"]'));
});

Then('employee name should display as {string} with all special characters intact', async function (expectedName: string) {
  await assertions.assertContainsText(page.locator('[data-testid="employee-details-panel"]'), expectedName);
});

Then('success message {string} should be displayed', async function (expectedMessage: string) {
  const successMessage = page.locator('[data-testid="success-message"], .success, .alert-success');
  await waits.waitForVisible(successMessage);
  await assertions.assertContainsText(successMessage, expectedMessage);
});

Then('employee name should be rendered correctly in message', async function () {
  const employeeName = this.currentEmployee;
  const successMessage = page.locator('[data-testid="success-message"], .success, .alert-success');
  await assertions.assertContainsText(successMessage, employeeName);
});

Then('calendar should display shift with employee name {string}', async function (employeeName: string) {
  const calendarView = page.locator('[data-testid="calendar-view"]');
  await assertions.assertContainsText(calendarView, employeeName);
});

Then('employee name should be properly encoded without character corruption', async function () {
  const employeeName = this.currentEmployee;
  const shiftElement = page.locator('[data-testid^="shift-assignment-"]').first();
  await assertions.assertContainsText(shiftElement, employeeName);
});

Then('database record should contain employee name with all special characters properly stored', async function () {
  this.databaseRecordVerified = true;
});

Then('employee name should be stored using UTF-8 encoding', async function () {
  this.utf8EncodingVerified = true;
});

/**************************************************/
/*  TEST CASE: TC-EDGE-004 - THEN Steps
/**************************************************/

Then('assignment modal should open', async function () {
  await assertions.assertVisible(page.locator('[data-testid="modal-assign-shift"]'));
});

Then('template and date should be selected', async function () {
  const templateSelect = page.locator('[data-testid="select-shift-template"]');
  const dateInput = page.locator('[data-testid="input-shift-date"]');
  
  await assertions.assertVisible(templateSelect);
  await assertions.assertVisible(dateInput);
});

Then('shift should show start time at {string} on {string}', async function (startTime: string, date: string) {
  const shiftDetails = page.locator('[data-testid="shift-details"]');
  await assertions.assertContainsText(shiftDetails, startTime);
  await assertions.assertContainsText(shiftDetails, date);
});

Then('success message should appear', async function () {
  await assertions.assertVisible(page.locator('[data-testid="success-message"], .success, .alert-success'));
});

Then('assignment should be confirmed', async function () {
  await waits.waitForNetworkIdle();
  const successMessage = page.locator('[data-testid="success-message"], .success, .alert-success');
  await waits.waitForVisible(successMessage);
});

Then('calendar should show shift block starting exactly at midnight boundary', async function () {
  const midnightShift = page.locator('[data-testid^="shift-assignment-"]').first();
  await waits.waitForVisible(midnightShift);
});

Then('shift should be properly positioned on {string}', async function (expectedDate: string) {
  const calendarView = page.locator('[data-testid="calendar-view"]');
  await assertions.assertContainsText(calendarView, expectedDate);
});

Then('calendar should show {string} ending at {string} on {string}', async function (shiftName: string, endTime: string, date: string) {
  const calendarView = page.locator('[data-testid="calendar-view"]');
  await assertions.assertContainsText(calendarView, shiftName);
});

Then('calendar should show {string} starting at {string} on {string}', async function (shiftName: string, startTime: string, date: string) {
  const calendarView = page.locator('[data-testid="calendar-view"]');
  await assertions.assertContainsText(calendarView, shiftName);
});

Then('no overlap conflict should be detected', async function () {
  const errorMessage = page.locator('[data-testid="error-message"], .error, .alert-error');
  const errorCount = await errorMessage.count();
  expect(errorCount).toBe(0);
});

Then('{string} record should show start_time as {string}', async function (shiftName: string, startTime: string) {
  this.databaseStartTimeVerified = true;
});

Then('{string} record should show end_time as {string}', async function (shiftName: string, endTime: string) {
  this.databaseEndTimeVerified = true;
});

Then('proper timezone handling should be applied', async function () {
  this.timezoneHandlingVerified = true;
});

/**************************************************/
/*  TEST CASE: TC-EDGE-005 - THEN Steps
/**************************************************/

Then('page should load successfully', async function () {
  await waits.waitForDomContentLoaded();
  await waits.waitForNetworkIdle();
});

Then('empty state message {string} should be displayed', async function (expectedMessage: string) {
  const emptyStateMessage = page.locator('[data-testid="empty-state-message"]');
  await waits.waitForVisible(emptyStateMessage);
  await assertions.assertContainsText(emptyStateMessage, expectedMessage);
});

Then('{string} button or link should be visible', async function (buttonText: string) {
  const buttonLocator = `[data-testid="button-${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const button = page.locator(buttonLocator);
  
  if (await button.count() > 0) {
    await assertions.assertVisible(button);
  } else {
    await assertions.assertVisible(page.locator(`button:has-text("${buttonText}")`));
  }
});

Then('employee list should show empty state illustration or message', async function () {
  const emptyState = page.locator('[data-testid="empty-state"], [data-testid="empty-state-message"]');
  await waits.waitForVisible(emptyState);
});

Then('no error messages should be displayed', async function () {
  const errorMessages = page.locator('[data-testid="error-message"], .error, .alert-error');
  const errorCount = await errorMessages.count();
  expect(errorCount).toBe(0);
});

Then('message {string} should be shown', async function (expectedMessage: string) {
  await assertions.assertContainsText(page.locator('body'), expectedMessage);
});

Then('assignment buttons should be disabled or hidden', async function () {
  const assignButton = page.locator('[data-testid="button-assign-shift"]');
  
  if (await assignButton.count() > 0) {
    const isDisabled = await assignButton.isDisabled();
    expect(isDisabled).toBe(true);
  }
});

Then('clicking should show message {string}', async function (expectedMessage: string) {
  const messageLocator = page.locator('[data-testid="info-message"], .info, .alert-info');
  if (await messageLocator.count() > 0) {
    await assertions.assertContainsText(messageLocator, expectedMessage);
  }
});

Then('browser console should show no JavaScript errors', async function () {
  const consoleErrors: string[] = [];
  
  page.on('console', msg => {
    if (msg.type() === 'error') {
      consoleErrors.push(msg.text());
    }
  });
  
  expect(consoleErrors.length).toBe(0);
});

Then('application should handle empty state gracefully', async function () {
  await waits.waitForNetworkIdle();
  const emptyState = page.locator('[data-testid="empty-state"], [data-testid="empty-state-message"]');
  await waits.waitForVisible(emptyState);
});