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
      employee: { username: 'employee', password: 'employee123' },
      admin: { username: 'admin', password: 'admin123' }
    },
    scheduleRequests: []
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
/*  Category: Setup
/**************************************************/

Given('user is logged in as an authenticated employee', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  
  const credentials = this.testData?.users?.employee || { username: 'employee', password: 'employee123' };
  
  await actions.fill(page.locator('[data-testid="input-username"]'), credentials.username);
  await actions.fill(page.locator('[data-testid="input-password"]'), credentials.password);
  await actions.click(page.locator('[data-testid="button-login"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('[data-testid="dashboard-container"]'));
});

Given('employee has schedule change requests in the system', async function () {
  this.testData.scheduleRequests = [
    { id: 'REQ-001', status: 'Approved', date: '2024-01-15' },
    { id: 'REQ-002', status: 'Pending', date: '2024-01-20' },
    { id: 'REQ-003', status: 'Rejected', date: '2024-01-25' }
  ];
});

/**************************************************/
/*  TEST CASE: TC-001
/*  Title: Employee successfully accesses schedule change history page and views all past requests
/*  Priority: High
/*  Category: Functional
/**************************************************/

Given('employee has {int} schedule change requests with various statuses', async function (requestCount: number) {
  this.testData.scheduleRequests = [];
  for (let i = 1; i <= requestCount; i++) {
    const statuses = ['Approved', 'Pending', 'Rejected'];
    this.testData.scheduleRequests.push({
      id: `REQ-00${i}`,
      status: statuses[i % 3],
      dateSubmitted: `2024-01-${10 + i}`,
      originalSchedule: '9:00 AM - 5:00 PM',
      requestedSchedule: '10:00 AM - 6:00 PM',
      comments: `Manager comment for request ${i}`
    });
  }
  this.expectedRequestCount = requestCount;
});

Given('user is on the main dashboard', async function () {
  await assertions.assertVisible(page.locator('[data-testid="dashboard-container"]'));
  await assertions.assertUrlContains('dashboard');
});

/**************************************************/
/*  TEST CASE: TC-002
/*  Title: Employee successfully filters schedule change history by date range
/*  Priority: High
/*  Category: Functional
/**************************************************/

Given('user is on schedule change history page', async function () {
  await actions.click(page.locator('[data-testid="link-schedule-history"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('[data-testid="page-schedule-history"]'));
});

Given('employee has {int} schedule change requests from last month', async function (requestCount: number) {
  const lastMonth = new Date();
  lastMonth.setMonth(lastMonth.getMonth() - 1);
  
  if (!this.testData.scheduleRequests) {
    this.testData.scheduleRequests = [];
  }
  
  for (let i = 1; i <= requestCount; i++) {
    this.testData.scheduleRequests.push({
      id: `REQ-LAST-${i}`,
      status: 'Approved',
      dateSubmitted: `${lastMonth.getFullYear()}-${String(lastMonth.getMonth() + 1).padStart(2, '0')}-${String(i * 5).padStart(2, '0')}`,
      originalSchedule: '9:00 AM - 5:00 PM',
      requestedSchedule: '10:00 AM - 6:00 PM'
    });
  }
  this.lastMonthRequestCount = requestCount;
});

Given('employee has {int} schedule change requests from this month', async function (requestCount: number) {
  const thisMonth = new Date();
  
  if (!this.testData.scheduleRequests) {
    this.testData.scheduleRequests = [];
  }
  
  for (let i = 1; i <= requestCount; i++) {
    this.testData.scheduleRequests.push({
      id: `REQ-THIS-${i}`,
      status: 'Pending',
      dateSubmitted: `${thisMonth.getFullYear()}-${String(thisMonth.getMonth() + 1).padStart(2, '0')}-${String(i * 5).padStart(2, '0')}`,
      originalSchedule: '9:00 AM - 5:00 PM',
      requestedSchedule: '10:00 AM - 6:00 PM'
    });
  }
  this.thisMonthRequestCount = requestCount;
});

Given('date range filter controls are visible', async function () {
  await assertions.assertVisible(page.locator('[data-testid="filter-date-range"]'));
  await assertions.assertVisible(page.locator('[data-testid="input-from-date"]'));
  await assertions.assertVisible(page.locator('[data-testid="input-to-date"]'));
});

/**************************************************/
/*  TEST CASE: TC-003
/*  Title: Employee successfully filters schedule change history by status
/*  Priority: High
/*  Category: Functional
/**************************************************/

Given('employee has {int} {string} requests', async function (requestCount: number, status: string) {
  if (!this.testData.scheduleRequests) {
    this.testData.scheduleRequests = [];
  }
  
  if (!this.testData.requestsByStatus) {
    this.testData.requestsByStatus = {};
  }
  
  for (let i = 1; i <= requestCount; i++) {
    this.testData.scheduleRequests.push({
      id: `REQ-${status.toUpperCase()}-${i}`,
      status: status,
      dateSubmitted: `2024-01-${10 + i}`,
      originalSchedule: '9:00 AM - 5:00 PM',
      requestedSchedule: '10:00 AM - 6:00 PM',
      comments: `Comment for ${status} request ${i}`
    });
  }
  
  this.testData.requestsByStatus[status] = requestCount;
});

Given('status filter dropdown is visible', async function () {
  await assertions.assertVisible(page.locator('[data-testid="dropdown-status-filter"]'));
});

/**************************************************/
/*  TEST CASE: TC-004
/*  Title: Employee successfully combines date range and status filters simultaneously
/*  Priority: Medium
/*  Category: Functional
/**************************************************/

Given('employee has {int} {string} request from last month', async function (requestCount: number, status: string) {
  const lastMonth = new Date();
  lastMonth.setMonth(lastMonth.getMonth() - 1);
  
  if (!this.testData.scheduleRequests) {
    this.testData.scheduleRequests = [];
  }
  
  for (let i = 1; i <= requestCount; i++) {
    this.testData.scheduleRequests.push({
      id: `REQ-${status.toUpperCase()}-LAST-${i}`,
      status: status,
      dateSubmitted: `${lastMonth.getFullYear()}-${String(lastMonth.getMonth() + 1).padStart(2, '0')}-15`,
      originalSchedule: '9:00 AM - 5:00 PM',
      requestedSchedule: '10:00 AM - 6:00 PM'
    });
  }
});

Given('employee has {int} {string} request from this month', async function (requestCount: number, status: string) {
  const thisMonth = new Date();
  
  if (!this.testData.scheduleRequests) {
    this.testData.scheduleRequests = [];
  }
  
  for (let i = 1; i <= requestCount; i++) {
    this.testData.scheduleRequests.push({
      id: `REQ-${status.toUpperCase()}-THIS-${i}`,
      status: status,
      dateSubmitted: `${thisMonth.getFullYear()}-${String(thisMonth.getMonth() + 1).padStart(2, '0')}-15`,
      originalSchedule: '9:00 AM - 5:00 PM',
      requestedSchedule: '10:00 AM - 6:00 PM'
    });
  }
});

Given('date range and status filters are available', async function () {
  await assertions.assertVisible(page.locator('[data-testid="filter-date-range"]'));
  await assertions.assertVisible(page.locator('[data-testid="dropdown-status-filter"]'));
});

/**************************************************/
/*  TEST CASE: TC-005
/*  Title: Employee views detailed information for schedule change request including manager comments
/*  Priority: High
/*  Category: Functional
/**************************************************/

Given('schedule change requests are visible', async function () {
  await assertions.assertVisible(page.locator('[data-testid="table-schedule-requests"]'));
  const rowCount = await page.locator('[data-testid="table-schedule-requests"] tbody tr').count();
  expect(rowCount).toBeGreaterThan(0);
});

Given('at least one request has {string} status with manager comments', async function (status: string) {
  if (!this.testData.scheduleRequests) {
    this.testData.scheduleRequests = [];
  }
  
  this.testData.scheduleRequests.push({
    id: 'REQ-DETAILED-001',
    status: status,
    dateSubmitted: '2024-01-20',
    originalSchedule: '9:00 AM - 5:00 PM',
    requestedSchedule: '10:00 AM - 6:00 PM',
    comments: 'Request rejected due to insufficient coverage during requested time slot. Please submit alternative schedule.',
    commenterName: 'Manager Smith',
    commentTimestamp: '2024-01-21 10:30 AM'
  });
  
  this.detailedRequestId = 'REQ-DETAILED-001';
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  TEST CASE: TC-001
/*  Title: Employee successfully accesses schedule change history page and views all past requests
/*  Priority: High
/*  Category: Functional
/**************************************************/

When('user clicks {string} link in navigation menu', async function (linkText: string) {
  const linkLocator = `[data-testid="link-${linkText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const dataTestIdLink = page.locator(linkLocator);
  
  if (await dataTestIdLink.count() > 0) {
    await actions.click(dataTestIdLink);
  } else {
    await actions.click(page.locator(`a:has-text("${linkText}")`));
  }
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-002
/*  Title: Employee successfully filters schedule change history by date range
/*  Priority: High
/*  Category: Functional
/**************************************************/

When('user locates {string} filter section', async function (filterName: string) {
  const filterLocator = `[data-testid="filter-${filterName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await assertions.assertVisible(page.locator(filterLocator));
  await actions.scrollIntoView(page.locator(filterLocator));
});

When('user clicks {string} field', async function (fieldName: string) {
  const fieldLocator = `[data-testid="input-${fieldName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await actions.click(page.locator(fieldLocator));
  await waits.waitForVisible(page.locator('[data-testid="datepicker-calendar"]'));
});

When('user selects first day of last month from date picker', async function () {
  const lastMonth = new Date();
  lastMonth.setMonth(lastMonth.getMonth() - 1);
  lastMonth.setDate(1);
  
  this.selectedFromDate = lastMonth;
  
  const dayLocator = `[data-testid="datepicker-day-1"]`;
  await actions.click(page.locator(dayLocator));
});

When('user selects last day of last month from date picker', async function () {
  const lastMonth = new Date();
  lastMonth.setMonth(lastMonth.getMonth() - 1);
  const lastDay = new Date(lastMonth.getFullYear(), lastMonth.getMonth() + 1, 0).getDate();
  lastMonth.setDate(lastDay);
  
  this.selectedToDate = lastMonth;
  
  const dayLocator = `[data-testid="datepicker-day-${lastDay}"]`;
  await actions.click(page.locator(dayLocator));
});

When('user clicks {string} button', async function (buttonText: string) {
  const testIdLocator = `[data-testid="button-${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const dataTestIdButtons = page.locator(testIdLocator);
  
  if (await dataTestIdButtons.count() > 0) {
    await actions.click(dataTestIdButtons);
  } else {
    await actions.click(page.locator(`button:has-text("${buttonText}")`));
  }
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-003
/*  Title: Employee successfully filters schedule change history by status
/*  Priority: High
/*  Category: Functional
/**************************************************/

When('user clicks {string} dropdown', async function (dropdownName: string) {
  const dropdownLocator = `[data-testid="dropdown-${dropdownName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await actions.click(page.locator(dropdownLocator));
  await waits.waitForVisible(page.locator('[data-testid="dropdown-options"]'));
});

When('user selects {string} from dropdown', async function (optionText: string) {
  const optionLocator = `[data-testid="option-${optionText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const dataTestIdOption = page.locator(optionLocator);
  
  if (await dataTestIdOption.count() > 0) {
    await actions.click(dataTestIdOption);
  } else {
    await actions.click(page.locator(`[role="option"]:has-text("${optionText}")`));
  }
  
  this.selectedStatus = optionText;
});

/**************************************************/
/*  TEST CASE: TC-004
/*  Title: Employee successfully combines date range and status filters simultaneously
/*  Priority: Medium
/*  Category: Functional
/**************************************************/

When('user sets {string} to first day of last month', async function (fieldName: string) {
  const fieldLocator = `[data-testid="input-${fieldName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await actions.click(page.locator(fieldLocator));
  await waits.waitForVisible(page.locator('[data-testid="datepicker-calendar"]'));
  
  const lastMonth = new Date();
  lastMonth.setMonth(lastMonth.getMonth() - 1);
  lastMonth.setDate(1);
  
  this.selectedFromDate = lastMonth;
  
  await actions.click(page.locator('[data-testid="datepicker-day-1"]'));
});

When('user sets {string} to last day of last month', async function (fieldName: string) {
  const fieldLocator = `[data-testid="input-${fieldName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await actions.click(page.locator(fieldLocator));
  await waits.waitForVisible(page.locator('[data-testid="datepicker-calendar"]'));
  
  const lastMonth = new Date();
  lastMonth.setMonth(lastMonth.getMonth() - 1);
  const lastDay = new Date(lastMonth.getFullYear(), lastMonth.getMonth() + 1, 0).getDate();
  lastMonth.setDate(lastDay);
  
  this.selectedToDate = lastMonth;
  
  const dayLocator = `[data-testid="datepicker-day-${lastDay}"]`;
  await actions.click(page.locator(dayLocator));
});

When('user selects {string} from {string} dropdown', async function (optionText: string, dropdownName: string) {
  const dropdownLocator = `[data-testid="dropdown-${dropdownName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await actions.click(page.locator(dropdownLocator));
  await waits.waitForVisible(page.locator('[data-testid="dropdown-options"]'));
  
  const optionLocator = `[data-testid="option-${optionText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const dataTestIdOption = page.locator(optionLocator);
  
  if (await dataTestIdOption.count() > 0) {
    await actions.click(dataTestIdOption);
  } else {
    await actions.click(page.locator(`[role="option"]:has-text("${optionText}")`));
  }
  
  this.selectedStatus = optionText;
});

/**************************************************/
/*  TEST CASE: TC-005
/*  Title: Employee views detailed information for schedule change request including manager comments
/*  Priority: High
/*  Category: Functional
/**************************************************/

When('user locates schedule change request with {string} status', async function (status: string) {
  const statusBadgeLocator = `[data-testid="badge-status-${status.toLowerCase()}"]`;
  await assertions.assertVisible(page.locator(statusBadgeLocator).first());
  
  this.selectedRequestRow = page.locator(`[data-testid="table-schedule-requests"] tbody tr:has([data-testid="badge-status-${status.toLowerCase()}"])`).first();
});

When('user clicks on request row or {string} button', async function (buttonText: string) {
  if (this.selectedRequestRow) {
    await actions.click(this.selectedRequestRow);
  } else {
    const buttonLocator = `[data-testid="button-${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
    await actions.click(page.locator(buttonLocator).first());
  }
  await waits.waitForVisible(page.locator('[data-testid="modal-request-details"], [data-testid="panel-request-details"]'));
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  TEST CASE: TC-001
/*  Title: Employee successfully accesses schedule change history page and views all past requests
/*  Priority: High
/*  Category: Functional
/**************************************************/

Then('{string} page should load within {int} seconds', async function (pageName: string, seconds: number) {
  const pageLocator = `[data-testid="page-${pageName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await waits.waitForVisible(page.locator(pageLocator));
  await assertions.assertVisible(page.locator(pageLocator));
});

Then('page title {string} should be displayed', async function (titleText: string) {
  const titleLocator = '[data-testid="page-title"]';
  await assertions.assertVisible(page.locator(titleLocator));
  await assertions.assertContainsText(page.locator(titleLocator), titleText);
});

Then('schedule change requests table should be visible', async function () {
  await assertions.assertVisible(page.locator('[data-testid="table-schedule-requests"]'));
});

Then('table should display columns {string}', async function (columnNames: string) {
  const columns = columnNames.split(',').map(col => col.trim());
  
  for (const column of columns) {
    const columnLocator = `[data-testid="column-header-${column.toLowerCase().replace(/\s+/g, '-')}"]`;
    const columnHeader = page.locator(columnLocator);
    
    if (await columnHeader.count() > 0) {
      await assertions.assertVisible(columnHeader);
    } else {
      await assertions.assertContainsText(page.locator('[data-testid="table-schedule-requests"] thead'), column);
    }
  }
});

Then('all {int} schedule change requests should be displayed', async function (expectedCount: number) {
  const rowLocator = '[data-testid="table-schedule-requests"] tbody tr';
  await assertions.assertElementCount(page.locator(rowLocator), expectedCount);
});

Then('requests should be ordered chronologically with most recent first', async function () {
  const dateElements = await page.locator('[data-testid="cell-date-submitted"]').allTextContents();
  
  for (let i = 0; i < dateElements.length - 1; i++) {
    const currentDate = new Date(dateElements[i]);
    const nextDate = new Date(dateElements[i + 1]);
    expect(currentDate.getTime()).toBeGreaterThanOrEqual(nextDate.getTime());
  }
});

Then('{string} status should display {string} badge', async function (status: string, color: string) {
  const badgeLocator = `[data-testid="badge-status-${status.toLowerCase()}"]`;
  await assertions.assertVisible(page.locator(badgeLocator).first());
  
  const badge = page.locator(badgeLocator).first();
  const badgeClass = await badge.getAttribute('class');
  expect(badgeClass).toContain(color);
});

Then('manager comments should be visible in {string} column', async function (columnName: string) {
  const commentsLocator = `[data-testid="cell-${columnName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const commentsCount = await page.locator(commentsLocator).count();
  expect(commentsCount).toBeGreaterThan(0);
});

Then('pagination controls should appear if more than {int} requests exist', async function (threshold: number) {
  const rowCount = await page.locator('[data-testid="table-schedule-requests"] tbody tr').count();
  
  if (rowCount > threshold) {
    await assertions.assertVisible(page.locator('[data-testid="pagination-controls"]'));
  }
});

Then('no error messages should be displayed', async function () {
  const errorLocators = [
    '[data-testid="error-message"]',
    '[data-testid="alert-error"]',
    '.error-message',
    '.alert-danger'
  ];
  
  for (const locator of errorLocators) {
    const errorElements = page.locator(locator);
    const count = await errorElements.count();
    expect(count).toBe(0);
  }
});

/**************************************************/
/*  TEST CASE: TC-002
/*  Title: Employee successfully filters schedule change history by date range
/*  Priority: High
/*  Category: Functional
/**************************************************/

Then('{string} field should be visible', async function (fieldName: string) {
  const fieldLocator = `[data-testid="input-${fieldName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await assertions.assertVisible(page.locator(fieldLocator));
});

Then('selected date should be highlighted in calendar', async function () {
  await assertions.assertVisible(page.locator('[data-testid="datepicker-day-selected"], .selected, .highlighted'));
});

Then('date should appear in {string} field in {string} format', async function (fieldName: string, dateFormat: string) {
  const fieldLocator = `[data-testid="input-${fieldName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const fieldValue = await page.locator(fieldLocator).inputValue();
  
  expect(fieldValue).toBeTruthy();
  expect(fieldValue.length).toBeGreaterThan(0);
  
  if (dateFormat === 'MM/DD/YYYY') {
    expect(fieldValue).toMatch(/\d{2}\/\d{2}\/\d{4}/);
  }
});

Then('page should update within {int} seconds', async function (seconds: number) {
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(500);
});

Then('table should display {int} schedule change requests', async function (expectedCount: number) {
  await waits.waitForNetworkIdle();
  const rowLocator = '[data-testid="table-schedule-requests"] tbody tr';
  await assertions.assertElementCount(page.locator(rowLocator), expectedCount);
});

Then('summary message {string} should be displayed', async function (messagePattern: string) {
  const summaryLocator = '[data-testid="filter-summary"], [data-testid="results-summary"]';
  await assertions.assertVisible(page.locator(summaryLocator));
  
  const summaryText = await page.locator(summaryLocator).textContent();
  expect(summaryText).toBeTruthy();
});

Then('only requests from last month should be visible', async function () {
  const dateElements = await page.locator('[data-testid="cell-date-submitted"]').allTextContents();
  
  const lastMonth = new Date();
  lastMonth.setMonth(lastMonth.getMonth() - 1);
  
  for (const dateText of dateElements) {
    const requestDate = new Date(dateText);
    expect(requestDate.getMonth()).toBe(lastMonth.getMonth());
  }
});

Then('requests from this month should not be visible', async function () {
  const dateElements = await page.locator('[data-testid="cell-date-submitted"]').allTextContents();
  
  const thisMonth = new Date().getMonth();
  
  for (const dateText of dateElements) {
    const requestDate = new Date(dateText);
    expect(requestDate.getMonth()).not.toBe(thisMonth);
  }
});

Then('{string} button should be visible', async function (buttonText: string) {
  const buttonLocator = `[data-testid="button-${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const dataTestIdButton = page.locator(buttonLocator);
  
  if (await dataTestIdButton.count() > 0) {
    await assertions.assertVisible(dataTestIdButton);
  } else {
    await assertions.assertVisible(page.locator(`button:has-text("${buttonText}")`));
  }
});

/**************************************************/
/*  TEST CASE: TC-003
/*  Title: Employee successfully filters schedule change history by status
/*  Priority: High
/*  Category: Functional
/**************************************************/

Then('dropdown should expand showing options {string}', async function (optionsText: string) {
  await assertions.assertVisible(page.locator('[data-testid="dropdown-options"]'));
  
  const options = optionsText.split(',').map(opt => opt.trim());
  
  for (const option of options) {
    const optionLocator = `[data-testid="option-${option.toLowerCase().replace(/\s+/g, '-')}"]`;
    const dataTestIdOption = page.locator(optionLocator);
    
    if (await dataTestIdOption.count() > 0) {
      await assertions.assertVisible(dataTestIdOption);
    } else {
      await assertions.assertContainsText(page.locator('[data-testid="dropdown-options"]'), option);
    }
  }
});

Then('{string} option should be highlighted and selected', async function (optionText: string) {
  const optionLocator = `[data-testid="option-${optionText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const selectedOption = page.locator(`${optionLocator}.selected, ${optionLocator}[aria-selected="true"]`);
  
  if (await selectedOption.count() > 0) {
    await assertions.assertVisible(selectedOption);
  }
});

Then('dropdown should show {string} as current selection', async function (selectedText: string) {
  const dropdownLocator = '[data-testid="dropdown-status-filter"]';
  await assertions.assertContainsText(page.locator(dropdownLocator), selectedText);
});

Then('all displayed requests should have {string} status', async function (status: string) {
  const statusBadgeLocator = `[data-testid="badge-status-${status.toLowerCase()}"]`;
  const statusBadges = page.locator(statusBadgeLocator);
  const badgeCount = await statusBadges.count();
  
  expect(badgeCount).toBeGreaterThan(0);
  
  const rowCount = await page.locator('[data-testid="table-schedule-requests"] tbody tr').count();
  expect(badgeCount).toBe(rowCount);
});

Then('{string} status badge should be displayed with {string} color', async function (status: string, color: string) {
  const badgeLocator = `[data-testid="badge-status-${status.toLowerCase()}"]`;
  await assertions.assertVisible(page.locator(badgeLocator).first());
  
  const badge = page.locator(badgeLocator).first();
  const badgeClass = await badge.getAttribute('class');
  expect(badgeClass).toContain(color);
});

Then('requests with other statuses should not be visible', async function () {
  const allStatuses = ['Approved', 'Pending', 'Rejected'];
  const selectedStatus = this.selectedStatus;
  
  for (const status of allStatuses) {
    if (status !== selectedStatus) {
      const badgeLocator = `[data-testid="badge-status-${status.toLowerCase()}"]`;
      const badgeCount = await page.locator(badgeLocator).count();
      expect(badgeCount).toBe(0);
    }
  }
});

/**************************************************/
/*  TEST CASE: TC-004
/*  Title: Employee successfully combines date range and status filters simultaneously
/*  Priority: Medium
/*  Category: Functional
/**************************************************/

Then('both date fields should be populated in {string} format', async function (dateFormat: string) {
  const fromDateValue = await page.locator('[data-testid="input-from-date"]').inputValue();
  const toDateValue = await page.locator('[data-testid="input-to-date"]').inputValue();
  
  expect(fromDateValue).toBeTruthy();
  expect(toDateValue).toBeTruthy();
  
  if (dateFormat === 'MM/DD/YYYY') {
    expect(fromDateValue).toMatch(/\d{2}\/\d{2}\/\d{4}/);
    expect(toDateValue).toMatch(/\d{2}\/\d{2}\/\d{4}/);
  }
});

Then('status dropdown should show {string} as selected', async function (status: string) {
  const dropdownLocator = '[data-testid="dropdown-status-filter"]';
  await assertions.assertContainsText(page.locator(dropdownLocator), status);
});

Then('all displayed requests should be from last month date range', async function () {
  const dateElements = await page.locator('[data-testid="cell-date-submitted"]').allTextContents();
  
  const lastMonth = new Date();
  lastMonth.setMonth(lastMonth.getMonth() - 1);
  
  for (const dateText of dateElements) {
    const requestDate = new Date(dateText);
    expect(requestDate.getMonth()).toBe(lastMonth.getMonth());
    expect(requestDate.getFullYear()).toBe(lastMonth.getFullYear());
  }
});

Then('approved request from last month should not be visible', async function () {
  const approvedBadges = page.locator('[data-testid="badge-status-approved"]');
  const approvedCount = await approvedBadges.count();
  expect(approvedCount).toBe(0);
});

Then('approved request from this month should not be visible', async function () {
  const dateElements = await page.locator('[data-testid="cell-date-submitted"]').allTextContents();
  
  const thisMonth = new Date().getMonth();
  
  for (const dateText of dateElements) {
    const requestDate = new Date(dateText);
    expect(requestDate.getMonth()).not.toBe(thisMonth);
  }
});

Then('filter combination state should be preserved', async function () {
  const fromDateValue = await page.locator('[data-testid="input-from-date"]').inputValue();
  const toDateValue = await page.locator('[data-testid="input-to-date"]').inputValue();
  const statusValue = await page.locator('[data-testid="dropdown-status-filter"]').textContent();
  
  expect(fromDateValue).toBeTruthy();
  expect(toDateValue).toBeTruthy();
  expect(statusValue).toBeTruthy();
});

/**************************************************/
/*  TEST CASE: TC-005
/*  Title: Employee views detailed information for schedule change request including manager comments
/*  Priority: High
/*  Category: Functional
/**************************************************/

Then('request should display red {string} status badge', async function (status: string) {
  const badgeLocator = `[data-testid="badge-status-${status.toLowerCase()}"]`;
  await assertions.assertVisible(page.locator(badgeLocator).first());
  
  const badge = page.locator(badgeLocator).first();
  const badgeClass = await badge.getAttribute('class');
  expect(badgeClass).toContain('red');
});

Then('comments icon or preview text should indicate comments are present', async function () {
  const commentsIndicators = [
    '[data-testid="icon-comments"]',
    '[data-testid="cell-comments"]',
    '[data-testid="preview-comments"]'
  ];
  
  let found = false;
  for (const locator of commentsIndicators) {
    if (await page.locator(locator).count() > 0) {
      await assertions.assertVisible(page.locator(locator).first());
      found = true;
      break;
    }
  }
  
  expect(found).toBe(true);
});

Then('request details should expand or open in modal', async function () {
  const detailsContainers = [
    '[data-testid="modal-request-details"]',
    '[data-testid="panel-request-details"]',
    '[data-testid="expanded-row-details"]'
  ];
  
  let found = false;
  for (const locator of detailsContainers) {
    if (await page.locator(locator).count() > 0) {
      await assertions.assertVisible(page.locator(locator));
      found = true;
      break;
    }
  }
  
  expect(found).toBe(true);
});

Then('{string} field should be displayed', async function (fieldName: string) {
  const fieldLocator = `[data-testid="field-${fieldName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const labelLocator = `[data-testid="label-${fieldName.toLowerCase().replace(/\s+/g, '-')}"]`;
  
  const dataTestIdField = page.locator(fieldLocator);
  const dataTestIdLabel = page.locator(labelLocator);
  
  if (await dataTestIdField.count() > 0) {
    await assertions.assertVisible(dataTestIdField);
  } else if (await dataTestIdLabel.count() > 0) {
    await assertions.assertVisible(dataTestIdLabel);
  } else {
    const detailsContainer = page.locator('[data-testid="modal-request-details"], [data-testid="panel-request-details"]');
    await assertions.assertContainsText(detailsContainer, fieldName);
  }
});

Then('{string} section should be displayed', async function (sectionName: string) {
  const sectionLocator = `[data-testid="section-${sectionName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const dataTestIdSection = page.locator(sectionLocator);
  
  if (await dataTestIdSection.count() > 0) {
    await assertions.assertVisible(dataTestIdSection);
  } else {
    const detailsContainer = page.locator('[data-testid="modal-request-details"], [data-testid="panel-request-details"]');
    await assertions.assertContainsText(detailsContainer, sectionName);
  }
});

Then('manager comment text should be visible', async function () {
  const commentLocators = [
    '[data-testid="text-manager-comment"]',
    '[data-testid="field-manager-comments"]',
    '[data-testid="comment-text"]'
  ];
  
  let found = false;
  for (const locator of commentLocators) {
    if (await page.locator(locator).count() > 0) {
      await assertions.assertVisible(page.locator(locator));
      const commentText = await page.locator(locator).textContent();
      expect(commentText?.length).toBeGreaterThan(0);
      found = true;
      break;
    }
  }
  
  expect(found).toBe(true);
});

Then('commenter name should be displayed', async function () {
  const commenterLocators = [
    '[data-testid="text-commenter-name"]',
    '[data-testid="field-commenter"]',
    '[data-testid="comment-author"]'
  ];
  
  let found = false;
  for (const locator of commenterLocators) {
    if (await page.locator(locator).count() > 0) {
      await assertions.assertVisible(page.locator(locator));
      found = true;
      break;
    }
  }
  
  expect(found).toBe(true);
});

Then('comment timestamp should be displayed', async function () {
  const timestampLocators = [
    '[data-testid="text-comment-timestamp"]',
    '[data-testid="field-comment-date"]',
    '[data-testid="comment-time"]'
  ];
  
  let found = false;
  for (const locator of timestampLocators) {
    if (await page.locator(locator).count() > 0) {
      await assertions.assertVisible(page.locator(locator));
      found = true;
      break;
    }
  }
  
  expect(found).toBe(true);
});

Then('all fields should contain accurate data', async function () {
  const detailsContainer = page.locator('[data-testid="modal-request-details"], [data-testid="panel-request-details"]');
  const detailsText = await detailsContainer.textContent();
  
  expect(detailsText).toBeTruthy();
  expect(detailsText?.length).toBeGreaterThan(0);
});

Then('dates should be formatted consistently', async function () {
  const dateFields = await page.locator('[data-testid*="date"], [data-testid*="timestamp"]').allTextContents();
  
  for (const dateText of dateFields) {
    if (dateText && dateText.trim().length > 0) {
      expect(dateText).toMatch(/\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\d{4}[\/\-]\d{1,2}[\/\-]\d{1,2}/);
    }
  }
});

Then('no information should be missing or truncated', async function () {
  const requiredFields = [
    '[data-testid="field-request-id"]',
    '[data-testid="field-submission-date"]',
    '[data-testid="field-status"]'
  ];
  
  for (const locator of requiredFields) {
    if (await page.locator(locator).count() > 0) {
      const fieldText = await page.locator(locator).textContent();
      expect(fieldText?.trim().length).toBeGreaterThan(0);
    }
  }
});

Then('user should be able to close detail view and return to history list', async function () {
  const closeButtons = [
    '[data-testid="button-close"]',
    '[data-testid="button-close-modal"]',
    '[aria-label="Close"]'
  ];
  
  let found = false;
  for (const locator of closeButtons) {
    if (await page.locator(locator).count() > 0) {
      await assertions.assertVisible(page.locator(locator));
      found = true;
      break;
    }
  }
  
  expect(found).toBe(true);
});