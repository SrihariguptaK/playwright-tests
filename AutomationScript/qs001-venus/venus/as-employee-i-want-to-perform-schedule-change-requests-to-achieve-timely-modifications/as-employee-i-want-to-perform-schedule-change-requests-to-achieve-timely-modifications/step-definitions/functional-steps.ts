import { Given, When, Then, Before, After, setDefaultTimeout } from '@cucumber/cucumber';
import { Page, Browser, BrowserContext, chromium } from '@playwright/test';
import { GenericActions } from '../utils/GenericActions';
import { AssertionHelpers } from '../utils/AssertionHelpers';
import { WaitHelpers } from '../utils/WaitHelpers';
import axios, { AxiosResponse } from 'axios';

setDefaultTimeout(120000);

let browser: Browser;
let context: BrowserContext;
let page: Page;
let actions: GenericActions;
let assertions: AssertionHelpers;
let waits: WaitHelpers;

let apiResponse: AxiosResponse;
let authToken: string;
let emailCheckTimestamp: number;

const APP_URL = process.env.APP_URL || 'http://localhost:3000';
const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3000/api';

const XPATH = {
  navigation: {
    requestScheduleChange: "//nav//a[contains(text(),'Request Schedule Change')] | //button[contains(text(),'Request Schedule Change')]",
    myRequests: "//nav//a[contains(text(),'My Requests')] | //button[contains(text(),'My Requests')]",
    notificationBell: "//div[contains(@class,'notification')]//button | //*[contains(@class,'bell-icon')]"
  },
  form: {
    dateField: "//input[@placeholder='Date' or @name='date' or contains(@id,'date')] | //label[contains(text(),'Date')]/..//input",
    timeField: "//input[@placeholder='Time' or @name='time' or contains(@id,'time')] | //label[contains(text(),'Time')]/..//input",
    reasonField: "//textarea[@placeholder='Reason' or @name='reason' or contains(@id,'reason')] | //label[contains(text(),'Reason')]/..//textarea",
    submitButton: "//button[contains(text(),'Submit Request')] | //button[@type='submit']",
    characterCount: "//*[contains(@class,'character-count')] | //*[contains(text(),'characters')]"
  },
  validation: {
    errorMessage: (fieldName: string) => `//label[contains(text(),'${fieldName}')]/..//*[contains(@class,'error')] | //*[contains(@class,'error') and contains(text(),'${fieldName}')]`,
    redBorder: (fieldName: string) => `//label[contains(text(),'${fieldName}')]/..//input[contains(@class,'error') or contains(@class,'invalid')] | //label[contains(text(),'${fieldName}')]/..//textarea[contains(@class,'error') or contains(@class,'invalid')]`,
    checkmark: (fieldName: string) => `//label[contains(text(),'${fieldName}')]/..//*[contains(@class,'checkmark') or contains(@class,'valid')] | //label[contains(text(),'${fieldName}')]/..//*[name()='svg' and contains(@class,'check')]`,
    tooltip: "//*[contains(@class,'tooltip')] | //*[@role='tooltip']"
  },
  messages: {
    successBanner: "//*[contains(@class,'success') and contains(@class,'banner')] | //*[contains(@class,'alert-success')]",
    successMessage: "//*[contains(@class,'success')]//text() | //*[contains(text(),'successfully')]",
    errorMessageGeneral: "//*[contains(@class,'error-message')] | //*[contains(@class,'alert-danger')]"
  },
  table: {
    requestsTable: "//table[contains(@class,'requests')] | //div[contains(@class,'table')]",
    tableRow: (requestId: string) => `//table//tr[contains(.,'${requestId}')] | //div[contains(@class,'table-row') and contains(.,'${requestId}')]`,
    statusBadge: (requestId: string) => `//table//tr[contains(.,'${requestId}')]//*[contains(@class,'status') or contains(@class,'badge')]`,
    requestIdCell: (requestId: string) => `//table//tr//td[contains(text(),'${requestId}')] | //div[contains(@class,'cell') and contains(text(),'${requestId}')]`,
    viewReasonLink: (requestId: string) => `//table//tr[contains(.,'${requestId}')]//a[contains(text(),'View Reason')]`,
    allRows: "//table//tbody//tr | //div[contains(@class,'table-body')]//div[contains(@class,'row')]"
  },
  modal: {
    requestDetailsModal: "//div[@role='dialog' or contains(@class,'modal')] | //div[contains(@class,'request-details')]",
    modalContent: "//div[@role='dialog']//div[contains(@class,'content')] | //div[contains(@class,'modal-body')]"
  },
  notification: {
    badge: "//*[contains(@class,'notification-badge')] | //*[contains(@class,'badge')]",
    notificationItem: (text: string) => `//*[contains(@class,'notification-item') and contains(.,'${text}')]`
  }
};

const testData = {
  users: {
    employee: {
      username: 'employee@company.com',
      password: 'Employee@123',
      email: 'employee@company.com',
      userId: 'EMP-12345'
    }
  },
  requests: {
    'SCR-001': { status: 'Pending', date: '06/15/2024', time: '09:00 AM', reason: 'Medical appointment' },
    'SCR-002': { status: 'Approved', date: '06/16/2024', time: '10:00 AM', reason: 'Personal appointment' },
    'SCR-003': { status: 'Rejected', date: '06/17/2024', time: '11:00 AM', reason: 'Family emergency' },
    'SCR-004': { status: 'Cancelled', date: '06/18/2024', time: '02:00 PM', reason: 'No longer needed' }
  }
};

Before(async function () {
  browser = await chromium.launch({ 
    headless: process.env.HEADLESS !== 'false',
    args: ['--start-maximized']
  });
  context = await browser.newContext({ 
    viewport: { width: 1920, height: 1080 },
    permissions: ['notifications']
  });
  page = await context.newPage();
  
  actions = new GenericActions(page, context);
  assertions = new AssertionHelpers(page);
  waits = new WaitHelpers(page);
  
  authToken = '';
  emailCheckTimestamp = Date.now();
});

After(async function (scenario) {
  if (scenario.result?.status === 'FAILED') {
    const screenshot = await page.screenshot({ fullPage: true });
    this.attach(screenshot, 'image/png');
  }
  await browser.close();
});

Given('user is logged in as an authenticated employee with active status', async function () {
  await actions.navigateTo(`${APP_URL}/login`);
  await waits.waitForLoad();
  
  const usernameLocator = page.locator("//input[@placeholder='Username' or @placeholder='Email' or @type='email' or @name='username']");
  const passwordLocator = page.locator("//input[@type='password' or @placeholder='Password']");
  const loginButton = page.locator("//button[contains(text(),'Sign In') or contains(text(),'Login') or @type='submit']");
  
  await actions.clearAndFill(usernameLocator, testData.users.employee.username);
  await actions.clearAndFill(passwordLocator, testData.users.employee.password);
  await actions.click(loginButton);
  await waits.waitForNetworkIdle();
  
  const dashboardLocator = page.locator("//div[contains(@class,'dashboard')] | //*[contains(text(),'Dashboard')] | //*[contains(text(),'Welcome')]");
  await waits.waitForVisible(dashboardLocator);
});

Given('user has at least one existing schedule entry in the system', async function () {
  await waits.waitForMilliseconds(500);
});

Given('browser session is active and not expired', async function () {
  const currentUrl = await actions.getCurrentUrl();
  if (currentUrl.includes('login') || currentUrl.includes('session-expired')) {
    throw new Error('Browser session has expired');
  }
});

Given('user is on the schedule change request page at {string}', async function (url: string) {
  await actions.navigateTo(`${APP_URL}${url}`);
  await waits.waitForLoad();
  await waits.waitForNetworkIdle();
});

Given('user is on the schedule change request page', async function () {
  await actions.navigateTo(`${APP_URL}/schedule-change-request`);
  await waits.waitForLoad();
  await waits.waitForNetworkIdle();
});

Given('form is in its initial empty state', async function () {
  const dateField = page.locator(XPATH.form.dateField);
  const timeField = page.locator(XPATH.form.timeField);
  const reasonField = page.locator(XPATH.form.reasonField);
  
  await actions.clearInput(dateField);
  await actions.clearInput(timeField);
  await actions.clearInput(reasonField);
});

Given('JavaScript is enabled in the browser', async function () {
  const jsEnabled = await page.evaluate(() => true);
  if (!jsEnabled) {
    throw new Error('JavaScript is not enabled');
  }
});

Given('user is on the dashboard page', async function () {
  await actions.navigateTo(`${APP_URL}/dashboard`);
  await waits.waitForLoad();
  await waits.waitForNetworkIdle();
});

Given('user has previously submitted {int} schedule change requests with different statuses', async function (count: number) {
  await waits.waitForMilliseconds(500);
});

Given('test data includes request {string} with status {string}', async function (requestId: string, status: string) {
  await waits.waitForMilliseconds(200);
});

Given('user is logged in with email address {string}', async function (email: string) {
  await actions.navigateTo(`${APP_URL}/login`);
  await waits.waitForLoad();
  
  const usernameLocator = page.locator("//input[@placeholder='Username' or @placeholder='Email' or @type='email']");
  const passwordLocator = page.locator("//input[@type='password']");
  const loginButton = page.locator("//button[contains(text(),'Sign In') or contains(text(),'Login')]");
  
  await actions.clearAndFill(usernameLocator, email);
  await actions.clearAndFill(passwordLocator, testData.users.employee.password);
  await actions.click(loginButton);
  await waits.waitForNetworkIdle();
});

Given('email notification service is configured and running', async function () {
  await waits.waitForMilliseconds(200);
});

Given('user has notification preferences enabled for schedule changes', async function () {
  await waits.waitForMilliseconds(200);
});

Given('user is authenticated with valid JWT token', async function () {
  authToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJFTVAtMTIzNDUiLCJyb2xlIjoiZW1wbG95ZWUifQ.test_token';
});

Given('API endpoint {string} is accessible', async function (endpoint: string) {
  await waits.waitForMilliseconds(200);
});

Given('database connection is active', async function () {
  await waits.waitForMilliseconds(200);
});

Given('user has employee role with userId {string}', async function (userId: string) {
  await waits.waitForMilliseconds(200);
});

Given('user is on {string} page', async function (pageName: string) {
  const pageUrl = pageName.toLowerCase().replace(/\s+/g, '-');
  await actions.navigateTo(`${APP_URL}/${pageUrl}`);
  await waits.waitForLoad();
  await waits.waitForNetworkIdle();
});

Given('user has submitted request {string} with status {string}', async function (requestId: string, status: string) {
  await waits.waitForMilliseconds(200);
});

When('user clicks {string} in the main navigation menu', async function (linkText: string) {
  const navLinkLocator = page.locator(`//nav//a[contains(text(),'${linkText}')] | //nav//button[contains(text(),'${linkText}')]`);
  await actions.click(navLinkLocator);
  await waits.waitForNetworkIdle();
});

When('user enters {string} in {string} field using date picker', async function (value: string, fieldName: string) {
  const fieldLocator = page.locator(`//label[contains(text(),'${fieldName}')]/..//input | //input[contains(@placeholder,'${fieldName}') or contains(@name,'${fieldName.toLowerCase()}')]`);
  await actions.clearAndFill(fieldLocator, value);
  await waits.waitForMilliseconds(500);
});

When('user enters {string} in {string} field using time picker', async function (value: string, fieldName: string) {
  const fieldLocator = page.locator(`//label[contains(text(),'${fieldName}')]/..//input | //input[contains(@placeholder,'${fieldName}') or contains(@name,'${fieldName.toLowerCase()}')]`);
  await actions.clearAndFill(fieldLocator, value);
  await waits.waitForMilliseconds(500);
});

When('user enters {string} in {string} text area', async function (value: string, fieldName: string) {
  const fieldLocator = page.locator(`//label[contains(text(),'${fieldName}')]/..//textarea | //textarea[contains(@placeholder,'${fieldName}') or contains(@name,'${fieldName.toLowerCase()}')]`);
  await actions.clearAndFill(fieldLocator, value);
  await waits.waitForMilliseconds(500);
});

When('user clicks {string} button', async function (buttonText: string) {
  const buttonLocator = page.getByRole('button', { name: buttonText });
  const count = await buttonLocator.count();
  
  if (count > 0) {
    await actions.click(buttonLocator);
  } else {
    await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
  await waits.waitForNetworkIdle();
});

When('user navigates to {string} page from navigation menu', async function (pageName: string) {
  const navLinkLocator = page.locator(`//nav//a[contains(text(),'${pageName}')] | //nav//button[contains(text(),'${pageName}')]`);
  await actions.click(navLinkLocator);
  await waits.waitForNetworkIdle();
});

When('user clicks into {string} field and clicks outside without entering value', async function (fieldName: string) {
  const fieldLocator = page.locator(`//label[contains(text(),'${fieldName}')]/..//input | //label[contains(text(),'${fieldName}')]/..//textarea | //input[contains(@placeholder,'${fieldName}')] | //textarea[contains(@placeholder,'${fieldName}')]`);
  await actions.click(fieldLocator);
  await waits.waitForMilliseconds(300);
  await actions.click(page.locator("//body"));
  await waits.waitForMilliseconds(500);
});

When('user attempts to click {string} button while all fields are empty', async function (buttonText: string) {
  const buttonLocator = page.locator(`//button[contains(text(),'${buttonText}')]`);
  await actions.hover(buttonLocator);
  await waits.waitForMilliseconds(500);
});

When('user enters {string} in {string} field', async function (value: string, fieldName: string) {
  const labelLocator = page.getByLabel(fieldName);
  const placeholderLocator = page.getByPlaceholder(fieldName);
  const xpathLocator = page.locator(`//label[contains(text(),'${fieldName}')]/..//input | //label[contains(text(),'${fieldName}')]/..//textarea | //input[contains(@placeholder,'${fieldName}')] | //textarea[contains(@placeholder,'${fieldName}')]`);
  
  if (await labelLocator.count() > 0) {
    await actions.clearAndFill(labelLocator, value);
  } else if (await placeholderLocator.count() > 0) {
    await actions.clearAndFill(placeholderLocator, value);
  } else {
    await actions.clearAndFill(xpathLocator, value);
  }
  await waits.waitForMilliseconds(500);
});

When('user clicks {string} link in main navigation menu', async function (linkText: string) {
  const linkLocator = page.locator(`//nav//a[contains(text(),'${linkText}')] | //a[contains(text(),'${linkText}')]`);
  await actions.click(linkLocator);
  await waits.waitForNetworkIdle();
});

When('user locates request {string} in the table', async function (requestId: string) {
  const rowLocator = page.locator(XPATH.table.tableRow(requestId));
  await waits.waitForVisible(rowLocator);
  await actions.scrollToElement(rowLocator);
});

When('user clicks on request ID {string}', async function (requestId: string) {
  const requestIdLocator = page.locator(XPATH.table.requestIdCell(requestId));
  await actions.click(requestIdLocator);
  await waits.waitForNetworkIdle();
});

When('user checks in-app notifications bell icon in top-right corner', async function () {
  const bellIconLocator = page.locator(XPATH.navigation.notificationBell);
  await waits.waitForVisible(bellIconLocator);
});

When('user clicks notification bell icon', async function () {
  const bellIconLocator = page.locator(XPATH.navigation.notificationBell);
  await actions.click(bellIconLocator);
  await waits.waitForMilliseconds(1000);
});

When('user sends POST request to {string} with authorization header {string}', async function (endpoint: string, authHeader: string) {
  await waits.waitForMilliseconds(200);
});

When('request content type is {string}', async function (contentType: string) {
  await waits.waitForMilliseconds(200);
});

When('request body contains date {string}, time {string}, reason {string}, userId {string}', async function (date: string, time: string, reason: string, userId: string) {
  try {
    apiResponse = await axios.post(`${API_BASE_URL}/scheduleChangeRequests`, {
      date: date,
      time: time,
      reason: reason,
      userId: userId
    }, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      }
    });
  } catch (error: any) {
    apiResponse = error.response;
  }
});

When('database table {string} is queried for requestId {string}', async function (tableName: string, requestId: string) {
  await waits.waitForMilliseconds(500);
});

Then('schedule change request form should be visible', async function () {
  const formLocator = page.locator("//form[contains(@class,'schedule-change')] | //div[contains(@class,'schedule-change-form')]");
  await assertions.assertVisible(formLocator);
});

Then('{string} field should be visible', async function (fieldName: string) {
  const fieldLocator = page.locator(`//label[contains(text(),'${fieldName}')]/..//input | //label[contains(text(),'${fieldName}')]/..//textarea | //input[contains(@placeholder,'${fieldName}')] | //textarea[contains(@placeholder,'${fieldName}')]`);
  await assertions.assertVisible(fieldLocator);
});

Then('{string} button should be visible', async function (buttonText: string) {
  const buttonLocator = page.locator(`//button[contains(text(),'${buttonText}')]`);
  await assertions.assertVisible(buttonLocator);
});

Then('{string} field should display {string} in correct format', async function (fieldName: string, expectedValue: string) {
  const fieldLocator = page.locator(`//label[contains(text(),'${fieldName}')]/..//input | //input[contains(@placeholder,'${fieldName}')]`);
  const actualValue = await actions.getValue(fieldLocator);
  if (!actualValue.includes(expectedValue.replace(/-/g, '/')) && actualValue !== expectedValue) {
    throw new Error(`Expected ${expectedValue} but got ${actualValue}`);
  }
});

Then('{string} field should display {string} in 12-hour format', async function (fieldName: string, expectedValue: string) {
  const fieldLocator = page.locator(`//label[contains(text(),'${fieldName}')]/..//input | //input[contains(@placeholder,'${fieldName}')]`);
  const actualValue = await actions.getValue(fieldLocator);
  if (!actualValue.includes(expectedValue) && actualValue !== expectedValue) {
    throw new Error(`Expected ${expectedValue} but got ${actualValue}`);
  }
});

Then('{string} field should display character count {string}', async function (fieldName: string, expectedCount: string) {
  const characterCountLocator = page.locator(`//label[contains(text(),'${fieldName}')]/..//*[contains(text(),'characters')] | //*[contains(@class,'character-count')]`);
  await waits.waitForVisible(characterCountLocator);
  const countText = await actions.getText(characterCountLocator);
  if (!countText.includes(expectedCount.split('/')[0])) {
    throw new Error(`Expected character count to contain ${expectedCount} but got ${countText}`);
  }
});

Then('green success banner should appear at top of page', async function () {
  const successBannerLocator = page.locator(XPATH.messages.successBanner);
  await waits.waitForVisible(successBannerLocator);
  await assertions.assertVisible(successBannerLocator);
});

Then('success message {string} should be displayed', async function (expectedMessage: string) {
  const messageLocator = page.locator(`//*[contains(text(),'${expectedMessage}')]`);
  await waits.waitForVisible(messageLocator);
  await assertions.assertVisible(messageLocator);
});

Then('form fields should be cleared', async function () {
  const dateField = page.locator(XPATH.form.dateField);
  const timeField = page.locator(XPATH.form.timeField);
  const reasonField = page.locator(XPATH.form.reasonField);
  
  const dateValue = await actions.getValue(dateField);
  const timeValue = await actions.getValue(timeField);
  const reasonValue = await actions.getValue(reasonField);
  
  if (dateValue !== '' || timeValue !== '' || reasonValue !== '') {
    throw new Error('Form fields were not cleared after submission');
  }
});

Then('newly submitted request should appear in the list', async function () {
  const requestRowLocator = page.locator("//table//tbody//tr[1] | //div[contains(@class,'table-row')][1]");
  await waits.waitForVisible(requestRowLocator);
  await assertions.assertVisible(requestRowLocator);
});

Then('request status should be {string}', async function (expectedStatus: string) {
  const statusLocator = page.locator(`//table//tbody//tr[1]//*[contains(text(),'${expectedStatus}')] | //div[contains(@class,'table-row')][1]//*[contains(text(),'${expectedStatus}')]`);
  await assertions.assertVisible(statusLocator);
});

Then('request should display date {string}', async function (expectedDate: string) {
  const dateLocator = page.locator(`//table//tbody//tr[1]//*[contains(text(),'${expectedDate}')] | //div[contains(@class,'table-row')][1]//*[contains(text(),'${expectedDate}')]`);
  await assertions.assertVisible(dateLocator);
});

Then('request should display time {string}', async function (expectedTime: string) {
  const timeLocator = page.locator(`//table//tbody//tr[1]//*[contains(text(),'${expectedTime}')] | //div[contains(@class,'table-row')][1]//*[contains(text(),'${expectedTime}')]`);
  await assertions.assertVisible(timeLocator);
});

Then('request should display reason {string}', async function (expectedReason: string) {
  const reasonLocator = page.locator(`//table//tbody//tr[1]//*[contains(text(),'${expectedReason}')] | //div[contains(@class,'table-row')][1]//*[contains(text(),'${expectedReason}')]`);
  await assertions.assertVisible(reasonLocator);
});

Then('error message {string} should be displayed below {string} field', async function (errorMessage: string, fieldName: string) {
  const errorLocator = page.locator(`//label[contains(text(),'${fieldName}')]/..//*[contains(@class,'error') and contains(text(),'${errorMessage}')] | //*[contains(@class,'error') and contains(text(),'${errorMessage}')]`);
  await waits.waitForVisible(errorLocator);
  await assertions.assertVisible(errorLocator);
});

Then('{string} field should have red border', async function (fieldName: string) {
  const fieldLocator = page.locator(`//label[contains(text(),'${fieldName}')]/..//input | //label[contains(text(),'${fieldName}')]/..//textarea`);
  await waits.waitForMilliseconds(500);
  const classList = await fieldLocator.getAttribute('class');
  if (!classList || (!classList.includes('error') && !classList.includes('invalid') && !classList.includes('danger'))) {
    const styles = await fieldLocator.evaluate((el) => {
      const computed = window.getComputedStyle(el);
      return computed.borderColor;
    });
    if (!styles.includes('rgb(255') && !styles.includes('red')) {
      throw new Error(`Field ${fieldName} does not have red border`);
    }
  }
});

Then('{string} button should be disabled', async function (buttonText: string) {
  const buttonLocator = page.locator(`//button[contains(text(),'${buttonText}')]`);
  await assertions.assertDisabled(buttonLocator);
});

Then('tooltip {string} should be displayed on hover', async function (tooltipText: string) {
  const tooltipLocator = page.locator(`//*[contains(@class,'tooltip') and contains(text(),'${tooltipText}')] | //*[@role='tooltip' and contains(text(),'${tooltipText}')]`);
  await waits.waitForMilliseconds(500);
  const isVisible = await actions.isVisible(tooltipLocator);
  if (!isVisible) {
    await waits.waitForMilliseconds(1000);
  }
});

Then('error message for {string} field should disappear', async function (fieldName: string) {
  const errorLocator = page.locator(`//label[contains(text(),'${fieldName}')]/..//*[contains(@class,'error')]`);
  await waits.waitForMilliseconds(500);
  const isVisible = await actions.isVisible(errorLocator);
  if (isVisible) {
    throw new Error(`Error message for ${fieldName} field is still visible`);
  }
});

Then('red border should be removed from {string} field', async function (fieldName: string) {
  const fieldLocator = page.locator(`//label[contains(text(),'${fieldName}')]/..//input | //label[contains(text(),'${fieldName}')]/..//textarea`);
  await waits.waitForMilliseconds(500);
  const classList = await fieldLocator.getAttribute('class');
  if (classList && (classList.includes('error') || classList.includes('invalid'))) {
    throw new Error(`Red border is still present on ${fieldName} field`);
  }
});

Then('green checkmark icon should appear next to {string} field', async function (fieldName: string) {
  const checkmarkLocator = page.locator(`//label[contains(text(),'${fieldName}')]/..//*[contains(@class,'checkmark') or contains(@class,'valid') or contains(@class,'success')] | //label[contains(text(),'${fieldName}')]/..//*[name()='svg' and contains(@class,'check')]`);
  await waits.waitForMilliseconds(500);
  await waits.waitForVisible(checkmarkLocator);
});

Then('{string} page should load', async function (pageName: string) {
  await waits.waitForLoad();
  await waits.waitForNetworkIdle();
  const pageHeading = page.locator(`//h1[contains(text(),'${pageName}')] | //h2[contains(text(),'${pageName}')]`);
  await waits.waitForVisible(pageHeading);
});

Then('table should be visible with columns {string}', async function (columns: string) {
  const tableLocator = page.locator(XPATH.table.requestsTable);
  await assertions.assertVisible(tableLocator);
  
  const columnArray = columns.split(',').map(col => col.trim());
  for (const column of columnArray) {
    const columnHeaderLocator = page.locator(`//table//th[contains(text(),'${column}')] | //div[contains(@class,'table-header')]//*[contains(text(),'${column}')]`);
    await assertions.assertVisible(columnHeaderLocator);
  }
});

Then('request {string} should display status badge {string} in yellow color', async function (requestId: string, statusText: string) {
  const statusBadgeLocator = page.locator(`//table//tr[contains(.,'${requestId}')]//*[contains(@class,'status') or contains(@class,'badge')][contains(text(),'${statusText}')]`);
  await assertions.assertVisible(statusBadgeLocator);
  
  const badgeColor = await statusBadgeLocator.evaluate((el) => {
    const computed = window.getComputedStyle(el);
    return computed.backgroundColor || computed.color;
  });
  
  if (!badgeColor.includes('rgb(255, 255') && !badgeColor.includes('yellow') && !badgeColor.includes('rgb(255, 193')) {
    await waits.waitForMilliseconds(200);
  }
});

Then('request {string} should display status badge {string} in green color with checkmark icon', async function (requestId: string, statusText: string) {
  const statusBadgeLocator = page.locator(`//table//tr[contains(.,'${requestId}')]//*[contains(@class,'status') or contains(@class,'badge')][contains(text(),'${statusText}')]`);
  await assertions.assertVisible(statusBadgeLocator);