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
    scheduleChanges: {},
    notificationQueue: []
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
/*  Setup: Notification service configuration
/**************************************************/

Given('notification service is configured and active', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="admin-settings"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//a[@id="notification-service"]'));
  await waits.waitForNetworkIdle();
  const serviceStatus = page.locator('//span[@id="service-status"]');
  await assertions.assertContainsText(serviceStatus, 'Active');
});

Given('system has error handling and logging enabled', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="system-configuration"]'));
  await waits.waitForNetworkIdle();
  const errorHandlingCheckbox = page.locator('//input[@id="error-handling-enabled"]');
  await actions.check(errorHandlingCheckbox);
  const loggingCheckbox = page.locator('//input[@id="logging-enabled"]');
  await actions.check(loggingCheckbox);
  await actions.click(page.locator('//button[@id="save-configuration"]'));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-001
/*  Title: System handles notification failure when user email address is invalid
/*  Priority: High
/*  Category: Negative
/*  Description: Validates graceful handling of invalid email addresses
/**************************************************/

Given('user account exists with email address {string}', async function (emailAddress: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="user-management"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//button[@id="create-user"]'));
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), 'testuser');
  await actions.fill(page.locator('//input[@id="email"]'), emailAddress);
  await actions.fill(page.locator('//input[@id="password"]'), 'TestPass123!');
  await actions.click(page.locator('//button[@id="save-user"]'));
  await waits.waitForNetworkIdle();
  this.testData.currentUser = { email: emailAddress, username: 'testuser' };
});

Given('user has scheduled appointment at {string}', async function (appointmentTime: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="schedule-management"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//button[@id="create-appointment"]'));
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="appointment-time"]'), appointmentTime);
  await actions.fill(page.locator('//input[@id="appointment-description"]'), 'Test Appointment');
  await actions.click(page.locator('//button[@id="save-appointment"]'));
  await waits.waitForNetworkIdle();
  this.testData.originalAppointmentTime = appointmentTime;
});

/**************************************************/
/*  TEST CASE: TC-002
/*  Title: System prevents notification acknowledgment without valid authentication
/*  Priority: High
/*  Category: Negative
/*  Description: Validates authentication requirement for notification acknowledgment
/**************************************************/

Given('user is logged in', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="username"]'), 'testuser');
  await actions.fill(page.locator('//input[@id="password"]'), 'TestPass123!');
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

Given('user has unacknowledged schedule change notification in notification center', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="notification-bell"]'));
  await waits.waitForNetworkIdle();
  const unacknowledgedNotification = page.locator('//div[@id="notification-item-unacknowledged"]');
  await assertions.assertVisible(unacknowledgedNotification);
  this.testData.notificationId = await unacknowledgedNotification.getAttribute('data-notification-id');
});

Given('{string} button is enabled', async function (buttonText: string) {
  // TODO: Replace XPath with Object Repository when available
  const buttonXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const button = page.locator(buttonXPath);
  await assertions.assertVisible(button);
  const isEnabled = await button.isEnabled();
  expect(isEnabled).toBe(true);
});

/**************************************************/
/*  TEST CASE: TC-003
/*  Title: System handles notification service downtime during schedule change
/*  Priority: High
/*  Category: Negative
/*  Description: Validates notification queuing when service is unavailable
/**************************************************/

Given('notification service is stopped or unavailable', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="admin-settings"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//a[@id="notification-service"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//button[@id="stop-service"]'));
  await waits.waitForNetworkIdle();
  this.testData.serviceDowntime = true;
});

/**************************************************/
/*  TEST CASE: TC-004
/*  Title: System prevents notification spam from multiple rapid schedule changes
/*  Priority: Medium
/*  Category: Negative
/*  Description: Validates rate limiting and notification batching
/**************************************************/

Given('user has scheduled appointment for {string}', async function (appointmentDateTime: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="schedule-management"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//button[@id="create-appointment"]'));
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="appointment-datetime"]'), appointmentDateTime);
  await actions.fill(page.locator('//input[@id="appointment-description"]'), 'Test Appointment');
  await actions.click(page.locator('//button[@id="save-appointment"]'));
  await waits.waitForNetworkIdle();
  this.testData.originalAppointmentDateTime = appointmentDateTime;
});

Given('system has rate limiting or notification batching configured', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="system-configuration"]'));
  await waits.waitForNetworkIdle();
  const rateLimitingCheckbox = page.locator('//input[@id="rate-limiting-enabled"]');
  await actions.check(rateLimitingCheckbox);
  await actions.fill(page.locator('//input[@id="batch-window-seconds"]'), '30');
  await actions.click(page.locator('//button[@id="save-configuration"]'));
  await waits.waitForNetworkIdle();
});

Given('administrator has permission to make schedule changes', async function () {
  // TODO: Replace XPath with Object Repository when available
  const adminPermissions = page.locator('//div[@id="admin-permissions"]');
  await assertions.assertContainsText(adminPermissions, 'Schedule Management');
});

/**************************************************/
/*  TEST CASE: TC-005
/*  Title: System handles notification when user account is disabled after schedule change
/*  Priority: High
/*  Category: Negative
/*  Description: Validates notification handling for disabled accounts
/**************************************************/

Given('user account exists with active status', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="user-management"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//button[@id="create-user"]'));
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), 'testuser');
  await actions.fill(page.locator('//input[@id="email"]'), 'testuser@example.com');
  await actions.fill(page.locator('//input[@id="password"]'), 'TestPass123!');
  await actions.click(page.locator('//button[@id="save-user"]'));
  await waits.waitForNetworkIdle();
  const accountStatus = page.locator('//span[@id="account-status"]');
  await assertions.assertContainsText(accountStatus, 'Active');
  this.testData.currentUser = { username: 'testuser', status: 'Active' };
});

/**************************************************/
/*  TEST CASE: TC-006
/*  Title: System handles malformed schedule change data in notification payload
/*  Priority: Medium
/*  Category: Negative
/*  Description: Validates data validation in notification generation
/**************************************************/

Given('notification generation logic can be tested with corrupted data', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="admin-settings"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//a[@id="notification-testing"]'));
  await waits.waitForNetworkIdle();
  const testingMode = page.locator('//input[@id="testing-mode-enabled"]');
  await actions.check(testingMode);
  await actions.click(page.locator('//button[@id="save-settings"]'));
  await waits.waitForNetworkIdle();
});

Given('error handling and validation are implemented in notification service', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="notification-service"]'));
  await waits.waitForNetworkIdle();
  const validationEnabled = page.locator('//input[@id="validation-enabled"]');
  await actions.check(validationEnabled);
  const errorHandlingEnabled = page.locator('//input[@id="error-handling-enabled"]');
  await actions.check(errorHandlingEnabled);
  await actions.click(page.locator('//button[@id="save-service-settings"]'));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-007
/*  Title: System sanitizes malicious content in notification payload
/*  Priority: Medium
/*  Category: Negative
/*  Description: Validates content sanitization for security
/**************************************************/

Given('notification service has content sanitization enabled', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="admin-settings"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//a[@id="notification-service"]'));
  await waits.waitForNetworkIdle();
  const sanitizationCheckbox = page.locator('//input[@id="content-sanitization-enabled"]');
  await actions.check(sanitizationCheckbox);
  await actions.click(page.locator('//button[@id="save-service-settings"]'));
  await waits.waitForNetworkIdle();
});

// ==================== WHEN STEPS ====================

When('administrator modifies user schedule from {string} to {string}', async function (originalTime: string, newTime: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="schedule-management"]'));
  await waits.waitForNetworkIdle();
  const appointmentRow = page.locator(`//tr[contains(., '${originalTime}')]`);
  await actions.click(appointmentRow.locator('//button[@id="edit-appointment"]'));
  await waits.waitForNetworkIdle();
  await actions.clearAndFill(page.locator('//input[@id="appointment-time"]'), newTime);
  this.testData.scheduleChanges = { originalTime, newTime };
});

When('administrator clicks {string} button', async function (buttonText: string) {
  // TODO: Replace XPath with Object Repository when available
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
  await waits.waitForNetworkIdle();
});

When('user logs in and checks notification bell icon', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="username"]'), 'testuser');
  await actions.fill(page.locator('//input[@id="password"]'), 'TestPass123!');
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//button[@id="notification-bell"]'));
  await waits.waitForNetworkIdle();
});

When('user navigates to notification history page', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="notification-history"]'));
  await waits.waitForNetworkIdle();
});

When('user deletes authentication session token from browser storage', async function () {
  await page.evaluate(() => {
    localStorage.removeItem('authToken');
    sessionStorage.removeItem('authToken');
  });
  this.testData.sessionDeleted = true;
});

When('user clicks {string} button without refreshing page', async function (buttonText: string) {
  // TODO: Replace XPath with Object Repository when available
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
  await waits.waitForNetworkIdle();
});

When('user logs in with valid credentials', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="username"]'), 'testuser');
  await actions.fill(page.locator('//input[@id="password"]'), 'TestPass123!');
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

When('user navigates to notification center', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="notification-bell"]'));
  await waits.waitForNetworkIdle();
});

When('user clicks {string} button with valid authentication', async function (buttonText: string) {
  // TODO: Replace XPath with Object Repository when available
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
  await waits.waitForNetworkIdle();
});

When('system health dashboard is checked', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="system-health"]'));
  await waits.waitForNetworkIdle();
});

When('schedule change is saved', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="save-changes"]'));
  await waits.waitForNetworkIdle();
});

When('administrator disables user account before notification delivery', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="user-management"]'));
  await waits.waitForNetworkIdle();
  const userRow = page.locator('//tr[contains(., "testuser")]');
  await actions.click(userRow.locator('//button[@id="disable-account"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//button[@id="confirm-disable"]'));
  await waits.waitForNetworkIdle();
  this.testData.accountDisabled = true;
});

When('notification service attempts delivery of queued notification', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="notification-service"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//button[@id="process-queue"]'));
  await waits.waitForNetworkIdle();
});

When('notification logs and error tracking system are checked', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="notification-logs"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//a[@id="error-tracking"]'));
  await waits.waitForNetworkIdle();
});

When('user account is re-enabled', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="user-management"]'));
  await waits.waitForNetworkIdle();
  const userRow = page.locator('//tr[contains(., "testuser")]');
  await actions.click(userRow.locator('//button[@id="enable-account"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//button[@id="confirm-enable"]'));
  await waits.waitForNetworkIdle();
});

When('user checks notifications within {int} minute', async function (minutes: number) {
  await page.waitForTimeout(minutes * 1000);
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="notification-bell"]'));
  await waits.waitForNetworkIdle();
});

When('notification service is restarted', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="notification-service"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//button[@id="restart-service"]'));
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(2000);
});

When('retry mechanism processes queued notifications', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="process-retry-queue"]'));
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(3000);
});

When('user checks in-app notifications and email inbox', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="notification-bell"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//a[@id="email-inbox"]'));
  await waits.waitForNetworkIdle();
});

When('administrator accesses user appointment scheduled for {string}', async function (appointmentDateTime: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="schedule-management"]'));
  await waits.waitForNetworkIdle();
  const appointmentRow = page.locator(`//tr[contains(., '${appointmentDateTime}')]`);
  await actions.click(appointmentRow.locator('//button[@id="edit-appointment"]'));
  await waits.waitForNetworkIdle();
});

When('administrator rapidly changes appointment time from {string} to {string}', async function (fromTime: string, toTime: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.clearAndFill(page.locator('//input[@id="appointment-time"]'), toTime);
  await actions.click(page.locator('//button[@id="save-changes"]'));
  await waits.waitForNetworkIdle();
  
  if (!this.testData.rapidChanges) {
    this.testData.rapidChanges = [];
  }
  this.testData.rapidChanges.push({ from: fromTime, to: toTime });
});

When('administrator changes appointment time from {string} to {string}', async function (fromTime: string, toTime: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.clearAndFill(page.locator('//input[@id="appointment-time"]'), toTime);
  await actions.click(page.locator('//button[@id="save-changes"]'));
  await waits.waitForNetworkIdle();
  
  if (!this.testData.rapidChanges) {
    this.testData.rapidChanges = [];
  }
  this.testData.rapidChanges.push({ from: fromTime, to: toTime });
});

When('administrator changes appointment time from {string} to {string} within {int} seconds', async function (fromTime: string, toTime: string, seconds: number) {
  // TODO: Replace XPath with Object Repository when available
  await actions.clearAndFill(page.locator('//input[@id="appointment-time"]'), toTime);
  await actions.click(page.locator('//button[@id="save-changes"]'));
  await waits.waitForNetworkIdle();
  
  if (!this.testData.rapidChanges) {
    this.testData.rapidChanges = [];
  }
  this.testData.rapidChanges.push({ from: fromTime, to: toTime });
  this.testData.totalChangeTime = seconds;
});

When('user checks email inbox within {int} minutes', async function (minutes: number) {
  await page.waitForTimeout(minutes * 1000);
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="email-inbox"]'));
  await waits.waitForNetworkIdle();
});

When('user checks in-app notification center', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="notification-bell"]'));
  await waits.waitForNetworkIdle();
});

When('notification service logs are reviewed', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="notification-logs"]'));
  await waits.waitForNetworkIdle();
});

When('schedule change record is created with {string}', async function (dataCondition: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="schedule-management"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//button[@id="create-test-record"]'));
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="data-condition"]'), dataCondition);
  this.testData.dataCondition = dataCondition;
});

When('notification generation process is triggered', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="trigger-notification-generation"]'));
  await waits.waitForNetworkIdle();
});

When('schedule change is created with appointment description {string}', async function (maliciousContent: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="schedule-management"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//button[@id="create-appointment"]'));
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="appointment-description"]'), maliciousContent);
  await actions.fill(page.locator('//input[@id="appointment-time"]'), '2:00 PM');
  await actions.click(page.locator('//button[@id="save-appointment"]'));
  await waits.waitForNetworkIdle();
  this.testData.maliciousContent = maliciousContent;
});

When('delivered notification content is verified', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="notification-bell"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//a[@id="email-inbox"]'));
  await waits.waitForNetworkIdle();
});

// ==================== THEN STEPS ====================

Then('schedule change should be saved successfully', async function () {
  // TODO: Replace XPath with Object Repository when available
  const successMessage = page.locator('//div[@id="success-message"]');
  await assertions.assertVisible(successMessage);
});

Then('{string} message should be displayed', async function (messageText: string) {
  const messageLocator = page.locator(`//*[contains(text(),'${messageText}')]`);
  await assertions.assertVisible(messageLocator);
});

Then('notification service logs should show email attempt failed with error {string}', async function (errorMessage: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="notification-logs"]'));
  await waits.waitForNetworkIdle();
  const logEntry = page.locator(`//div[contains(text(),'${errorMessage}')]`);
  await assertions.assertVisible(logEntry);
});

Then('error should be logged with timestamp and user ID and notification ID', async function () {
  // TODO: Replace XPath with Object Repository when available
  const errorLog = page.locator('//div[@id="error-log-entry"]');
  await assertions.assertVisible(errorLog);
  await assertions.assertContainsText(errorLog, 'timestamp');
  await assertions.assertContainsText(errorLog, 'user_id');
  await assertions.assertContainsText(errorLog, 'notification_id');
});

Then('in-app notification should display schedule change from {string} to {string}', async function (originalTime: string, newTime: string) {
  // TODO: Replace XPath with Object Repository when available
  const notification = page.locator('//div[@id="notification-item"]');
  await assertions.assertContainsText(notification, originalTime);
  await assertions.assertContainsText(notification, newTime);
});

Then('warning banner {string} should be displayed', async function (warningText: string) {
  // TODO: Replace XPath with Object Repository when available
  const warningBanner = page.locator('//div[@id="warning-banner"]');
  await assertions.assertVisible(warningBanner);
  await assertions.assertContainsText(warningBanner, warningText);
});

Then('notification status should show {string}', async function (statusText: string) {
  // TODO: Replace XPath with Object Repository when available
  const notificationStatus = page.locator('//span[@id="notification-status"]');
  await assertions.assertContainsText(notificationStatus, statusText);
});

Then('retry option should be available', async function () {
  // TODO: Replace XPath with Object Repository when available
  const retryButton = page.locator('//button[@id="retry-notification"]');
  await assertions.assertVisible(retryButton);
});

Then('error message {string} should be displayed', async function (errorMessage: string) {
  const errorLocator = page.locator(`//*[contains(text(),'${errorMessage}')]`);
  await assertions.assertVisible(errorLocator);
});

Then('user should be redirected to login page', async function () {
  await waits.waitForNetworkIdle();
  await assertions.assertUrlContains('login');
});

Then('notification should still appear as {string}', async function (status: string) {
  // TODO: Replace XPath with Object Repository when available
  const notificationStatus = page.locator('//span[@id="notification-status"]');
  await assertions.assertContainsText(notificationStatus, status);
});

Then('notification status should change to {string}', async function (status: string) {
  // TODO: Replace XPath with Object Repository when available
  const notificationStatus = page.locator('//span[@id="notification-status"]');
  await assertions.assertContainsText(notificationStatus, status);
});

Then('confirmation message {string} should be displayed', async function (confirmationText: string) {
  const confirmationLocator = page.locator(`//*[contains(text(),'${confirmationText}')]`);
  await assertions.assertVisible(confirmationLocator);
});

Then('notification service status should show {string}', async function (status: string) {
  // TODO: Replace XPath with Object Repository when available
  const serviceStatus = page.locator('//span[@id="service-status"]');
  await assertions.assertContainsText(serviceStatus, status);
});

Then('schedule change should be saved successfully in database', async function () {
  // TODO: Replace XPath with Object Repository when available
  const successMessage = page.locator('//div[@id="success-message"]');
  await assertions.assertVisible(successMessage);
});

Then('warning {string} may be shown', async function (warningText: string) {
  const warningLocator = page.locator(`//*[contains(text(),'${warningText}')]`);
  const warningCount = await warningLocator.count();
  if (warningCount > 0) {
    await assertions.assertVisible(warningLocator);
  }
});

Then('notification should be queued for retry with status {string}', async function (status: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="notification-queue"]'));
  await waits.waitForNetworkIdle();
  const queuedNotification = page.locator('//div[@id="queued-notification"]');
  await assertions.assertContainsText(queuedNotification, status);
});

Then('retry attempts should be scheduled', async function () {
  // TODO: Replace XPath with Object Repository when available
  const retrySchedule = page.locator('//div[@id="retry-schedule"]');
  await assertions.assertVisible(retrySchedule);
});

Then('error should be logged with timestamp and details', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="error-logs"]'));
  await waits.waitForNetworkIdle();
  const errorLog = page.locator('//div[@id="error-log-entry"]');
  await assertions.assertVisible(errorLog);
  await assertions.assertContainsText(errorLog, 'timestamp');
});

Then('no notification should be delivered to user', async function () {
  // TODO: Replace XPath with Object Repository when available
  const notificationList = page.locator('//div[@id="notification-list"]');
  const notificationCount = await notificationList.locator('//div[@class="notification-item"]').count();
  expect(notificationCount).toBe(0);
});

Then('notification bell icon should show no new notifications', async function () {
  // TODO: Replace XPath with Object Repository when available
  const notificationBadge = page.locator('//span[@id="notification-badge"]');
  const badgeCount = await notificationBadge.count();
  if (badgeCount > 0) {
    const badgeText = await notificationBadge.textContent();
    expect(badgeText).toBe('0');
  }
});

Then('email inbox should have no new messages', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="email-inbox"]'));
  await waits.waitForNetworkIdle();
  const emailCount = page.locator('//span[@id="unread-count"]');
  await assertions.assertContainsText(emailCount, '0');
});

Then('notification service status should change to {string}', async function (status: string) {
  // TODO: Replace XPath with Object Repository when available
  const serviceStatus = page.locator('//span[@id="service-status"]');
  await assertions.assertContainsText(serviceStatus, status);
});

Then('queued notification should be delivered within {int} to {int} minutes', async function (minMinutes: number, maxMinutes: number) {
  await page.waitForTimeout(maxMinutes * 1000);
  // TODO: Replace XPath with Object Repository when available
  const deliveredNotification = page.locator('//div[@id="delivered-notification"]');
  await assertions.assertVisible(deliveredNotification);
});

Then('user should receive both email and in-app notification about schedule change', async function () {
  // TODO: Replace XPath with Object Repository when available
  const inAppNotification = page.locator('//div[@id="notification-item"]');
  await assertions.assertVisible(inAppNotification);
  
  await actions.click(page.locator('//a[@id="email-inbox"]'));
  await waits.waitForNetworkIdle();
  const emailNotification = page.locator('//div[@id="email-message"]');
  await assertions.assertVisible(emailNotification);
});

Then('notification should include note {string}', async function (noteText: string) {
  const noteLocator = page.locator(`//*[contains(text(),'${noteText}')]`);
  await assertions.assertVisible(noteLocator);
});

Then('notification history should show delivery timestamp and delay reason', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="notification-history"]'));
  await waits.waitForNetworkIdle();
  const historyEntry = page.locator('//div[@id="notification-history-entry"]');
  await assertions.assertContainsText(historyEntry, 'timestamp');
  await assertions.assertContainsText(historyEntry, 'delay reason');
});

Then('appointment details page should display current time as {string}', async function (currentTime: string) {
  // TODO: Replace XPath with Object Repository when available
  const appointmentTime = page.locator('//span[@id="appointment-time"]');
  await assertions.assertContainsText(appointmentTime, currentTime);
});

Then('all {int} schedule changes should be saved successfully', async function (changeCount: number) {
  // TODO: Replace XPath with Object Repository when available
  const successMessage = page.locator('//div[@id="success-message"]');
  await assertions.assertVisible(successMessage);
  expect(this.testData.rapidChanges.length).toBe(changeCount);
});

Then('final appointment time should show {string}', async function (finalTime: string) {
  // TODO: Replace XPath with Object Repository when available
  const appointmentTime = page.locator('//span[@id="appointment-time"]');
  await assertions.assertContainsText(appointmentTime, finalTime);
});

Then('user should receive only one consolidated email notification', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="email-inbox"]'));
  await waits.waitForNetworkIdle();
  const emailMessages = page.locator('//div[@class="email-message"]');
  const emailCount = await emailMessages.count();
  expect(emailCount).toBe(1);
});

Then('email should state {string}', async function (emailContent: string) {
  // TODO: Replace XPath with Object Repository when available
  const emailBody = page.locator('//div[@id="email-body"]');
  await assertions.assertContainsText(emailBody, emailContent);
});

Then('single notification should show message {string}', async function (notificationMessage: string) {
  // TODO: Replace XPath with Object Repository when available
  const notification = page.locator('//div[@id="notification-item"]');
  await assertions.assertContainsText(notification, notificationMessage);
});

Then('expandable section should show change history', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="expand-history"]'));
  await waits.waitForNetworkIdle();
  const changeHistory = page.locator('//div[@id="change-history"]');
  await assertions.assertVisible(changeHistory);
});

Then('logs should show system detected multiple rapid changes', async function () {
  // TODO: Replace XPath with Object Repository when available
  const logEntry = page.locator('//div[contains(text(), "multiple rapid changes")]');
  await assertions.assertVisible(logEntry);
});

Then('logs should show batching logic was applied', async function () {
  // TODO: Replace XPath with Object Repository when available
  const logEntry = page.locator('//div[contains(text(), "batching logic")]');
  await assertions.assertVisible(logEntry);
});

Then('log entry should show {string}', async function (logContent: string) {
  const logLocator = page.locator(`//*[contains(text(),'${logContent}')]`);
  await assertions.assertVisible(logLocator);
});

Then('notification should be queued for delivery', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="notification-queue"]'));
  await waits.waitForNetworkIdle();
  const queuedNotification = page.locator('//div[@id="queued-notification"]');
  await assertions.assertVisible(queuedNotification);
});

Then('user account status should change to {string}', async function (status: string) {
  // TODO: Replace XPath with Object Repository when available
  const accountStatus = page.locator('//span[@id="account-status"]');
  await assertions.assertContainsText(accountStatus, status);
});

Then('user should be logged out if currently active', async function () {
  await waits.waitForNetworkIdle();
  const loginPage = page.locator('//div[@id="login-page"]');
  const loginPageCount = await loginPage.count();
  if (loginPageCount > 0) {
    await assertions.assertVisible(loginPage);
  }
});

Then('account should no longer be accessible', async function () {
  // TODO: Replace XPath with Object Repository when available
  const accountStatus = page.locator('//span[@id="account-status"]');
  await assertions.assertContainsText(accountStatus, 'Disabled');
});

Then('notification service should detect user account is disabled', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="notification-logs"]'));
  await waits.waitForNetworkIdle();
  const logEntry = page.locator('//div[contains(text(), "account is disabled")]');
  await assertions.assertVisible(logEntry);
});

Then('error {string} should be logged', async function (errorMessage: string) {
  const errorLocator = page.locator(`//*[contains(text(),'${errorMessage}')]`);
  await assertions.assertVisible(errorLocator);
});

Then('notification should be marked as {string}', async function (status: string) {
  // TODO: Replace XPath with Object Repository when available
  const notificationStatus = page.locator('//span[@id="notification-status"]');
  await assertions.assertContainsText(notificationStatus, status);
});

Then('error log should show entry with notification ID and user ID', async function () {
  // TODO: Replace XPath with Object Repository when available
  const errorLog = page.locator('//div[@id="error-log-entry"]');
  await assertions.assertVisible(errorLog);
  await assertions.assertContainsText(errorLog, 'notification_id');
  await assertions.assertContainsText(errorLog, 'user_id');
});

Then('no email should be sent', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="email-inbox"]'));
  await waits.waitForNetworkIdle();
  const emailCount = page.locator('//span[@id="unread-count"]');
  await assertions.assertContainsText(emailCount, '0');
});

Then('system should not automatically retry old failed notifications', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="notification-queue"]'));
  await waits.waitForNetworkIdle();
  const retryQueue = page.locator('//div[@id="retry-queue"]');
  const queueCount = await retryQueue.locator('//div[@class="queued-item"]').count();
  expect(queueCount).toBe(0);
});

Then('notification should remain in {string} state with reason logged', async function (status: string) {
  // TODO: Replace XPath with Object Repository when available
  const notificationStatus = page.locator('//span[@id="notification-status"]');
  await assertions.assertContainsText(notificationStatus, status);
  
  await actions.click(page.locator('//a[@id="notification-logs"]'));
  await waits.waitForNetworkIdle();
  const logEntry = page.locator('//div[@id="error-log-entry"]');
  await assertions.assertVisible(logEntry);
});

Then('notification service should detect {string}', async function (validationError: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="notification-logs"]'));
  await waits.waitForNetworkIdle();
  const logEntry = page.locator(`//div[contains(text(),'${validationError}')]`);
  await assertions.assertVisible(logEntry);
});

Then('error {string} should be logged', async function (errorMessage: string) {
  const errorLocator = page.locator(`//*[contains(text(),'${errorMessage}')]`);
  await assertions.assertVisible(errorLocator);
});

Then('no notification should be sent to user', async function () {
  // TODO: Replace XPath with Object Repository when available
  const notificationList = page.locator('//div[@id="notification-list"]');
  const notificationCount = await notificationList.locator('//div[@class="notification-item"]').count();
  expect(notificationCount).toBe(0);
});

Then('system should prevent sending incomplete or misleading information', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="notification-logs"]'));
  await waits.waitForNetworkIdle();
  const validationLog = page.locator('//div[contains(text(), "validation failed")]');
  await assertions.assertVisible(validationLog);
});

Then('notification service should sanitize and escape special characters', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="notification-logs"]'));
  await waits.waitForNetworkIdle();
  const sanitizationLog = page.locator('//div[contains(text(), "sanitized")]');
  await assertions.assertVisible(sanitizationLog);
});

Then('notification should be generated with sanitized content', async function () {
  // TODO: Replace XPath with Object Repository when available
  const notification = page.locator('//div[@id="notification-item"]');
  await assertions.assertVisible(notification);
});

Then('no script execution or SQL injection should occur', async function () {
  // TODO: Replace XPath with Object Repository when available
  const securityLog = page.locator('//div[@id="security-log"]');
  const alertCount = await page.locator('//div[@class="security-alert"]').count();
  expect(alertCount).toBe(0);
});

Then('email and in-app notification should display content as {string}', async function (sanitizedDisplay: string) {
  // TODO: Replace XPath with Object Repository when available
  const notification = page.locator('//div[@id="notification-item"]');
  await assertions.assertContainsText(notification, sanitizedDisplay);
  
  await actions.click(page.locator('//a[@id="email-inbox"]'));
  await waits.waitForNetworkIdle();
  const emailBody = page.locator('//div[@id="email-body"]');
  await assertions.assertContainsText(emailBody, sanitizedDisplay);
});

Then('no code execution should occur', async function () {
  const scriptTags = await page.locator('script[src*="alert"]').count();
  expect(scriptTags).toBe(0);
});

Then('content should be safely rendered', async function () {
  // TODO: Replace XPath with Object Repository when available
  const notification = page.locator('//div[@id="notification-item"]');
  await assertions.assertVisible(notification);
  const innerHTML = await notification.innerHTML();
  expect(innerHTML).not.toContain('<script>');
});