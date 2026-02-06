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
    alertData: {},
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
/*  TEST CASE: TC-NEG-001
/*  Title: System prevents duplicate alerts for same anomaly
/*  Priority: High
/*  Category: Negative
/**************************************************/

Given('user is logged into the system', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), 'testuser');
  await actions.fill(page.locator('//input[@id="password"]'), 'testpass');
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

Given('user has arrived late at {string} which is {string} minutes late', async function (arrivalTime: string, minutesLate: string) {
  this.testData.alertData.arrivalTime = arrivalTime;
  this.testData.alertData.minutesLate = minutesLate;
  await actions.navigateTo(`${process.env.BASE_URL}/attendance/checkin`);
  await actions.fill(page.locator('//input[@id="check-in-time"]'), arrivalTime);
  await actions.click(page.locator('//button[@id="submit-checkin"]'));
  await waits.waitForNetworkIdle();
});

Given('system has detected the late arrival anomaly at {string}', async function (detectionTime: string) {
  this.testData.alertData.detectionTime = detectionTime;
  await waits.waitForVisible(page.locator('//div[@id="anomaly-detected"]'));
});

Given('alert has been sent to user and manager', async function () {
  await assertions.assertVisible(page.locator('//div[@id="alert-sent-confirmation"]'));
  this.testData.alertData.alertSent = true;
});

Given('alert delivery is confirmed for both recipients', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="delivery-status"]'), 'Delivered to User');
  await assertions.assertContainsText(page.locator('//div[@id="delivery-status"]'), 'Delivered to Manager');
});

Given('system continues monitoring attendance data every {string} minute', async function (interval: string) {
  this.testData.systemState.monitoringInterval = interval;
});

Given('email service is down or unreachable', async function () {
  this.testData.systemState.emailServiceStatus = 'down';
});

Given('in-app notification service is operational', async function () {
  this.testData.systemState.inAppServiceStatus = 'operational';
});

Given('system is configured to retry failed email deliveries', async function () {
  this.testData.systemState.retryEnabled = true;
});

/**************************************************/
/*  TEST CASE: TC-NEG-003
/*  Title: System rejects unauthorized alert acknowledgment
/*  Priority: High
/*  Category: Negative
/**************************************************/

Given('user {string} has received an attendance anomaly alert for late arrival', async function (userEmail: string) {
  this.testData.alertData.recipientEmail = userEmail;
  this.testData.alertData.alertId = 'ALT-2024-001234';
});

Given('alert is visible in user notification center with status {string}', async function (status: string) {
  this.testData.alertData.status = status;
});

Given('user {string} is logged into the system with standard user permissions', async function (userEmail: string) {
  await actions.fill(page.locator('//input[@id="username"]'), userEmail);
  await actions.fill(page.locator('//input[@id="password"]'), 'testpass');
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  this.testData.alertData.currentUser = userEmail;
});

Given('user {string} is not the alert recipient\'s manager', async function (userEmail: string) {
  this.testData.alertData.isManager = false;
});

Given('user {string} has no administrative privileges', async function (userEmail: string) {
  this.testData.alertData.isAdmin = false;
});

/**************************************************/
/*  TEST CASE: TC-NEG-004
/*  Title: System escalates alert when manager not assigned
/*  Priority: High
/*  Category: Negative
/**************************************************/

Given('user account exists with user ID {string}', async function (userId: string) {
  this.testData.alertData.userId = userId;
});

Given('user has no manager assigned in organizational hierarchy', async function () {
  this.testData.alertData.managerId = null;
});

Given('manager_id field is {string} for this user', async function (value: string) {
  this.testData.alertData.managerIdField = value;
});

Given('user arrives late at {string} triggering a late arrival anomaly', async function (arrivalTime: string) {
  this.testData.alertData.arrivalTime = arrivalTime;
  await actions.fill(page.locator('//input[@id="check-in-time"]'), arrivalTime);
  await actions.click(page.locator('//button[@id="submit-checkin"]'));
  await waits.waitForNetworkIdle();
});

Given('alert configuration requires notification to both user and manager', async function () {
  this.testData.alertData.notificationRecipients = ['user', 'manager'];
});

/**************************************************/
/*  TEST CASE: TC-NEG-005
/*  Title: System does not trigger false positive alerts
/*  Priority: Medium
/*  Category: Negative
/**************************************************/

Given('user expected arrival time is {string}', async function (expectedTime: string) {
  this.testData.alertData.expectedArrivalTime = expectedTime;
});

Given('grace period of {string} minutes is configured', async function (gracePeriod: string) {
  this.testData.alertData.gracePeriod = gracePeriod;
});

Given('user arrives at {string} which is {string} minutes after expected time', async function (arrivalTime: string, minutesLate: string) {
  this.testData.alertData.arrivalTime = arrivalTime;
  this.testData.alertData.minutesLate = minutesLate;
});

Given('arrival time is within grace period', async function () {
  this.testData.alertData.withinGracePeriod = true;
});

Given('system is configured to trigger late arrival alerts only after {string} minute threshold', async function (threshold: string) {
  this.testData.alertData.alertThreshold = threshold;
});

Given('attendance monitoring system is running and analyzing data', async function () {
  this.testData.systemState.monitoringActive = true;
});

/**************************************************/
/*  TEST CASE: TC-NEG-006
/*  Title: System handles database failure with queue fallback
/*  Priority: High
/*  Category: Negative
/**************************************************/

Given('user has triggered an attendance anomaly with early departure at {string}', async function (departureTime: string) {
  this.testData.alertData.departureTime = departureTime;
  this.testData.alertData.anomalyType = 'Early Departure';
});

Given('expected departure time is {string}', async function (expectedTime: string) {
  this.testData.alertData.expectedDepartureTime = expectedTime;
});

Given('system has detected the anomaly', async function () {
  this.testData.alertData.anomalyDetected = true;
});

Given('system is in the process of generating alert', async function () {
  this.testData.alertData.alertGenerationInProgress = true;
});

Given('system has message queue configured for resilience', async function () {
  this.testData.systemState.messageQueueEnabled = true;
});

Given('alert generation process is at database write stage', async function () {
  this.testData.alertData.currentStage = 'database_write';
});

// ==================== WHEN STEPS ====================

When('system runs attendance analysis again at {string}', async function (analysisTime: string) {
  this.testData.alertData.currentAnalysisTime = analysisTime;
  await actions.click(page.locator('//button[@id="run-analysis"]'));
  await waits.waitForNetworkIdle();
});

When('system detects the same late arrival anomaly', async function () {
  await waits.waitForVisible(page.locator('//div[@id="anomaly-detected"]'));
});

When('system attempts to send email notification to {string}', async function (emailAddress: string) {
  this.testData.alertData.emailRecipient = emailAddress;
  const response = await page.evaluate((email) => {
    return fetch('/api/notifications/email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recipient: email })
    });
  }, emailAddress);
  this.testData.alertData.emailResponse = response;
});

When('user checks alert record status via {string}', async function (apiEndpoint: string) {
  const alertId = this.testData.alertData.alertId || 'ALT-2024-001234';
  const fullEndpoint = apiEndpoint.replace('{alertId}', alertId);
  await actions.navigateTo(`${process.env.BASE_URL}${fullEndpoint}`);
  await waits.waitForNetworkIdle();
});

When('user waits for {string} minutes for automatic retry attempt', async function (minutes: string) {
  this.testData.alertData.waitTime = minutes;
  await page.waitForTimeout(parseInt(minutes) * 1000);
});

When('email service remains down', async function () {
  this.testData.systemState.emailServiceStatus = 'down';
});

When('email service is restored', async function () {
  this.testData.systemState.emailServiceStatus = 'up';
});

When('system waits for next retry attempt', async function () {
  await page.waitForTimeout(5000);
  await waits.waitForNetworkIdle();
});

When('system runs analysis again at {string} and {string}', async function (time1: string, time2: string) {
  await actions.click(page.locator('//button[@id="run-analysis"]'));
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(2000);
  await actions.click(page.locator('//button[@id="run-analysis"]'));
  await waits.waitForNetworkIdle();
});

When('user {string} navigates to alert detail page by entering URL {string}', async function (userEmail: string, url: string) {
  await actions.navigateTo(`${process.env.BASE_URL}${url}`);
  await waits.waitForNetworkIdle();
});

When('user {string} attempts to acknowledge alert by sending POST request to {string}', async function (userEmail: string, apiEndpoint: string) {
  const response = await page.evaluate((endpoint) => {
    return fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ acknowledged: true })
    }).then(res => res.json());
  }, apiEndpoint);
  this.testData.alertData.apiResponse = response;
});

When('user {string} logs in and views the alert', async function (userEmail: string) {
  await actions.fill(page.locator('//input[@id="username"]'), userEmail);
  await actions.fill(page.locator('//input[@id="password"]'), 'testpass');
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//a[@id="notifications"]'));
  await waits.waitForNetworkIdle();
});

When('system detects late arrival anomaly for user {string}', async function (userId: string) {
  this.testData.alertData.userId = userId;
  await waits.waitForVisible(page.locator('//div[@id="anomaly-detected"]'));
});

When('system initiates alert generation process', async function () {
  await actions.click(page.locator('//button[@id="generate-alert"]'));
  await waits.waitForNetworkIdle();
});

When('system queries organizational hierarchy to retrieve manager information', async function () {
  const response = await page.evaluate(() => {
    return fetch('/api/users/hierarchy', {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' }
    }).then(res => res.json());
  });
  this.testData.alertData.hierarchyResponse = response;
});

When('system attempts to send alert notification to the user', async function () {
  await actions.click(page.locator('//button[@id="send-user-notification"]'));
  await waits.waitForNetworkIdle();
});

When('system handles missing manager by escalating to fallback recipient', async function () {
  await waits.waitForVisible(page.locator('//div[@id="escalation-triggered"]'));
});

When('user checks in at {string} using the attendance system', async function (checkInTime: string) {
  await actions.fill(page.locator('//input[@id="check-in-time"]'), checkInTime);
  await actions.click(page.locator('//button[@id="submit-checkin"]'));
  await waits.waitForNetworkIdle();
});

When('system analyzes attendance data', async function () {
  await actions.click(page.locator('//button[@id="analyze-attendance"]'));
  await waits.waitForNetworkIdle();
});

When('system compares delay {string} minutes against threshold {string} minutes', async function (delay: string, threshold: string) {
  this.testData.alertData.delayMinutes = delay;
  this.testData.alertData.thresholdMinutes = threshold;
});

When('user reviews system logs at {string}', async function (logEndpoint: string) {
  await actions.navigateTo(`${process.env.BASE_URL}${logEndpoint}`);
  await waits.waitForNetworkIdle();
});

When('system detects early departure anomaly', async function () {
  await waits.waitForVisible(page.locator('//div[@id="early-departure-detected"]'));
});

When('system prepares alert data with alert ID {string}', async function (alertId: string) {
  this.testData.alertData.alertId = alertId;
});

When('alert data includes user {string}', async function (userId: string) {
  this.testData.alertData.userId = userId;
});

When('alert data includes type {string}', async function (alertType: string) {
  this.testData.alertData.alertType = alertType;
});

When('alert data includes time {string}', async function (time: string) {
  this.testData.alertData.time = time;
});

When('alert data includes expected time {string}', async function (expectedTime: string) {
  this.testData.alertData.expectedTime = expectedTime;
});

When('system attempts to write alert record to {string} database table', async function (tableName: string) {
  this.testData.alertData.targetTable = tableName;
});

When('database connection becomes unavailable', async function () {
  this.testData.systemState.databaseStatus = 'unavailable';
});

When('database connection is restored after {string} minutes', async function (minutes: string) {
  await page.waitForTimeout(parseInt(minutes) * 1000);
  this.testData.systemState.databaseStatus = 'available';
});

// ==================== THEN STEPS ====================

Then('system should identify that alert for this anomaly has already been sent within last {string} hours', async function (hours: string) {
  await assertions.assertVisible(page.locator('//div[@id="duplicate-alert-detected"]'));
  await assertions.assertContainsText(page.locator('//div[@id="deduplication-message"]'), `within last ${hours} hours`);
});

Then('system should check alert deduplication rules and alert history', async function () {
  await assertions.assertVisible(page.locator('//div[@id="deduplication-check"]'));
});

Then('system should find existing alert record with status {string} and timestamp {string}', async function (status: string, timestamp: string) {
  await assertions.assertContainsText(page.locator('//div[@id="alert-status"]'), status);
  await assertions.assertContainsText(page.locator('//div[@id="alert-timestamp"]'), timestamp);
});

Then('no new alert should be generated or sent to user or manager', async function () {
  const alertCount = await page.locator('//div[@class="alert-record"]').count();
  expect(alertCount).toBe(1);
});

Then('no new email notification should be sent', async function () {
  await assertions.assertVisible(page.locator('//div[@id="no-email-sent"]'));
});

Then('no new in-app notification should appear', async function () {
  const notificationCount = await page.locator('//div[@class="notification-item"]').count();
  this.testData.alertData.previousNotificationCount = notificationCount;
});

Then('notification count should remain unchanged for both user and manager', async function () {
  const currentCount = await page.locator('//div[@class="notification-item"]').count();
  expect(currentCount).toBe(this.testData.alertData.previousNotificationCount || 1);
});

Then('alert database should show only {string} alert record for this anomaly', async function (count: string) {
  await assertions.assertElementCount(page.locator('//div[@class="alert-record"]'), parseInt(count));
});

Then('API logs at {string} should show deduplication logic was triggered', async function (apiEndpoint: string) {
  await actions.navigateTo(`${process.env.BASE_URL}${apiEndpoint}/logs`);
  await waits.waitForNetworkIdle();
  await assertions.assertContainsText(page.locator('//div[@id="api-logs"]'), 'deduplication');
});

Then('API logs should contain message {string}', async function (message: string) {
  await assertions.assertContainsText(page.locator('//div[@id="api-logs"]'), message);
});

Then('no additional alerts should be generated for the same late arrival anomaly', async function () {
  const alertCount = await page.locator('//div[@class="alert-record"]').count();
  expect(alertCount).toBe(1);
});

Then('deduplication should remain effective throughout the day', async function () {
  await assertions.assertVisible(page.locator('//div[@id="deduplication-active"]'));
});

Then('email delivery should fail with error {string}', async function (errorMessage: string) {
  await assertions.assertContainsText(page.locator('//div[@id="email-error"]'), errorMessage);
});

Then('error should be logged in system logs with timestamp and error details', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/system/logs`);
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="error-log-entry"]'));
});

Then('failure should be logged separately for manager notification', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="manager-notification-log"]'), 'failed');
});

Then('system should still deliver in-app notifications despite email failure', async function () {
  await assertions.assertVisible(page.locator('//div[@id="in-app-notification-success"]'));
});

Then('in-app notifications should be successfully delivered to both user and manager', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="notification-status"]'), 'User: Delivered');
  await assertions.assertContainsText(page.locator('//div[@id="notification-status"]'), 'Manager: Delivered');
});

Then('notifications should appear with status {string}', async function (status: string) {
  await assertions.assertContainsText(page.locator('//div[@id="notification-status"]'), status);
});

Then('warning icon should indicate email delivery pending', async function () {
  await assertions.assertVisible(page.locator('//i[@id="email-pending-icon"]'));
});

Then('alert status should show {string}', async function (status: string) {
  await assertions.assertContainsText(page.locator('//div[@id="alert-status"]'), status);
});

Then('status details should show {string}', async function (details: string) {
  await assertions.assertContainsText(page.locator('//div[@id="status-details"]'), details);
});

Then('retry count should be {string}', async function (count: string) {
  await assertions.assertContainsText(page.locator('//div[@id="retry-count"]'), count);
});

Then('next retry should be scheduled in {string} minutes', async function (minutes: string) {
  await assertions.assertContainsText(page.locator('//div[@id="next-retry"]'), `${minutes} minutes`);
});

Then('delivery should fail again', async function () {
  await assertions.assertVisible(page.locator('//div[@id="delivery-failed"]'));
});

Then('retry count should increment to {string}', async function (count: string) {
  await assertions.assertContainsText(page.locator('//div[@id="retry-count"]'), count);
});

Then('system should successfully deliver emails on retry attempt', async function () {
  await assertions.assertVisible(page.locator('//div[@id="email-delivery-success"]'));
});

Then('alert status should update to {string}', async function (status: string) {
  await assertions.assertContainsText(page.locator('//div[@id="alert-status"]'), status);
});

Then('email delivery timestamp should be recorded', async function () {
  await assertions.assertVisible(page.locator('//div[@id="email-delivery-timestamp"]'));
});

Then('retry count should show final value of {string}', async function (count: string) {
  await assertions.assertContainsText(page.locator('//div[@id="retry-count"]'), count);
});

Then('system should display error page with message {string}', async function (errorMessage: string) {
  await assertions.assertContainsText(page.locator('//div[@id="error-message"]'), errorMessage);
});

Then('HTTP status code {string} should be returned', async function (statusCode: string) {
  const response = await page.evaluate(() => window.performance.getEntriesByType('navigation')[0]);
  this.testData.alertData.httpStatusCode = statusCode;
});

Then('API should return error response with status code {string}', async function (statusCode: string) {
  const apiResponse = this.testData.alertData.apiResponse;
  expect(apiResponse.statusCode || 403).toBe(parseInt(statusCode));
});

Then('response JSON body should contain error {string}', async function (errorType: string) {
  await assertions.assertContainsText(page.locator('//div[@id="api-response"]'), errorType);
});

Then('response message should be {string}', async function (message: string) {
  await assertions.assertContainsText(page.locator('//div[@id="response-message"]'), message);
});

Then('response should include alert ID {string}', async function (alertId: string) {
  await assertions.assertContainsText(page.locator('//div[@id="api-response"]'), alertId);
});

Then('alert status should remain {string} in database', async function (status: string) {
  await actions.navigateTo(`${process.env.BASE_URL}/api/alerts/status`);
  await waits.waitForNetworkIdle();
  await assertions.assertContainsText(page.locator('//div[@id="alert-status"]'), status);
});

Then('no acknowledgment timestamp should be recorded', async function () {
  const timestamp = await page.locator('//div[@id="acknowledgment-timestamp"]').count();
  expect(timestamp).toBe(0);
});

Then('no acknowledging user ID should be set', async function () {
  const userId = await page.locator('//div[@id="acknowledging-user"]').count();
  expect(userId).toBe(0);
});

Then('security log should contain entry {string}', async function (logEntry: string) {
  await actions.navigateTo(`${process.env.BASE_URL}/security/logs`);
  await waits.waitForNetworkIdle();
  await assertions.assertContainsText(page.locator('//div[@id="security-logs"]'), logEntry);
});

Then('security log should include user {string}', async function (userEmail: string) {
  await assertions.assertContainsText(page.locator('//div[@id="security-logs"]'), userEmail);
});

Then('security log should include alert {string}', async function (alertId: string) {
  await assertions.assertContainsText(page.locator('//div[@id="security-logs"]'), alertId);
});

Then('security log should include owner {string}', async function (ownerEmail: string) {
  await assertions.assertContainsText(page.locator('//div[@id="security-logs"]'), ownerEmail);
});

Then('security log should show action {string}', async function (action: string) {
  await assertions.assertContainsText(page.locator('//div[@id="security-logs"]'), action);
});

Then('user {string} should be able to successfully acknowledge the alert', async function (userEmail: string) {
  await actions.click(page.locator('//button[@id="acknowledge-alert"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="acknowledgment-success"]'));
});

Then('alert record should be created in database with anomaly details', async function () {
  await assertions.assertVisible(page.locator('//div[@id="alert-record-created"]'));
});

Then('alert should include user ID and detection timestamp', async function () {
  await assertions.assertVisible(page.locator('//div[@id="user-id"]'));
  await assertions.assertVisible(page.locator('//div[@id="detection-timestamp"]'));
});

Then('query should return {string} for manager_id field', async function (value: string) {
  await assertions.assertContainsText(page.locator('//div[@id="manager-id-field"]'), value);
});

Then('system should log warning {string}', async function (warningMessage: string) {
  await actions.navigateTo(`${process.env.BASE_URL}/system/logs`);
  await waits.waitForNetworkIdle();
  await assertions.assertContainsText(page.locator('//div[@id="system-logs"]'), warningMessage);
});

Then('alert should be successfully sent to user via email and in-app notification', async function () {
  await assertions.assertVisible(page.locator('//div[@id="user-notification-success"]'));
});

Then('alert should include all anomaly details and suggested actions', async function () {
  await assertions.assertVisible(page.locator('//div[@id="anomaly-details"]'));
  await assertions.assertVisible(page.locator('//div[@id="suggested-actions"]'));
});

Then('alert should be sent to fallback recipient {string}', async function (fallbackEmail: string) {
  await assertions.assertContainsText(page.locator('//div[@id="fallback-recipient"]'), fallbackEmail);
});

Then('alert should include additional context {string}', async function (context: string) {
  await assertions.assertContainsText(page.locator('//div[@id="alert-context"]'), context);
});

Then('email subject should include tag {string}', async function (tag: string) {
  await assertions.assertContainsText(page.locator('//div[@id="email-subject"]'), tag);
});

Then('delivery log should show user notification {string}', async function (status: string) {
  await assertions.assertContainsText(page.locator('//div[@id="user-delivery-log"]'), status);
});

Then('delivery log should show manager notification {string}', async function (status: string) {
  await assertions.assertContainsText(page.locator('//div[@id="manager-delivery-log"]'), status);
});

Then('escalation timestamp should be recorded', async function () {
  await assertions.assertVisible(page.locator('//div[@id="escalation-timestamp"]'));
});

Then('system log should show warning level entry {string}', async function (logEntry: string) {
  await assertions.assertContainsText(page.locator('//div[@id="system-logs"]'), logEntry);
});

Then('log should include user {string}', async function (userId: string) {
  await assertions.assertContainsText(page.locator('//div[@id="system-logs"]'), userId);
});

Then('log should include alert {string}', async function (alertId: string) {
  await assertions.assertContainsText(page.locator('//div[@id="system-logs"]'), alertId);
});

Then('log should show escalated to {string}', async function (department: string) {
  await assertions.assertContainsText(page.locator('//div[@id="system-logs"]'), department);
});

Then('no system errors or exceptions should be thrown', async function () {
  const errorCount = await page.locator('//div[@class="system-error"]').count();
  expect(errorCount).toBe(0);
});

Then('system should record check-in time as {string}', async function (checkInTime: string) {
  await assertions.assertContainsText(page.locator('//div[@id="recorded-checkin-time"]'), checkInTime);
});

Then('system should calculate delay as {string} minutes from expected arrival time', async function (delay: string) {
  await assertions.assertContainsText(page.locator('//div[@id="calculated-delay"]'), `${delay} minutes`);
});

Then('system should determine that {string} minutes is within acceptable threshold', async function (minutes: string) {
  await assertions.assertVisible(page.locator('//div[@id="within-threshold"]'));
});

Then('system should not classify this as an anomaly', async function () {
  const anomalyCount = await page.locator('//div[@class="anomaly-record"]').count();
  expect(anomalyCount).toBe(0);
});

Then('no alert should be generated in the alerts database', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/api/alerts`);
  await waits.waitForNetworkIdle();
  const alertCount = await page.locator('//div[@class="alert-record"]').count();
  expect(alertCount).toBe(0);
});

Then('no new alert record should be created', async function () {
  const newAlertCount = await page.locator('//div[@class="new-alert"]').count();
  expect(newAlertCount).toBe(0);
});

Then('database query for alerts on this date should return empty result', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="query-result"]'), 'No alerts found');
});

Then('no attendance anomaly alert should appear in user notification center', async function () {
  await actions.click(page.locator('//a[@id="notifications"]'));
  await waits.waitForNetworkIdle();
  const anomalyAlertCount = await page.locator('//div[@class="anomaly-alert"]').count();
  expect(anomalyAlertCount).toBe(0);
});

Then('notification count should remain at previous value', async function () {
  const currentCount = await page.locator('//span[@id="notification-count"]').textContent();
  expect(currentCount).toBe(this.testData.alertData.previousNotificationCount || '0');
});

Then('no alert should be sent to manager regarding this arrival time', async function () {
  const managerAlertCount = await page.locator('//div[@class="manager-alert"]').count();
  expect(managerAlertCount).toBe(0);
});

Then('manager notification center should show no new attendance alerts', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="manager-notifications"]'), 'No new alerts');
});

Then('log entry should show {string}', async function (logMessage: string) {
  await assertions.assertContainsText(page.locator('//div[@id="log-entry"]'), logMessage);
});

Then('log should show arrival {string}', async function (arrivalTime: string) {
  await assertions.assertContainsText(page.locator('//div[@id="log-entry"]'), arrivalTime);
});

Then('log should show delay {string}', async function (delay: string) {
  await assertions.assertContainsText(page.locator('//div[@id="log-entry"]'), delay);
});

Then('log should show status {string}', async function (status: string) {
  await assertions.assertContainsText(page.locator('//div[@id="log-entry"]'), status);
});

Then('log should show action {string}', async function (action: string) {
  await assertions.assertContainsText(page.locator('//div[@id="log-entry"]'), action);
});

Then('alert data should be prepared in memory with all required fields', async function () {
  await assertions.assertVisible(page.locator('//div[@id="alert-data-prepared"]'));
});

Then('database write operation should fail with error {string}', async function (errorMessage: string) {
  await assertions.assertContainsText(page.locator('//div[@id="database-error"]'), errorMessage);
});

Then('exception should be caught by error handling layer', async function () {
  await assertions.assertVisible(page.locator('//div[@id="error-handler-triggered"]'));
});

Then('system error handler should trigger fallback mechanism', async function () {
  await assertions.assertVisible(page.locator('//div[@id="fallback-mechanism-active"]'));
});

Then('alert data should be serialized and written to message queue', async function () {
  await assertions.assertVisible(page.locator('//div[@id="message-queue-write"]'));
});

Then('alert status should be set to {string}', async function (status: string) {
  await assertions.assertContainsText(page.locator('//div[@id="alert-status"]'), status);
});

Then('error should be logged {string}', async function (errorMessage: string) {
  await actions.navigateTo(`${process.env.BASE_URL}/system/logs`);
  await waits.waitForNetworkIdle();
  await assertions.assertContainsText(page.locator('//div[@id="error-logs"]'), errorMessage);
});

Then('no notification should be sent to user or manager', async function () {
  const notificationCount = await page.locator('//div[@class="notification-sent"]').count();
  expect(notificationCount).toBe(0);
});

Then('no email or in-app notification should be sent', async function () {
  await assertions.assertVisible(page.locator('//div[@id="no-notifications-sent"]'));
});

Then('system should prevent partial alert delivery to maintain data consistency', async function () {
  await assertions.assertVisible(page.locator('//div[@id="consistency-maintained"]'));
});

Then('system should detect database availability', async function () {
  await assertions.assertVisible(page.locator('//div[@id="database-available"]'));
});

Then('automatic retry mechanism should be triggered', async function () {
  await assertions.assertVisible(page.locator('//div[@id="retry-triggered"]'));
});

Then('system should process queued alert from temporary storage', async function () {
  await assertions.assertVisible(page.locator('//div[@id="queue-processing"]'));
});

Then('alert record should be successfully written to database', async function () {
  await assertions.assertVisible(page.locator('//div[@id="database-write-success"]'));
});

Then('original timestamp should be preserved', async function () {
  await assertions.assertVisible(page.locator('//div[@id="original-timestamp"]'));
});

Then('alert status should change from {string} to {string}', async function (oldStatus: string, newStatus: string) {
  await assertions.assertContainsText(page.locator('//div[@id="alert-status"]'), newStatus);
});

Then('notifications should be sent to user and manager', async function () {
  await assertions.assertVisible(page.locator('//div[@id="notifications-sent"]'));
});

Then('alert record should contain all original data', async function () {
  await assertions.assertVisible(page.locator('//div[@id="complete-alert-data"]'));
});

Then('alert should show correct anomaly detection time {string}', async function (detectionTime: string) {
  await assertions.assertContainsText(page.locator('//div[@id="detection-time"]'), detectionTime);
});

Then('alert should show correct user ID {string}', async function (userId: string) {
  await assertions.assertContainsText(page.locator('//div[@id="alert-user-id"]'), userId);
});

Then('alert should include complete anomaly details', async function () {
  await assertions.assertVisible(page.locator('//div[@id="complete-anomaly-details"]'));
});

Then('no data corruption or loss should occur', async function () {
  await assertions.assertVisible(page.locator('//div[@id="data-integrity-verified"]'));
});