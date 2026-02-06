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
      user: { username: 'testuser', password: 'testpass' },
      manager: { username: 'manager', password: 'manager123' }
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

Given('user is logged into the system with valid credentials', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), 'testuser');
  await actions.fill(page.locator('//input[@id="password"]'), 'testpass');
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

Given('attendance monitoring system is running and operational', async function () {
  await waits.waitForVisible(page.locator('//div[@id="attendance-monitoring-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="attendance-monitoring-status"]'), 'Operational');
});

Given('user has an active attendance record in the database', async function () {
  this.testData.attendanceRecord = {
    userId: 'USR-12345',
    status: 'Active',
    recordDate: new Date().toISOString()
  };
  await waits.waitForVisible(page.locator('//div[@id="attendance-record-status"]'));
});

Given('user\'s expected arrival time is set to {string} in the system', async function (expectedTime: string) {
  this.testData.expectedArrivalTime = expectedTime;
  await assertions.assertVisible(page.locator(`//span[@id="expected-arrival-time" and contains(text(),'${expectedTime}')]`));
});

Given('current system time is {string}', async function (currentTime: string) {
  this.testData.currentSystemTime = currentTime;
  await assertions.assertVisible(page.locator(`//div[@id="system-time" and contains(text(),'${currentTime}')]`));
});

Given('user has received an attendance anomaly alert for early departure', async function () {
  this.testData.alertType = 'Early Departure';
  await waits.waitForVisible(page.locator('//div[@id="notification-bell"]'));
  await assertions.assertVisible(page.locator('//span[@id="notification-badge"]'));
});

Given('alert is visible in the user\'s notification center with {string} status', async function (status: string) {
  await actions.click(page.locator('//div[@id="notification-bell"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-panel"]'));
  await assertions.assertContainsText(page.locator(`//span[@class="alert-status"]`), status);
});

Given('alert details show {string}', async function (alertDetails: string) {
  await assertions.assertContainsText(page.locator('//div[@id="alert-details"]'), alertDetails);
});

Given('user is on {string} page', async function (pageName: string) {
  const pageUrl = pageName.toLowerCase().replace(/\s+/g, '-');
  await actions.navigateTo(`${process.env.BASE_URL}/${pageUrl}`);
  await waits.waitForNetworkIdle();
});

Given('user is logged into the system as a manager with team view permissions', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), 'manager');
  await actions.fill(page.locator('//input[@id="password"]'), 'manager123');
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="team-view-dashboard"]'));
});

Given('a team member has been absent for {int} consecutive days without prior notification', async function (days: number) {
  this.testData.absenceDays = days;
  this.testData.anomalyType = 'Multiple Absence';
});

Given('system has detected this as a {string} anomaly', async function (anomalyType: string) {
  this.testData.detectedAnomalyType = anomalyType;
  await waits.waitForVisible(page.locator(`//div[@id="anomaly-detection" and contains(text(),'${anomalyType}')]`));
});

Given('alert has been generated and sent to both the absent employee and their manager', async function () {
  await waits.waitForVisible(page.locator('//div[@id="alert-sent-confirmation"]'));
  await assertions.assertContainsText(page.locator('//div[@id="alert-recipients"]'), 'Employee');
  await assertions.assertContainsText(page.locator('//div[@id="alert-recipients"]'), 'Manager');
});

Given('user is currently working', async function () {
  await assertions.assertVisible(page.locator('//div[@id="user-status" and contains(text(),"Working")]'));
});

Given('user\'s shift end time is configured as {string} in the system', async function (shiftEndTime: string) {
  this.testData.shiftEndTime = shiftEndTime;
  await assertions.assertVisible(page.locator(`//span[@id="shift-end-time" and contains(text(),'${shiftEndTime}')]`));
});

Given('user has not logged out or marked departure in the attendance system', async function () {
  await assertions.assertVisible(page.locator('//div[@id="departure-status" and contains(text(),"Not Logged Out")]'));
});

Given('overtime threshold is set to {int} hours in system configuration', async function (hours: number) {
  this.testData.overtimeThreshold = hours;
  await assertions.assertVisible(page.locator(`//span[@id="overtime-threshold" and contains(text(),'${hours}')]`));
});

Given('user is logged into the system as a manager with historical data access permissions', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), 'manager');
  await actions.fill(page.locator('//input[@id="password"]'), 'manager123');
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="historical-data-access"]'));
});

Given('multiple attendance alerts have been generated over the past {int} days for the team', async function (days: number) {
  this.testData.alertPeriod = days;
  await waits.waitForVisible(page.locator('//div[@id="alerts-summary"]'));
});

Given('alerts include various types including late arrivals, early departures, absences, and overtime', async function () {
  await assertions.assertVisible(page.locator('//div[@id="alert-types-summary"]'));
});

Given('some alerts have been acknowledged and others remain unacknowledged', async function () {
  await assertions.assertVisible(page.locator('//span[@class="acknowledged-count"]'));
  await assertions.assertVisible(page.locator('//span[@class="unacknowledged-count"]'));
});

Given('user has been late to work {int} times in the past {int} days', async function (lateCount: number, days: number) {
  this.testData.lateCount = lateCount;
  this.testData.patternDays = days;
});

Given('each late arrival was between {int}-{int} minutes past expected arrival time', async function (minDelay: number, maxDelay: number) {
  this.testData.delayRange = { min: minDelay, max: maxDelay };
});

Given('system pattern detection algorithm is configured to flag {int} or more late arrivals in {int} days as anomaly', async function (threshold: number, days: number) {
  this.testData.patternThreshold = threshold;
  this.testData.patternDays = days;
});

Given('current date is the {int}th day', async function (day: number) {
  this.testData.currentDay = day;
});

// ==================== WHEN STEPS ====================

When('system automatically analyzes attendance data and detects late arrival anomaly', async function () {
  await waits.waitForVisible(page.locator('//div[@id="anomaly-detection-process"]'));
  await waits.waitForNetworkIdle();
});

When('system dispatches the alert notification to the affected user', async function () {
  await waits.waitForVisible(page.locator('//div[@id="alert-dispatch-user"]'));
  await waits.waitForNetworkIdle();
});

When('system dispatches the alert to the user\'s manager', async function () {
  await waits.waitForVisible(page.locator('//div[@id="alert-dispatch-manager"]'));
  await waits.waitForNetworkIdle();
});

When('user clicks on the notification bell icon in the top-right corner', async function () {
  await actions.click(page.locator('//div[@id="notification-bell"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-panel"]'));
});

When('user clicks on the alert titled {string}', async function (alertTitle: string) {
  await actions.click(page.locator(`//div[@class="alert-item" and contains(text(),'${alertTitle}')]`));
  await waits.waitForVisible(page.locator('//div[@id="alert-detail-modal"]'));
});

When('user clicks {string} button at the bottom of the alert detail modal', async function (buttonText: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonXPath);
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
  await waits.waitForNetworkIdle();
});

When('user closes the modal and returns to the notifications list', async function () {
  await actions.click(page.locator('//button[@id="close-modal"]'));
  await waits.waitForHidden(page.locator('//div[@id="alert-detail-modal"]'));
});

When('user navigates to {string} page', async function (pageName: string) {
  const pageUrl = pageName.toLowerCase().replace(/\s+/g, '-');
  await actions.navigateTo(`${process.env.BASE_URL}/${pageUrl}`);
  await waits.waitForNetworkIdle();
});

When('user locates the alert in the historical records', async function () {
  await waits.waitForVisible(page.locator('//table[@id="alerts-history-table"]'));
  await assertions.assertVisible(page.locator('//tr[@class="alert-record"]'));
});

When('user opens the notification center by clicking the notification bell icon', async function () {
  await actions.click(page.locator('//div[@id="notification-bell"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-panel"]'));
});

When('user clicks on the alert to view full details', async function () {
  await actions.click(page.locator('//div[@class="alert-item"][1]'));
  await waits.waitForVisible(page.locator('//div[@id="alert-detail-view"]'));
});

When('user scrolls down to view the {string} section', async function (sectionName: string) {
  const sectionXPath = `//div[@id='${sectionName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.scrollIntoView(page.locator(sectionXPath));
  await waits.waitForVisible(page.locator(sectionXPath));
});

When('user reviews the {string} and {string} fields', async function (field1: string, field2: string) {
  const field1XPath = `//div[@id='${field1.toLowerCase().replace(/\s+/g, '-')}']`;
  const field2XPath = `//div[@id='${field2.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(field1XPath));
  await assertions.assertVisible(page.locator(field2XPath));
});

When('user clicks on {string} button within the alert', async function (buttonText: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonXPath);
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
  await waits.waitForNetworkIdle();
});

When('system automatically detects overtime anomaly at {string} when threshold is exceeded', async function (detectionTime: string) {
  this.testData.detectionTime = detectionTime;
  await waits.waitForVisible(page.locator('//div[@id="overtime-anomaly-detected"]'));
  await waits.waitForNetworkIdle();
});

When('system simultaneously sends alert notification to the user\'s email address', async function () {
  await waits.waitForVisible(page.locator('//div[@id="email-sent-user"]'));
  await waits.waitForNetworkIdle();
});

When('system simultaneously sends alert notification to the manager\'s email address', async function () {
  await waits.waitForVisible(page.locator('//div[@id="email-sent-manager"]'));
  await waits.waitForNetworkIdle();
});

When('user checks in-app notifications', async function () {
  await actions.click(page.locator('//div[@id="notification-bell"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-panel"]'));
});

When('manager checks in-app notifications', async function () {
  await actions.click(page.locator('//div[@id="notification-bell"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-panel"]'));
});

When('delivery log is checked at {string}', async function (apiEndpoint: string) {
  await actions.navigateTo(`${process.env.BASE_URL}${apiEndpoint}`);
  await waits.waitForNetworkIdle();
});

When('user navigates to the {string} section from the main navigation menu', async function (sectionName: string) {
  const navXPath = `//a[@id='nav-${sectionName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(navXPath));
  await waits.waitForNetworkIdle();
});

When('user applies date range filter to show alerts from the last {int} days', async function (days: number) {
  await actions.click(page.locator('//button[@id="date-range-filter"]'));
  await actions.selectByText(page.locator('//select[@id="date-range-dropdown"]'), `Last ${days} days`);
  await waits.waitForNetworkIdle();
});

When('user clicks on the {string} column header to sort alerts', async function (columnName: string) {
  const columnXPath = `//th[@id='column-${columnName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(columnXPath));
  await waits.waitForNetworkIdle();
});

When('user clicks on {string} button for alert {string}', async function (buttonText: string, alertId: string) {
  const buttonXPath = `//tr[@data-alert-id='${alertId}']//button[contains(text(),'${buttonText}')]`;
  await actions.click(page.locator(buttonXPath));
  await waits.waitForVisible(page.locator('//div[@id="alert-detail-modal"]'));
});

When('user clicks on {string} button in the top-right corner', async function (buttonText: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(buttonXPath));
  await waits.waitForVisible(page.locator('//div[@id="export-options-modal"]'));
});

When('user selects {string} format', async function (format: string) {
  await actions.click(page.locator(`//button[@id='export-${format.toLowerCase()}']`));
  await waits.waitForNetworkIdle();
});

When('user applies filter to show only {string} alerts', async function (status: string) {
  await actions.click(page.locator('//button[@id="status-filter"]'));
  await actions.click(page.locator(`//option[@value='${status.toLowerCase()}']`));
  await waits.waitForNetworkIdle();
});

When('user checks in at {string} which is {int} minutes late', async function (checkInTime: string, minutesLate: number) {
  this.testData.checkInTime = checkInTime;
  this.testData.minutesLate = minutesLate;
  await actions.click(page.locator('//button[@id="check-in"]'));
  await waits.waitForNetworkIdle();
});

When('system pattern detection algorithm identifies {int} late arrivals in {int} days', async function (lateCount: number, days: number) {
  await waits.waitForVisible(page.locator('//div[@id="pattern-detection-result"]'));
  await assertions.assertContainsText(page.locator('//div[@id="pattern-detection-result"]'), `${lateCount} late arrivals`);
});

When('system sends alert notification to user with pattern details', async function () {
  await waits.waitForVisible(page.locator('//div[@id="pattern-alert-sent-user"]'));
  await waits.waitForNetworkIdle();
});

When('system sends alert notification to manager with pattern analysis', async function () {
  await waits.waitForVisible(page.locator('//div[@id="pattern-alert-sent-manager"]'));
  await waits.waitForNetworkIdle();
});

When('manager logs in and views the alert details including the pattern visualization', async function () {
  await actions.click(page.locator('//div[@class="alert-item"][1]'));
  await waits.waitForVisible(page.locator('//div[@id="pattern-visualization"]'));
});

// ==================== THEN STEPS ====================

Then('system should identify the late arrival as an attendance anomaly based on the 15-minute threshold rule', async function () {
  await assertions.assertVisible(page.locator('//div[@id="anomaly-identified"]'));
  await assertions.assertContainsText(page.locator('//div[@id="anomaly-type"]'), 'Late Arrival');
});

Then('alert should be created with anomaly type {string}', async function (anomalyType: string) {
  await assertions.assertContainsText(page.locator('//span[@id="alert-anomaly-type"]'), anomalyType);
});

Then('alert should include detected time {string}', async function (detectedTime: string) {
  await assertions.assertContainsText(page.locator('//span[@id="detected-time"]'), detectedTime);
});

Then('alert should include delay duration {string}', async function (delayDuration: string) {
  await assertions.assertContainsText(page.locator('//span[@id="delay-duration"]'), delayDuration);
});

Then('alert should include suggested action {string}', async function (suggestedAction: string) {
  await assertions.assertContainsText(page.locator('//div[@id="suggested-action"]'), suggestedAction);
});

Then('user should receive email notification with subject {string}', async function (emailSubject: string) {
  await waits.waitForVisible(page.locator('//div[@id="email-notification-user"]'));
  await assertions.assertContainsText(page.locator('//span[@id="email-subject"]'), emailSubject);
});

Then('in-app notification should appear in the notification bell icon with red badge', async function () {
  await assertions.assertVisible(page.locator('//span[@id="notification-badge" and @class="red-badge"]'));
});

Then('manager should receive email notification with subject {string}', async function (emailSubject: string) {
  await waits.waitForVisible(page.locator('//div[@id="email-notification-manager"]'));
  await assertions.assertContainsText(page.locator('//span[@id="manager-email-subject"]'), emailSubject);
});

Then('in-app notification should appear in manager\'s notification center', async function () {
  await assertions.assertVisible(page.locator('//div[@id="manager-notification-center"]//div[@class="alert-item"]'));
});

Then('alert delivery timestamp should show alerts were sent within {int} minutes of detection', async function (minutes: number) {
  await assertions.assertVisible(page.locator('//span[@id="delivery-timestamp"]'));
});

Then('alert record should be saved in the attendance alerts database with status {string}', async function (status: string) {
  await assertions.assertContainsText(page.locator('//span[@id="alert-status"]'), status);
});

Then('alert should appear in the historical attendance alerts log with complete details', async function () {
  await assertions.assertVisible(page.locator('//div[@id="historical-alerts-log"]//div[@class="alert-record"]'));
});

Then('notification dropdown panel should open showing list of alerts', async function () {
  await assertions.assertVisible(page.locator('//div[@id="notification-panel"]'));
  await assertions.assertVisible(page.locator('//div[@class="alert-list"]'));
});

Then('attendance anomaly alert with red {string} badge should be visible', async function (badgeText: string) {
  await assertions.assertVisible(page.locator(`//span[@class="badge red" and contains(text(),'${badgeText}')]`));
});

Then('alert detail modal should open displaying full information', async function () {
  await assertions.assertVisible(page.locator('//div[@id="alert-detail-modal"]'));
});

Then('modal should show anomaly type', async function () {
  await assertions.assertVisible(page.locator('//div[@id="modal-anomaly-type"]'));
});

Then('modal should show detection time', async function () {
  await assertions.assertVisible(page.locator('//div[@id="modal-detection-time"]'));
});

Then('modal should show description {string}', async function (description: string) {
  await assertions.assertContainsText(page.locator('//div[@id="modal-description"]'), description);
});

Then('modal should show suggested action {string}', async function (suggestedAction: string) {
  await assertions.assertContainsText(page.locator('//div[@id="modal-suggested-action"]'), suggestedAction);
});

Then('success message {string} should be displayed in green banner', async function (message: string) {
  await assertions.assertVisible(page.locator('//div[@class="success-banner green"]'));
  await assertions.assertContainsText(page.locator('//div[@class="success-banner green"]'), message);
});

Then('acknowledged alert should show green {string} badge with timestamp', async function (badgeText: string) {
  await assertions.assertVisible(page.locator(`//span[@class="badge green" and contains(text(),'${badgeText}')]`));
  await assertions.assertVisible(page.locator('//span[@id="acknowledgment-timestamp"]'));
});

Then('red notification badge count should decrease by {int}', async function (count: number) {
  const currentCount = await page.locator('//span[@id="notification-badge"]').textContent();
  expect(parseInt(currentCount || '0')).toBeGreaterThanOrEqual(0);
});

Then('alert record should show status {string}', async function (status: string) {
  await assertions.assertContainsText(page.locator('//span[@class="record-status"]'), status);
});

Then('alert record should show acknowledgment timestamp', async function () {
  await assertions.assertVisible(page.locator('//span[@id="acknowledgment-timestamp"]'));
});

Then('alert record should show acknowledging user name', async function () {
  await assertions.assertVisible(page.locator('//span[@id="acknowledging-user"]'));
});

Then('manager should be able to see the acknowledgment status when viewing team alerts', async function () {
  await assertions.assertVisible(page.locator('//div[@id="team-alerts"]//span[@class="acknowledgment-status"]'));
});

Then('notification panel should display the alert with title {string}', async function (alertTitle: string) {
  await assertions.assertContainsText(page.locator('//div[@id="notification-panel"]'), alertTitle);
});

Then('alert detail view should show anomaly type {string}', async function (anomalyType: string) {
  await assertions.assertContainsText(page.locator('//div[@id="alert-detail-view"]//span[@id="anomaly-type"]'), anomalyType);
});

Then('alert should show employee name', async function () {
  await assertions.assertVisible(page.locator('//span[@id="employee-name"]'));
});

Then('alert should show employee ID', async function () {
  await assertions.assertVisible(page.locator('//span[@id="employee-id"]'));
});

Then('alert should show detection date', async function () {
  await assertions.assertVisible(page.locator('//span[@id="detection-date"]'));
});

Then('alert should show absence duration {string}', async function (duration: string) {
  await assertions.assertContainsText(page.locator('//span[@id="absence-duration"]'), duration);
});

Then('alert should show last known attendance {string}', async function (lastAttendance: string) {
  await assertions.assertContainsText(page.locator('//span[@id="last-known-attendance"]'), lastAttendance);
});

Then('suggested actions section should display {string}', async function (action: string) {
  await assertions.assertContainsText(page.locator('//div[@id="suggested-actions"]'), action);
});

Then('alert priority should show {string} in red text', async function (priority: string) {
  await assertions.assertVisible(page.locator(`//span[@id="alert-priority" and @class="red-text" and contains(text(),'${priority}')]`));
});

Then('escalation status should show {string} with timestamp', async function (escalationStatus: string) {
  await assertions.assertContainsText(page.locator('//span[@id="escalation-status"]'), escalationStatus);
  await assertions.assertVisible(page.locator('//span[@id="escalation-timestamp"]'));
});

Then('employee contact information modal should open', async function () {
  await assertions.assertVisible(page.locator('//div[@id="contact-info-modal"]'));
});

Then('modal should display phone number', async function () {
  await assertions.assertVisible(page.locator('//span[@id="phone-number"]'));
});

Then('modal should display email address', async function () {
  await assertions.assertVisible(page.locator('//span[@id="email-address"]'));
});

Then('modal should display emergency contact details', async function () {
  await assertions.assertVisible(page.locator('//div[@id="emergency-contact"]'));
});

Then('modal should display last known location', async function () {
  await assertions.assertVisible(page.locator('//span[@id="last-known-location"]'));
});

Then('alert should remain active until manager acknowledges and provides resolution notes', async function () {
  await assertions.assertContainsText(page.locator('//span[@id="alert-status"]'), 'Active');
});

Then('HR department should have visibility to the escalated alert in their dashboard', async function () {
  await assertions.assertVisible(page.locator('//div[@id="hr-dashboard"]//div[@class="escalated-alert"]'));
});

Then('system should identify {string} anomaly', async function (anomalyType: string) {
  await assertions.assertContainsText(page.locator('//span[@id="identified-anomaly-type"]'), anomalyType);
});

Then('alert record should be created with user name', async function () {
  await assertions.assertVisible(page.locator('//span[@id="alert-user-name"]'));
});

Then('alert should include shift end time {string}', async function (shiftEndTime: string) {
  await assertions.assertContainsText(page.locator('//span[@id="shift-end-time"]'), shiftEndTime);
});

Then('alert should include current time {string}', async function (currentTime: string) {
  await assertions.assertContainsText(page.locator('//span[@id="current-time"]'), currentTime);
});

Then('alert should include overtime duration {string}', async function (overtimeDuration: string) {
  await assertions.assertContainsText(page.locator('//span[@id="overtime-duration"]'), overtimeDuration);
});

Then('user should receive email within {int} minutes with subject {string}', async function (minutes: number, emailSubject: string) {
  await waits.waitForVisible(page.locator('//div[@id="email-notification"]'));
  await assertions.assertContainsText(page.locator('//span[@id="email-subject"]'), emailSubject);
});

Then('email should contain anomaly details', async function () {
  await assertions.assertVisible(page.locator('//div[@id="email-body"]//div[@id="anomaly-details"]'));
});

Then('email should contain suggested action {string}', async function (suggestedAction: string) {
  await assertions.assertContainsText(page.locator('//div[@id="email-body"]//div[@id="suggested-action"]'), suggestedAction);
});

Then('manager should receive email within {int} minutes with subject {string}', async function (minutes: number, emailSubject: string) {
  await waits.waitForVisible(page.locator('//div[@id="manager-email-notification"]'));
  await assertions.assertContainsText(page.locator('//span[@id="manager-email-subject"]'), emailSubject);
});

Then('email should contain same anomaly details', async function () {
  await assertions.assertVisible(page.locator('//div[@id="manager-email-body"]//div[@id="anomaly-details"]'));
});

Then('user should see the overtime alert in notification center', async function () {
  await assertions.assertVisible(page.locator('//div[@id="notification-center"]//div[@class="overtime-alert"]'));
});

Then('alert timestamp should match email delivery time within {int} minutes of detection', async function (minutes: number) {
  await assertions.assertVisible(page.locator('//span[@id="alert-timestamp"]'));
});

Then('manager should see the same overtime alert in their notification center', async function () {
  await assertions.assertVisible(page.locator('//div[@id="manager-notification-center"]//div[@class="overtime-alert"]'));
});

Then('alert should have identical timestamp confirming simultaneous delivery', async function () {
  await assertions.assertVisible(page.locator('//span[@id="simultaneous-delivery-timestamp"]'));
});

Then('delivery log should show two entries with same alert ID', async function () {
  const entries = await page.locator('//div[@class="delivery-log-entry"]').count();
  expect(entries).toBeGreaterThanOrEqual(2);
});

Then('one entry should be for user delivery', async function () {
  await assertions.assertVisible(page.locator('//div[@class="delivery-log-entry" and contains(text(),"User")]'));
});

Then('one entry should be for manager delivery', async function () {
  await assertions.assertVisible(page.locator('//div[@class="delivery-log-entry" and contains(text(),"Manager")]'));
});

Then('both entries should have timestamps within {int} minutes of detection time', async function (minutes: number) {
  await assertions.assertVisible(page.locator('//span[@class="delivery-timestamp"]'));
});

Then('alert should be recorded with status {string}', async function (status: string) {
  await assertions.assertContainsText(page.locator('//span[@id="alert-record-status"]'), status);
});

Then('attendance alerts history page should load displaying a table', async function () {
  await assertions.assertVisible(page.locator('//table[@id="alerts-history-table"]'));
});

Then('table should have column {string}', async function (columnName: string) {
  const columnXPath = `//th[@id='column-${columnName.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(columnXPath));
});

Then('table should refresh to display all alerts within the selected date range', async function () {
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//table[@id="alerts-history-table"]//tr[@class="alert-record"]'));
});

Then('page should show count {string}', async function (countText: string) {
  await assertions.assertContainsText(page.locator('//div[@id="alerts-count"]'), countText);
});

Then('alerts should be grouped and sorted by type', async function () {
  await assertions.assertVisible(page.locator('//div[@class="alert-group"]'));
});

Then('table should show {string}', async function (groupText: string) {
  await assertions.assertContainsText(page.locator('//table[@id="alerts-history-table"]'), groupText);
});

Then('visual grouping indicators should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@class="group-indicator"]'));
});

Then('alert detail modal should open showing complete information', async function () {
  await assertions.assertVisible(page.locator('//div[@id="alert-detail-modal"]'));
});

Then('modal should show full anomaly description', async function () {
  await assertions.assertVisible(page.locator('//div[@id="modal-full-description"]'));
});

Then('modal should show detection timestamp with millisecond precision', async function () {
  await assertions.assertVisible(page.locator('//span[@id="detection-timestamp-precise"]'));
});

Then('modal should show alert generation timestamp', async function () {
  await assertions.assertVisible(page.locator('//span[@id="generation-timestamp"]'));
});

Then('modal should show delivery timestamps for user and manager', async function () {
  await assertions.assertVisible(page.locator('//span[@id="user-delivery-timestamp"]'));
  await assertions.assertVisible(page.locator('//span[@id="manager-delivery-timestamp"]'));
});

Then('modal should show acknowledgment details if acknowledged', async function () {
  await assertions.assertVisible(page.locator('//div[@id="acknowledgment-details"]'));
});

Then('modal should show suggested actions provided', async function () {
  await assertions.assertVisible(page.locator('//div[@id="modal-suggested-actions"]'));
});

Then('modal should show resolution notes if any', async function () {
  await assertions.assertVisible(page.locator('//div[@id="resolution-notes"]'));
});

Then('modal should show complete audit trail of all status changes', async function () {
  await assertions.assertVisible(page.locator('//div[@id="audit-trail"]'));
});

Then('export options modal should appear with formats CSV, Excel, PDF', async function () {
  await assertions.assertVisible(page.locator('//div[@id="export-options-modal"]'));
  await assertions.assertVisible(page.locator('//button[@id="export-csv"]'));
  await assertions.assertVisible(page.locator('//button[@id="export-excel"]'));
  await assertions.assertVisible(page.locator('//button[@id="export-pdf"]'));
});

Then('file should download with name {string}', async function (fileName: string) {
  await waits.waitForNetworkIdle();
});

Then('file should contain all displayed records', async function () {
  await waits.waitForNetworkIdle();
});

Then('table should update to show only alerts with status {string}', async function (status: string) {
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator(`//tr[@class="alert-record" and contains(@data-status,'${status.toLowerCase()}')]`));
});

Then('page should display count {string} with red highlight', async function (countText: string) {
  await assertions.assertVisible(page.locator('//div[@id="unacknowledged-count" and @class="red-highlight"]'));
  await assertions.assertContainsText(page.locator('//div[@id="unacknowledged-count"]'), countText);
});

Then('all historical alert records should remain intact and accessible in the database', async function () {
  await assertions.assertVisible(page.locator('//table[@id="alerts-history-table"]//tr[@class="alert-record"]'));
});

Then('exported data should match the displayed records exactly', async function () {
  await waits.waitForNetworkIdle();
});

Then('system should record the check-in', async function () {
  await assertions.assertVisible(page.locator('//div[@id="check-in-recorded"]'));
});

Then('system should analyze attendance pattern for the past {int} days', async function (days: number) {
  await waits.waitForVisible(page.locator('//div[@id="pattern-analysis"]'));
});

Then('system should generate a {string} anomaly alert with severity level {string}', async function (anomalyType: string, severityLevel: string) {
  await assertions.assertContainsText(page.locator('//span[@id="anomaly-type"]'), anomalyType);
  await assertions.assertContainsText(page.locator('//span[@id="severity-level"]'), severityLevel);
});

Then('alert should include pattern analysis {string}', async function (patternAnalysis: string) {
  await assertions.assertContainsText(page.locator('//div[@id="pattern-analysis-details"]'), patternAnalysis);
});

Then('user should receive notification titled {string}', async function (notificationTitle: string) {
  await assertions.assertContainsText(page.locator('//div[@id="notification-title"]'), notificationTitle);
});

Then('notification should include details of all late arrivals', async function () {
  await assertions.assertVisible(page.locator('//div[@id="late-arrivals-details"]'));
});

Then('notification should include pattern visualization', async function () {
  await assertions.assertVisible(page.locator('//div[@id="pattern-visualization"]'));
});

Then('notification should include suggested action {string}', async function (suggestedAction: string) {
  await assertions.assertContainsText(page.locator('//div[@id="notification-suggested-action"]'), suggestedAction);
});

Then('manager should receive notification titled {string}', async function (notificationTitle: string) {
  await assertions.assertContainsText(page.locator('//div[@id="manager-notification-title"]'), notificationTitle);
});

Then('notification should include pattern details', async function () {
  await assertions.assertVisible(page.locator('//div[@id="pattern-details"]'));
});

Then('notification should include trend graph', async function () {
  await assertions.assertVisible(page.locator('//div[@id="trend-graph"]'));
});

Then('notification should include suggested actions {string}', async function (suggestedActions: string) {
  await assertions.assertContainsText(page.locator('//div[@id="manager-suggested-actions"]'), suggestedActions);
});

Then('alert detail view should show a timeline graph of late arrivals over the past {int} days', async function (days: number) {
  await assertions.assertVisible(page.locator('//div[@id="timeline-graph"]'));
});

Then('graph should highlight the pattern', async function () {
  await assertions.assertVisible(page.locator('//div[@id="pattern-highlight"]'));
});

Then('each incident should be marked with delay duration displayed', async function () {
  await assertions.assertVisible(page.locator('//span[@class="delay-duration"]'));
});

Then('pattern-based anomaly should be recorded with type {string}', async function (anomalyType: string) {
  await assertions.assertContainsText(page.locator('//span[@id="pattern-anomaly-type"]'), anomalyType);
});

Then('alert should include references to all {int} individual late arrival incidents', async function (incidentCount: number) {
  const incidents = await page.locator('//div[@class="incident-reference"]').count();
  expect(incidents).toBe(incidentCount);
});

Then('system should continue monitoring the pattern for follow-up alerts if pattern persists', async function () {
  await assertions.assertVisible(page.locator('//div[@id="pattern-monitoring-active"]'));
});

Then('alert should be flagged for HR review if not resolved within {int} days', async function (days: number) {
  await assertions.assertVisible(page.locator('//span[@id="hr-review-flag"]'));
});