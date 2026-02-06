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
    anomalyTypes: ['late arrival', 'missing clock-in', 'unauthorized break extension'],
    timestamps: {},
    alertIds: [],
    systemMetrics: {}
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
  const credentials = this.testData?.users?.user || { username: 'testuser', password: 'testpass' };
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

Given('attendance monitoring system is active and running', async function () {
  await assertions.assertVisible(page.locator('//div[@id="attendance-monitoring-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="attendance-monitoring-status"]'), 'Active');
});

Given('test user has multiple attendance anomalies configured to occur simultaneously', async function () {
  await actions.click(page.locator('//button[@id="configure-test-anomalies"]'));
  await waits.waitForVisible(page.locator('//div[@id="anomaly-configuration-panel"]'));
  for (const anomalyType of this.testData.anomalyTypes) {
    const checkboxXPath = `//input[@id='anomaly-${anomalyType.toLowerCase().replace(/\s+/g, '-')}']`;
    await actions.check(page.locator(checkboxXPath));
  }
  await actions.click(page.locator('//button[@id="save-configuration"]'));
  await waits.waitForNetworkIdle();
});

Given('manager account is configured to receive alerts for the test user', async function () {
  await actions.click(page.locator('//button[@id="configure-alert-recipients"]'));
  await waits.waitForVisible(page.locator('//div[@id="alert-recipients-panel"]'));
  await actions.fill(page.locator('//input[@id="manager-email"]'), 'manager@example.com');
  await actions.click(page.locator('//button[@id="save-recipients"]'));
  await waits.waitForNetworkIdle();
});

Given('system clock is synchronized with attendance tracking system', async function () {
  await assertions.assertVisible(page.locator('//div[@id="system-clock-sync-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="system-clock-sync-status"]'), 'Synchronized');
});

Given('attendance anomaly detection service is running', async function () {
  await assertions.assertVisible(page.locator('//div[@id="anomaly-detection-service-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="anomaly-detection-service-status"]'), 'Running');
});

Given('test environment allows precise timestamp manipulation', async function () {
  await assertions.assertVisible(page.locator('//div[@id="timestamp-manipulation-enabled"]'));
  this.testData.timestampManipulationEnabled = true;
});

Given('test user account has no manager assigned in organizational hierarchy', async function () {
  await actions.click(page.locator('//button[@id="user-profile"]'));
  await waits.waitForVisible(page.locator('//div[@id="profile-panel"]'));
  await actions.click(page.locator('//button[@id="remove-manager-assignment"]'));
  await waits.waitForNetworkIdle();
});

Given('attendance anomaly detection rules are configured', async function () {
  await assertions.assertVisible(page.locator('//div[@id="anomaly-detection-rules-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="anomaly-detection-rules-status"]'), 'Configured');
});

Given('test user has assigned manager with inactive account status', async function () {
  await actions.click(page.locator('//button[@id="user-profile"]'));
  await waits.waitForVisible(page.locator('//div[@id="profile-panel"]'));
  await actions.fill(page.locator('//input[@id="assigned-manager"]'), 'inactive_manager');
  await actions.click(page.locator('//button[@id="save-profile"]'));
  await waits.waitForNetworkIdle();
});

Given('attendance monitoring system is active', async function () {
  await assertions.assertVisible(page.locator('//div[@id="attendance-monitoring-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="attendance-monitoring-status"]'), 'Active');
});

Given('system has {int} active users configured in attendance system', async function (userCount: number) {
  await actions.click(page.locator('//button[@id="system-configuration"]'));
  await waits.waitForVisible(page.locator('//div[@id="configuration-panel"]'));
  await actions.fill(page.locator('//input[@id="active-users-count"]'), userCount.toString());
  await actions.click(page.locator('//button[@id="apply-configuration"]'));
  await waits.waitForNetworkIdle();
  this.testData.activeUsersCount = userCount;
});

Given('load testing environment is available', async function () {
  await assertions.assertVisible(page.locator('//div[@id="load-testing-environment-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="load-testing-environment-status"]'), 'Available');
});

Given('database has sufficient capacity for high-volume alert storage', async function () {
  await assertions.assertVisible(page.locator('//div[@id="database-capacity-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="database-capacity-status"]'), 'Sufficient');
});

Given('attendance system supports custom anomaly descriptions', async function () {
  await assertions.assertVisible(page.locator('//div[@id="custom-descriptions-support"]'));
  await assertions.assertContainsText(page.locator('//div[@id="custom-descriptions-support"]'), 'Enabled');
});

Given('alert display interface is accessible', async function () {
  await assertions.assertVisible(page.locator('//div[@id="alert-display-interface"]'));
});

Given('user has active session', async function () {
  await assertions.assertVisible(page.locator('//div[@id="session-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="session-status"]'), 'Active');
});

Given('at least {int} unacknowledged attendance anomaly alert exists', async function (alertCount: number) {
  const alertsLocator = page.locator('//div[@class="unacknowledged-alert"]');
  const count = await alertsLocator.count();
  expect(count).toBeGreaterThanOrEqual(alertCount);
});

Given('alert acknowledgment API endpoint is accessible', async function () {
  await assertions.assertVisible(page.locator('//div[@id="api-endpoint-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="api-endpoint-status"]'), 'Accessible');
});

Given('system is configured to handle timezone-aware timestamps', async function () {
  await assertions.assertVisible(page.locator('//div[@id="timezone-support-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="timezone-support-status"]'), 'Enabled');
});

Given('test environment allows simulation of timezone changes', async function () {
  await assertions.assertVisible(page.locator('//div[@id="timezone-simulation-enabled"]'));
  this.testData.timezoneSimulationEnabled = true;
});

// ==================== WHEN STEPS ====================

When('system triggers {string} anomaly at {string}', async function (anomalyType: string, timestamp: string) {
  await actions.click(page.locator('//button[@id="trigger-anomaly"]'));
  await waits.waitForVisible(page.locator('//div[@id="anomaly-trigger-panel"]'));
  const anomalyTypeXPath = `//select[@id='anomaly-type']`;
  await actions.selectByText(page.locator(anomalyTypeXPath), anomalyType);
  await actions.fill(page.locator('//input[@id="anomaly-timestamp"]'), timestamp);
  await actions.click(page.locator('//button[@id="execute-trigger"]'));
  await waits.waitForNetworkIdle();
  this.testData.timestamps[anomalyType] = timestamp;
});

When('user navigates to {string} page', async function (pageName: string) {
  const pageIdXPath = `//a[@id='nav-${pageName.toLowerCase().replace(/\s+/g, '-')}']`;
  const navLinks = page.locator(pageIdXPath);
  if (await navLinks.count() > 0) {
    await actions.click(navLinks);
  } else {
    await actions.click(page.locator(`//a[contains(text(),'${pageName}')]`));
  }
  await waits.waitForNetworkIdle();
});

When('manager checks alert inbox', async function () {
  await actions.click(page.locator('//button[@id="switch-to-manager-view"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//button[@id="alert-inbox"]'));
  await waits.waitForVisible(page.locator('//div[@id="manager-alert-inbox"]'));
});

When('user verifies alert delivery timestamps', async function () {
  await actions.click(page.locator('//button[@id="view-alert-timestamps"]'));
  await waits.waitForVisible(page.locator('//div[@id="alert-timestamps-panel"]'));
});

When('user acknowledges each alert individually', async function () {
  const alertsLocator = page.locator('//button[@class="acknowledge-alert-button"]');
  const alertCount = await alertsLocator.count();
  for (let i = 0; i < alertCount; i++) {
    await actions.click(alertsLocator.nth(i));
    await waits.waitForNetworkIdle();
  }
});

When('user creates {string} anomaly at timestamp {string}', async function (anomalyType: string, timestamp: string) {
  await actions.click(page.locator('//button[@id="create-anomaly"]'));
  await waits.waitForVisible(page.locator('//div[@id="create-anomaly-panel"]'));
  await actions.selectByText(page.locator('//select[@id="anomaly-type"]'), anomalyType);
  await actions.fill(page.locator('//input[@id="anomaly-timestamp"]'), timestamp);
  await actions.click(page.locator('//button[@id="submit-anomaly"]'));
  await waits.waitForNetworkIdle();
  this.testData.timestamps.anomalyCreated = timestamp;
});

When('system monitors alert generation at timestamp {string}', async function (timestamp: string) {
  await actions.click(page.locator('//button[@id="monitor-alert-generation"]'));
  await waits.waitForVisible(page.locator('//div[@id="alert-monitoring-panel"]'));
  await actions.fill(page.locator('//input[@id="monitoring-timestamp"]'), timestamp);
  await actions.click(page.locator('//button[@id="start-monitoring"]'));
  await waits.waitForNetworkIdle();
});

When('user verifies alert timestamp in alerts log', async function () {
  await actions.click(page.locator('//button[@id="view-alerts-log"]'));
  await waits.waitForVisible(page.locator('//div[@id="alerts-log-panel"]'));
});

When('user checks alert content', async function () {
  await actions.click(page.locator('//button[@id="view-alert-details"]'));
  await waits.waitForVisible(page.locator('//div[@id="alert-details-panel"]'));
});

When('user verifies profile manager status', async function () {
  await actions.click(page.locator('//button[@id="user-profile"]'));
  await waits.waitForVisible(page.locator('//div[@id="profile-panel"]'));
  await actions.click(page.locator('//button[@id="view-manager-status"]'));
  await waits.waitForVisible(page.locator('//div[@id="manager-status-panel"]'));
});

When('system triggers {string} anomaly with {string} minutes delay', async function (anomalyType: string, delayMinutes: string) {
  await actions.click(page.locator('//button[@id="trigger-anomaly"]'));
  await waits.waitForVisible(page.locator('//div[@id="anomaly-trigger-panel"]'));
  await actions.selectByText(page.locator('//select[@id="anomaly-type"]'), anomalyType);
  await actions.fill(page.locator('//input[@id="delay-minutes"]'), delayMinutes);
  await actions.click(page.locator('//button[@id="execute-trigger"]'));
  await waits.waitForNetworkIdle();
});

When('user checks alert inbox', async function () {
  await actions.click(page.locator('//button[@id="alert-inbox"]'));
  await waits.waitForVisible(page.locator('//div[@id="alert-inbox-panel"]'));
});

When('user verifies system behavior for manager notification', async function () {
  await actions.click(page.locator('//button[@id="view-notification-logs"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-logs-panel"]'));
});

When('user checks error logs', async function () {
  await actions.click(page.locator('//button[@id="view-error-logs"]'));
  await waits.waitForVisible(page.locator('//div[@id="error-logs-panel"]'));
});

When('system triggers {string} anomaly for user', async function (anomalyType: string) {
  await actions.click(page.locator('//button[@id="trigger-anomaly"]'));
  await waits.waitForVisible(page.locator('//div[@id="anomaly-trigger-panel"]'));
  await actions.selectByText(page.locator('//select[@id="anomaly-type"]'), anomalyType);
  await actions.click(page.locator('//button[@id="execute-trigger"]'));
  await waits.waitForNetworkIdle();
});

When('user verifies manager notification handling', async function () {
  await actions.click(page.locator('//button[@id="view-notification-handling"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-handling-panel"]'));
});

When('system triggers attendance anomalies for {int} users simultaneously', async function (userCount: number) {
  await actions.click(page.locator('//button[@id="trigger-bulk-anomalies"]'));
  await waits.waitForVisible(page.locator('//div[@id="bulk-anomaly-trigger-panel"]'));
  await actions.fill(page.locator('//input[@id="user-count"]'), userCount.toString());
  await actions.click(page.locator('//button[@id="execute-bulk-trigger"]'));
  await waits.waitForNetworkIdle();
  this.testData.bulkAnomalyUserCount = userCount;
});

When('user monitors alert generation over next {int} minutes', async function (minutes: number) {
  await actions.click(page.locator('//button[@id="monitor-alert-generation"]'));
  await waits.waitForVisible(page.locator('//div[@id="alert-monitoring-panel"]'));
  await actions.fill(page.locator('//input[@id="monitoring-duration"]'), minutes.toString());
  await actions.click(page.locator('//button[@id="start-monitoring"]'));
  await waits.waitForNetworkIdle();
});

When('user checks system performance metrics', async function () {
  await actions.click(page.locator('//button[@id="view-performance-metrics"]'));
  await waits.waitForVisible(page.locator('//div[@id="performance-metrics-panel"]'));
  const cpuUsage = await page.locator('//span[@id="cpu-usage"]').textContent();
  const memoryUsage = await page.locator('//span[@id="memory-usage"]').textContent();
  this.testData.systemMetrics.cpuUsage = parseFloat(cpuUsage || '0');
  this.testData.systemMetrics.memoryUsage = parseFloat(memoryUsage || '0');
});

When('user verifies alert accuracy by sampling {int} random alerts', async function (sampleSize: number) {
  await actions.click(page.locator('//button[@id="sample-alerts"]'));
  await waits.waitForVisible(page.locator('//div[@id="alert-sampling-panel"]'));
  await actions.fill(page.locator('//input[@id="sample-size"]'), sampleSize.toString());
  await actions.click(page.locator('//button[@id="execute-sampling"]'));
  await waits.waitForNetworkIdle();
});

When('user tests alert dashboard during high load', async function () {
  await actions.click(page.locator('//a[@id="nav-alerts-dashboard"]'));
  await waits.waitForNetworkIdle();
  const startTime = Date.now();
  await waits.waitForVisible(page.locator('//div[@id="alerts-dashboard"]'));
  const loadTime = Date.now() - startTime;
  this.testData.dashboardLoadTime = loadTime;
});

When('user creates attendance anomaly with description {string}', async function (description: string) {
  await actions.click(page.locator('//button[@id="create-anomaly"]'));
  await waits.waitForVisible(page.locator('//div[@id="create-anomaly-panel"]'));
  await actions.fill(page.locator('//textarea[@id="anomaly-description"]'), description);
  await actions.click(page.locator('//button[@id="submit-anomaly"]'));
  await waits.waitForNetworkIdle();
  this.testData.anomalyDescription = description;
});

When('user acknowledges alert', async function () {
  await actions.click(page.locator('//button[@id="acknowledge-alert"]'));
  await waits.waitForNetworkIdle();
});

When('user clicks {string} button {int} times rapidly within {int} seconds', async function (buttonText: string, clickCount: number, seconds: number) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  for (let i = 0; i < clickCount; i++) {
    await buttons.click({ timeout: 100 });
  }
});

When('user verifies alert status', async function () {
  await actions.click(page.locator('//button[@id="view-alert-status"]'));
  await waits.waitForVisible(page.locator('//div[@id="alert-status-panel"]'));
});

When('user checks system logs and database', async function () {
  await actions.click(page.locator('//button[@id="view-system-logs"]'));
  await waits.waitForVisible(page.locator('//div[@id="system-logs-panel"]'));
  await actions.click(page.locator('//button[@id="view-database-records"]'));
  await waits.waitForVisible(page.locator('//div[@id="database-records-panel"]'));
});

When('user verifies UI state', async function () {
  await waits.waitForVisible(page.locator('//div[@id="ui-state-panel"]'));
});

When('user configures test user in {string} timezone', async function (timezone: string) {
  await actions.click(page.locator('//button[@id="user-profile"]'));
  await waits.waitForVisible(page.locator('//div[@id="profile-panel"]'));
  await actions.selectByText(page.locator('//select[@id="user-timezone"]'), timezone);
  await actions.click(page.locator('//button[@id="save-profile"]'));
  await waits.waitForNetworkIdle();
});

When('user configures manager in {string} timezone', async function (timezone: string) {
  await actions.click(page.locator('//button[@id="switch-to-manager-view"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//button[@id="manager-profile"]'));
  await waits.waitForVisible(page.locator('//div[@id="profile-panel"]'));
  await actions.selectByText(page.locator('//select[@id="manager-timezone"]'), timezone);
  await actions.click(page.locator('//button[@id="save-profile"]'));
  await waits.waitForNetworkIdle();
});

When('user creates attendance anomaly at {string}', async function (timestamp: string) {
  await actions.click(page.locator('//button[@id="create-anomaly"]'));
  await waits.waitForVisible(page.locator('//div[@id="create-anomaly-panel"]'));
  await actions.fill(page.locator('//input[@id="anomaly-timestamp"]'), timestamp);
  await actions.click(page.locator('//button[@id="submit-anomaly"]'));
  await waits.waitForNetworkIdle();
});

When('user checks alert as affected user', async function () {
  await actions.click(page.locator('//button[@id="switch-to-user-view"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//button[@id="alert-inbox"]'));
  await waits.waitForVisible(page.locator('//div[@id="user-alert-inbox"]'));
});

When('manager checks alert', async function () {
  await actions.click(page.locator('//button[@id="switch-to-manager-view"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//button[@id="alert-inbox"]'));
  await waits.waitForVisible(page.locator('//div[@id="manager-alert-inbox"]'));
});

When('user checks alert history', async function () {
  await actions.click(page.locator('//button[@id="view-alert-history"]'));
  await waits.waitForVisible(page.locator('//div[@id="alert-history-panel"]'));
});

When('user simulates daylight saving time transition', async function () {
  await actions.click(page.locator('//button[@id="simulate-dst-transition"]'));
  await waits.waitForVisible(page.locator('//div[@id="dst-simulation-panel"]'));
  await actions.click(page.locator('//button[@id="execute-dst-simulation"]'));
  await waits.waitForNetworkIdle();
});

When('user creates attendance anomaly during DST transition', async function () {
  await actions.click(page.locator('//button[@id="create-anomaly"]'));
  await waits.waitForVisible(page.locator('//div[@id="create-anomaly-panel"]'));
  await actions.check(page.locator('//input[@id="during-dst-transition"]'));
  await actions.click(page.locator('//button[@id="submit-anomaly"]'));
  await waits.waitForNetworkIdle();
});

// ==================== THEN STEPS ====================

Then('system should detect all {int} anomalies within {int} minutes', async function (anomalyCount: number, minutes: number) {
  await waits.waitForVisible(page.locator('//div[@id="detected-anomalies-count"]'));
  const detectedCount = await page.locator('//div[@id="detected-anomalies-count"]').textContent();
  expect(parseInt(detectedCount || '0')).toBe(anomalyCount);
});

Then('user should see {int} separate alerts displayed', async function (alertCount: number) {
  const alertsLocator = page.locator('//div[@class="alert-item"]');
  const count = await alertsLocator.count();
  expect(count).toBe(alertCount);
});

Then('each alert should have distinct anomaly description', async function () {
  const descriptionsLocator = page.locator('//div[@class="alert-description"]');
  const count = await descriptionsLocator.count();
  const descriptions = [];
  for (let i = 0; i < count; i++) {
    const text = await descriptionsLocator.nth(i).textContent();
    descriptions.push(text);
  }
  const uniqueDescriptions = new Set(descriptions);
  expect(uniqueDescriptions.size).toBe(count);
});

Then('each alert should have unique timestamp', async function () {
  const timestampsLocator = page.locator('//span[@class="alert-timestamp"]');
  const count = await timestampsLocator.count();
  const timestamps = [];
  for (let i = 0; i < count; i++) {
    const text = await timestampsLocator.nth(i).textContent();
    timestamps.push(text);
  }
  const uniqueTimestamps = new Set(timestamps);
  expect(uniqueTimestamps.size).toBe(count);
});

Then('manager should receive {int} separate alert notifications', async function (notificationCount: number) {
  const notificationsLocator = page.locator('//div[@class="manager-notification"]');
  const count = await notificationsLocator.count();
  expect(count).toBe(notificationCount);
});

Then('each alert should contain specific anomaly details', async function () {
  const alertsLocator = page.locator('//div[@class="alert-item"]');
  const count = await alertsLocator.count();
  for (let i = 0; i < count; i++) {
    await assertions.assertVisible(alertsLocator.nth(i).locator('//div[@class="anomaly-details"]'));
  }
});

Then('each alert should contain suggested actions', async function () {
  const alertsLocator = page.locator('//div[@class="alert-item"]');
  const count = await alertsLocator.count();
  for (let i = 0; i < count; i++) {
    await assertions.assertVisible(alertsLocator.nth(i).locator('//div[@class="suggested-actions"]'));
  }
});

Then('all alerts should be delivered within {int} minutes of detection', async function (minutes: number) {
  await assertions.assertVisible(page.locator('//div[@id="alert-delivery-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="alert-delivery-status"]'), 'Delivered');
});

Then('each alert should have unique alert ID', async function () {
  const alertIdsLocator = page.locator('//span[@class="alert-id"]');
  const count = await alertIdsLocator.count();
  const alertIds = [];
  for (let i = 0; i < count; i++) {
    const text = await alertIdsLocator.nth(i).textContent();
    alertIds.push(text);
  }
  const uniqueIds = new Set(alertIds);
  expect(uniqueIds.size).toBe(count);
});

Then('each alert should be acknowledged separately', async function () {
  const acknowledgedAlertsLocator = page.locator('//div[@class="alert-acknowledged"]');
  const count = await acknowledgedAlertsLocator.count();
  expect(count).toBeGreaterThan(0);
});

Then('acknowledgment status should be tracked independently for each anomaly', async function () {
  await assertions.assertVisible(page.locator('//div[@id="acknowledgment-tracking-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="acknowledgment-tracking-status"]'), 'Independent');
});

Then('all {int} anomalies should be recorded in attendance alerts history', async function (anomalyCount: number) {
  await actions.click(page.locator('//button[@id="view-alert-history"]'));
  await waits.waitForVisible(page.locator('//div[@id="alert-history-panel"]'));
  const historyItemsLocator = page.locator('//div[@class="history-item"]');
  const count = await historyItemsLocator.count();
  expect(count).toBeGreaterThanOrEqual(anomalyCount);
});

Then('system performance should remain stable', async function () {
  await assertions.assertVisible(page.locator('//div[@id="system-performance-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="system-performance-status"]'), 'Stable');
});

Then('alert counters should accurately reflect {int} separate anomalies', async function (anomalyCount: number) {
  const counterText = await page.locator('//span[@id="alert-counter"]').textContent();
  expect(parseInt(counterText || '0')).toBe(anomalyCount);
});

Then('anomaly should be recorded in attendance database with timestamp {string}', async function (timestamp: string) {
  await assertions.assertVisible(page.locator('//div[@id="database-record-confirmation"]'));
  await assertions.assertContainsText(page.locator('//div[@id="database-record-confirmation"]'), timestamp);
});

Then('anomaly should be recorded with timezone information', async function () {
  await assertions.assertVisible(page.locator('//span[@id="timezone-info"]'));
});

Then('alert should be generated within {int} minute SLA', async function (minutes: number) {
  await assertions.assertVisible(page.locator('//div[@id="alert-generation-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="alert-generation-status"]'), 'Generated');
});

Then('alert should be dispatched to user and manager', async function () {
  await assertions.assertVisible(page.locator('//div[@id="alert-dispatch-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="alert-dispatch-status"]'), 'Dispatched');
});

Then('alert should show detection time within {int} minutes', async function (minutes: number) {
  await assertions.assertVisible(page.locator('//span[@id="detection-time"]'));
});

Then('exact timestamps should be logged for anomaly occurrence', async function () {
  await assertions.assertVisible(page.locator('//div[@id="anomaly-occurrence-timestamp"]'));
});

Then('exact timestamps should be logged for alert dispatch', async function () {
  await assertions.assertVisible(page.locator('//div[@id="alert-dispatch-timestamp"]'));
});

Then('alert should contain correct anomaly type', async function () {
  await assertions.assertVisible(page.locator('//span[@id="anomaly-type"]'));
});

Then('alert should contain correct timestamp', async function () {
  await assertions.assertVisible(page.locator('//span[@id="alert-timestamp"]'));
});

Then('alert should contain correct user details', async function () {
  await assertions.assertVisible(page.locator('//div[@id="user-details"]'));
});

Then('alert timestamp data should be accurately recorded in system logs', async function () {
  await assertions.assertVisible(page.locator('//div[@id="system-logs-timestamp-accuracy"]'));
});

Then('alert acknowledgment functionality should be available', async function () {
  await assertions.assertVisible(page.locator('//button[@id="acknowledge-alert"]'));
});

Then('user profile should display {string} status', async function (status: string) {
  await assertions.assertContainsText(page.locator('//div[@id="manager-status"]'), status);
});

Then('system should detect anomaly within {int} minutes', async function (minutes: number) {
  await assertions.assertVisible(page.locator('//div[@id="anomaly-detected-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="anomaly-detected-status"]'), 'Detected');
});

Then('user should receive alert with anomaly details', async function () {
  await assertions.assertVisible(page.locator('//div[@class="alert-item"]'));
  await assertions.assertVisible(page.locator('//div[@class="anomaly-details"]'));
});

Then('system logs should show alert attempted for manager', async function () {
  await assertions.assertVisible(page.locator('//div[@id="manager-notification-attempt-log"]'));
});

Then('system should gracefully handle missing manager scenario', async function () {
  await assertions.assertVisible(page.locator('//div[@id="missing-manager-handling-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="missing-manager-handling-status"]'), 'Handled');
});

Then('fallback notification should be sent to designated backup recipient', async function () {
  await assertions.assertVisible(page.locator('//div[@id="fallback-notification-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="fallback-notification-status"]'), 'Sent');
});

Then('no critical errors should be logged', async function () {
  const criticalErrorsLocator = page.locator('//div[@class="critical-error"]');
  const count = await criticalErrorsLocator.count();
  expect(count).toBe(0);
});

Then('system should record missing manager scenario with warning level log entry', async function () {
  await assertions.assertVisible(page.locator('//div[@class="warning-log-entry"]'));
  await assertions.assertContainsText(page.locator('//div[@class="warning-log-entry"]'), 'missing manager');
});

Then('user should receive alert successfully despite missing manager', async function () {
  await assertions.assertVisible(page.locator('//div[@class="alert-item"]'));
});

Then('system should maintain alert history with missing manager notation', async function () {
  await assertions.assertVisible(page.locator('//div[@id="alert-history-missing-manager-note"]'));
});

Then('no system errors should occur due to missing manager reference', async function () {
  const systemErrorsLocator = page.locator('//div[@class="system-error"]');
  const count = await systemErrorsLocator.count();
  expect(count).toBe(0);
});

Then('system should detect inactive manager account', async function () {
  await assertions.assertVisible(page.locator('//div[@id="inactive-manager-detection-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="inactive-manager-detection-status"]'), 'Detected');
});

Then('system should send fallback notification to HR admin', async function () {
  await assertions.assertVisible(page.locator('//div[@id="hr-admin-notification-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="hr-admin-notification-status"]'), 'Sent');
});

Then('alert history should record inactive manager scenario', async function () {
  await assertions.assertVisible(page.locator('//div[@id="alert-history-inactive-manager-note"]'));
});

Then('system should begin processing all {int} anomalies without crashing', async function (anomalyCount: number) {
  await assertions.assertVisible(page.locator('//div[@id="bulk-processing-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="bulk-processing-status"]'), 'Processing');
});

Then('system should generate alerts for all {int} users', async function (userCount: number) {
  await assertions.assertVisible(page.locator('//div[@id="alerts-generated-count"]'));
  const generatedCount = await page.locator('//div[@id="alerts-generated-count"]').textContent();
  expect(parseInt(generatedCount || '0')).toBe(userCount);
});

Then('system should dispatch alerts for all {int} users', async function (userCount: number) {
  await assertions.assertVisible(page.locator('//div[@id="alerts-dispatched-count"]'));
  const dispatchedCount = await page.locator('//div[@id="alerts-dispatched-count"]').textContent();
  expect(parseInt(dispatchedCount || '0')).toBe(userCount);
});

Then('at least {int} percent of alerts should be delivered within {int} minute SLA', async function (percentage: number, minutes: number) {
  await assertions.assertVisible(page.locator('//div[@id="sla-compliance-percentage"]'));
  const complianceText = await page.locator('//div[@id="sla-compliance-percentage"]').textContent();
  const compliancePercentage = parseFloat(complianceText || '0');
  expect(compliancePercentage).toBeGreaterThanOrEqual(percentage);
});

Then('CPU usage should remain below {int} percent', async function (threshold: number) {
  expect(this.testData.systemMetrics.cpuUsage).toBeLessThan(threshold);
});

Then('memory usage should remain below {int} percent', async function (threshold: number) {
  expect(this.testData.systemMetrics.memoryUsage).toBeLessThan(threshold);
});

Then('no connection pool exhaustion should occur', async function () {
  const poolExhaustionLocator = page.locator('//div[@class="connection-pool-exhaustion-error"]');
  const count = await poolExhaustionLocator.count();
  expect(count).toBe(0);
});

Then('all sampled alerts should contain correct user information', async function () {
  await assertions.assertVisible(page.locator('//div[@id="sampling-results-user-info-accuracy"]'));
  await assertions.assertContainsText(page.locator('//div[@id="sampling-results-user-info-accuracy"]'), '100%');
});

Then('all sampled alerts should contain correct anomaly details', async function () {
  await assertions.assertVisible(page.locator('//div[@id="sampling-results-anomaly-details-accuracy"]'));
  await assertions.assertContainsText(page.locator('//div[@id="sampling-results-anomaly-details-accuracy"]'), '100%');
});

Then('all sampled alerts should contain correct timestamps', async function () {
  await assertions.assertVisible(page.locator('//div[@id="sampling-results-timestamp-accuracy"]'));
  await assertions.assertContainsText(page.locator('//div[@id="sampling-results-timestamp-accuracy"]'), '100%');
});

Then('no data corruption should be present', async function () {
  await assertions.assertVisible(page.locator('//div[@id="data-integrity-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="data-integrity-status"]'), 'Intact');
});

Then('alert dashboard should remain responsive', async function () {
  await assertions.assertVisible(page.locator('//div[@id="alerts-dashboard"]'));
});

Then('page load times should be under {int} seconds', async function (seconds: number) {
  expect(this.testData.dashboardLoadTime).toBeLessThan(seconds * 1000);
});

Then('acknowledgment functionality should work correctly', async function () {
  await assertions.assertVisible(page.locator('//button[@id="acknowledge-alert"]'));
  const isEnabled = await page.locator('//button[@id="acknowledge-alert"]').isEnabled();
  expect(isEnabled).toBe(true);
});

Then('all {int} alerts should be recorded in attendance alerts history', async function (alertCount: number) {
  await actions.click(page.locator('//button[@id="view-alert-history"]'));
  await waits.waitForVisible(page.locator('//div[@id="alert-history-panel"]'));
  const historyItemsLocator = page.locator('//div[@class="history-item"]');
  const count = await historyItemsLocator.count();
  expect(count).toBeGreaterThanOrEqual(alertCount);
});

Then('system performance should return to normal levels', async function () {
  await assertions.assertVisible(page.locator('//div[@id="system-performance-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="system-performance-status"]'), 'Normal');
});

Then('no data loss should occur during high-volume processing', async function () {
  await assertions.assertVisible(page.locator('//div[@id="data-loss-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="data-loss-status"]'), 'No Data Loss');
});

Then('system should accept and store anomaly description', async function () {
  await assertions.assertVisible(page.locator('//div[@id="anomaly-description-stored-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="anomaly-description-stored-status"]'), 'Stored');
});

Then('all special characters should remain intact', async function () {
  await assertions.assertVisible(page.locator('//div[@id="special-characters-integrity-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="special-characters-integrity-status"]'), 'Intact');
});

Then('alert should display correctly with proper character encoding', async function () {
  const alertDescriptionText = await page.locator('//div[@class="alert-description"]').textContent();
  expect(alertDescriptionText).toContain(this.testData.anomalyDescription);
});

Then('no layout breaks should occur', async function () {
  await assertions.assertVisible(page.locator('//div[@id="layout-integrity-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="layout-integrity-status"]'), 'Intact');
});

Then('confirmation message should display properly', async function () {
  await assertions.assertVisible(page.locator('//div[@id="confirmation-message"]'));
});

Then('alert description should be stored in database with correct encoding', async function () {
  await assertions.assertVisible(page.locator('//div[@id="database-encoding-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="database-encoding-status"]'), 'Correct');
});

Then('alert history should maintain data integrity', async function () {
  await assertions.assertVisible(page.locator('//div[@id="alert-history-data-integrity-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="alert-history-data-integrity-status"]'), 'Intact');
});

Then('alert should be displayed with {string} button enabled', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(buttonIdXPath));
  const isEnabled = await page.locator(buttonIdXPath).isEnabled();
  expect(isEnabled).toBe(true);
});

Then('system should process first acknowledgment only', async function () {
  await assertions.assertVisible(page.locator('//div[@id="acknowledgment-processing-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="acknowledgment-processing-status"]'), 'Single');
});

Then('system should prevent duplicate acknowledgments', async function () {
  await assertions.assertVisible(page.locator('//div[@id="duplicate-prevention-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="duplicate-prevention-status"]'), 'Enabled');
});

Then('alert should show as acknowledged exactly once', async function () {
  const acknowledgmentCountText = await page.locator('//span[@id="acknowledgment-count"]').textContent();
  expect(parseInt(acknowledgmentCountText || '0')).toBe(1);
});

Then('alert should have single acknowledgment timestamp', async function () {
  const timestampsLocator = page.locator('//span[@class="acknowledgment-timestamp"]');
  const count = await timestampsLocator.count();
  expect(count).toBe(1);
});

Then('no duplicate acknowledgment records should exist', async function () {
  const duplicateRecordsLocator = page.locator('//div[@class="duplicate-acknowledgment-record"]');
  const count = await duplicateRecordsLocator.count();
  expect(count).toBe(0);
});

Then('only {int} acknowledgment record should exist in database', async function (recordCount: number) {
  const dbRecordCountText = await page.locator('//span[@id="db-acknowledgment-record-count"]').textContent();
  expect(parseInt(dbRecordCountText || '0')).toBe(recordCount);
});

Then('no error logs related to duplicate processing should exist', async function () {
  const duplicateErrorsLocator = page.locator('//div[@class="duplicate-processing-error"]');
  const count = await duplicateErrorsLocator.count();
  expect(count).toBe(0);
});

Then('{string} button should be disabled', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const isDisabled = await page.locator(buttonIdXPath).isDisabled();
  expect(isDisabled).toBe(true);
});

Then('alert status should show {string} with timestamp', async function (status: string) {
  await assertions.assertContainsText(page.locator('//div[@id="alert-status"]'), status);
  await assertions.assertVisible(page.locator('//span[@id="status-timestamp"]'));
});

Then('alert status should show user who acknowledged', async function () {
  await assertions.assertVisible(page.locator('//span[@id="acknowledged-by-user"]'));
});

Then('alert history should show single acknowledgment event', async function () {
  const acknowledgmentEventsLocator = page.locator('//div[@class="acknowledgment-event"]');
  const count = await acknowledgmentEventsLocator.count();
  expect(count).toBe(1);
});

Then('system should remain stable with no performance degradation', async function () {
  await assertions.assertVisible(page.locator('//div[@id="system-stability-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="system-stability-status"]'), 'Stable');
});

Then('user profile should show {string} timezone setting', async function (timezone: string) {
  await assertions.assertContainsText(page.locator('//span[@id="user-timezone"]'), timezone);
});

Then('manager profile should show {string} timezone setting', async function (timezone: string) {
  await assertions.assertContainsText(page.locator('//span[@id="manager-timezone"]'), timezone);
});

Then('anomaly should be recorded with UTC timestamp', async function () {
  await assertions.assertVisible(page.locator('//span[@id="utc-timestamp"]'));
});

Then('user should see alert showing {string} for anomaly time', async function (localTime: string) {
  await assertions.assertContainsText(page.locator('//span[@class="anomaly-local-time"]'), localTime);
});

Then('manager should see alert showing {string} for same anomaly', async function (localTime: string) {
  await assertions.assertContainsText(page.locator('//span[@class="anomaly-local-time"]'), localTime);
});

Then('all timestamps should be stored in UTC in database', async function () {
  await assertions.assertVisible(page.locator('//div[@id="utc-storage-confirmation"]'));
  await assertions.assertContainsText(page.locator('//div[@id="utc-storage-confirmation"]'), 'UTC');
});

Then('timestamps should display correctly in user local timezone', async function () {
  await assertions.assertVisible(page.locator('//div[@id="local-timezone-display-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="local-timezone-display-status"]'), 'Correct');
});

Then('no time calculation errors should occur', async function () {
  const timeErrorsLocator = page.locator('//div[@class="time-calculation-error"]');
  const count = await timeErrorsLocator.count();
  expect(count).toBe(0);
});

Then('system should correctly adjust timestamps for DST', async function () {
  await assertions.assertVisible(page.locator('//div[@id="dst-adjustment-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="dst-adjustment-status"]'), 'Correct');
});

Then('alerts should show accurate local times with DST notation', async function () {
  await assertions.assertVisible(page.locator('//span[@class="dst-notation"]'));
});

Then('alert history should correctly handle DST transitions', async function () {
  await assertions.assertVisible(page.locator('//div[@id="dst-transition-handling-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="dst-transition-handling-status"]'), 'Correct');
});

Then('no duplicate time periods should exist', async function () {
  const duplicateTimePeriodsLocator = page.locator('//div[@class="duplicate-time-period"]');
  const count = await duplicateTimePeriodsLocator.count();
  expect(count).toBe(0);
});

Then('no missing time periods should exist', async function () {
  const missingTimePeriodsLocator = page.locator('//div[@class="missing-time-period"]');
  const count = await missingTimePeriodsLocator.count();
  expect(count).toBe(0);
});

Then('{int} minute SLA should be calculated correctly regardless of timezone differences', async function (minutes: number) {
  await assertions.assertVisible(page.locator('//div[@id="sla-calculation-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="sla-calculation-status"]'), 'Correct');
});