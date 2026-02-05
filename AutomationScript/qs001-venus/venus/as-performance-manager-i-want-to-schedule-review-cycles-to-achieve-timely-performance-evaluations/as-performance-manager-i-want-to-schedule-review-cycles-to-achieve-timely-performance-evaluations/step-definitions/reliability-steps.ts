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
      performanceManager: { username: 'perfmanager', password: 'perfpass123' }
    },
    metrics: {},
    chaosState: {},
    timestamps: {}
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
/*  BACKGROUND STEPS - Common Setup
/*  Used across all reliability test scenarios
/**************************************************/

Given('Performance Manager is authenticated with scheduling permissions', async function () {
  const credentials = this.testData?.users?.performanceManager || { username: 'perfmanager', password: 'perfpass123' };
  
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="dashboard"]'));
});

Given('review cycle management page is accessible', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[contains(text(),"Review Cycle Management")]'));
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="review-cycle-management"]'));
});

/**************************************************/
/*  TEST CASE: TC-REL-001
/*  Title: Database connection failure during review cycle scheduling with automatic recovery
/*  Priority: Critical
/*  Category: Reliability - Chaos Engineering - Database Resilience
/*  Description: Validates circuit breaker pattern and automatic recovery when database fails
/**************************************************/

Given('database monitoring tools are configured', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/monitoring`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="database-monitoring-dashboard"]'));
  
  this.testData.monitoringConfigured = true;
});

Given('circuit breaker is enabled for database connections', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/circuit-breaker-config`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const circuitBreakerStatus = page.locator('//span[@id="circuit-breaker-status"]');
  await assertions.assertContainsText(circuitBreakerStatus, 'Enabled');
  
  this.testData.circuitBreakerEnabled = true;
});

Given('baseline MTTR target is {string} seconds', async function (mttrTarget: string) {
  this.testData.mttrTarget = parseInt(mttrTarget);
  this.testData.metrics.baselineMTTR = parseInt(mttrTarget);
});

Given('review cycle is already scheduled and active in the system', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/review-cycles`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="active-review-cycles"]'));
  
  const activeReviewCycle = page.locator('//div[@class="review-cycle-card"][1]');
  await assertions.assertVisible(activeReviewCycle);
  
  this.testData.reviewCycleScheduled = true;
});

Given('notification service is operational with message queue configured', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/notification-service-status`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const serviceStatus = page.locator('//span[@id="notification-service-status"]');
  await assertions.assertContainsText(serviceStatus, 'Operational');
  
  // TODO: Replace XPath with Object Repository when available
  const queueStatus = page.locator('//span[@id="message-queue-status"]');
  await assertions.assertContainsText(queueStatus, 'Configured');
  
  this.testData.notificationServiceOperational = true;
});

Given('retry policy is configured with exponential backoff initial {string} seconds max {string} seconds max attempts {string}', async function (initialDelay: string, maxDelay: string, maxAttempts: string) {
  this.testData.retryPolicy = {
    initialDelay: parseInt(initialDelay),
    maxDelay: parseInt(maxDelay),
    maxAttempts: parseInt(maxAttempts)
  };
  
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/retry-policy-config`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const initialDelayField = page.locator('//input[@id="initial-delay"]');
  await assertions.assertContainsText(initialDelayField, initialDelay);
});

Given('dead letter queue is configured for failed notifications', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/dead-letter-queue`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const dlqStatus = page.locator('//span[@id="dlq-status"]');
  await assertions.assertContainsText(dlqStatus, 'Configured');
  
  this.testData.deadLetterQueueConfigured = true;
});

Given('steady state hypothesis is {string} percent of scheduled reviews occur on time regardless of notification service status', async function (targetPercentage: string) {
  this.testData.steadyStateHypothesis = {
    targetPercentage: parseFloat(targetPercentage),
    metric: 'on-time-review-completion'
  };
});

Given('multi-instance API gateway deployment with minimum {string} instances behind load balancer', async function (instanceCount: string) {
  this.testData.apiGatewayInstances = parseInt(instanceCount);
  
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/api-gateway-status`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const instanceCountElement = page.locator('//span[@id="active-instances-count"]');
  await assertions.assertContainsText(instanceCountElement, instanceCount);
});

Given('load balancer health checks configured with {string} second interval', async function (interval: string) {
  this.testData.healthCheckInterval = parseInt(interval);
  
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/load-balancer-config`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const healthCheckInterval = page.locator('//input[@id="health-check-interval"]');
  await assertions.assertContainsText(healthCheckInterval, interval);
});

Given('session persistence sticky sessions are configured', async function () {
  // TODO: Replace XPath with Object Repository when available
  const stickySessionsEnabled = page.locator('//input[@id="sticky-sessions-enabled"]');
  const isChecked = await stickySessionsEnabled.isChecked();
  expect(isChecked).toBe(true);
  
  this.testData.stickySessionsEnabled = true;
});

Given('RTO target is {string} seconds for API gateway failover', async function (rtoTarget: string) {
  this.testData.rtoTarget = parseInt(rtoTarget);
});

Given('RPO target is zero data loss for in-flight transactions', async function () {
  this.testData.rpoTarget = 0;
});

Given('baseline availability SLO is {string} percent', async function (sloTarget: string) {
  this.testData.baselineAvailabilitySLO = parseFloat(sloTarget);
});

// ==================== WHEN STEPS ====================

When('user navigates to {string} page', async function (pageName: string) {
  // TODO: Replace XPath with Object Repository when available
  const pageXPath = `//a[contains(text(),'${pageName}')]`;
  await actions.click(page.locator(pageXPath));
  await waits.waitForNetworkIdle();
});

When('user configures quarterly review cycle with start date and frequency and notification settings', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="review-cycle-name"]'), 'Q1 2024 Performance Review');
  await actions.fill(page.locator('//input[@id="start-date"]'), '2024-01-01');
  await actions.selectByText(page.locator('//select[@id="frequency"]'), 'Quarterly');
  await actions.check(page.locator('//input[@id="enable-notifications"]'));
  
  this.testData.reviewCycleConfigured = true;
});

When('database connection failure is injected using chaos engineering tool to simulate network partition', async function () {
  this.testData.timestamps.failureInjectionStart = Date.now();
  
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/chaos-engineering/inject-failure`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await actions.selectByText(page.locator('//select[@id="failure-type"]'), 'Database Connection Failure');
  await actions.click(page.locator('//button[@id="inject-failure"]'));
  await waits.waitForNetworkIdle();
  
  this.testData.chaosState.databaseFailureInjected = true;
});

When('user clicks {string} button to submit POST request to {string}', async function (buttonText: string, apiEndpoint: string) {
  this.testData.apiEndpoint = apiEndpoint;
  
  // TODO: Replace XPath with Object Repository when available
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    // Fallback to text-based XPath
    await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
  
  await waits.waitForNetworkIdle();
});

When('database logs and monitoring dashboards are checked for uncommitted transactions', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/database-logs`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="transaction-log-viewer"]'));
  
  this.testData.databaseLogsChecked = true;
});

When('database connection is restored', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/chaos-engineering/restore-service`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await actions.selectByText(page.locator('//select[@id="service-to-restore"]'), 'Database Connection');
  await actions.click(page.locator('//button[@id="restore-service"]'));
  await waits.waitForNetworkIdle();
  
  this.testData.timestamps.databaseRestored = Date.now();
  this.testData.chaosState.databaseFailureInjected = false;
});

When('user clicks retry button to resubmit review cycle schedule', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="retry"]'));
  await waits.waitForNetworkIdle();
});

When('MTTR is measured from failure injection to successful operation', async function () {
  const failureStart = this.testData.timestamps.failureInjectionStart;
  const recoveryComplete = Date.now();
  const mttrSeconds = (recoveryComplete - failureStart) / 1000;
  
  this.testData.metrics.actualMTTR = mttrSeconds;
});

When('scheduled review cycle triggers and notifications are sent to {string} managers', async function (managerCount: string) {
  this.testData.managerCount = parseInt(managerCount);
  
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/trigger-scheduled-review`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="manager-count"]'), managerCount);
  await actions.click(page.locator('//button[@id="trigger-review-cycle"]'));
  await waits.waitForNetworkIdle();
  
  this.testData.timestamps.reviewCycleTriggered = Date.now();
});

When('blast radius is defined to limit chaos experiment to notification service only', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/chaos-engineering/define-blast-radius`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await actions.selectByText(page.locator('//select[@id="target-service"]'), 'Notification Service');
  await actions.check(page.locator('//input[@id="isolate-service"]'));
  
  this.testData.chaosState.blastRadiusDefined = true;
});

When('notification service failure is injected by shutting down notification API endpoint with {string} percent error rate for {string} minutes', async function (errorRate: string, duration: string) {
  this.testData.timestamps.notificationFailureStart = Date.now();
  
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/chaos-engineering/inject-failure`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await actions.selectByText(page.locator('//select[@id="failure-type"]'), 'Notification Service Failure');
  await actions.fill(page.locator('//input[@id="error-rate"]'), errorRate);
  await actions.fill(page.locator('//input[@id="duration-minutes"]'), duration);
  await actions.click(page.locator('//button[@id="inject-failure"]'));
  await waits.waitForNetworkIdle();
  
  this.testData.chaosState.notificationFailureInjected = true;
});

When('scheduled review cycle execution is triggered during notification service outage', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/trigger-scheduled-review`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="trigger-review-cycle"]'));
  await waits.waitForNetworkIdle();
  
  this.testData.timestamps.reviewCycleTriggeredDuringOutage = Date.now();
});

When('retry mechanism attempts are verified with exponential backoff pattern', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/retry-logs`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="retry-log-viewer"]'));
  
  this.testData.retryMechanismVerified = true;
});

When('notification service is restored to operational state', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/chaos-engineering/restore-service`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await actions.selectByText(page.locator('//select[@id="service-to-restore"]'), 'Notification Service');
  await actions.click(page.locator('//button[@id="restore-service"]'));
  await waits.waitForNetworkIdle();
  
  this.testData.timestamps.notificationServiceRestored = Date.now();
  this.testData.chaosState.notificationFailureInjected = false;
});

When('steady state hypothesis is validated for review cycle execution rate', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/review-cycle-metrics`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const onTimeCompletionRate = page.locator('//span[@id="on-time-completion-rate"]');
  const rateText = await onTimeCompletionRate.textContent();
  const actualRate = parseFloat(rateText?.replace('%', '') || '0');
  
  this.testData.metrics.actualOnTimeCompletionRate = actualRate;
});

When('peak load simulation is generated with {string} concurrent Performance Managers scheduling review cycles simultaneously via POST to {string}', async function (concurrentUsers: string, apiEndpoint: string) {
  this.testData.concurrentUsers = parseInt(concurrentUsers);
  this.testData.apiEndpoint = apiEndpoint;
  this.testData.timestamps.peakLoadStart = Date.now();
  
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/load-testing/simulate-peak-load`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="concurrent-users"]'), concurrentUsers);
  await actions.fill(page.locator('//input[@id="api-endpoint"]'), apiEndpoint);
  await actions.click(page.locator('//button[@id="start-load-test"]'));
  await waits.waitForNetworkIdle();
});

When('baseline metrics are monitored for request distribution and response times and error rates and active connections', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/load-balancer-metrics`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="metrics-dashboard"]'));
  
  this.testData.baselineMetricsRecorded = true;
});

When('primary API gateway instance handling {string} percent of traffic is abruptly terminated to simulate catastrophic failure', async function (trafficPercentage: string) {
  this.testData.timestamps.instanceFailureStart = Date.now();
  this.testData.trafficPercentage = parseFloat(trafficPercentage);
  
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/chaos-engineering/terminate-instance`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await actions.selectByText(page.locator('//select[@id="instance-to-terminate"]'), 'Primary API Gateway Instance');
  await actions.click(page.locator('//button[@id="terminate-instance"]'));
  await waits.waitForNetworkIdle();
  
  this.testData.chaosState.primaryInstanceTerminated = true;
});

When('load balancer health check detection and automatic failover behavior are observed', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/load-balancer-events`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="failover-events-log"]'));
  
  this.testData.failoverObserved = true;
});

When('in-flight requests that were being processed by failed instance are monitored', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/in-flight-requests`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="in-flight-requests-monitor"]'));
  
  this.testData.inFlightRequestsMonitored = true;
});

When('RTO is measured by recording time from instance failure to full traffic recovery', async function () {
  const failureStart = this.testData.timestamps.instanceFailureStart;
  const recoveryComplete = Date.now();
  const rtoSeconds = (recoveryComplete - failureStart) / 1000;
  
  this.testData.metrics.actualRTO = rtoSeconds;
});

When('data integrity is verified by checking all review cycle schedules submitted during failover', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/data-integrity-check`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="verify-data-integrity"]'));
  await waits.waitForNetworkIdle();
  
  this.testData.dataIntegrityVerified = true;
});

When('availability impact is calculated and SLO compliance is verified', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/availability-metrics`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const availabilityPercentage = page.locator('//span[@id="availability-percentage"]');
  const availabilityText = await availabilityPercentage.textContent();
  const actualAvailability = parseFloat(availabilityText?.replace('%', '') || '0');
  
  this.testData.metrics.actualAvailability = actualAvailability;
});

When('failed API gateway instance is restored', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/chaos-engineering/restore-instance`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await actions.selectByText(page.locator('//select[@id="instance-to-restore"]'), 'Primary API Gateway Instance');
  await actions.click(page.locator('//button[@id="restore-instance"]'));
  await waits.waitForNetworkIdle();
  
  this.testData.timestamps.instanceRestored = Date.now();
  this.testData.chaosState.primaryInstanceTerminated = false;
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  TEST CASE: TC-REL-001 - THEN STEPS
/*  Database Resilience Validation
/**************************************************/

Then('review cycle configuration form should load successfully within {string} seconds', async function (maxLoadTime: string) {
  const startTime = Date.now();
  
  // TODO: Replace XPath with Object Repository when available
  await waits.waitForVisible(page.locator('//form[@id="review-cycle-configuration-form"]'));
  
  const endTime = Date.now();
  const loadTimeSeconds = (endTime - startTime) / 1000;
  
  expect(loadTimeSeconds).toBeLessThanOrEqual(parseFloat(maxLoadTime));
});

Then('all form fields should be populated', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//input[@id="review-cycle-name"]'));
  await assertions.assertVisible(page.locator('//input[@id="start-date"]'));
  await assertions.assertVisible(page.locator('//select[@id="frequency"]'));
  await assertions.assertVisible(page.locator('//input[@id="enable-notifications"]'));
});

Then('database connection should be severed', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/database-connection-status`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const connectionStatus = page.locator('//span[@id="database-connection-status"]');
  await assertions.assertContainsText(connectionStatus, 'Disconnected');
});

Then('system should detect database unavailability within {string} seconds', async function (maxDetectionTime: string) {
  const detectionStartTime = Date.now();
  
  // TODO: Replace XPath with Object Repository when available
  await waits.waitForVisible(page.locator('//div[@id="database-unavailable-alert"]'));
  
  const detectionEndTime = Date.now();
  const detectionTimeSeconds = (detectionEndTime - detectionStartTime) / 1000;
  
  expect(detectionTimeSeconds).toBeLessThanOrEqual(parseFloat(maxDetectionTime));
});

Then('circuit breaker should open', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/circuit-breaker-status`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const circuitBreakerState = page.locator('//span[@id="circuit-breaker-state"]');
  await assertions.assertContainsText(circuitBreakerState, 'Open');
});

Then('error message {string} should be displayed', async function (expectedErrorMessage: string) {
  // TODO: Replace XPath with Object Repository when available
  const errorMessage = page.locator('//div[@id="error-message"]');
  await assertions.assertVisible(errorMessage);
  await assertions.assertContainsText(errorMessage, expectedErrorMessage);
});

Then('no partial data should be committed to database', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/database-transactions`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const partialTransactionCount = page.locator('//span[@id="partial-transaction-count"]');
  await assertions.assertContainsText(partialTransactionCount, '0');
});

Then('all transaction changes should be rolled back completely', async function () {
  // TODO: Replace XPath with Object Repository when available
  const rollbackStatus = page.locator('//span[@id="rollback-status"]');
  await assertions.assertContainsText(rollbackStatus, 'Complete');
});

Then('no orphaned records should exist', async function () {
  // TODO: Replace XPath with Object Repository when available
  const orphanedRecordCount = page.locator('//span[@id="orphaned-record-count"]');
  await assertions.assertContainsText(orphanedRecordCount, '0');
});

Then('database integrity should be maintained', async function () {
  // TODO: Replace XPath with Object Repository when available
  const integrityCheckStatus = page.locator('//span[@id="integrity-check-status"]');
  await assertions.assertContainsText(integrityCheckStatus, 'Passed');
});

Then('system should detect database availability', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/database-connection-status`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const connectionStatus = page.locator('//span[@id="database-connection-status"]');
  await assertions.assertContainsText(connectionStatus, 'Connected');
});

Then('circuit breaker should transition to half-open state', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/circuit-breaker-status`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const circuitBreakerState = page.locator('//span[@id="circuit-breaker-state"]');
  await assertions.assertContainsText(circuitBreakerState, 'Half-Open');
});

Then('request should succeed', async function () {
  // TODO: Replace XPath with Object Repository when available
  const requestStatus = page.locator('//span[@id="request-status"]');
  await assertions.assertContainsText(requestStatus, 'Success');
});

Then('review cycle should be saved successfully', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="review-cycle-saved-confirmation"]'));
});

Then('confirmation message should be displayed', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="confirmation-message"]'));
});

Then('MTTR should be less than {string} seconds', async function (maxMTTR: string) {
  const actualMTTR = this.testData.metrics.actualMTTR;
  expect(actualMTTR).toBeLessThan(parseFloat(maxMTTR));
});

Then('system availability should remain above {string} percent during incident', async function (minAvailability: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/availability-metrics`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const availabilityPercentage = page.locator('//span[@id="availability-during-incident"]');
  const availabilityText = await availabilityPercentage.textContent();
  const actualAvailability = parseFloat(availabilityText?.replace('%', '') || '0');
  
  expect(actualAvailability).toBeGreaterThan(parseFloat(minAvailability));
});

Then('database connection should be restored to normal state', async function () {
  // TODO: Replace XPath with Object Repository when available
  const connectionStatus = page.locator('//span[@id="database-connection-status"]');
  await assertions.assertContainsText(connectionStatus, 'Connected');
});

Then('circuit breaker should return to closed state', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/circuit-breaker-status`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const circuitBreakerState = page.locator('//span[@id="circuit-breaker-state"]');
  await assertions.assertContainsText(circuitBreakerState, 'Closed');
});

Then('review cycle data should be consistent and complete', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/data-consistency-check`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const consistencyStatus = page.locator('//span[@id="data-consistency-status"]');
  await assertions.assertContainsText(consistencyStatus, 'Consistent');
});

Then('no data corruption or partial records should exist', async function () {
  // TODO: Replace XPath with Object Repository when available
  const corruptionCheckStatus = page.locator('//span[@id="corruption-check-status"]');
  await assertions.assertContainsText(corruptionCheckStatus, 'No Corruption Detected');
});

Then('system logs should capture failure and recovery events', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/system-logs`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[contains(text(),"Database Connection Failure")]'));
  await assertions.assertVisible(page.locator('//div[contains(text(),"Database Connection Restored")]'));
});

Then('monitoring alerts should be triggered and resolved', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/monitoring-alerts`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@class="alert-triggered"]'));
  await assertions.assertVisible(page.locator('//div[@class="alert-resolved"]'));
});

/**************************************************/
/*  TEST CASE: TC-REL-002 - THEN STEPS
/*  Notification Service Resilience Validation
/**************************************************/

Then('review cycle should execute on schedule', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/review-cycle-execution-log`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const executionStatus = page.locator('//span[@id="execution-status"]');
  await assertions.assertContainsText(executionStatus, 'Executed On Schedule');
});

Then('all {string} notification requests should be processed successfully within {string} seconds', async function (notificationCount: string, maxProcessingTime: string) {
  const startTime = Date.now();
  
  // TODO: Replace XPath with Object Repository when available
  await waits.waitForVisible(page.locator('//div[@id="notifications-processed-confirmation"]'));
  
  const endTime = Date.now();
  const processingTimeSeconds = (endTime - startTime) / 1000;
  
  expect(processingTimeSeconds).toBeLessThanOrEqual(parseFloat(maxProcessingTime));
  
  // TODO: Replace XPath with Object Repository when available
  const processedCount = page.locator('//span[@id="notifications-processed-count"]');
  await assertions.assertContainsText(processedCount, notificationCount);
});

Then('baseline metrics should be recorded', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/baseline-metrics`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="baseline-metrics-recorded"]'));
});

Then('chaos experiment scope should be isolated to notification microservice', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/chaos-engineering/experiment-scope`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const targetService = page.locator('//span[@id="target-service"]');
  await assertions.assertContainsText(targetService, 'Notification Microservice');
});

Then('primary scheduling service should remain unaffected', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/scheduling-service-status`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const serviceStatus = page.locator('//span[@id="scheduling-service-status"]');
  await assertions.assertContainsText(serviceStatus, 'Operational');
});

Then('notification service should return {string} Service Unavailable errors', async function (httpStatusCode: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/notification-service-errors`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const errorCode = page.locator('//span[@id="error-code"]');
  await assertions.assertContainsText(errorCode, httpStatusCode);
});

Then('notification requests should fail gracefully', async function () {
  // TODO: Replace XPath with Object Repository when available
  const failureMode = page.locator('//span[@id="failure-mode"]');
  await assertions.assertContainsText(failureMode, 'Graceful');
});

Then('messages should be queued in retry queue with exponential backoff', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/retry-queue`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const queuedMessageCount = page.locator('//span[@id="queued-message-count"]');
  const count = await queuedMessageCount.textContent();
  expect(parseInt(count || '0')).toBeGreaterThan(0);
});

Then('no exceptions should bubble up to user interface', async function () {
  // TODO: Replace XPath with Object Repository when available
  const exceptionCount = page.locator('//span[@id="ui-exception-count"]');
  await assertions.assertContainsText(exceptionCount, '0');
});

Then('review cycle status should show {string}', async function (expectedStatus: string) {
  // TODO: Replace XPath with Object Repository when available
  const reviewCycleStatus = page.locator('//span[@id="review-cycle-status"]');
  await assertions.assertContainsText(reviewCycleStatus, expectedStatus);
});

Then('notification status should show {string}', async function (expectedStatus: string) {
  // TODO: Replace XPath with Object Repository when available
  const notificationStatus = page.locator('//span[@id="notification-status"]');
  await assertions.assertContainsText(notificationStatus, expectedStatus);
});

Then('system should attempt retries at {string} seconds {string} seconds {string} seconds {string} seconds {string} seconds intervals', async function (interval1: string, interval2: string, interval3: string, interval4: string, interval5: string) {
  const expectedIntervals = [interval1, interval2, interval3, interval4, interval5];
  
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/retry-intervals`);
  await waits.waitForNetworkIdle();
  
  for (let i = 0; i < expectedIntervals.length; i++) {
    // TODO: Replace XPath with Object Repository when available
    const intervalElement = page.locator(`//span[@id="retry-interval-${i + 1}"]`);
    await assertions.assertContainsText(intervalElement, expectedIntervals[i]);
  }
});

Then('failed notifications after {string} attempts should move to dead letter queue', async function (maxAttempts: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/dead-letter-queue`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const dlqMessageCount = page.locator('//span[@id="dlq-message-count"]');
  const count = await dlqMessageCount.textContent();
  expect(parseInt(count || '0')).toBeGreaterThan(0);
});

Then('retry metrics should be logged correctly', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/retry-metrics`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="retry-metrics-dashboard"]'));
});

Then('queued notifications should be processed successfully within {string} minutes of service restoration', async function (maxProcessingTime: string) {
  const restorationTime = this.testData.timestamps.notificationServiceRestored;
  const startTime = Date.now();
  
  // TODO: Replace XPath with Object Repository when available
  await waits.waitForVisible(page.locator('//div[@id="queued-notifications-processed"]'));
  
  const endTime = Date.now();
  const processingTimeMinutes = (endTime - restorationTime) / 60000;
  
  expect(processingTimeMinutes).toBeLessThanOrEqual(parseFloat(maxProcessingTime));
});

Then('eventual consistency should be achieved', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/consistency-status`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const consistencyStatus = page.locator('//span[@id="consistency-status"]');
  await assertions.assertContainsText(consistencyStatus, 'Achieved');
});

Then('{string} percent SLO for on-time reviews should be maintained', async function (targetSLO: string) {
  const actualRate = this.testData.metrics.actualOnTimeCompletionRate;
  expect(actualRate).toBeGreaterThanOrEqual(parseFloat(targetSLO));
});

Then('{string} percent or more of scheduled reviews should have occurred on time', async function (targetPercentage: string) {
  const actualRate = this.testData.metrics.actualOnTimeCompletionRate;
  expect(actualRate).toBeGreaterThanOrEqual(parseFloat(targetPercentage));
});

Then('system should demonstrate graceful degradation', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/degradation-status`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const degradationMode = page.locator('//span[@id="degradation-mode"]');
  await assertions.assertContainsText(degradationMode, 'Graceful');
});

Then('MTBF for notification service should be recorded', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/mtbf-metrics`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//span[@id="mtbf-value"]'));
});

Then('notification service should be restored to normal operation', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/notification-service-status`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const serviceStatus = page.locator('//span[@id="notification-service-status"]');
  await assertions.assertContainsText(serviceStatus, 'Operational');
});

Then('all queued notifications should be successfully delivered', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/notification-delivery-status`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const deliveryStatus = page.locator('//span[@id="delivery-status"]');
  await assertions.assertContainsText(deliveryStatus, 'All Delivered');
});

Then('dead letter queue should be reviewed and processed', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/dead-letter-queue`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const dlqProcessedStatus = page.locator('//span[@id="dlq-processed-status"]');
  await assertions.assertContainsText(dlqProcessedStatus, 'Processed');
});

Then('retry metrics should be captured in monitoring system', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/monitoring-system`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="retry-metrics-captured"]'));
});

Then('chaos experiment results should be documented', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/chaos-engineering/experiment-results`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="experiment-documentation"]'));
});

Then('system should return to steady state with {string} percent or more on-time review completion', async function (targetPercentage: string) {
  const actualRate = this.testData.metrics.actualOnTimeCompletionRate;
  expect(actualRate).toBeGreaterThanOrEqual(parseFloat(targetPercentage));
});

/**************************************************/
/*  TEST CASE: TC-REL-003 - THEN STEPS
/*  API Gateway High Availability Validation
/**************************************************/

Then('all {string} API gateway instances should be handling requests', async function (instanceCount: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/api-gateway-instances`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const activeInstanceCount = page.locator('//span[@id="active-instance-count"]');
  await assertions.assertContainsText(activeInstanceCount, instanceCount);
});

Then('load should be distributed evenly at {string} percent each', async function (expectedPercentage: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/load-distribution`);
  await waits.waitForNetworkIdle();
  
  const instanceCount = this.testData.apiGatewayInstances;
  for (let i = 1; i <= instanceCount; i++) {
    // TODO: Replace XPath with Object Repository when available
    const instanceLoad = page.locator(`//span[@id="instance-${i}-load-percentage"]`);
    const loadText = await instanceLoad.textContent();
    const actualLoad = parseFloat(loadText?.replace('%', '') || '0');
    expect(actualLoad).toBeCloseTo(parseFloat(expectedPercentage), 1);
  }
});

Then('response times should be under {string} seconds', async function (maxResponseTime: string) {
  // TODO: Replace XPath with Object Repository when available
  const avgResponseTime = page.locator('//span[@id="average-response-time"]');
  const responseTimeText = await avgResponseTime.textContent();
  const actualResponseTime = parseFloat(responseTimeText?.replace('s', '') || '0');
  
  expect(actualResponseTime).toBeLessThan(parseFloat(maxResponseTime));
});

Then('success rate should be {string} percent', async function (expectedSuccessRate: string) {
  // TODO: Replace XPath with Object Repository when available
  const successRate = page.locator('//span[@id="success-rate"]');
  const successRateText = await successRate.textContent();
  const actualSuccessRate = parseFloat(successRateText?.replace('%', '') || '0');
  
  expect(actualSuccessRate).toBe(parseFloat(expectedSuccessRate));
});

Then('baseline metrics should be recorded with average response time {string} seconds', async function (expectedResponseTime: string) {
  this.testData.metrics.baselineResponseTime = parseFloat(expectedResponseTime);
  
  // TODO: Replace XPath with Object Repository when available
  const avgResponseTime = page.locator('//span[@id="baseline-average-response-time"]');
  await assertions.assertContainsText(avgResponseTime, expectedResponseTime);
});

Then('error rate should be {string} percent', async function (expectedErrorRate: string) {
  // TODO: Replace XPath with Object Repository when available
  const errorRate = page.locator('//span[@id="error-rate"]');
  const errorRateText = await errorRate.textContent();
  const actualErrorRate = parseFloat(errorRateText?.replace('%', '') || '0');
  
  expect(actualErrorRate).toBe(parseFloat(expectedErrorRate));
});

Then('{string} active sessions should be distributed across instances', async function (sessionCount: string) {
  // TODO: Replace XPath with Object Repository when available
  const totalActiveSessions = page.locator('//span[@id="total-active-sessions"]');
  await assertions.assertContainsText(totalActiveSessions, sessionCount);
});

Then('primary instance should stop responding immediately', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/instance-status`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const primaryInstanceStatus = page.locator('//span[@id="primary-instance-status"]');
  await assertions.assertContainsText(primaryInstanceStatus, 'Not Responding');
});

Then('load balancer should detect failed instance within {string} to {string} seconds', async function (minDetectionTime: string, maxDetectionTime: string) {
  const detectionStartTime = this.testData.timestamps.instanceFailureStart;
  
  // TODO: Replace XPath with Object Repository when available
  await waits.waitForVisible(page.locator('//div[@id="instance-failure-detected"]'));
  
  const detectionEndTime = Date.now();
  const detectionTimeSeconds = (detectionEndTime - detectionStartTime) / 1000;
  
  expect(detectionTimeSeconds).toBeGreaterThanOrEqual(parseFloat(minDetectionTime));
  expect(detectionTimeSeconds).toBeLessThanOrEqual(parseFloat(maxDetectionTime));
});

Then('failed instance should be automatically removed from rotation', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/load-balancer-rotation`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const rotationStatus = page.locator('//span[@id="failed-instance-rotation-status"]');
  await assertions.assertContainsText(rotationStatus, 'Removed');
});

Then('traffic should be redistributed to remaining {string} healthy instances', async function (healthyInstanceCount: string) {
  // TODO: Replace XPath with Object Repository when available
  const activeInstanceCount = page.locator('//span[@id="active-instance-count"]');
  await assertions.assertContainsText(activeInstanceCount, healthyInstanceCount);
});

Then('in-flight requests should be completed successfully via connection draining or automatically retried', async function () {
  // TODO: Replace XPath with Object Repository when available
  const inFlightRequestStatus = page.locator('//span[@id="in-flight-request-status"]');
  await assertions.assertContainsText(inFlightRequestStatus, 'Completed');
});

Then('zero requests should result in data loss', async function () {
  // TODO: Replace XPath with Object Repository when available
  const dataLossCount = page.locator('//span[@id="data-loss-count"]');
  await assertions.assertContainsText(dataLossCount, '0');
});

Then('users may experience brief delay of {string} to {string} seconds but no failed transactions', async function (minDelay: string, maxDelay: string) {
  // TODO: Replace XPath with Object Repository when available
  const failedTransactionCount = page.locator('//span[@id="failed-transaction-count"]');
  await assertions.assertContainsText(failedTransactionCount, '0');
});

Then('RTO should be {string} seconds or less from failure detection to complete traffic redistribution', async function (maxRTO: string) {
  const actualRTO = this.testData.metrics.actualRTO;
  expect(actualRTO).toBeLessThanOrEqual(parseFloat(maxRTO));
});

Then('{string} percent of review cycle schedules should be saved correctly', async function (expectedPercentage: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/data-integrity-report`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const successRate = page.locator('//span[@id="save-success-rate"]');
  const successRateText = await successRate.textContent();
  const actualSuccessRate = parseFloat(successRateText?.replace('%', '') || '0');
  
  expect(actualSuccessRate).toBe(parseFloat(expectedPercentage));
});

Then('no duplicate entries should exist', async function () {
  // TODO: Replace XPath with Object Repository when available
  const duplicateCount = page.locator('//span[@id="duplicate-entry-count"]');
  await assertions.assertContainsText(duplicateCount, '0');
});

Then('no partial records should exist', async function () {
  // TODO: Replace XPath with Object Repository when available
  const partialRecordCount = page.locator('//span[@id="partial-record-count"]');
  await assertions.assertContainsText(partialRecordCount, '0');
});

Then('RPO of zero data loss should be achieved', async function () {
  const actualRPO = this.testData.rpoTarget;
  expect(actualRPO).toBe(0);
  
  // TODO: Replace XPath with Object Repository when available
  const dataLossCount = page.locator('//span[@id="data-loss-count"]');
  await assertions.assertContainsText(dataLossCount, '0');
});

Then('availability should remain at or above {string} percent for the test period', async function (minAvailability: string) {
  const actualAvailability = this.testData.metrics.actualAvailability;
  expect(actualAvailability).toBeGreaterThanOrEqual(parseFloat(minAvailability));
});

Then('maximum user-perceived downtime should be {string} seconds', async function (maxDowntime: string) {
  // TODO: Replace XPath with Object Repository when available
  const perceivedDowntime = page.locator('//span[@id="user-perceived-downtime"]');
  const downtimeText = await perceivedDowntime.textContent();
  const actualDowntime = parseFloat(downtimeText?.replace('s', '') || '0');
  
  expect(actualDowntime).toBeLessThanOrEqual(parseFloat(maxDowntime));
});

Then('SLO should be maintained', async function () {
  const actualAvailability = this.testData.metrics.actualAvailability;
  const targetSLO = this.testData.baselineAvailabilitySLO;
  
  expect(actualAvailability).toBeGreaterThanOrEqual(targetSLO);
});

Then('restored instance should pass health checks', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/health-check-status`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const healthCheckStatus = page.locator('//span[@id="restored-instance-health-status"]');
  await assertions.assertContainsText(healthCheckStatus, 'Passed');
});

Then('instance should be automatically added back to rotation', async function () {
  // TODO: Replace XPath with Object Repository when available
  const rotationStatus = page.locator('//span[@id="restored-instance-rotation-status"]');
  await assertions.assertContainsText(rotationStatus, 'Added');
});

Then('load should redistribute evenly across all {string} instances', async function (instanceCount: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/load-distribution`);
  await waits.waitForNetworkIdle();
  
  const totalInstances = parseInt(instanceCount);
  const expectedLoadPercentage = 100 / totalInstances;
  
  for (let i = 1; i <= totalInstances; i++) {
    // TODO: Replace XPath with Object Repository when available
    const instanceLoad = page.locator(`//span[@id="instance-${i}-load-percentage"]`);
    const loadText = await instanceLoad.textContent();
    const actualLoad = parseFloat(loadText?.replace('%', '') || '0');
    expect(actualLoad).toBeCloseTo(expectedLoadPercentage, 1);
  }
});

Then('all API gateway instances should be operational and healthy', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/api-gateway-instances`);
  await waits.waitForNetworkIdle();
  
  const instanceCount = this.testData.apiGatewayInstances;
  for (let i = 1; i <= instanceCount; i++) {
    // TODO: Replace XPath with Object Repository when available
    const instanceStatus = page.locator(`//span[@id="instance-${i}-status"]`);
    await assertions.assertContainsText(instanceStatus, 'Healthy');
  }
});

Then('load balancer routing should be restored to normal distribution', async function () {
  // TODO: Replace XPath with Object Repository when available
  const routingStatus = page.locator('//span[@id="load-balancer-routing-status"]');
  await assertions.assertContainsText(routingStatus, 'Normal');
});

Then('no data loss or corruption should have occurred during failover', async function () {
  // TODO: Replace XPath with Object Repository when available
  const dataLossCount = page.locator('//span[@id="data-loss-count"]');
  await assertions.assertContainsText(dataLossCount, '0');
  
  // TODO: Replace XPath with Object Repository when available
  const corruptionCount = page.locator('//span[@id="data-corruption-count"]');
  await assertions.assertContainsText(corruptionCount, '0');
});

Then('all review cycle schedules should be verified in database', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/database-verification`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  const verificationStatus = page.locator('//span[@id="verification-status"]');
  await assertions.assertContainsText(verificationStatus, 'Verified');
});

Then('failover metrics should be captured and logged', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/failover-metrics`);
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="failover-metrics-dashboard"]'));
});

Then('availability SLO of {string} percent should be maintained', async function (targetSLO: string) {
  const actualAvailability = this.testData.metrics.actualAvailability;
  expect(actualAvail