import { Given, When, Then, Before, After, setDefaultTimeout } from '@cucumber/cucumber';
import { Page, Browser, BrowserContext, chromium, expect } from '@playwright/test';
import { BasePage } from '../pages/BasePage';
import { GenericActions } from '../utils/GenericActions';
import { AssertionHelpers } from '../utils/AssertionHelpers';
import { WaitHelpers } from '../utils/WaitHelpers';

// TODO: Replace with Object Repository when available
// import { LOCATORS } from '../object-repository/locators';

setDefaultTimeout(120000);

let browser: Browser;
let context: BrowserContext;
let page: Page;
let basePage: BasePage;
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
  
  this.testData = {
    alerts: [],
    metrics: {},
    systemState: {},
    queuedAlerts: [],
    deliveredAlerts: [],
    failedAlerts: []
  };
});

After(async function (scenario) {
  if (scenario.result?.status === 'FAILED') {
    const screenshot = await page.screenshot();
    this.attach(screenshot, 'image/png');
  }
  await page?.close();
  await context?.close();
  await browser?.close();
});

// ==================== GIVEN STEPS ====================

/**************************************************/
/*  TEST CASE: TC-REL-001
/*  Title: Alert service maintains resilience during database connection failure
/*  Priority: Critical
/*  Category: Reliability
/**************************************************/

Given('attendance anomaly detection service is running', async function () {
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000/admin/alerts');
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="alert-service-status"]'));
  const statusText = await page.locator('//span[@id="service-status"]').textContent();
  expect(statusText).toContain('Running');
});

Given('database connection is healthy', async function () {
  await assertions.assertVisible(page.locator('//div[@id="database-health"]'));
  const dbStatus = await page.locator('//span[@id="db-connection-status"]').textContent();
  expect(dbStatus).toContain('Healthy');
  this.testData.systemState.databaseHealthy = true;
});

Given('message queue buffer system is configured', async function () {
  await assertions.assertVisible(page.locator('//div[@id="message-queue-config"]'));
  const queueStatus = await page.locator('//span[@id="queue-status"]').textContent();
  expect(queueStatus).toContain('Configured');
  this.testData.systemState.queueConfigured = true;
});

Given('monitoring tools are active to track MTTR', async function () {
  await actions.click(page.locator('//button[@id="monitoring-dashboard"]'));
  await waits.waitForVisible(page.locator('//div[@id="mttr-tracker"]'));
  await assertions.assertVisible(page.locator('//div[@id="mttr-tracker"]'));
  this.testData.metrics.mttrStartTime = Date.now();
});

Given('baseline is established by generating {int} test attendance anomalies', async function (count: number) {
  await actions.click(page.locator('//button[@id="generate-test-anomalies"]'));
  await actions.fill(page.locator('//input[@id="anomaly-count"]'), count.toString());
  await actions.click(page.locator('//button[@id="submit-generate"]'));
  await waits.waitForNetworkIdle();
  this.testData.baselineAnomalyCount = count;
});

Given('all {int} alerts are delivered successfully within {int} minutes', async function (alertCount: number, minutes: number) {
  const timeout = minutes * 60 * 1000;
  const startTime = Date.now();
  
  await waits.waitForVisible(page.locator('//div[@id="alert-delivery-status"]'));
  
  while (Date.now() - startTime < timeout) {
    const deliveredCount = await page.locator('//span[@id="delivered-count"]').textContent();
    if (parseInt(deliveredCount || '0') >= alertCount) {
      break;
    }
    await page.waitForTimeout(5000);
  }
  
  const finalCount = await page.locator('//span[@id="delivered-count"]').textContent();
  expect(parseInt(finalCount || '0')).toBeGreaterThanOrEqual(alertCount);
  this.testData.metrics.baselineDeliveryRate = 100;
});

/**************************************************/
/*  TEST CASE: TC-REL-002
/*  Title: Alert dispatch maintains resilience under network partition and latency injection
/*  Priority: Critical
/*  Category: Reliability
/**************************************************/

Given('alert notification service is operational', async function () {
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000/admin/notifications');
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="notification-service-status"]'));
  const status = await page.locator('//span[@id="notification-status"]').textContent();
  expect(status).toContain('Operational');
});

Given('multiple notification channels are configured with {string} and {string} and {string}', async function (channel1: string, channel2: string, channel3: string) {
  await actions.click(page.locator('//button[@id="notification-channels"]'));
  await waits.waitForVisible(page.locator('//div[@id="channels-list"]'));
  
  await assertions.assertVisible(page.locator(`//div[@id="channel-${channel1.toLowerCase()}"]`));
  await assertions.assertVisible(page.locator(`//div[@id="channel-${channel2.toLowerCase()}"]`));
  await assertions.assertVisible(page.locator(`//div[@id="channel-${channel3.toLowerCase()}"]`));
  
  this.testData.notificationChannels = [channel1, channel2, channel3];
});

Given('network chaos tools are configured', async function () {
  await actions.click(page.locator('//button[@id="chaos-engineering"]'));
  await waits.waitForVisible(page.locator('//div[@id="chaos-tools"]'));
  await assertions.assertVisible(page.locator('//div[@id="network-chaos-config"]'));
  this.testData.systemState.chaosToolsReady = true;
});

Given('baseline alert delivery rate is established at {int} percent', async function (rate: number) {
  await waits.waitForVisible(page.locator('//div[@id="delivery-metrics"]'));
  const baselineRate = await page.locator('//span[@id="baseline-delivery-rate"]').textContent();
  expect(parseInt(baselineRate || '0')).toBe(rate);
  this.testData.metrics.baselineDeliveryRate = rate;
});

Given('hypothesis is defined as {string}', async function (hypothesis: string) {
  await actions.fill(page.locator('//textarea[@id="chaos-hypothesis"]'), hypothesis);
  this.testData.chaosHypothesis = hypothesis;
});

Given('blast radius is limited to notification service only', async function () {
  await actions.click(page.locator('//input[@id="limit-blast-radius"]'));
  await actions.selectByText(page.locator('//select[@id="blast-radius-scope"]'), 'Notification Service');
  this.testData.systemState.blastRadiusLimited = true;
});

/**************************************************/
/*  TEST CASE: TC-REL-003
/*  Title: External notification API failure triggers circuit breaker and automatic failover
/*  Priority: High
/*  Category: Reliability
/**************************************************/

Given('multiple notification providers are configured with primary and fallback', async function () {
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000/admin/notification-providers');
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="primary-provider"]'));
  await assertions.assertVisible(page.locator('//div[@id="fallback-provider"]'));
  this.testData.systemState.multipleProvidersConfigured = true;
});

Given('circuit breaker is configured with {int} percent error rate threshold', async function (threshold: number) {
  await actions.click(page.locator('//button[@id="circuit-breaker-config"]'));
  await waits.waitForVisible(page.locator('//input[@id="error-rate-threshold"]'));
  await actions.fill(page.locator('//input[@id="error-rate-threshold"]'), threshold.toString());
  this.testData.circuitBreaker = { errorRateThreshold: threshold };
});

Given('circuit breaker is configured with {int} request minimum threshold', async function (minRequests: number) {
  await actions.fill(page.locator('//input[@id="min-request-threshold"]'), minRequests.toString());
  this.testData.circuitBreaker.minRequestThreshold = minRequests;
});

Given('fallback notification mechanism is available', async function () {
  await assertions.assertVisible(page.locator('//div[@id="fallback-mechanism"]'));
  const fallbackStatus = await page.locator('//span[@id="fallback-status"]').textContent();
  expect(fallbackStatus).toContain('Available');
});

Given('API mock service is ready to simulate failures', async function () {
  await actions.click(page.locator('//button[@id="api-mock-service"]'));
  await waits.waitForVisible(page.locator('//div[@id="mock-service-controls"]'));
  await assertions.assertVisible(page.locator('//div[@id="mock-service-controls"]'));
  this.testData.systemState.mockServiceReady = true;
});

/**************************************************/
/*  TEST CASE: TC-REL-004
/*  Title: Alert data integrity is maintained during service crash and recovery
/*  Priority: Critical
/*  Category: Reliability
/**************************************************/

Given('alert service is running with transaction logging enabled', async function () {
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000/admin/alert-service');
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="transaction-logging"]'));
  const loggingStatus = await page.locator('//span[@id="transaction-log-status"]').textContent();
  expect(loggingStatus).toContain('Enabled');
});

Given('database with ACID compliance is configured', async function () {
  await assertions.assertVisible(page.locator('//div[@id="acid-compliance"]'));
  const acidStatus = await page.locator('//span[@id="acid-status"]').textContent();
  expect(acidStatus).toContain('Configured');
  this.testData.systemState.acidCompliant = true;
});

Given('alert processing queue with persistence is enabled', async function () {
  await assertions.assertVisible(page.locator('//div[@id="persistent-queue"]'));
  const queueStatus = await page.locator('//span[@id="persistent-queue-status"]').textContent();
  expect(queueStatus).toContain('Enabled');
});

Given('backup and recovery mechanisms are configured', async function () {
  await actions.click(page.locator('//button[@id="backup-recovery"]'));
  await waits.waitForVisible(page.locator('//div[@id="recovery-config"]'));
  await assertions.assertVisible(page.locator('//div[@id="recovery-config"]'));
  this.testData.systemState.recoveryConfigured = true;
});

// ==================== WHEN STEPS ====================

When('database connection is terminated', async function () {
  await actions.click(page.locator('//button[@id="simulate-db-failure"]'));
  await waits.waitForNetworkIdle();
  this.testData.systemState.databaseHealthy = false;
  this.testData.metrics.outageStartTime = Date.now();
});

When('{int} attendance anomalies are generated during database outage', async function (count: number) {
  await actions.fill(page.locator('//input[@id="anomaly-count"]'), count.toString());
  await actions.click(page.locator('//button[@id="generate-during-outage"]'));
  await waits.waitForNetworkIdle();
  this.testData.outageAnomalyCount = count;
});

When('system behavior is monitored for {int} minutes during outage', async function (minutes: number) {
  const monitoringDuration = minutes * 60 * 1000;
  this.testData.metrics.monitoringStartTime = Date.now();
  
  await actions.click(page.locator('//button[@id="start-monitoring"]'));
  await page.waitForTimeout(Math.min(monitoringDuration, 10000));
  
  this.testData.metrics.monitoringEndTime = Date.now();
});

When('database connection is restored', async function () {
  await actions.click(page.locator('//button[@id="restore-db-connection"]'));
  await waits.waitForNetworkIdle();
  this.testData.systemState.databaseHealthy = true;
  this.testData.metrics.recoveryStartTime = Date.now();
});

When('{int} test alerts are sent to establish steady state', async function (count: number) {
  await actions.fill(page.locator('//input[@id="test-alert-count"]'), count.toString());
  await actions.click(page.locator('//button[@id="send-test-alerts"]'));
  await waits.waitForNetworkIdle();
  this.testData.steadyStateAlertCount = count;
});

When('{int} percent packet loss is applied to network path', async function (packetLoss: number) {
  await actions.click(page.locator('//button[@id="apply-packet-loss"]'));
  await actions.fill(page.locator('//input[@id="packet-loss-percentage"]'), packetLoss.toString());
  await actions.click(page.locator('//button[@id="apply-chaos"]'));
  await waits.waitForNetworkIdle();
  this.testData.chaosConfig = { packetLoss };
});

When('{int} millisecond latency is injected to network path for {int} minutes', async function (latency: number, duration: number) {
  await actions.fill(page.locator('//input[@id="latency-ms"]'), latency.toString());
  await actions.fill(page.locator('//input[@id="chaos-duration"]'), duration.toString());
  await actions.click(page.locator('//button[@id="inject-latency"]'));
  await waits.waitForNetworkIdle();
  this.testData.chaosConfig.latency = latency;
  this.testData.chaosConfig.duration = duration;
});

When('{int} attendance anomaly alerts are generated during chaos period', async function (count: number) {
  await actions.fill(page.locator('//input[@id="chaos-alert-count"]'), count.toString());
  await actions.click(page.locator('//button[@id="generate-chaos-alerts"]'));
  await waits.waitForNetworkIdle();
  this.testData.chaosAlertCount = count;
});

When('network chaos is removed', async function () {
  await actions.click(page.locator('//button[@id="remove-chaos"]'));
  await waits.waitForNetworkIdle();
  this.testData.metrics.chaosEndTime = Date.now();
});

When('primary email API is configured to return {string} status code for all requests', async function (statusCode: string) {
  await actions.click(page.locator('//button[@id="configure-api-mock"]'));
  await waits.waitForVisible(page.locator('//input[@id="mock-status-code"]'));
  await actions.fill(page.locator('//input[@id="mock-status-code"]'), statusCode);
  await actions.selectByText(page.locator('//select[@id="mock-target"]'), 'Primary Email API');
  await actions.click(page.locator('//button[@id="apply-mock-config"]'));
  await waits.waitForNetworkIdle();
  this.testData.mockConfig = { statusCode, target: 'Primary Email API' };
});

When('{int} attendance anomaly alerts requiring email notifications are generated', async function (count: number) {
  await actions.fill(page.locator('//input[@id="email-alert-count"]'), count.toString());
  await actions.click(page.locator('//button[@id="generate-email-alerts"]'));
  await waits.waitForNetworkIdle();
  this.testData.emailAlertCount = count;
});

When('primary email API is restored to healthy state', async function () {
  await actions.click(page.locator('//button[@id="restore-primary-api"]'));
  await waits.waitForNetworkIdle();
  this.testData.systemState.primaryApiHealthy = true;
});

When('system waits for circuit breaker half-open period of {int} minutes', async function (minutes: number) {
  const waitTime = minutes * 60 * 1000;
  await page.waitForTimeout(Math.min(waitTime, 10000));
});

When('{int} new alerts are generated', async function (count: number) {
  await actions.fill(page.locator('//input[@id="new-alert-count"]'), count.toString());
  await actions.click(page.locator('//button[@id="generate-new-alerts"]'));
  await waits.waitForNetworkIdle();
});

When('processing of {int} attendance anomaly alerts is initiated in batches of {int}', async function (totalCount: number, batchSize: number) {
  await actions.fill(page.locator('//input[@id="total-alert-count"]'), totalCount.toString());
  await actions.fill(page.locator('//input[@id="batch-size"]'), batchSize.toString());
  await actions.click(page.locator('//button[@id="start-batch-processing"]'));
  await waits.waitForNetworkIdle();
  this.testData.batchProcessing = { totalCount, batchSize };
});

When('alert service process is forcefully terminated during processing of second batch', async function () {
  await page.waitForTimeout(5000);
  await actions.click(page.locator('//button[@id="force-terminate-service"]'));
  await waits.waitForNetworkIdle();
  this.testData.metrics.crashTime = Date.now();
  this.testData.systemState.serviceCrashed = true;
});

When('alert service is restarted', async function () {
  await actions.click(page.locator('//button[@id="restart-service"]'));
  await waits.waitForNetworkIdle();
  this.testData.metrics.restartTime = Date.now();
});

When('end-to-end alert count and delivery status is validated in database', async function () {
  await actions.click(page.locator('//button[@id="validate-database"]'));
  await waits.waitForVisible(page.locator('//div[@id="validation-results"]'));
  await waits.waitForNetworkIdle();
});

// ==================== THEN STEPS ====================

Then('database connection failure should be detected', async function () {
  await waits.waitForVisible(page.locator('//div[@id="db-failure-alert"]'));
  await assertions.assertVisible(page.locator('//div[@id="db-failure-alert"]'));
  const alertText = await page.locator('//span[@id="db-failure-message"]').textContent();
  expect(alertText).toContain('Database connection failure detected');
});

Then('service should log error but remain operational', async function () {
  await assertions.assertVisible(page.locator('//div[@id="error-log"]'));
  const serviceStatus = await page.locator('//span[@id="service-operational-status"]').textContent();
  expect(serviceStatus).toContain('Operational');
});

Then('alerts should be queued in message buffer', async function () {
  await waits.waitForVisible(page.locator('//div[@id="message-buffer"]'));
  const queuedCount = await page.locator('//span[@id="queued-alert-count"]').textContent();
  expect(parseInt(queuedCount || '0')).toBeGreaterThan(0);
  this.testData.queuedAlerts = parseInt(queuedCount || '0');
});

Then('no alerts should be lost', async function () {
  const queuedCount = await page.locator('//span[@id="queued-alert-count"]').textContent();
  expect(parseInt(queuedCount || '0')).toBe(this.testData.outageAnomalyCount);
});

Then('circuit breaker should open to prevent cascading failures', async function () {
  await waits.waitForVisible(page.locator('//div[@id="circuit-breaker-status"]'));
  const cbStatus = await page.locator('//span[@id="circuit-breaker-state"]').textContent();
  expect(cbStatus).toContain('OPEN');
});

Then('service should remain responsive', async function () {
  await assertions.assertVisible(page.locator('//div[@id="service-health"]'));
  const responseTime = await page.locator('//span[@id="response-time"]').textContent();
  expect(parseInt(responseTime || '0')).toBeLessThan(5000);
});

Then('health check endpoint should return degraded status', async function () {
  const healthStatus = await page.locator('//span[@id="health-check-status"]').textContent();
  expect(healthStatus).toContain('Degraded');
});

Then('no memory leaks or resource exhaustion should be observed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="resource-metrics"]'));
  const memoryStatus = await page.locator('//span[@id="memory-status"]').textContent();
  expect(memoryStatus).toContain('Normal');
});

Then('service should automatically detect restored connection', async function () {
  await waits.waitForVisible(page.locator('//div[@id="connection-restored"]'));
  const restoredMessage = await page.locator('//span[@id="restore-message"]').textContent();
  expect(restoredMessage).toContain('Connection restored');
});

Then('circuit breaker should transition to half-open state', async function () {
  await waits.waitForVisible(page.locator('//span[@id="circuit-breaker-state"]'));
  const cbState = await page.locator('//span[@id="circuit-breaker-state"]').textContent();
  expect(cbState).toContain('HALF-OPEN');
});

Then('circuit breaker should transition to closed state within {int} minutes', async function (minutes: number) {
  const timeout = minutes * 60 * 1000;
  const startTime = Date.now();
  
  while (Date.now() - startTime < timeout) {
    const cbState = await page.locator('//span[@id="circuit-breaker-state"]').textContent();
    if (cbState?.includes('CLOSED')) {
      break;
    }
    await page.waitForTimeout(5000);
  }
  
  const finalState = await page.locator('//span[@id="circuit-breaker-state"]').textContent();
  expect(finalState).toContain('CLOSED');
});

Then('all {int} queued alerts should be delivered within {int} minutes of recovery', async function (alertCount: number, minutes: number) {
  const timeout = minutes * 60 * 1000;
  const startTime = Date.now();
  
  while (Date.now() - startTime < timeout) {
    const deliveredCount = await page.locator('//span[@id="delivered-count"]').textContent();
    if (parseInt(deliveredCount || '0') >= alertCount) {
      break;
    }
    await page.waitForTimeout(5000);
  }
  
  const finalDelivered = await page.locator('//span[@id="delivered-count"]').textContent();
  expect(parseInt(finalDelivered || '0')).toBeGreaterThanOrEqual(alertCount);
});

Then('no data loss should occur', async function () {
  const lostAlerts = await page.locator('//span[@id="lost-alert-count"]').textContent();
  expect(parseInt(lostAlerts || '0')).toBe(0);
});

Then('total system availability should be at least {float} percent', async function (availability: number) {
  await waits.waitForVisible(page.locator('//span[@id="system-availability"]'));
  const actualAvailability = await page.locator('//span[@id="system-availability"]').textContent();
  expect(parseFloat(actualAvailability || '0')).toBeGreaterThanOrEqual(availability);
});

Then('baseline metrics should show {int} percent delivery rate', async function (rate: number) {
  const deliveryRate = await page.locator('//span[@id="baseline-delivery-rate"]').textContent();
  expect(parseInt(deliveryRate || '0')).toBe(rate);
});

Then('average delivery time should be less than {int} minutes', async function (minutes: number) {
  const avgTime = await page.locator('//span[@id="avg-delivery-time"]').textContent();
  expect(parseInt(avgTime || '0')).toBeLessThan(minutes);
});

Then('MTBF baseline should be established', async function () {
  await assertions.assertVisible(page.locator('//div[@id="mtbf-baseline"]'));
  const mtbf = await page.locator('//span[@id="mtbf-value"]').textContent();
  expect(parseFloat(mtbf || '0')).toBeGreaterThan(0);
  this.testData.metrics.mtbf = parseFloat(mtbf || '0');
});

Then('network degradation should be applied successfully', async function () {
  await waits.waitForVisible(page.locator('//div[@id="chaos-status"]'));
  const chaosStatus = await page.locator('//span[@id="chaos-active"]').textContent();
  expect(chaosStatus).toContain('Active');
});

Then('service should detect increased latency and packet loss', async function () {
  await assertions.assertVisible(page.locator('//div[@id="network-metrics"]'));
  const latencyDetected = await page.locator('//span[@id="latency-detected"]').textContent();
  expect(latencyDetected).toContain('Yes');
});

Then('retry mechanism should activate with exponential backoff', async function () {
  await waits.waitForVisible(page.locator('//div[@id="retry-mechanism"]'));
  const retryStatus = await page.locator('//span[@id="retry-active"]').textContent();
  expect(retryStatus).toContain('Active');
});

Then('alerts should queue for retry', async function () {
  const retryQueueCount = await page.locator('//span[@id="retry-queue-count"]').textContent();
  expect(parseInt(retryQueueCount || '0')).toBeGreaterThan(0);
});

Then('at least {int} alerts out of {int} should be delivered within chaos window', async function (minDelivered: number, total: number) {
  await page.waitForTimeout(10000);
  const deliveredCount = await page.locator('//span[@id="chaos-delivered-count"]').textContent();
  expect(parseInt(deliveredCount || '0')).toBeGreaterThanOrEqual(minDelivered);
});

Then('circuit breaker should open for failed channels', async function () {
  const cbStatus = await page.locator('//span[@id="channel-circuit-breaker"]').textContent();
  expect(cbStatus).toContain('OPEN');
});

Then('system should automatically failover to alternative notification channels', async function () {
  await waits.waitForVisible(page.locator('//div[@id="failover-status"]'));
  const failoverActive = await page.locator('//span[@id="failover-active"]').textContent();
  expect(failoverActive).toContain('Yes');
});

Then('all remaining queued alerts should be delivered within {int} minutes', async function (minutes: number) {
  const timeout = minutes * 60 * 1000;
  await page.waitForTimeout(Math.min(timeout, 10000));
  const remainingQueue = await page.locator('//span[@id="remaining-queue-count"]').textContent();
  expect(parseInt(remainingQueue || '0')).toBe(0);
});

Then('final delivery rate should be at least {int} percent', async function (rate: number) {
  const finalRate = await page.locator('//span[@id="final-delivery-rate"]').textContent();
  expect(parseInt(finalRate || '0')).toBeGreaterThanOrEqual(rate);
});

Then('MTTR should be less than or equal to {int} minutes', async function (minutes: number) {
  const mttr = await page.locator('//span[@id="mttr-value"]').textContent();
  expect(parseInt(mttr || '0')).toBeLessThanOrEqual(minutes);
});

Then('system should return to steady state', async function () {
  const systemState = await page.locator('//span[@id="system-state"]').textContent();
  expect(systemState).toContain('Steady');
});

Then('no duplicate alert notifications should be sent', async function () {
  const duplicateCount = await page.locator('//span[@id="duplicate-alert-count"]').textContent();
  expect(parseInt(duplicateCount || '0')).toBe(0);
});

Then('email API mock should be configured to simulate complete outage', async function () {
  await assertions.assertVisible(page.locator('//div[@id="mock-config-status"]'));
  const mockStatus = await page.locator('//span[@id="mock-outage-status"]').textContent();
  expect(mockStatus).toContain('Configured');
});

Then('system should attempt to send via primary email API', async function () {
  await waits.waitForVisible(page.locator('//div[@id="api-attempt-log"]'));
  const attemptLog = await page.locator('//span[@id="primary-api-attempts"]').textContent();
  expect(parseInt(attemptLog || '0')).toBeGreaterThan(0);
});

Then('system should receive {string} errors', async function (statusCode: string) {
  const errorLog = await page.locator('//div[@id="error-log"]').textContent();
  expect(errorLog).toContain(statusCode);
});

Then('circuit breaker should track failure rate', async function () {
  await assertions.assertVisible(page.locator('//div[@id="failure-rate-tracker"]'));
  const failureRate = await page.locator('//span[@id="current-failure-rate"]').textContent();
  expect(parseFloat(failureRate || '0')).toBeGreaterThan(0);
});

Then('circuit breaker should open after {int} consecutive failures', async function (failures: number) {
  const consecutiveFailures = await page.locator('//span[@id="consecutive-failures"]').textContent();
  expect(parseInt(consecutiveFailures || '0')).toBeGreaterThanOrEqual(failures);
});

Then('circuit breaker should open within {int} seconds', async function (seconds: number) {
  await page.waitForTimeout(seconds * 1000);
  const cbState = await page.locator('//span[@id="circuit-breaker-state"]').textContent();
  expect(cbState).toContain('OPEN');
});

Then('system should stop calling failed email API', async function () {
  const apiCallCount = await page.locator('//span[@id="api-call-count-after-open"]').textContent();
  expect(parseInt(apiCallCount || '0')).toBe(0);
});

Then('logs should indicate circuit breaker state change to {string}', async function (state: string) {
  const logEntry = await page.locator('//div[@id="circuit-breaker-log"]').textContent();
  expect(logEntry).toContain(`State changed to ${state}`);
});

Then('automatic failover to secondary notification channel should occur', async function () {
  await waits.waitForVisible(page.locator('//div[@id="secondary-channel-active"]'));
  const secondaryActive = await page.locator('//span[@id="secondary-channel-status"]').textContent();
  expect(secondaryActive).toContain('Active');
});

Then('all {int} alerts should be successfully delivered via fallback channel within {int} minutes', async function (count: number, minutes: number) {
  const timeout = minutes * 60 * 1000;
  await page.waitForTimeout(Math.min(timeout, 10000));
  const fallbackDelivered = await page.locator('//span[@id="fallback-delivered-count"]').textContent();
  expect(parseInt(fallbackDelivered || '0')).toBeGreaterThanOrEqual(count);
});

Then('no user-facing errors should occur', async function () {
  const userErrors = await page.locator('//span[@id="user-facing-errors"]').textContent();
  expect(parseInt(userErrors || '0')).toBe(0);
});

Then('availability should be maintained at least {int} percent', async function (availability: number) {
  const actualAvailability = await page.locator('//span[@id="availability-percentage"]').textContent();
  expect(parseFloat(actualAvailability || '0')).toBeGreaterThanOrEqual(availability);
});

Then('circuit breaker should transition to {string} state', async function (state: string) {
  await waits.waitForVisible(page.locator('//span[@id="circuit-breaker-state"]'));
  const cbState = await page.locator('//span[@id="circuit-breaker-state"]').textContent();
  expect(cbState).toContain(state);
});

Then('system should send test request to primary API', async function () {
  const testRequest = await page.locator('//span[@id="test-request-sent"]').textContent();
  expect(testRequest).toContain('Yes');
});

Then('primary email API should successfully deliver alerts', async function () {
  const primaryDelivered = await page.locator('//span[@id="primary-api-delivered"]').textContent();
  expect(parseInt(primaryDelivered || '0')).toBeGreaterThan(0);
});

Then('circuit breaker should close after {int} consecutive successes', async function (successes: number) {
  const consecutiveSuccesses = await page.locator('//span[@id="consecutive-successes"]').textContent();
  expect(parseInt(consecutiveSuccesses || '0')).toBeGreaterThanOrEqual(successes);
});

Then('system should return to normal operation', async function () {
  const operationMode = await page.locator('//span[@id="operation-mode"]').textContent();
  expect(operationMode).toContain('Normal');
});

Then('first batch of {int} alerts should begin processing', async function (batchSize: number) {
  await waits.waitForVisible(page.locator('//div[@id="batch-processing-status"]'));
  const processingBatch = await page.locator('//span[@id="current-batch"]').textContent();
  expect(processingBatch).toContain('1');
});

Then('alerts should be written to persistent queue with transaction IDs', async function () {
  await assertions.assertVisible(page.locator('//div[@id="transaction-log"]'));
  const transactionCount = await page.locator('//span[@id="transaction-count"]').textContent();
  expect(parseInt(transactionCount || '0')).toBeGreaterThan(0);
});

Then('service should crash immediately', async function () {
  await waits.waitForVisible(page.locator('//div[@id="service-crash-indicator"]'));
  const crashStatus = await page.locator('//span[@id="crash-status"]').textContent();
  expect(crashStatus).toContain('Crashed');
});

Then('in-flight transactions should be interrupted', async function () {
  const interruptedTx = await page.locator('//span[@id="interrupted-transactions"]').textContent();
  expect(parseInt(interruptedTx || '0')).toBeGreaterThan(0);
});

Then('service should become unavailable', async function () {
  const serviceAvailable = await page.locator('//span[@id="service-availability"]').textContent();
  expect(serviceAvailable).toContain('Unavailable');
});

Then('first batch of {int} alerts should be successfully committed to database', async function (count: number) {
  const committedCount = await page.locator('//span[@id="committed-alert-count"]').textContent();
  expect(parseInt(committedCount || '0')).toBe(count);
});

Then('all {int} alerts from first batch should be persisted with {string} status', async function (count: number, status: string) {
  const persistedWithStatus = await page.locator(`//span[@id="alerts-with-status-${status.toLowerCase()}"]`).textContent();
  expect(parseInt(persistedWithStatus || '0')).toBe(count);
});

Then('no partial or corrupted records should be found', async function () {
  const corruptedRecords = await page.locator('//span[@id="corrupted-records"]').textContent();
  expect(parseInt(corruptedRecords || '0')).toBe(0);
});

Then('second batch alerts should be rolled back or marked as {string}', async function (status: string) {
  const secondBatchStatus = await page.locator('//span[@id="second-batch-status"]').textContent();
  expect(secondBatchStatus).toContain(status);
});

Then('no alerts should be marked as delivered when they were not', async function () {
  const falseDelivered = await page.locator('//span[@id="false-delivered-count"]').textContent();
  expect(parseInt(falseDelivered || '0')).toBe(0);
});

Then('data integrity should be maintained', async function () {
  const integrityCheck = await page.locator('//span[@id="data-integrity-status"]').textContent();
  expect(integrityCheck).toContain('Maintained');
});

Then('service should restart automatically within {int} minutes', async function (minutes: number) {
  const timeout = minutes * 60 * 1000;
  await page.waitForTimeout(Math.min(timeout, 10000));
  const serviceStatus = await page.locator('//span[@id="service-status"]').textContent();
  expect(serviceStatus).toContain('Running');
});

Then('service should perform recovery routine checking for incomplete transactions', async function () {
  await waits.waitForVisible(page.locator('//div[@id="recovery-routine"]'));
  const recoveryStatus = await page.locator('//span[@id="recovery-check-status"]').textContent();
  expect(recoveryStatus).toContain('Complete');
});

Then('automatic reprocessing of {int} pending alerts should occur without duplicates', async function (count: number) {
  const reprocessedCount = await page.locator('//span[@id="reprocessed-alert-count"]').textContent();
  expect(parseInt(reprocessedCount || '0')).toBe(count);
});

Then('all {int} remaining alerts should be processed successfully within {int} minutes', async function (count: number, minutes: number) {
  const timeout = minutes * 60 * 1000;
  await page.waitForTimeout(Math.min(timeout, 10000));
  const processedCount = await page.locator('//span[@id="remaining-processed-count"]').textContent();
  expect(parseInt(processedCount || '0')).toBe(count);
});

Then('no duplicate alerts should be sent', async function () {
  const duplicates = await page.locator('//span[@id="duplicate-alerts"]').textContent();
  expect(parseInt(duplicates || '0')).toBe(0);
});

Then('total data loss should be {int}', async function (expectedLoss: number) {
  const dataLoss = await page.locator('//span[@id="total-data-loss"]').textContent();
  expect(parseInt(dataLoss || '0')).toBe(expectedLoss);
});

Then('alert audit log should show complete history', async function () {
  await assertions.assertVisible(page.locator('//div[@id="audit-log"]'));
  const auditComplete = await page.locator('//span[@id="audit-completeness"]').textContent();
  expect(auditComplete).toContain('Complete');
});

Then('exactly {int} alerts should exist in database with unique IDs', async function (count: number) {
  const totalAlerts = await page.locator('//span[@id="total-alerts-in-db"]').textContent();
  expect(parseInt(totalAlerts || '0')).toBe(count);
  
  const uniqueIds = await page.locator('//span[@id="unique-alert-ids"]').textContent();
  expect(parseInt(uniqueIds || '0')).toBe(count);
});

Then('all alerts should be marked as {string}', async function (status: string) {
  const alertsWithStatus = await page.locator(`//span[@id="all-alerts-status"]`).textContent();
  expect(alertsWithStatus).toContain(status);
});

Then('no orphaned or duplicate records should exist', async function () {
  const orphanedRecords = await page.locator('//span[@id="orphaned-records"]').textContent();
  expect(parseInt(orphanedRecords || '0')).toBe(0);
  
  const duplicateRecords = await page.locator('//span[@id="duplicate-records"]').textContent();
  expect(parseInt(duplicateRecords || '0')).toBe(0);
});

Then('transaction log should show proper rollback and replay', async function () {
  await assertions.assertVisible(page.locator('//div[@id="transaction-log-analysis"]'));
  const rollbackCount = await page.locator('//span[@id="rollback-count"]').textContent();
  expect(parseInt(rollbackCount || '0')).toBeGreaterThan(0);
  
  const replayCount = await page.locator('//span[@id="replay-count"]').textContent();
  expect(parseInt(replayCount || '0')).toBeGreaterThan(0);
});