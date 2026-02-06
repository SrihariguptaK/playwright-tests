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
    circuitBreaker: {
      threshold: 5,
      timeWindow: 10,
      states: ['OPEN', 'CLOSED', 'HALF-OPEN']
    },
    retryPolicy: {
      attempts: 3,
      backoffPattern: ['1s', '2s', '4s']
    },
    queueConfig: {
      capacity: 500,
      processingRate: 50
    },
    metrics: {
      baselineCpu: 40,
      baselineMemory: 60,
      baselineQueueDepth: 50
    }
  };
  
  this.systemState = {};
  this.notificationQueue = [];
  this.auditLogs = [];
  this.metrics = {};
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

// ==================== BACKGROUND STEPS ====================

// TODO: Replace XPath with Object Repository when available
Given('notification service is operational', async function () {
  const serviceStatusXPath = '//div[@id="notification-service-status"]';
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000/admin/services');
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator(serviceStatusXPath));
  await assertions.assertContainsText(page.locator(serviceStatusXPath), 'operational');
  this.systemState.notificationService = 'operational';
});

// TODO: Replace XPath with Object Repository when available
Given('monitoring and alerting systems are active', async function () {
  const monitoringStatusXPath = '//div[@id="monitoring-status"]';
  await waits.waitForVisible(page.locator(monitoringStatusXPath));
  await assertions.assertContainsText(page.locator(monitoringStatusXPath), 'active');
  this.systemState.monitoring = 'active';
});

// TODO: Replace XPath with Object Repository when available
Given('audit logging is enabled', async function () {
  const auditLoggingXPath = '//div[@id="audit-logging-status"]';
  await waits.waitForVisible(page.locator(auditLoggingXPath));
  await assertions.assertContainsText(page.locator(auditLoggingXPath), 'enabled');
  this.systemState.auditLogging = 'enabled';
});

// ==================== GIVEN STEPS ====================

/**************************************************/
/*  TEST CASE: TC-REL-001
/*  Title: Notification service maintains availability during database connection failure with circuit breaker protection
/*  Priority: Critical
/*  Category: Reliability - Chaos Engineering
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('circuit breaker is configured with threshold of {int} failures in {int} seconds', async function (threshold: number, timeWindow: number) {
  const circuitBreakerConfigXPath = '//div[@id="circuit-breaker-config"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/circuit-breaker');
  await waits.waitForNetworkIdle();
  
  const thresholdFieldXPath = '//input[@id="threshold"]';
  const timeWindowFieldXPath = '//input[@id="time-window"]';
  const saveButtonXPath = '//button[@id="save-config"]';
  
  await actions.clearAndFill(page.locator(thresholdFieldXPath), threshold.toString());
  await actions.clearAndFill(page.locator(timeWindowFieldXPath), timeWindow.toString());
  await actions.click(page.locator(saveButtonXPath));
  await waits.waitForNetworkIdle();
  
  this.systemState.circuitBreaker = {
    threshold: threshold,
    timeWindow: timeWindow,
    state: 'CLOSED'
  };
});

// TODO: Replace XPath with Object Repository when available
Given('schedule database is accessible and healthy', async function () {
  const databaseStatusXPath = '//div[@id="database-status"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/database-health');
  await waits.waitForNetworkIdle();
  await assertions.assertContainsText(page.locator(databaseStatusXPath), 'healthy');
  this.systemState.database = 'healthy';
});

// TODO: Replace XPath with Object Repository when available
Given('message queue is operational', async function () {
  const queueStatusXPath = '//div[@id="message-queue-status"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/queue-health');
  await waits.waitForNetworkIdle();
  await assertions.assertContainsText(page.locator(queueStatusXPath), 'operational');
  this.systemState.messageQueue = 'operational';
});

// TODO: Replace XPath with Object Repository when available
Given('{int} active users have scheduled appointments', async function (userCount: number) {
  const activeUsersXPath = '//div[@id="active-users-count"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/users');
  await waits.waitForNetworkIdle();
  await assertions.assertContainsText(page.locator(activeUsersXPath), userCount.toString());
  this.systemState.activeUsers = userCount;
});

// TODO: Replace XPath with Object Repository when available
Given('baseline notification delivery time is less than {int} seconds', async function (seconds: number) {
  const deliveryTimeXPath = '//div[@id="baseline-delivery-time"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/metrics');
  await waits.waitForNetworkIdle();
  const deliveryTimeText = await page.locator(deliveryTimeXPath).textContent();
  const deliveryTime = parseInt(deliveryTimeText?.replace(/\D/g, '') || '0');
  expect(deliveryTime).toBeLessThan(seconds);
  this.metrics.baselineDeliveryTime = deliveryTime;
});

// TODO: Replace XPath with Object Repository when available
Given('MTBF is greater than {int} hours', async function (hours: number) {
  const mtbfXPath = '//div[@id="mtbf-metric"]';
  const mtbfText = await page.locator(mtbfXPath).textContent();
  const mtbf = parseInt(mtbfText?.replace(/\D/g, '') || '0');
  expect(mtbf).toBeGreaterThan(hours);
  this.metrics.mtbf = mtbf;
});

/**************************************************/
/*  TEST CASE: TC-REL-002
/*  Title: Email service provider failure triggers automatic fallback with retry logic
/*  Priority: Critical
/*  Category: Reliability - Failover
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('primary email service provider is configured and operational', async function () {
  const primaryEspStatusXPath = '//div[@id="primary-esp-status"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/email-providers');
  await waits.waitForNetworkIdle();
  await assertions.assertContainsText(page.locator(primaryEspStatusXPath), 'operational');
  this.systemState.primaryEsp = 'operational';
});

// TODO: Replace XPath with Object Repository when available
Given('secondary email service provider is configured as fallback', async function () {
  const secondaryEspStatusXPath = '//div[@id="secondary-esp-status"]';
  await assertions.assertContainsText(page.locator(secondaryEspStatusXPath), 'configured');
  this.systemState.secondaryEsp = 'configured';
});

// TODO: Replace XPath with Object Repository when available
Given('retry policy is configured with {int} attempts and exponential backoff of {string}', async function (attempts: number, backoffPattern: string) {
  const retryPolicyXPath = '//div[@id="retry-policy-config"]';
  await waits.waitForVisible(page.locator(retryPolicyXPath));
  
  const attemptsFieldXPath = '//input[@id="retry-attempts"]';
  const backoffFieldXPath = '//input[@id="backoff-pattern"]';
  const saveButtonXPath = '//button[@id="save-retry-policy"]';
  
  await actions.clearAndFill(page.locator(attemptsFieldXPath), attempts.toString());
  await actions.clearAndFill(page.locator(backoffFieldXPath), backoffPattern);
  await actions.click(page.locator(saveButtonXPath));
  await waits.waitForNetworkIdle();
  
  this.systemState.retryPolicy = {
    attempts: attempts,
    backoffPattern: backoffPattern
  };
});

// TODO: Replace XPath with Object Repository when available
Given('in-app notification service is independent and operational', async function () {
  const inAppServiceXPath = '//div[@id="in-app-notification-status"]';
  await assertions.assertContainsText(page.locator(inAppServiceXPath), 'operational');
  this.systemState.inAppService = 'operational';
});

// TODO: Replace XPath with Object Repository when available
Given('{int} users have valid email addresses and active sessions', async function (userCount: number) {
  const validUsersXPath = '//div[@id="valid-users-count"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/users/active');
  await waits.waitForNetworkIdle();
  await assertions.assertContainsText(page.locator(validUsersXPath), userCount.toString());
  this.systemState.validUsers = userCount;
});

// TODO: Replace XPath with Object Repository when available
Given('monitoring alerts are configured for ESP failures', async function () {
  const alertConfigXPath = '//div[@id="esp-alert-config"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/alerts');
  await waits.waitForNetworkIdle();
  await assertions.assertContainsText(page.locator(alertConfigXPath), 'configured');
  this.systemState.espAlerts = 'configured';
});

/**************************************************/
/*  TEST CASE: TC-REL-003
/*  Title: Message queue handles saturation and resource exhaustion under high load with backpressure mechanism
/*  Priority: Critical
/*  Category: Reliability - Load Testing
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('message queue is configured with capacity limit of {int} messages', async function (capacity: number) {
  const queueCapacityXPath = '//div[@id="queue-capacity-config"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/queue-config');
  await waits.waitForNetworkIdle();
  
  const capacityFieldXPath = '//input[@id="queue-capacity"]';
  const saveButtonXPath = '//button[@id="save-queue-config"]';
  
  await actions.clearAndFill(page.locator(capacityFieldXPath), capacity.toString());
  await actions.click(page.locator(saveButtonXPath));
  await waits.waitForNetworkIdle();
  
  this.systemState.queueCapacity = capacity;
});

// TODO: Replace XPath with Object Repository when available
Given('notification service is configured with backpressure handling', async function () {
  const backpressureConfigXPath = '//div[@id="backpressure-config"]';
  await assertions.assertContainsText(page.locator(backpressureConfigXPath), 'enabled');
  this.systemState.backpressure = 'enabled';
});

// TODO: Replace XPath with Object Repository when available
Given('dead letter queue is configured for failed messages', async function () {
  const dlqConfigXPath = '//div[@id="dlq-config"]';
  await assertions.assertContainsText(page.locator(dlqConfigXPath), 'configured');
  this.systemState.dlq = 'configured';
});

// TODO: Replace XPath with Object Repository when available
Given('system monitoring tracks queue depth, memory usage, and CPU utilization', async function () {
  const monitoringMetricsXPath = '//div[@id="monitoring-metrics"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/monitoring');
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator(monitoringMetricsXPath));
  this.systemState.monitoring = 'tracking';
});

// TODO: Replace XPath with Object Repository when available
Given('{int} test user accounts have scheduled appointments', async function (userCount: number) {
  const testUsersXPath = '//div[@id="test-users-count"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/test-users');
  await waits.waitForNetworkIdle();
  await assertions.assertContainsText(page.locator(testUsersXPath), userCount.toString());
  this.systemState.testUsers = userCount;
});

// TODO: Replace XPath with Object Repository when available
Given('baseline CPU usage is below {int} percent', async function (percentage: number) {
  const cpuUsageXPath = '//div[@id="cpu-usage"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/metrics/cpu');
  await waits.waitForNetworkIdle();
  const cpuText = await page.locator(cpuUsageXPath).textContent();
  const cpuUsage = parseInt(cpuText?.replace(/\D/g, '') || '0');
  expect(cpuUsage).toBeLessThan(percentage);
  this.metrics.baselineCpu = cpuUsage;
});

// TODO: Replace XPath with Object Repository when available
Given('baseline memory usage is below {int} percent', async function (percentage: number) {
  const memoryUsageXPath = '//div[@id="memory-usage"]';
  const memoryText = await page.locator(memoryUsageXPath).textContent();
  const memoryUsage = parseInt(memoryText?.replace(/\D/g, '') || '0');
  expect(memoryUsage).toBeLessThan(percentage);
  this.metrics.baselineMemory = memoryUsage;
});

// TODO: Replace XPath with Object Repository when available
Given('baseline queue depth is below {int} messages', async function (depth: number) {
  const queueDepthXPath = '//div[@id="queue-depth"]';
  const depthText = await page.locator(queueDepthXPath).textContent();
  const queueDepth = parseInt(depthText?.replace(/\D/g, '') || '0');
  expect(queueDepth).toBeLessThan(depth);
  this.metrics.baselineQueueDepth = queueDepth;
});

// ==================== WHEN STEPS ====================

// TODO: Replace XPath with Object Repository when available
When('database connections are terminated using chaos engineering tool', async function () {
  const chaosToolXPath = '//div[@id="chaos-engineering-tool"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/chaos-engineering');
  await waits.waitForNetworkIdle();
  
  const terminateDbButtonXPath = '//button[@id="terminate-database-connections"]';
  await actions.click(page.locator(terminateDbButtonXPath));
  await waits.waitForNetworkIdle();
  
  this.systemState.chaosAction = 'database-terminated';
});

// TODO: Replace XPath with Object Repository when available
When('{int} schedule change events are triggered across different user accounts', async function (eventCount: number) {
  const triggerEventsXPath = '//div[@id="trigger-events"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/trigger-events');
  await waits.waitForNetworkIdle();
  
  const eventCountFieldXPath = '//input[@id="event-count"]';
  const triggerButtonXPath = '//button[@id="trigger-schedule-changes"]';
  
  await actions.clearAndFill(page.locator(eventCountFieldXPath), eventCount.toString());
  await actions.click(page.locator(triggerButtonXPath));
  await waits.waitForNetworkIdle();
  
  this.systemState.triggeredEvents = eventCount;
});

// TODO: Replace XPath with Object Repository when available
When('system health endpoints are checked', async function () {
  await actions.navigateTo(process.env.BASE_URL + '/admin/health');
  await waits.waitForNetworkIdle();
  this.systemState.healthCheckTime = new Date().toISOString();
});

// TODO: Replace XPath with Object Repository when available
When('database connectivity is restored after {int} minutes', async function (minutes: number) {
  const restoreDbButtonXPath = '//button[@id="restore-database-connectivity"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/chaos-engineering');
  await waits.waitForNetworkIdle();
  
  await page.waitForTimeout(minutes * 60 * 1000);
  
  await actions.click(page.locator(restoreDbButtonXPath));
  await waits.waitForNetworkIdle();
  
  this.systemState.databaseRestored = true;
});

// TODO: Replace XPath with Object Repository when available
When('automatic recovery is observed', async function () {
  const recoveryStatusXPath = '//div[@id="recovery-status"]';
  await waits.waitForVisible(page.locator(recoveryStatusXPath));
  await assertions.assertContainsText(page.locator(recoveryStatusXPath), 'recovering');
  this.systemState.recoveryObserved = true;
});

// TODO: Replace XPath with Object Repository when available
When('notification delivery is validated for all users', async function () {
  const deliveryValidationXPath = '//div[@id="delivery-validation"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/notification-delivery');
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator(deliveryValidationXPath));
  this.systemState.deliveryValidated = true;
});

// TODO: Replace XPath with Object Repository when available
When('SLO compliance is verified', async function () {
  const sloComplianceXPath = '//div[@id="slo-compliance"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/slo-compliance');
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator(sloComplianceXPath));
  this.systemState.sloVerified = true;
});

// TODO: Replace XPath with Object Repository when available
When('{int} schedule changes are processed', async function (changeCount: number) {
  const processChangesXPath = '//div[@id="process-changes"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/process-changes');
  await waits.waitForNetworkIdle();
  
  const changeCountFieldXPath = '//input[@id="change-count"]';
  const processButtonXPath = '//button[@id="process-schedule-changes"]';
  
  await actions.clearAndFill(page.locator(changeCountFieldXPath), changeCount.toString());
  await actions.click(page.locator(processButtonXPath));
  await waits.waitForNetworkIdle();
  
  this.systemState.processedChanges = changeCount;
});

// TODO: Replace XPath with Object Repository when available
When('primary ESP is configured to return HTTP {int} errors', async function (statusCode: number) {
  const espConfigXPath = '//div[@id="esp-error-config"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/esp-config');
  await waits.waitForNetworkIdle();
  
  const statusCodeFieldXPath = '//input[@id="error-status-code"]';
  const applyButtonXPath = '//button[@id="apply-error-config"]';
  
  await actions.clearAndFill(page.locator(statusCodeFieldXPath), statusCode.toString());
  await actions.click(page.locator(applyButtonXPath));
  await waits.waitForNetworkIdle();
  
  this.systemState.primaryEspError = statusCode;
});

// TODO: Replace XPath with Object Repository when available
When('{int} schedule change events are triggered during ESP outage', async function (eventCount: number) {
  const triggerDuringOutageXPath = '//div[@id="trigger-during-outage"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/trigger-events');
  await waits.waitForNetworkIdle();
  
  const eventCountFieldXPath = '//input[@id="event-count"]';
  const triggerButtonXPath = '//button[@id="trigger-during-outage"]';
  
  await actions.clearAndFill(page.locator(eventCountFieldXPath), eventCount.toString());
  await actions.click(page.locator(triggerButtonXPath));
  await waits.waitForNetworkIdle();
  
  this.systemState.eventsTriggeredDuringOutage = eventCount;
});

// TODO: Replace XPath with Object Repository when available
When('retry behavior and fallback activation are monitored', async function () {
  const retryMonitorXPath = '//div[@id="retry-monitor"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/retry-monitor');
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator(retryMonitorXPath));
  this.systemState.retryMonitored = true;
});

// TODO: Replace XPath with Object Repository when available
When('email delivery through secondary ESP is verified', async function () {
  const secondaryEspDeliveryXPath = '//div[@id="secondary-esp-delivery"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/email-delivery');
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator(secondaryEspDeliveryXPath));
  this.systemState.secondaryEspVerified = true;
});

// TODO: Replace XPath with Object Repository when available
When('primary ESP is restored to healthy state', async function () {
  const restoreEspButtonXPath = '//button[@id="restore-primary-esp"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/esp-config');
  await waits.waitForNetworkIdle();
  await actions.click(page.locator(restoreEspButtonXPath));
  await waits.waitForNetworkIdle();
  this.systemState.primaryEspRestored = true;
});

// TODO: Replace XPath with Object Repository when available
When('{int} new schedule changes are triggered', async function (changeCount: number) {
  const newChangesXPath = '//div[@id="new-changes"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/trigger-events');
  await waits.waitForNetworkIdle();
  
  const changeCountFieldXPath = '//input[@id="new-change-count"]';
  const triggerButtonXPath = '//button[@id="trigger-new-changes"]';
  
  await actions.clearAndFill(page.locator(changeCountFieldXPath), changeCount.toString());
  await actions.click(page.locator(triggerButtonXPath));
  await waits.waitForNetworkIdle();
  
  this.systemState.newChangesTriggered = changeCount;
});

// TODO: Replace XPath with Object Repository when available
When('notification audit trail is validated for all {int} notifications', async function (notificationCount: number) {
  const auditTrailXPath = '//div[@id="audit-trail"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/audit-trail');
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator(auditTrailXPath));
  this.systemState.auditTrailValidated = notificationCount;
});

// TODO: Replace XPath with Object Repository when available
When('resilience metrics are calculated', async function () {
  const resilienceMetricsXPath = '//div[@id="resilience-metrics"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/resilience-metrics');
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator(resilienceMetricsXPath));
  this.systemState.resilienceCalculated = true;
});

// TODO: Replace XPath with Object Repository when available
When('{int} simultaneous schedule changes are triggered within {int} seconds', async function (changeCount: number, seconds: number) {
  const simultaneousChangesXPath = '//div[@id="simultaneous-changes"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/load-test');
  await waits.waitForNetworkIdle();
  
  const changeCountFieldXPath = '//input[@id="simultaneous-change-count"]';
  const durationFieldXPath = '//input[@id="duration-seconds"]';
  const triggerButtonXPath = '//button[@id="trigger-simultaneous-changes"]';
  
  await actions.clearAndFill(page.locator(changeCountFieldXPath), changeCount.toString());
  await actions.clearAndFill(page.locator(durationFieldXPath), seconds.toString());
  await actions.click(page.locator(triggerButtonXPath));
  await waits.waitForNetworkIdle();
  
  this.systemState.simultaneousChanges = changeCount;
});

// TODO: Replace XPath with Object Repository when available
When('backpressure activation and system behavior are monitored', async function () {
  const backpressureMonitorXPath = '//div[@id="backpressure-monitor"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/backpressure-monitor');
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator(backpressureMonitorXPath));
  this.systemState.backpressureMonitored = true;
});

// TODO: Replace XPath with Object Repository when available
When('priority-based processing is observed', async function () {
  const priorityProcessingXPath = '//div[@id="priority-processing"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/priority-processing');
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator(priorityProcessingXPath));
  this.systemState.priorityProcessingObserved = true;
});

// TODO: Replace XPath with Object Repository when available
When('queue drain rate and system recovery are monitored over {int} minutes', async function (minutes: number) {
  const queueDrainMonitorXPath = '//div[@id="queue-drain-monitor"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/queue-drain-monitor');
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator(queueDrainMonitorXPath));
  
  await page.waitForTimeout(minutes * 60 * 1000);
  
  this.systemState.queueDrainMonitored = minutes;
});

// TODO: Replace XPath with Object Repository when available
When('notification delivery completeness is validated', async function () {
  const deliveryCompletenessXPath = '//div[@id="delivery-completeness"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/delivery-completeness');
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator(deliveryCompletenessXPath));
  this.systemState.deliveryCompletenessValidated = true;
});

// TODO: Replace XPath with Object Repository when available
When('data integrity is verified', async function () {
  const dataIntegrityXPath = '//div[@id="data-integrity"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/data-integrity');
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator(dataIntegrityXPath));
  this.systemState.dataIntegrityVerified = true;
});

// ==================== THEN STEPS ====================

// TODO: Replace XPath with Object Repository when available
Then('database becomes unavailable', async function () {
  const databaseStatusXPath = '//div[@id="database-status"]';
  await waits.waitForVisible(page.locator(databaseStatusXPath));
  await assertions.assertContainsText(page.locator(databaseStatusXPath), 'unavailable');
});

// TODO: Replace XPath with Object Repository when available
Then('connection attempts fail with timeout errors', async function () {
  const connectionErrorsXPath = '//div[@id="connection-errors"]';
  await waits.waitForVisible(page.locator(connectionErrorsXPath));
  await assertions.assertContainsText(page.locator(connectionErrorsXPath), 'timeout');
});

// TODO: Replace XPath with Object Repository when available
Then('circuit breaker transitions to {string} state after {int} failed attempts', async function (state: string, attempts: number) {
  const circuitBreakerStateXPath = '//div[@id="circuit-breaker-state"]';
  await waits.waitForVisible(page.locator(circuitBreakerStateXPath));
  await assertions.assertContainsText(page.locator(circuitBreakerStateXPath), state);
  
  const failedAttemptsXPath = '//div[@id="failed-attempts-count"]';
  await assertions.assertContainsText(page.locator(failedAttemptsXPath), attempts.toString());
});

// TODO: Replace XPath with Object Repository when available
Then('{int} notifications are queued in message queue', async function (notificationCount: number) {
  const queuedNotificationsXPath = '//div[@id="queued-notifications-count"]';
  await waits.waitForVisible(page.locator(queuedNotificationsXPath));
  await assertions.assertContainsText(page.locator(queuedNotificationsXPath), notificationCount.toString());
});

// TODO: Replace XPath with Object Repository when available
Then('error logs are generated with appropriate severity', async function () {
  const errorLogsXPath = '//div[@id="error-logs"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/logs');
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator(errorLogsXPath));
  await assertions.assertContainsText(page.locator(errorLogsXPath), 'ERROR');
});

// TODO: Replace XPath with Object Repository when available
Then('notifications are not dropped', async function () {
  const droppedNotificationsXPath = '//div[@id="dropped-notifications-count"]';
  await assertions.assertContainsText(page.locator(droppedNotificationsXPath), '0');
});

// TODO: Replace XPath with Object Repository when available
Then('service remains operational without crashes', async function () {
  const serviceStatusXPath = '//div[@id="service-status"]';
  await waits.waitForVisible(page.locator(serviceStatusXPath));
  await assertions.assertContainsText(page.locator(serviceStatusXPath), 'operational');
});

// TODO: Replace XPath with Object Repository when available
Then('circuit breaker status is {string}', async function (status: string) {
  const circuitBreakerStatusXPath = '//div[@id="circuit-breaker-status"]';
  await waits.waitForVisible(page.locator(circuitBreakerStatusXPath));
  await assertions.assertContainsText(page.locator(circuitBreakerStatusXPath), status);
});

// TODO: Replace XPath with Object Repository when available
Then('notification queue depth is {int}', async function (depth: number) {
  const queueDepthXPath = '//div[@id="notification-queue-depth"]';
  await waits.waitForVisible(page.locator(queueDepthXPath));
  await assertions.assertContainsText(page.locator(queueDepthXPath), depth.toString());
});

// TODO: Replace XPath with Object Repository when available
Then('no memory leaks are detected', async function () {
  const memoryLeaksXPath = '//div[@id="memory-leaks"]';
  await waits.waitForVisible(page.locator(memoryLeaksXPath));
  await assertions.assertContainsText(page.locator(memoryLeaksXPath), 'none');
});

// TODO: Replace XPath with Object Repository when available
Then('CPU usage remains below {int} percent', async function (percentage: number) {
  const cpuUsageXPath = '//div[@id="cpu-usage"]';
  const cpuText = await page.locator(cpuUsageXPath).textContent();
  const cpuUsage = parseInt(cpuText?.replace(/\D/g, '') || '0');
  expect(cpuUsage).toBeLessThan(percentage);
});

// TODO: Replace XPath with Object Repository when available
Then('database connection is restored successfully', async function () {
  const databaseConnectionXPath = '//div[@id="database-connection-status"]';
  await waits.waitForVisible(page.locator(databaseConnectionXPath));
  await assertions.assertContainsText(page.locator(databaseConnectionXPath), 'restored');
});

// TODO: Replace XPath with Object Repository when available
Then('circuit breaker transitions to {string} state', async function (state: string) {
  const circuitBreakerStateXPath = '//div[@id="circuit-breaker-state"]';
  await waits.waitForVisible(page.locator(circuitBreakerStateXPath));
  await assertions.assertContainsText(page.locator(circuitBreakerStateXPath), state);
});

// TODO: Replace XPath with Object Repository when available
Then('circuit breaker transitions from {string} to {string} after {int} successful requests', async function (fromState: string, toState: string, requestCount: number) {
  const circuitBreakerStateXPath = '//div[@id="circuit-breaker-state"]';
  await waits.waitForVisible(page.locator(circuitBreakerStateXPath));
  await assertions.assertContainsText(page.locator(circuitBreakerStateXPath), toState);
  
  const successfulRequestsXPath = '//div[@id="successful-requests-count"]';
  await assertions.assertContainsText(page.locator(successfulRequestsXPath), requestCount.toString());
});

// TODO: Replace XPath with Object Repository when available
Then('all {int} queued notifications are processed within {int} minutes', async function (notificationCount: number, minutes: number) {
  const processedNotificationsXPath = '//div[@id="processed-notifications-count"]';
  await waits.waitForVisible(page.locator(processedNotificationsXPath));
  
  await page.waitForTimeout(minutes * 60 * 1000);
  
  await assertions.assertContainsText(page.locator(processedNotificationsXPath), notificationCount.toString());
});

// TODO: Replace XPath with Object Repository when available
Then('MTTR is less than {int} minutes', async function (minutes: number) {
  const mttrXPath = '//div[@id="mttr-metric"]';
  const mttrText = await page.locator(mttrXPath).textContent();
  const mttr = parseInt(mttrText?.replace(/\D/g, '') || '0');
  expect(mttr).toBeLessThan(minutes);
});

// TODO: Replace XPath with Object Repository when available
Then('{int} percent notification delivery success is achieved', async function (percentage: number) {
  const deliverySuccessXPath = '//div[@id="delivery-success-rate"]';
  const successText = await page.locator(deliverySuccessXPath).textContent();
  const successRate = parseInt(successText?.replace(/\D/g, '') || '0');
  expect(successRate).toBe(percentage);
});

// TODO: Replace XPath with Object Repository when available
Then('no duplicate notifications are sent', async function () {
  const duplicateNotificationsXPath = '//div[@id="duplicate-notifications-count"]';
  await assertions.assertContainsText(page.locator(duplicateNotificationsXPath), '0');
});

// TODO: Replace XPath with Object Repository when available
Then('notification content is accurate', async function () {
  const contentAccuracyXPath = '//div[@id="content-accuracy"]';
  await waits.waitForVisible(page.locator(contentAccuracyXPath));
  await assertions.assertContainsText(page.locator(contentAccuracyXPath), 'accurate');
});

// TODO: Replace XPath with Object Repository when available
Then('total system downtime for notification feature is {int}', async function (downtime: number) {
  const downtimeXPath = '//div[@id="system-downtime"]';
  const downtimeText = await page.locator(downtimeXPath).textContent();
  const actualDowntime = parseInt(downtimeText?.replace(/\D/g, '') || '0');
  expect(actualDowntime).toBe(downtime);
});

// TODO: Replace XPath with Object Repository when available
Then('availability is {int} percent in degraded mode', async function (percentage: number) {
  const availabilityXPath = '//div[@id="availability-degraded"]';
  const availabilityText = await page.locator(availabilityXPath).textContent();
  const availability = parseInt(availabilityText?.replace(/\D/g, '') || '0');
  expect(availability).toBe(percentage);
});

// TODO: Replace XPath with Object Repository when available
Then('RTO is less than {int} minutes', async function (minutes: number) {
  const rtoXPath = '//div[@id="rto-metric"]';
  const rtoText = await page.locator(rtoXPath).textContent();
  const rto = parseInt(rtoText?.replace(/\D/g, '') || '0');
  expect(rto).toBeLessThan(minutes);
});

// TODO: Replace XPath with Object Repository when available
Then('RPO is {int} with no data loss', async function (rpo: number) {
  const rpoXPath = '//div[@id="rpo-metric"]';
  const rpoText = await page.locator(rpoXPath).textContent();
  const actualRpo = parseInt(rpoText?.replace(/\D/g, '') || '0');
  expect(actualRpo).toBe(rpo);
  
  const dataLossXPath = '//div[@id="data-loss"]';
  await assertions.assertContainsText(page.locator(dataLossXPath), 'none');
});

// TODO: Replace XPath with Object Repository when available
Then('MTTR is less than {int} minutes meeting SLO target', async function (minutes: number) {
  const mttrSloXPath = '//div[@id="mttr-slo"]';
  const mttrText = await page.locator(mttrSloXPath).textContent();
  const mttr = parseInt(mttrText?.replace(/\D/g, '') || '0');
  expect(mttr).toBeLessThan(minutes);
  
  const sloMetXPath = '//div[@id="slo-met"]';
  await assertions.assertContainsText(page.locator(sloMetXPath), 'true');
});

// TODO: Replace XPath with Object Repository when available
Then('all services are restored to normal operation', async function () {
  const servicesStatusXPath = '//div[@id="all-services-status"]';
  await waits.waitForVisible(page.locator(servicesStatusXPath));
  await assertions.assertContainsText(page.locator(servicesStatusXPath), 'normal');
});

// TODO: Replace XPath with Object Repository when available
Then('circuit breaker is in {string} state', async function (state: string) {
  const circuitBreakerStateXPath = '//div[@id="circuit-breaker-state"]';
  await waits.waitForVisible(page.locator(circuitBreakerStateXPath));
  await assertions.assertContainsText(page.locator(circuitBreakerStateXPath), state);
});

// TODO: Replace XPath with Object Repository when available
Then('notification queue is empty', async function () {
  const queueDepthXPath = '//div[@id="notification-queue-depth"]';
  await assertions.assertContainsText(page.locator(queueDepthXPath), '0');
});

// TODO: Replace XPath with Object Repository when available
Then('no orphaned notifications exist in the system', async function () {
  const orphanedNotificationsXPath = '//div[@id="orphaned-notifications-count"]';
  await assertions.assertContainsText(page.locator(orphanedNotificationsXPath), '0');
});

// TODO: Replace XPath with Object Repository when available
Then('incident is logged with root cause analysis', async function () {
  const incidentLogXPath = '//div[@id="incident-log"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/incidents');
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator(incidentLogXPath));
  await assertions.assertContainsText(page.locator(incidentLogXPath), 'root cause');
});

// TODO: Replace XPath with Object Repository when available
Then('{int} percent delivery success is achieved on both channels', async function (percentage: number) {
  const emailDeliveryXPath = '//div[@id="email-delivery-success"]';
  const inAppDeliveryXPath = '//div[@id="in-app-delivery-success"]';
  
  const emailText = await page.locator(emailDeliveryXPath).textContent();
  const emailSuccess = parseInt(emailText?.replace(/\D/g, '') || '0');
  expect(emailSuccess).toBe(percentage);
  
  const inAppText = await page.locator(inAppDeliveryXPath).textContent();
  const inAppSuccess = parseInt(inAppText?.replace(/\D/g, '') || '0');
  expect(inAppSuccess).toBe(percentage);
});

// TODO: Replace XPath with Object Repository when available
Then('average delivery time is {int} seconds for email', async function (seconds: number) {
  const emailDeliveryTimeXPath = '//div[@id="email-delivery-time"]';
  const deliveryText = await page.locator(emailDeliveryTimeXPath).textContent();
  const deliveryTime = parseInt(deliveryText?.replace(/\D/g, '') || '0');
  expect(deliveryTime).toBe(seconds);
});

// TODO: Replace XPath with Object Repository when available
Then('average delivery time is {int} seconds for in-app notifications', async function (seconds: number) {
  const inAppDeliveryTimeXPath = '//div[@id="in-app-delivery-time"]';
  const deliveryText = await page.locator(inAppDeliveryTimeXPath).textContent();
  const deliveryTime = parseInt(deliveryText?.replace(/\D/g, '') || '0');
  expect(deliveryTime).toBe(seconds);
});

// TODO: Replace XPath with Object Repository when available
Then('primary ESP returns {int} errors for all email send requests', async function (statusCode: number) {
  const espErrorsXPath = '//div[@id="primary-esp-errors"]';
  await waits.waitForVisible(page.locator(espErrorsXPath));
  await assertions.assertContainsText(page.locator(espErrorsXPath), statusCode.toString());
});

// TODO: Replace XPath with Object Repository when available
Then('system attempts to send emails via primary ESP', async function () {
  const sendAttemptsXPath = '//div[@id="primary-esp-send-attempts"]';
  await waits.waitForVisible(page.locator(sendAttemptsXPath));
  const attemptsText = await page.locator(sendAttemptsXPath).textContent();
  const attempts = parseInt(attemptsText?.replace(/\D/g, '') || '0');
  expect(attempts).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Then('system receives {int} errors', async function (statusCode: number) {
  const receivedErrorsXPath = '//div[@id="received-errors"]';
  await waits.waitForVisible(page.locator(receivedErrorsXPath));
  await assertions.assertContainsText(page.locator(receivedErrorsXPath), statusCode.toString());
});

// TODO: Replace XPath with Object Repository when available
Then('retry logic initiates with exponential backoff at {string}', async function (backoffPattern: string) {
  const retryLogicXPath = '//div[@id="retry-logic-pattern"]';
  await waits.waitForVisible(page.locator(retryLogicXPath));
  await assertions.assertContainsText(page.locator(retryLogicXPath), backoffPattern);
});

// TODO: Replace XPath with Object Repository when available
Then('system switches to secondary ESP after {int} failed attempts', async function (attempts: number) {
  const fallbackActivationXPath = '//div[@id="fallback-activation"]';
  await waits.waitForVisible(page.locator(fallbackActivationXPath));
  await assertions.assertContainsText(page.locator(fallbackActivationXPath), 'secondary ESP');
  
  const failedAttemptsXPath = '//div[@id="failed-attempts-before-fallback"]';
  await assertions.assertContainsText(page.locator(failedAttemptsXPath), attempts.toString());
});

// TODO: Replace XPath with Object Repository when available
Then('fallback mechanism activates within {int} seconds of initial failure', async function (seconds: number) {
  const fallbackTimeXPath = '//div[@id="fallback-activation-time"]';
  const timeText = await page.locator(fallbackTimeXPath).textContent();
  const activationTime = parseInt(timeText?.replace(/\D/g, '') || '0');
  expect(activationTime).toBeLessThanOrEqual(seconds);
});

// TODO: Replace XPath with Object Repository when available
Then('total retry duration is {int} seconds', async function (seconds: number) {
  const retryDurationXPath = '//div[@id="total-retry-duration"]';
  const durationText = await page.locator(retryDurationXPath).textContent();
  const duration = parseInt(durationText?.replace(/\D/g, '') || '0');
  expect(duration).toBe(seconds);
});

// TODO: Replace XPath with Object Repository when available
Then('all {int} emails are successfully sent via secondary ESP within {int} seconds', async function (emailCount: number, seconds: number) {
  const secondaryEspEmailsXPath = '//div[@id="secondary-esp-emails-sent"]';
  await waits.waitForVisible(page.locator(secondaryEspEmailsXPath));
  await assertions.assertContainsText(page.locator(secondaryEspEmailsXPath), emailCount.toString());
  
  const deliveryTimeXPath = '//div[@id="secondary-esp-delivery-time"]';
  const timeText = await page.locator(deliveryTimeXPath).textContent();
  const deliveryTime = parseInt(timeText?.replace(/\D/g, '') || '0');
  expect(deliveryTime).toBeLessThanOrEqual(seconds);
});

// TODO: Replace XPath with Object Repository when available
Then('all {int} in-app notifications are delivered within {int} seconds', async function (notificationCount: number, seconds: number) {
  const inAppNotificationsXPath = '//div[@id="in-app-notifications-delivered"]';
  await waits.waitForVisible(page.locator(inAppNotificationsXPath));
  await assertions.assertContainsText(page.locator(inAppNotificationsXPath), notificationCount.toString());
  
  const deliveryTimeXPath = '//div[@id="in-app-delivery-time"]';
  const timeText = await page.locator(deliveryTimeXPath).textContent();
  const deliveryTime = parseInt(timeText?.replace(/\D/g, '') || '0');
  expect(deliveryTime).toBeLessThanOrEqual(seconds);
});

// TODO: Replace XPath with Object Repository when available
Then('total email delivery time is less than {int} seconds', async function (seconds: number) {
  const totalDeliveryTimeXPath = '//div[@id="total-email-delivery-time"]';
  const timeText = await page.locator(totalDeliveryTimeXPath).textContent();
  const totalTime = parseInt(timeText?.replace(/\D/g, '') || '0');
  expect(totalTime).toBeLessThan(seconds);
});

// TODO: Replace XPath with Object Repository when available
Then('system detects primary ESP recovery', async function () {
  const espRecoveryXPath = '//div[@id="primary-esp-recovery"]';
  await waits.waitForVisible(page.locator(espRecoveryXPath));
  await assertions.assertContainsText(page.locator(espRecoveryXPath), 'recovered');
});

// TODO: Replace XPath with Object Repository when available
Then('new notifications route through primary ESP', async function () {
  const routingXPath = '//div[@id="notification-routing"]';
  await waits.waitForVisible(page.locator(routingXPath));
  await assertions.assertContainsText(page.locator(routingXPath), 'primary ESP');
});

// TODO: Replace XPath with Object Repository when available
Then('delivery time returns to baseline of less than {int} seconds', async function (seconds: number) {
  const baselineDeliveryTimeXPath = '//div[@id="baseline-delivery-time"]';
  const timeText = await page.locator(baselineDeliveryTimeXPath).textContent();
  const deliveryTime = parseInt(timeText?.replace(/\D/g, '') || '0');
  expect(deliveryTime).toBeLessThan(seconds);
});

// TODO: Replace XPath with Object Repository when available
Then('audit logs show {int} successful deliveries via primary ESP before failure', async function (deliveryCount: number) {
  const auditLogsXPath = '//div[@id="audit-logs-primary-before-failure"]';
  await actions.navigateTo(process.env.BASE_URL + '/admin/audit-logs');
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator(auditLogsXPath));
  await assertions.assertContainsText(page.locator(auditLogsXPath), deliveryCount.toString());
});

// TODO: Replace XPath with Object Repository when available
Then('audit logs show {int} successful deliveries via secondary ESP during failure', async function (deliveryCount: number) {
  const auditLogsXPath = '//div[@id="audit-logs-secondary-during-failure"]';
  await waits.waitForVisible(page.locator(auditLogsXPath));
  await assertions.assertContainsText(page.locator(auditLogsXPath), deliveryCount.toString());
});

// TODO: Replace XPath with Object Repository when available
Then('audit logs show {int} successful deliveries via primary ESP after recovery', async function (deliveryCount: number) {
  const auditLogsXPath = '//div[@id="audit-logs-primary-after-recovery"]';
  await waits.waitForVisible(page.locator(auditLogsXPath));
  await assertions.assertContainsText(page.locator(auditLogsXPath), deliveryCount.toString());
});

// TODO: Replace XPath with Object Repository when available
Then('no duplicate emails are sent', async function () {
  const duplicateEmailsXPath = '//div[@id="duplicate-emails-count"]';
  await assertions.assertContainsText(page.locator(duplicateEmailsXPath), '0');
});

// TODO: Replace XPath with Object Repository when available
Then('delivery status accurately reflects channel used', async function () {
  const deliveryStatusXPath = '//div[@id="delivery-status-accuracy"]';
  await waits.waitForVisible(page.locator(deliveryStatusXPath));
  await assertions.assertContainsText(page.locator(deliveryStatusXPath), 'accurate');
});

// TODO: Replace XPath with Object Repository when available
Then('email channel availability is {int} percent via fallback', async function (percentage: number) {
  const emailAvailabilityXPath = '//div[@id="email-channel-availability"]';
  const availabilityText = await page.locator(emailAvailabilityXPath).textContent();
  const availability = parseInt(availabilityText?.replace(/\D/g, '') || '0');
  expect(availability).toBe(percentage);
});

// TODO: Replace XPath with Object Repository when available
Then('in-app channel availability is {int} percent', async function (percentage: number) {
  const inAppAvailabilityXPath = '//div[@id="in-app-channel-availability"]';
  const availabilityText = await page.locator(inAppAvailabilityXPath).textContent();
  const availability = parseInt(availabilityText?.replace(/\D/g, '') || '0');
  expect(availability).toBe(percentage);
});

// TODO: Replace XPath with Object Repository when available
Then('MTTR for email channel is less than {int} seconds', async function (seconds: number) {
  const mttrXPath = '//div[@id="email-channel-mttr"]';
  const mttrText = await page.locator(mttrXPath).textContent();
  const mttr = parseInt(mttrText?.replace(/\D/g, '') || '0');
  expect(mttr).toBeLessThan(seconds);
});

// TODO: Replace XPath with Object Repository when available
Then('user impact is {int} missed notifications', async function (missedCount: number) {
  const missedNotificationsXPath = '//div[@id="missed-notifications-count"]';
  await assertions.assertContainsText(page.locator(missedNotificationsXPath), missedCount.toString());
});

// TODO: Replace XPath with Object Repository when available
Then('SLO compliance is {int} percent notification delivery maintained', async function (percentage: number) {
  const sloComplianceXPath = '//div[@id="slo-compliance-percentage"]';
  const complianceText = await page.locator(sloComplianceXPath).textContent();
  const compliance = parseInt(complianceText?.replace(/\D/g, '') || '0');
  expect(compliance).toBe(percentage);
});

// TODO: Replace XPath with Object Repository when available
Then('primary ESP is restored and active', async function () {
  const primaryEspStatusXPath = '//div[@id="primary-esp-status"]';
  await waits.waitForVisible(page.locator(primaryEspStatusXPath));
  await assertions.assertContainsText(page.locator(primaryEspStatusXPath), 'active');
});

// TODO: Replace XPath with Object Repository when available
Then('all notifications are delivered successfully', async function () {
  const deliverySuccessXPath = '//div[@id="all-notifications-delivered"]';
  await waits.waitForVisible(page.locator(deliverySuccessXPath));
  await assertions.assertContainsText(page.locator(deliverySuccessXPath), 'success');
});

// TODO: Replace XPath with Object Repository when available
Then('no pending retry queues exist', async function () {
  const pendingRetryQueuesXPath = '//div[@id="pending-retry-queues-count"]';
  await assertions.assertContainsText(page.locator(pendingRetryQueuesXPath), '0');
});

// TODO: Replace XPath with Object Repository when available
Then('fallback mechanism is reset to monitor primary ESP', async function () {
  const fallbackMechanismXPath = '//div[@id="fallback-mechanism-status"]';
  await waits.waitForVisible(page.locator(fallbackMechanismXPath));
  await assertions.assertContainsText(page.locator(fallbackMechanismXPath), 'monitoring primary');
});

// TODO: Replace XPath with Object Repository when available
Then('alert notifications are sent to operations team', async function () {
  const alertNotificationsXPath = '//div[@id="alert-notifications-sent"]';
  await waits.waitForVisible(page.locator(alertNotificationsXPath));
  await assertions.assertContainsText(page.locator(alertNotificationsXPath), 'sent');
});

// TODO: Replace XPath with Object Repository when available
Then('queue processing rate is {int} messages per second', async function (rate: number) {
  const processingRateXPath = '//div[@id="queue-processing-rate"]';
  const rateText = await page.locator(processingRateXPath).textContent();
  const actualRate = parseInt(rateText?.replace(/\D/g, '') || '0');
  expect(actualRate).toBe(rate);
});

// TODO: Replace XPath with Object Repository when available
Then('CPU usage is {int} percent', async function (percentage: number) {
  const cpuUsageXPath = '//div[@id="cpu-usage"]';
  const cpuText = await page.locator(cpuUsageXPath).textContent();
  const cpuUsage = parseInt(cpuText?.replace(/\D/g, '') || '0');
  expect(cpuUsage).toBe(percentage);
});

// TODO: Replace XPath with Object Repository when available
Then('memory usage is {int} percent', async function (percentage: number) {
  const memoryUsageXPath = '//div[@id="memory-usage"]';
  const memoryText = await page.locator(memoryUsageXPath).textContent();
  const memoryUsage = parseInt(memoryText?.replace(/\D/g, '') || '0');
  expect(memoryUsage).toBe(percentage);
});

// TODO: Replace XPath with Object Repository when available
Then('queue depth peaks at {int} messages', async function (depth: number) {
  const queueDepthPeakXPath = '//div[@id="queue-depth-peak"]';
  const depthText = await page.locator(queueDepthPeakXPath).textContent();
  const peakDepth = parseInt(depthText?.replace(/\D/g, '') || '0');
  expect(peakDepth).toBe(depth);
});

// TODO: Replace XPath with Object Repository when available
Then('all notifications are delivered within {int} seconds', async function (seconds: number) {
  const allDeliveredXPath = '//div[@id="all-notifications-delivery-time"]';
  const timeText = await page.locator(allDeliveredXPath).textContent();
  const deliveryTime = parseInt(timeText?.replace(/\D/g, '') || '0');
  expect(deliveryTime).toBeLessThanOrEqual(seconds);
});

// TODO: Replace XPath with Object Repository when available
Then('queue depth rapidly increases to {int} messages', async function (depth: number) {
  const queueDepthXPath = '//div[@id="queue-depth"]';
  await waits.waitForVisible(page.locator(queueDepthXPath));
  const depthText = await page.locator(queueDepthXPath).textContent();
  const actualDepth = parseInt(depthText?.replace(/\D/g, '') || '0');
  expect(actualDepth).toBe(depth);
});

// TODO: Replace XPath with Object Repository when available
Then('new messages experience backpressure', async function () {
  const backpressureStatusXPath = '//div[@id="backpressure-status"]';
  await waits.waitForVisible(page.locator(backpressureStatusXPath));
  await assertions.assertContainsText(page.locator(backpressureStatusXPath), 'active');
});

// TODO: Replace XPath with Object Repository when available
Then('system detects queue saturation condition', async function () {
  const saturationDetectionXPath = '//div[@id="queue-saturation-detected"]';
  await waits.waitForVisible(page.locator(saturationDetectionXPath));
  await assertions.assertContainsText(page.locator(saturationDetectionXPath), 'true');
});

// TODO: Replace XPath with Object Repository when available
Then('backpressure mechanism activates producer rate limiting', async function () {
  const rateLimitingXPath = '//div[@id="producer-rate-limiting"]';
  await waits.waitForVisible(page.locator(rateLimitingXPath));
  await assertions.assertContainsText(page.locator(rateLimitingXPath), 'active');
});

// TODO: Replace XPath with Object Repository when available
Then('queue remains at capacity of {int} messages', async function (capacity: number) {
  const queueCapacityXPath = '