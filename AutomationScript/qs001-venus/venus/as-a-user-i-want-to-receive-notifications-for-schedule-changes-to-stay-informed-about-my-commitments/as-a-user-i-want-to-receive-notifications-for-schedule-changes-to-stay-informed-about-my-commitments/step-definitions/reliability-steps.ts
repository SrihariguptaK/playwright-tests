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
    metrics: {},
    notifications: [],
    instances: [],
    systemState: {},
    chaosConfig: {},
    baselineMetrics: {}
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

// ==================== BACKGROUND STEPS ====================

Given('notification service is running in production-like environment', async function () {
  await actions.navigateTo(process.env.NOTIFICATION_SERVICE_URL || 'http://localhost:8080/notification-service');
  await waits.waitForNetworkIdle();
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="service-status"]'));
  const statusText = await page.locator('//div[@id="service-status"]').textContent();
  expect(statusText).toContain('Running');
});

Given('monitoring tools are active to track metrics', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="monitoring-dashboard"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="metrics-panel"]'));
  await assertions.assertVisible(page.locator('//div[@id="health-status"]'));
  this.testData.monitoringActive = true;
});

Given('test user accounts with scheduled appointments are configured', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="test-users"]'));
  await waits.waitForNetworkIdle();
  const userCount = await page.locator('//div[@class="test-user-item"]').count();
  expect(userCount).toBeGreaterThan(0);
  this.testData.testUsersConfigured = true;
});

// ==================== GIVEN STEPS ====================

/**************************************************/
/*  TEST CASE: TC-REL-001
/*  Title: Notification service recovers automatically from database connection failure without notification loss
/*  Priority: Critical
/*  Category: Reliability - Database Failure
/**************************************************/

Given('schedule database is operational with active connections', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="database-status"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="db-connection-status"]'));
  const connectionStatus = await page.locator('//span[@id="db-connection-count"]').textContent();
  const activeConnections = parseInt(connectionStatus || '0');
  expect(activeConnections).toBeGreaterThan(0);
  this.testData.initialDbConnections = activeConnections;
});

Given('message queue system is configured for notification persistence', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="message-queue-config"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="queue-status"]'));
  const queueStatus = await page.locator('//span[@id="queue-persistence-enabled"]').textContent();
  expect(queueStatus).toContain('Enabled');
  this.testData.queueConfigured = true;
});

Given('baseline is established with {int} schedule changes delivered within {int} minute', async function (changeCount: number, timeLimit: number) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="create-baseline"]'));
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="baseline-change-count"]'), changeCount.toString());
  await actions.fill(page.locator('//input[@id="baseline-time-limit"]'), timeLimit.toString());
  await actions.click(page.locator('//button[@id="execute-baseline"]'));
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(timeLimit * 60 * 1000);
  const deliveredCount = await page.locator('//span[@id="baseline-delivered-count"]').textContent();
  expect(parseInt(deliveredCount || '0')).toBe(changeCount);
  this.testData.baselineMetrics = { changeCount, timeLimit, deliveredCount: changeCount };
});

/**************************************************/
/*  TEST CASE: TC-REL-002
/*  Title: System maintains notification delivery when email service experiences high latency
/*  Priority: Critical
/*  Category: Reliability - Email Latency
/**************************************************/

Given('notification service is configured with dual-channel delivery', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="notification-config"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//input[@id="email-channel-enabled"]'));
  await assertions.assertVisible(page.locator('//input[@id="inapp-channel-enabled"]'));
  const emailEnabled = await page.locator('//input[@id="email-channel-enabled"]').isChecked();
  const inappEnabled = await page.locator('//input[@id="inapp-channel-enabled"]').isChecked();
  expect(emailEnabled).toBe(true);
  expect(inappEnabled).toBe(true);
});

Given('email service provider API integration is active', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="email-api-status"]'));
  await waits.waitForNetworkIdle();
  const apiStatus = await page.locator('//span[@id="email-api-connection"]').textContent();
  expect(apiStatus).toContain('Active');
  this.testData.emailApiActive = true;
});

Given('circuit breaker is configured with {int} second timeout threshold', async function (timeoutSeconds: number) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="circuit-breaker-config"]'));
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="circuit-breaker-timeout"]'), timeoutSeconds.toString());
  await actions.click(page.locator('//button[@id="save-circuit-breaker-config"]'));
  await waits.waitForNetworkIdle();
  this.testData.circuitBreakerTimeout = timeoutSeconds;
});

Given('in-app notification service is operational as fallback mechanism', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="inapp-service-status"]'));
  await waits.waitForNetworkIdle();
  const inappStatus = await page.locator('//span[@id="inapp-service-health"]').textContent();
  expect(inappStatus).toContain('Operational');
  this.testData.inappServiceOperational = true;
});

Given('chaos engineering platform is configured with latency injection capability', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="chaos-engineering"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="latency-injection-panel"]'));
  const latencyCapability = await page.locator('//span[@id="latency-injection-enabled"]').textContent();
  expect(latencyCapability).toContain('Enabled');
  this.testData.chaosConfig.latencyInjectionEnabled = true;
});

Given('baseline metrics show {int} percent notification delivery within {int} minute', async function (deliveryPercent: number, timeLimit: number) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="baseline-metrics"]'));
  await waits.waitForNetworkIdle();
  const baselineDeliveryRate = await page.locator('//span[@id="baseline-delivery-rate"]').textContent();
  expect(parseInt(baselineDeliveryRate || '0')).toBeGreaterThanOrEqual(deliveryPercent);
  this.testData.baselineMetrics.deliveryPercent = deliveryPercent;
  this.testData.baselineMetrics.timeLimit = timeLimit;
});

Given('chaos hypothesis is defined as {string}', async function (hypothesis: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//textarea[@id="chaos-hypothesis"]'), hypothesis);
  await actions.click(page.locator('//button[@id="save-hypothesis"]'));
  await waits.waitForNetworkIdle();
  this.testData.chaosConfig.hypothesis = hypothesis;
});

Given('blast radius is limited to {int} percent of user base', async function (blastRadiusPercent: number) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="blast-radius-percent"]'), blastRadiusPercent.toString());
  await actions.click(page.locator('//button[@id="apply-blast-radius"]'));
  await waits.waitForNetworkIdle();
  this.testData.chaosConfig.blastRadiusPercent = blastRadiusPercent;
});

/**************************************************/
/*  TEST CASE: TC-REL-003
/*  Title: Notification service maintains zero notification loss during instance crash with automatic failover
/*  Priority: Critical
/*  Category: Reliability - High Availability
/**************************************************/

Given('notification service is deployed with minimum {int} instances behind load balancer', async function (instanceCount: number) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="service-instances"]'));
  await waits.waitForNetworkIdle();
  const activeInstances = await page.locator('//div[@class="instance-item active"]').count();
  expect(activeInstances).toBeGreaterThanOrEqual(instanceCount);
  this.testData.instances = [];
  for (let i = 0; i < activeInstances; i++) {
    const instanceId = await page.locator(`(//div[@class="instance-item active"])[${i + 1}]//span[@class="instance-id"]`).textContent();
    this.testData.instances.push({ id: instanceId, status: 'active' });
  }
});

Given('load balancer is configured with health checks at {int} second interval', async function (intervalSeconds: number) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="load-balancer-config"]'));
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="health-check-interval"]'), intervalSeconds.toString());
  await actions.click(page.locator('//button[@id="save-lb-config"]'));
  await waits.waitForNetworkIdle();
  this.testData.healthCheckInterval = intervalSeconds;
});

Given('{int} consecutive health check failures trigger instance removal', async function (failureThreshold: number) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="health-check-failure-threshold"]'), failureThreshold.toString());
  await actions.click(page.locator('//button[@id="save-failure-threshold"]'));
  await waits.waitForNetworkIdle();
  this.testData.healthCheckFailureThreshold = failureThreshold;
});

Given('shared message queue is accessible by all service instances', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="shared-queue-status"]'));
  await waits.waitForNetworkIdle();
  const queueAccessibility = await page.locator('//span[@id="queue-shared-access"]').textContent();
  expect(queueAccessibility).toContain('All Instances');
  this.testData.sharedQueueAccessible = true;
});

Given('database connection pooling is configured across all instances', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="connection-pool-config"]'));
  await waits.waitForNetworkIdle();
  const poolingStatus = await page.locator('//span[@id="connection-pooling-status"]').textContent();
  expect(poolingStatus).toContain('Configured');
  this.testData.connectionPoolingConfigured = true;
});

Given('session persistence is disabled to allow stateless failover', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="session-config"]'));
  await waits.waitForNetworkIdle();
  const sessionPersistence = await page.locator('//input[@id="session-persistence-enabled"]').isChecked();
  expect(sessionPersistence).toBe(false);
  this.testData.sessionPersistenceDisabled = true;
});

Given('monitoring is configured for instance health and notification processing metrics', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="monitoring-config"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="instance-health-monitoring"]'));
  await assertions.assertVisible(page.locator('//div[@id="notification-processing-metrics"]'));
  this.testData.monitoringConfigured = true;
});

Given('{string} is operational with active connections', async function (serviceName: string) {
  // TODO: Replace XPath with Object Repository when available
  const serviceXPath = `//div[@id='${serviceName.toLowerCase().replace(/\s+/g, '-')}-status']`;
  await assertions.assertVisible(page.locator(serviceXPath));
  const connectionStatus = await page.locator(`${serviceXPath}//span[@class='connection-status']`).textContent();
  expect(connectionStatus).toContain('Active');
});

Given('{string} is configured for {string}', async function (systemName: string, purpose: string) {
  // TODO: Replace XPath with Object Repository when available
  const systemXPath = `//div[@id='${systemName.toLowerCase().replace(/\s+/g, '-')}-config']`;
  await actions.click(page.locator(`//button[@id='view-${systemName.toLowerCase().replace(/\s+/g, '-')}']`));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator(systemXPath));
});

Given('{string} is configured with {string}', async function (component: string, configuration: string) {
  // TODO: Replace XPath with Object Repository when available
  const componentXPath = `//div[@id='${component.toLowerCase().replace(/\s+/g, '-')}-settings']`;
  await actions.click(page.locator(`//button[@id='configure-${component.toLowerCase().replace(/\s+/g, '-')}']`));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator(componentXPath));
});

// ==================== WHEN STEPS ====================

When('database connections are terminated', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="chaos-actions"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//button[@id="terminate-db-connections"]'));
  await waits.waitForNetworkIdle();
  this.testData.dbConnectionsTerminated = true;
  this.testData.dbTerminationTime = Date.now();
});

When('{int} schedule changes are created while database is down', async function (changeCount: number) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="create-schedule-changes"]'));
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="schedule-change-count"]'), changeCount.toString());
  await actions.click(page.locator('//button[@id="execute-schedule-changes"]'));
  await waits.waitForNetworkIdle();
  this.testData.scheduledChangesWhileDown = changeCount;
});

When('system behavior is monitored for {int} minutes during outage', async function (monitoringMinutes: number) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="start-monitoring"]'));
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(monitoringMinutes * 60 * 1000);
  this.testData.monitoringDuration = monitoringMinutes;
});

When('database connectivity is restored', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="restore-db-connections"]'));
  await waits.waitForNetworkIdle();
  this.testData.dbRestorationTime = Date.now();
});

When('network latency of {int} seconds is injected to email service provider API', async function (latencySeconds: number) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="inject-latency"]'));
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="latency-duration"]'), latencySeconds.toString());
  await actions.selectByText(page.locator('//select[@id="latency-target"]'), 'Email Service Provider API');
  await actions.click(page.locator('//button[@id="apply-latency-injection"]'));
  await waits.waitForNetworkIdle();
  this.testData.chaosConfig.injectedLatency = latencySeconds;
  this.testData.chaosConfig.latencyInjectionTime = Date.now();
});

When('{int} schedule changes are created affecting users in blast radius', async function (changeCount: number) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="create-schedule-changes-blast-radius"]'));
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="blast-radius-change-count"]'), changeCount.toString());
  await actions.click(page.locator('//button[@id="execute-blast-radius-changes"]'));
  await waits.waitForNetworkIdle();
  this.testData.blastRadiusChanges = changeCount;
});

When('latency injection is removed after {int} minutes', async function (durationMinutes: number) {
  await page.waitForTimeout(durationMinutes * 60 * 1000);
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="remove-latency-injection"]'));
  await waits.waitForNetworkIdle();
  this.testData.chaosConfig.latencyRemovalTime = Date.now();
});

When('steady state is monitored for {int} schedule changes with normal latency', async function (changeCount: number) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="monitor-steady-state"]'));
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="steady-state-change-count"]'), changeCount.toString());
  await actions.click(page.locator('//button[@id="start-steady-state-monitoring"]'));
  await waits.waitForNetworkIdle();
  this.testData.steadyStateChanges = changeCount;
});

When('baseline high availability is verified with {int} service instances running', async function (instanceCount: number) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="verify-ha-baseline"]'));
  await waits.waitForNetworkIdle();
  const runningInstances = await page.locator('//div[@class="instance-item running"]').count();
  expect(runningInstances).toBe(instanceCount);
  this.testData.baselineInstanceCount = instanceCount;
});

When('continuous load of {int} schedule changes is generated over {int} minute period', async function (changeCount: number, durationMinutes: number) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="generate-continuous-load"]'));
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="continuous-load-count"]'), changeCount.toString());
  await actions.fill(page.locator('//input[@id="continuous-load-duration"]'), durationMinutes.toString());
  await actions.click(page.locator('//button[@id="start-continuous-load"]'));
  await waits.waitForNetworkIdle();
  this.testData.continuousLoadChanges = changeCount;
  this.testData.continuousLoadDuration = durationMinutes;
});

When('primary instance handling majority of traffic is identified', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="identify-primary-instance"]'));
  await waits.waitForNetworkIdle();
  const primaryInstanceId = await page.locator('//div[@class="instance-item primary"]//span[@class="instance-id"]').textContent();
  this.testData.primaryInstanceId = primaryInstanceId;
});

When('primary notification service instance is forcefully terminated', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="terminate-primary-instance"]'));
  await waits.waitForNetworkIdle();
  this.testData.instanceTerminationTime = Date.now();
});

When('replacement instance is brought up', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="bring-up-replacement-instance"]'));
  await waits.waitForNetworkIdle();
  this.testData.replacementInstanceStartTime = Date.now();
});

When('{int} new schedule changes are created post-recovery', async function (changeCount: number) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="create-post-recovery-changes"]'));
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="post-recovery-change-count"]'), changeCount.toString());
  await actions.click(page.locator('//button[@id="execute-post-recovery-changes"]'));
  await waits.waitForNetworkIdle();
  this.testData.postRecoveryChanges = changeCount;
});

When('{int} schedule changes are created', async function (changeCount: number) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="create-schedule-changes"]'));
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="schedule-change-count"]'), changeCount.toString());
  await actions.click(page.locator('//button[@id="execute-schedule-changes"]'));
  await waits.waitForNetworkIdle();
});

When('{string} is {string}', async function (component: string, action: string) {
  // TODO: Replace XPath with Object Repository when available
  const actionXPath = `//button[@id='${action.toLowerCase().replace(/\s+/g, '-')}-${component.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(actionXPath));
  await waits.waitForNetworkIdle();
});

// ==================== THEN STEPS ====================

Then('notification service should detect database unavailability', async function () {
  // TODO: Replace XPath with Object Repository when available
  await waits.waitForVisible(page.locator('//div[@id="db-unavailability-detected"]'));
  await assertions.assertVisible(page.locator('//div[@id="db-unavailability-detected"]'));
  const detectionMessage = await page.locator('//div[@id="db-unavailability-detected"]').textContent();
  expect(detectionMessage).toContain('Database Unavailable');
});

Then('notification events should be queued to message buffer', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="message-buffer-status"]'));
  const queuedCount = await page.locator('//span[@id="queued-notification-count"]').textContent();
  expect(parseInt(queuedCount || '0')).toBeGreaterThan(0);
  this.testData.queuedNotifications = parseInt(queuedCount || '0');
});

Then('service should remain operational without crash', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="service-status"]'));
  const serviceStatus = await page.locator('//span[@id="service-operational-status"]').textContent();
  expect(serviceStatus).toContain('Operational');
});

Then('health check endpoints should return degraded status', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="check-health-endpoints"]'));
  await waits.waitForNetworkIdle();
  const healthStatus = await page.locator('//span[@id="health-endpoint-status"]').textContent();
  expect(healthStatus).toContain('Degraded');
});

Then('circuit breaker should open to prevent cascading failures', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="circuit-breaker-status"]'));
  const breakerState = await page.locator('//span[@id="circuit-breaker-state"]').textContent();
  expect(breakerState).toContain('Open');
});

Then('service should detect database availability within {int} seconds', async function (detectionSeconds: number) {
  const startTime = Date.now();
  // TODO: Replace XPath with Object Repository when available
  await waits.waitForVisible(page.locator('//div[@id="db-availability-detected"]'));
  const detectionTime = (Date.now() - startTime) / 1000;
  expect(detectionTime).toBeLessThanOrEqual(detectionSeconds);
});

Then('circuit breaker should transition to half-open then closed state', async function () {
  // TODO: Replace XPath with Object Repository when available
  await page.waitForTimeout(2000);
  const halfOpenState = await page.locator('//span[@id="circuit-breaker-state"]').textContent();
  expect(halfOpenState).toContain('Half-Open');
  await page.waitForTimeout(3000);
  const closedState = await page.locator('//span[@id="circuit-breaker-state"]').textContent();
  expect(closedState).toContain('Closed');
});

Then('all {int} queued notifications should be delivered within {int} minutes', async function (notificationCount: number, timeLimit: number) {
  const startTime = Date.now();
  await page.waitForTimeout(timeLimit * 60 * 1000);
  // TODO: Replace XPath with Object Repository when available
  const deliveredCount = await page.locator('//span[@id="delivered-notification-count"]').textContent();
  expect(parseInt(deliveredCount || '0')).toBe(notificationCount);
  const deliveryTime = (Date.now() - startTime) / 1000 / 60;
  expect(deliveryTime).toBeLessThanOrEqual(timeLimit);
});

Then('notification data integrity should be maintained', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="verify-data-integrity"]'));
  await waits.waitForNetworkIdle();
  const integrityStatus = await page.locator('//span[@id="data-integrity-status"]').textContent();
  expect(integrityStatus).toContain('Maintained');
});

Then('new notifications should be delivered within {int} minute', async function (timeLimit: number) {
  await page.waitForTimeout(timeLimit * 60 * 1000);
  // TODO: Replace XPath with Object Repository when available
  const newDeliveredCount = await page.locator('//span[@id="new-delivered-count"]').textContent();
  expect(parseInt(newDeliveredCount || '0')).toBeGreaterThan(0);
});

Then('MTTR should be less than {int} minutes', async function (mttrLimit: number) {
  // TODO: Replace XPath with Object Repository when available
  const mttrValue = await page.locator('//span[@id="mttr-value"]').textContent();
  const mttrMinutes = parseFloat(mttrValue || '0');
  expect(mttrMinutes).toBeLessThan(mttrLimit);
});

Then('notification delivery rate should be {int} percent with {int} total notifications', async function (deliveryRate: number, totalNotifications: number) {
  // TODO: Replace XPath with Object Repository when available
  const actualDeliveryRate = await page.locator('//span[@id="delivery-rate-percent"]').textContent();
  const actualTotalNotifications = await page.locator('//span[@id="total-notifications"]').textContent();
  expect(parseInt(actualDeliveryRate || '0')).toBe(deliveryRate);
  expect(parseInt(actualTotalNotifications || '0')).toBe(totalNotifications);
});

Then('RTO compliance should be verified', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="verify-rto-compliance"]'));
  await waits.waitForNetworkIdle();
  const rtoCompliance = await page.locator('//span[@id="rto-compliance-status"]').textContent();
  expect(rtoCompliance).toContain('Compliant');
});

Then('no duplicate notifications should be sent to users', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="check-duplicate-notifications"]'));
  await waits.waitForNetworkIdle();
  const duplicateCount = await page.locator('//span[@id="duplicate-notification-count"]').textContent();
  expect(parseInt(duplicateCount || '0')).toBe(0);
});

Then('{int} percent dual-channel delivery should occur within {int} minute', async function (deliveryPercent: number, timeLimit: number) {
  await page.waitForTimeout(timeLimit * 60 * 1000);
  // TODO: Replace XPath with Object Repository when available
  const dualChannelRate = await page.locator('//span[@id="dual-channel-delivery-rate"]').textContent();
  expect(parseInt(dualChannelRate || '0')).toBe(deliveryPercent);
});

Then('average email delivery time should be {int} milliseconds', async function (avgTimeMs: number) {
  // TODO: Replace XPath with Object Repository when available
  const actualAvgTime = await page.locator('//span[@id="avg-email-delivery-time"]').textContent();
  expect(parseInt(actualAvgTime || '0')).toBeLessThanOrEqual(avgTimeMs);
});

Then('in-app delivery time should be {int} milliseconds', async function (deliveryTimeMs: number) {
  // TODO: Replace XPath with Object Repository when available
  const actualInappTime = await page.locator('//span[@id="inapp-delivery-time"]').textContent();
  expect(parseInt(actualInappTime || '0')).toBeLessThanOrEqual(deliveryTimeMs);
});

Then('in-app notifications should be delivered within {int} minute for all {int} changes', async function (timeLimit: number, changeCount: number) {
  await page.waitForTimeout(timeLimit * 60 * 1000);
  // TODO: Replace XPath with Object Repository when available
  const inappDeliveredCount = await page.locator('//span[@id="inapp-delivered-count"]').textContent();
  expect(parseInt(inappDeliveredCount || '0')).toBe(changeCount);
});

Then('email delivery attempts should timeout after {int} seconds', async function (timeoutSeconds: number) {
  // TODO: Replace XPath with Object Repository when available
  const emailTimeout = await page.locator('//span[@id="email-timeout-duration"]').textContent();
  expect(parseInt(emailTimeout || '0')).toBe(timeoutSeconds);
});

Then('circuit breaker should open after {int} consecutive timeout failures', async function (failureThreshold: number) {
  // TODO: Replace XPath with Object Repository when available
  const consecutiveFailures = await page.locator('//span[@id="consecutive-timeout-failures"]').textContent();
  expect(parseInt(consecutiveFailures || '0')).toBe(failureThreshold);
  const breakerState = await page.locator('//span[@id="circuit-breaker-state"]').textContent();
  expect(breakerState).toContain('Open');
});

Then('email service should be marked as degraded', async function () {
  // TODO: Replace XPath with Object Repository when available
  const emailServiceStatus = await page.locator('//span[@id="email-service-status"]').textContent();
  expect(emailServiceStatus).toContain('Degraded');
});

Then('retry queue should be activated', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="retry-queue-status"]'));
  const retryQueueActive = await page.locator('//span[@id="retry-queue-active"]').textContent();
  expect(retryQueueActive).toContain('Active');
});

Then('retry attempts should follow exponential backoff pattern with intervals {string}', async function (intervals: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="view-retry-intervals"]'));
  await waits.waitForNetworkIdle();
  const actualIntervals = await page.locator('//span[@id="retry-interval-pattern"]').textContent();
  expect(actualIntervals).toContain(intervals);
});

Then('maximum {int} retry attempts per notification should occur', async function (maxRetries: number) {
  // TODO: Replace XPath with Object Repository when available
  const actualMaxRetries = await page.locator('//span[@id="max-retry-attempts"]').textContent();
  expect(parseInt(actualMaxRetries || '0')).toBe(maxRetries);
});

Then('no system overload should occur', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="check-system-load"]'));
  await waits.waitForNetworkIdle();
  const systemOverload = await page.locator('//span[@id="system-overload-status"]').textContent();
  expect(systemOverload).toContain('No Overload');
});

Then('email API latency should return to less than {int} milliseconds', async function (latencyMs: number) {
  // TODO: Replace XPath with Object Repository when available
  const currentLatency = await page.locator('//span[@id="email-api-latency"]').textContent();
  expect(parseInt(currentLatency || '0')).toBeLessThan(latencyMs);
});

Then('circuit breaker should transition to half-open state within {int} seconds', async function (transitionSeconds: number) {
  const startTime = Date.now();
  // TODO: Replace XPath with Object Repository when available
  await page.waitForTimeout(transitionSeconds * 1000);
  const breakerState = await page.locator('//span[@id="circuit-breaker-state"]').textContent();
  expect(breakerState).toContain('Half-Open');
  const transitionTime = (Date.now() - startTime) / 1000;
  expect(transitionTime).toBeLessThanOrEqual(transitionSeconds);
});

Then('all {int} email notifications should be delivered within {int} minutes post-recovery', async function (notificationCount: number, timeLimit: number) {
  await page.waitForTimeout(timeLimit * 60 * 1000);
  // TODO: Replace XPath with Object Repository when available
  const emailDeliveredCount = await page.locator('//span[@id="email-delivered-post-recovery"]').textContent();
  expect(parseInt(emailDeliveredCount || '0')).toBe(notificationCount);
});

Then('users should receive exactly {int} email and {int} in-app notification per change', async function (emailCount: number, inappCount: number) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="verify-notification-counts"]'));
  await waits.waitForNetworkIdle();
  const emailPerChange = await page.locator('//span[@id="email-per-change"]').textContent();
  const inappPerChange = await page.locator('//span[@id="inapp-per-change"]').textContent();
  expect(parseInt(emailPerChange || '0')).toBe(emailCount);
  expect(parseInt(inappPerChange || '0')).toBe(inappCount);
});

Then('chaos hypothesis should be confirmed', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="confirm-chaos-hypothesis"]'));
  await waits.waitForNetworkIdle();
  const hypothesisConfirmed = await page.locator('//span[@id="hypothesis-confirmation"]').textContent();
  expect(hypothesisConfirmed).toContain('Confirmed');
});

Then('overall notification success rate should be {int} percent', async function (successRate: number) {
  // TODO: Replace XPath with Object Repository when available
  const actualSuccessRate = await page.locator('//span[@id="overall-success-rate"]').textContent();
  expect(parseInt(actualSuccessRate || '0')).toBe(successRate);
});

Then('MTTR should be {int} seconds', async function (mttrSeconds: number) {
  // TODO: Replace XPath with Object Repository when available
  const actualMttr = await page.locator('//span[@id="mttr-seconds"]').textContent();
  expect(parseInt(actualMttr || '0')).toBeLessThanOrEqual(mttrSeconds);
});

Then('load balancer should distribute traffic evenly at {int} percent each', async function (trafficPercent: number) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="view-traffic-distribution"]'));
  await waits.waitForNetworkIdle();
  const instanceCount = await page.locator('//div[@class="instance-traffic"]').count();
  for (let i = 0; i < instanceCount; i++) {
    const instanceTraffic = await page.locator(`(//div[@class="instance-traffic"])[${i + 1}]//span[@class="traffic-percent"]`).textContent();
    const traffic = parseInt(instanceTraffic || '0');
    expect(traffic).toBeGreaterThanOrEqual(trafficPercent - 5);
    expect(traffic).toBeLessThanOrEqual(trafficPercent + 5);
  }
});

Then('health checks should pass every {int} seconds for all instances', async function (intervalSeconds: number) {
  // TODO: Replace XPath with Object Repository when available
  await page.waitForTimeout(intervalSeconds * 1000 * 3);
  const healthChecksPassed = await page.locator('//div[@class="health-check-passed"]').count();
  expect(healthChecksPassed).toBeGreaterThan(0);
});

Then('notifications should process normally across all instances', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="verify-normal-processing"]'));
  await waits.waitForNetworkIdle();
  const processingStatus = await page.locator('//span[@id="processing-status"]').textContent();
  expect(processingStatus).toContain('Normal');
});

Then('delivery rate should be {int} percent within {int} minute SLA', async function (deliveryRate: number, slaMinutes: number) {
  await page.waitForTimeout(slaMinutes * 60 * 1000);
  // TODO: Replace XPath with Object Repository when available
  const actualDeliveryRate = await page.locator('//span[@id="sla-delivery-rate"]').textContent();
  expect(parseInt(actualDeliveryRate || '0')).toBe(deliveryRate);
});

Then('{int} to {int} notifications should be in active processing state', async function (minNotifications: number, maxNotifications: number) {
  // TODO: Replace XPath with Object Repository when available
  const activeProcessingCount = await page.locator('//div[@class="notification-processing"]').count();
  expect(activeProcessingCount).toBeGreaterThanOrEqual(minNotifications);
  expect(activeProcessingCount).toBeLessThanOrEqual(maxNotifications);
});

Then('primary instance should crash immediately', async function () {
  // TODO: Replace XPath with Object Repository when available
  await page.waitForTimeout(1000);
  const primaryInstanceStatus = await page.locator('//div[@class="instance-item primary"]//span[@class="instance-status"]').textContent();
  expect(primaryInstanceStatus).toContain('Crashed');
});

Then('health check should fail for crashed instance', async function () {
  // TODO: Replace XPath with Object Repository when available
  await page.waitForTimeout(5000);
  const crashedInstanceHealth = await page.locator('//div[@class="instance-item crashed"]//span[@class="health-check-status"]').textContent();
  expect(crashedInstanceHealth).toContain('Failed');
});

Then('in-flight notifications should remain in message queue as unacknowledged', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="view-message-queue"]'));
  await waits.waitForNetworkIdle();
  const unacknowledgedCount = await page.locator('//span[@id="unacknowledged-message-count"]').textContent();
  expect(parseInt(unacknowledgedCount || '0')).toBeGreaterThan(0);
});

Then('load balancer should detect failure within {int} seconds', async function (detectionSeconds: number) {
  const startTime = Date.now();
  // TODO: Replace XPath with Object Repository when available
  await page.waitForTimeout(detectionSeconds * 1000);
  const failureDetected = await page.locator('//div[@id="lb-failure-detection"]').textContent();
  expect(failureDetected).toContain('Detected');
  const detectionTime = (Date.now() - startTime) / 1000;
  expect(detectionTime).toBeLessThanOrEqual(detectionSeconds);
});

Then('failed instance should be removed from pool', async function () {
  // TODO: Replace XPath with Object Repository when available
  await page.waitForTimeout(2000);
  const poolInstances = await page.locator('//div[@class="instance-item in-pool"]').count();
  expect(poolInstances).toBeLessThan(this.testData.baselineInstanceCount);
});

Then('traffic should be redistributed to {int} remaining instances', async function (remainingInstances: number) {
  // TODO: Replace XPath with Object Repository when available
  await page.waitForTimeout(3000);
  const activeInstances = await page.locator('//div[@class="instance-item active in-pool"]').count();
  expect(activeInstances).toBe(remainingInstances);
});

Then('message queue should reassign unacknowledged notifications within {int} seconds', async function (reassignSeconds: number) {
  const startTime = Date.now();
  await page.waitForTimeout(reassignSeconds * 1000);
  // TODO: Replace XPath with Object Repository when available
  const reassignedCount = await page.locator('//span[@id="reassigned-notification-count"]').textContent();
  expect(parseInt(reassignedCount || '0')).toBeGreaterThan(0);
  const reassignTime = (Date.now() - startTime) / 1000;
  expect(reassignTime).toBeLessThanOrEqual(reassignSeconds);
});

Then('no notifications should be lost', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="verify-notification-loss"]'));
  await waits.waitForNetworkIdle();
  const lostNotifications = await page.locator('//span[@id="lost-notification-count"]').textContent();
  expect(parseInt(lostNotifications || '0')).toBe(0);
});

Then('notification delivery should continue with less than {int} second interruption', async function (interruptionSeconds: number) {
  // TODO: Replace XPath with Object Repository when available
  const actualInterruption = await page.locator('//span[@id="delivery-interruption-duration"]').textContent();
  expect(parseInt(actualInterruption || '0')).toBeLessThan(interruptionSeconds);
});

Then('all {int} notifications should be delivered successfully', async function (notificationCount: number) {
  // TODO: Replace XPath with Object Repository when available
  const successfulDeliveries = await page.locator('//span[@id="successful-delivery-count"]').textContent();
  expect(parseInt(successfulDeliveries || '0')).toBe(notificationCount);
});

Then('new instance should start within {int} seconds', async function (startSeconds: number) {
  const startTime = Date.now();
  await page.waitForTimeout(startSeconds * 1000);
  // TODO: Replace XPath with Object Repository when available
  const newInstanceStatus = await page.locator('//div[@class="instance-item new"]//span[@class="instance-status"]').textContent();
  expect(newInstanceStatus).toContain('Running');
  const startupTime = (Date.now() - startTime) / 1000;
  expect(startupTime).toBeLessThanOrEqual(startSeconds);
});

Then('new instance should pass health checks', async function () {
  // TODO: Replace XPath with Object Repository when available
  await page.waitForTimeout(5000);
  const newInstanceHealth = await page.locator('//div[@class="instance-item new"]//span[@class="health-check-status"]').textContent();
  expect(newInstanceHealth).toContain('Passed');
});

Then('new instance should be added to load balancer pool', async function () {
  // TODO: Replace XPath with Object Repository when available
  await page.waitForTimeout(3000);
  const poolInstances = await page.locator('//div[@class="instance-item in-pool"]').count();
  expect(poolInstances).toBe(this.testData.baselineInstanceCount);
});

Then('traffic should be rebalanced to {int} instances', async function (instanceCount: number) {
  // TODO: Replace XPath with Object Repository when available
  await page.waitForTimeout(5000);
  const activeInstances = await page.locator('//div[@class="instance-item active in-pool"]').count();
  expect(activeInstances).toBe(instanceCount);
});

Then('service availability should be {float} percent', async function (availabilityPercent: number) {
  // TODO: Replace XPath with Object Repository when available
  const actualAvailability = await page.locator('//span[@id="service-availability-percent"]').textContent();
  expect(parseFloat(actualAvailability || '0')).toBeGreaterThanOrEqual(availabilityPercent);
});

Then('MTTR should be {int} seconds for failover time', async function (mttrSeconds: number) {
  // TODO: Replace XPath with Object Repository when available
  const failoverMttr = await page.locator('//span[@id="failover-mttr-seconds"]').textContent();
  expect(parseInt(failoverMttr || '0')).toBeLessThanOrEqual(mttrSeconds);
});

Then('RPO should be {int} with zero notification loss', async function (rpoValue: number) {
  // TODO: Replace XPath with Object Repository when available
  const actualRpo = await page.locator('//span[@id="rpo-value"]').textContent();
  expect(parseInt(actualRpo || '0')).toBe(rpoValue);
  const lostNotifications = await page.locator('//span[@id="lost-notification-count"]').textContent();
  expect(parseInt(lostNotifications || '0')).toBe(0);
});

Then('RTO should be {int} seconds for failover time', async function (rtoSeconds: number) {
  // TODO: Replace XPath with Object Repository when available
  const actualRto = await page.locator('//span[@id="rto-seconds"]').textContent();
  expect(parseInt(actualRto || '0')).toBeLessThanOrEqual(rtoSeconds);
});

Then('failover event should be logged with complete metrics', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="view-failover-logs"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="failover-event-log"]'));
  const metricsLogged = await page.locator('//div[@class="failover-metric"]').count();
  expect(metricsLogged).toBeGreaterThan(0);
});

Then('the {string} should be {string}', async function (element: string, expectedState: string) {
  // TODO: Replace XPath with Object Repository when available
  const elementXPath = `//div[@id='${element.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(elementXPath));
  const actualState = await page.locator(elementXPath).textContent();
  expect(actualState).toContain(expectedState);
});

Then('I should see {string}', async function (text: string) {
  await assertions.assertContainsText(page.locator('body'), text);
});

Then('{string} should be {string}', async function (metric: string, expectedValue: string) {
  // TODO: Replace XPath with Object Repository when available
  const metricXPath = `//span[@id='${metric.toLowerCase().replace(/\s+/g, '-')}']`;
  const actualValue = await page.locator(metricXPath).textContent();
  expect(actualValue).toContain(expectedValue);
});

Then('{string} should {string}', async function (component: string, expectedBehavior: string) {
  // TODO: Replace XPath with Object Repository when available
  const componentXPath = `//div[@id='${component.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(componentXPath));
});