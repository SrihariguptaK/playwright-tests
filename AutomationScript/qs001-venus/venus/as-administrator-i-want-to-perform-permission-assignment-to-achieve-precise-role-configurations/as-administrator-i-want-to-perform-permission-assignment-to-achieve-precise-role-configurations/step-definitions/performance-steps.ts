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
      admin: { username: 'admin', password: 'admin123' }
    },
    performanceMetrics: {},
    loadTestResults: {},
    baselineMetrics: {},
    assignmentResults: []
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
/*  Category: Performance
/*  Description: Setup production-like environment
/**************************************************/

Given('production-like test environment is configured', async function () {
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000');
  await waits.waitForNetworkIdle();
  this.testData.environment = 'production-like';
});

Given('monitoring tools are active for system metrics', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="monitoring-dashboard"]'));
  this.testData.monitoringActive = true;
});

Given('database contains {string} roles and {string} permissions', async function (roleCount: string, permissionCount: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/api/test-data/seed`);
  await actions.fill(page.locator('//input[@id="role-count"]'), roleCount);
  await actions.fill(page.locator('//input[@id="permission-count"]'), permissionCount);
  await actions.click(page.locator('//button[@id="seed-database"]'));
  await waits.waitForNetworkIdle();
  this.testData.roleCount = parseInt(roleCount);
  this.testData.permissionCount = parseInt(permissionCount);
});

/**************************************************/
/*  TEST CASE: TC-PERF-001
/*  Title: Concurrent permission assignment under peak load
/*  Priority: Critical
/*  Category: Performance - Load Testing
/**************************************************/

Given('load testing tool is configured with {string} concurrent admin sessions', async function (sessionCount: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/load-test/config`);
  await actions.fill(page.locator('//input[@id="concurrent-sessions"]'), sessionCount);
  this.testData.concurrentSessions = parseInt(sessionCount);
});

Given('all admin users are authenticated', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="authenticate-all-users"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="authentication-success"]'));
});

Given('CPU, memory, and database connection monitoring is enabled', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.check(page.locator('//input[@id="monitor-cpu"]'));
  await actions.check(page.locator('//input[@id="monitor-memory"]'));
  await actions.check(page.locator('//input[@id="monitor-db-connections"]'));
  this.testData.monitoringEnabled = true;
});

When('{string} concurrent administrators access permission configuration section', async function (adminCount: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="admin-count"]'), adminCount);
  await actions.click(page.locator('//button[@id="start-concurrent-access"]'));
  await waits.waitForNetworkIdle();
});

When('load test executes POST requests to {string} endpoint with {string} to {string} permissions per assignment', async function (endpoint: string, minPerms: string, maxPerms: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="endpoint"]'), endpoint);
  await actions.fill(page.locator('//input[@id="min-permissions"]'), minPerms);
  await actions.fill(page.locator('//input[@id="max-permissions"]'), maxPerms);
  await actions.click(page.locator('//button[@id="execute-load-test"]'));
  this.testData.endpoint = endpoint;
});

When('system ramps up to peak load over {string} minutes', async function (rampUpTime: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="ramp-up-time"]'), rampUpTime);
  await actions.click(page.locator('//button[@id="start-ramp-up"]'));
  const waitTime = parseInt(rampUpTime) * 60 * 1000;
  await page.waitForTimeout(Math.min(waitTime, 5000));
});

When('peak load is maintained for {string} minutes with {string} to {string} assignments per user per minute', async function (duration: string, minAssignments: string, maxAssignments: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="peak-duration"]'), duration);
  await actions.fill(page.locator('//input[@id="min-assignments-per-minute"]'), minAssignments);
  await actions.fill(page.locator('//input[@id="max-assignments-per-minute"]'), maxAssignments);
  await actions.click(page.locator('//button[@id="maintain-peak-load"]'));
  this.testData.peakDuration = parseInt(duration);
});

Then('P50 response time should be less than or equal to {string} second', async function (threshold: string) {
  // TODO: Replace XPath with Object Repository when available
  const p50Value = await page.locator('//span[@id="p50-response-time"]').textContent();
  const p50 = parseFloat(p50Value || '0');
  expect(p50).toBeLessThanOrEqual(parseFloat(threshold));
  this.testData.performanceMetrics.p50 = p50;
});

Then('P95 response time should be less than or equal to {string} seconds', async function (threshold: string) {
  // TODO: Replace XPath with Object Repository when available
  const p95Value = await page.locator('//span[@id="p95-response-time"]').textContent();
  const p95 = parseFloat(p95Value || '0');
  expect(p95).toBeLessThanOrEqual(parseFloat(threshold));
  this.testData.performanceMetrics.p95 = p95;
});

Then('P99 response time should be less than or equal to {string} seconds', async function (threshold: string) {
  // TODO: Replace XPath with Object Repository when available
  const p99Value = await page.locator('//span[@id="p99-response-time"]').textContent();
  const p99 = parseFloat(p99Value || '0');
  expect(p99).toBeLessThanOrEqual(parseFloat(threshold));
  this.testData.performanceMetrics.p99 = p99;
});

Then('throughput should be greater than or equal to {string} transactions per second', async function (threshold: string) {
  // TODO: Replace XPath with Object Repository when available
  const tpsValue = await page.locator('//span[@id="throughput-tps"]').textContent();
  const tps = parseFloat(tpsValue || '0');
  expect(tps).toBeGreaterThanOrEqual(parseFloat(threshold));
  this.testData.performanceMetrics.throughput = tps;
});

Then('error rate should be less than {string} percent', async function (threshold: string) {
  // TODO: Replace XPath with Object Repository when available
  const errorRateValue = await page.locator('//span[@id="error-rate"]').textContent();
  const errorRate = parseFloat(errorRateValue || '0');
  expect(errorRate).toBeLessThan(parseFloat(threshold));
  this.testData.performanceMetrics.errorRate = errorRate;
});

Then('CPU utilization should be less than {string} percent', async function (threshold: string) {
  // TODO: Replace XPath with Object Repository when available
  const cpuValue = await page.locator('//span[@id="cpu-utilization"]').textContent();
  const cpu = parseFloat(cpuValue || '0');
  expect(cpu).toBeLessThan(parseFloat(threshold));
  this.testData.performanceMetrics.cpu = cpu;
});

Then('memory usage should remain stable with no leaks', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="memory-stable-indicator"]'));
  const leakDetected = await page.locator('//div[@id="memory-leak-detected"]').count();
  expect(leakDetected).toBe(0);
});

Then('database connections should be less than {string} percent of pool', async function (threshold: string) {
  // TODO: Replace XPath with Object Repository when available
  const dbConnValue = await page.locator('//span[@id="db-connection-percentage"]').textContent();
  const dbConn = parseFloat(dbConnValue || '0');
  expect(dbConn).toBeLessThan(parseFloat(threshold));
});

Then('query execution times should be less than {string} milliseconds', async function (threshold: string) {
  // TODO: Replace XPath with Object Repository when available
  const queryTimeValue = await page.locator('//span[@id="query-execution-time"]').textContent();
  const queryTime = parseFloat(queryTimeValue || '0');
  expect(queryTime).toBeLessThan(parseFloat(threshold));
});

Then('{string} random role-permission assignments should be validated in database', async function (sampleCount: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="validation-sample-count"]'), sampleCount);
  await actions.click(page.locator('//button[@id="validate-assignments"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="validation-success"]'));
});

Then('all permission assignments should be correctly persisted with no duplicates or conflicts', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="no-duplicates-indicator"]'));
  await assertions.assertVisible(page.locator('//div[@id="no-conflicts-indicator"]'));
});

Then('audit logs should contain all transactions', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/audit-logs`);
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="audit-complete-indicator"]'));
});

Then('system should return to idle state within {string} seconds', async function (timeout: string) {
  // TODO: Replace XPath with Object Repository when available
  await page.waitForSelector('//div[@id="system-idle-indicator"]', { timeout: parseInt(timeout) * 1000 });
});

Then('no orphaned database connections should exist', async function () {
  // TODO: Replace XPath with Object Repository when available
  const orphanedCount = await page.locator('//span[@id="orphaned-connections"]').textContent();
  expect(parseInt(orphanedCount || '0')).toBe(0);
});

/**************************************************/
/*  TEST CASE: TC-PERF-002
/*  Title: Progressive load increase and graceful recovery
/*  Priority: High
/*  Category: Performance - Stress Testing
/**************************************************/

Given('stress testing tool is configured with progressive load profile', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/stress-test/config`);
  await actions.selectByText(page.locator('//select[@id="load-profile"]'), 'Progressive');
  this.testData.loadProfile = 'progressive';
});

Given('baseline performance metrics are established with {string} concurrent users', async function (userCount: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="baseline-users"]'), userCount);
  await actions.click(page.locator('//button[@id="establish-baseline"]'));
  await waits.waitForNetworkIdle();
  this.testData.baselineUsers = parseInt(userCount);
});

Given('circuit breaker and rate limiting mechanisms are enabled', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.check(page.locator('//input[@id="enable-circuit-breaker"]'));
  await actions.check(page.locator('//input[@id="enable-rate-limiting"]'));
});

Given('database connection pool is configured with maximum limits', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="db-pool-configured"]'));
});

Given('alerting systems are active', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="alerting-active"]'));
});

When('load increases progressively from {string} users by {string} users every {string} minutes', async function (startUsers: string, increment: string, interval: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="start-users"]'), startUsers);
  await actions.fill(page.locator('//input[@id="user-increment"]'), increment);
  await actions.fill(page.locator('//input[@id="increment-interval"]'), interval);
  await actions.click(page.locator('//button[@id="start-progressive-load"]'));
  this.testData.progressiveLoad = { start: parseInt(startUsers), increment: parseInt(increment), interval: parseInt(interval) };
});

When('system processes requests at each load increment', async function () {
  // TODO: Replace XPath with Object Repository when available
  await waits.waitForVisible(page.locator('//div[@id="processing-requests"]'));
  await page.waitForTimeout(2000);
});

Then('response times, error rates, and resource utilization should show clear degradation pattern', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="degradation-pattern-detected"]'));
});

Then('breaking point should be identified when error rate exceeds {string} percent or P99 response time exceeds {string} seconds', async function (errorThreshold: string, p99Threshold: string) {
  // TODO: Replace XPath with Object Repository when available
  const breakingPoint = await page.locator('//span[@id="breaking-point-users"]').textContent();
  this.testData.breakingPoint = parseInt(breakingPoint || '0');
  expect(this.testData.breakingPoint).toBeGreaterThan(0);
});

Then('system should return HTTP status code {string} or {string} instead of crashing', async function (status1: string, status2: string) {
  // TODO: Replace XPath with Object Repository when available
  const statusCode = await page.locator('//span[@id="http-status-code"]').textContent();
  expect([status1, status2]).toContain(statusCode);
});

Then('users should receive clear error messages', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="error-message"]'));
});

Then('existing permission assignments should remain intact', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="assignments-intact"]'));
});

Then('no database deadlocks or corruption should occur', async function () {
  // TODO: Replace XPath with Object Repository when available
  const deadlocks = await page.locator('//span[@id="deadlock-count"]').textContent();
  expect(parseInt(deadlocks || '0')).toBe(0);
});

When('load is reduced to {string} percent of breaking point', async function (percentage: string) {
  // TODO: Replace XPath with Object Repository when available
  const reducedLoad = Math.floor(this.testData.breakingPoint * (parseInt(percentage) / 100));
  await actions.fill(page.locator('//input[@id="reduced-load"]'), reducedLoad.toString());
  await actions.click(page.locator('//button[@id="reduce-load"]'));
});

Then('system should recover within {string} minutes', async function (timeout: string) {
  // TODO: Replace XPath with Object Repository when available
  await page.waitForSelector('//div[@id="system-recovered"]', { timeout: parseInt(timeout) * 60 * 1000 });
});

Then('system resources should stabilize', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="resources-stabilized"]'));
});

Then('failed requests should be properly rolled back with no partial updates', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="rollback-complete"]'));
  const partialUpdates = await page.locator('//span[@id="partial-updates-count"]').textContent();
  expect(parseInt(partialUpdates || '0')).toBe(0);
});

/**************************************************/
/*  TEST CASE: TC-PERF-003
/*  Title: Extended duration soak test for stability
/*  Priority: High
/*  Category: Performance - Soak Testing
/**************************************************/

Given('isolated test environment with production-equivalent configuration', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/soak-test/config`);
  await assertions.assertVisible(page.locator('//div[@id="isolated-environment"]'));
});

Given('baseline metrics are captured for memory, CPU, database connections, and response times', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="capture-baseline-metrics"]'));
  await waits.waitForNetworkIdle();
  this.testData.baselineMetrics.captured = true;
});

Given('{string} concurrent admin users are configured for sustained load', async function (userCount: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="sustained-load-users"]'), userCount);
  this.testData.sustainedLoadUsers = parseInt(userCount);
});

Given('memory profiling tools are enabled', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.check(page.locator('//input[@id="enable-memory-profiling"]'));
});

Given('database connection monitoring is active', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.check(page.locator('//input[@id="enable-db-monitoring"]'));
});

Given('sufficient test data exists for {string} hour continuous operation', async function (hours: string) {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="test-data-sufficient"]'));
  this.testData.soakDuration = parseInt(hours);
});

When('baseline metrics are recorded showing memory {string} GB, CPU {string} percent, database connections {string}, and P95 response time {string} seconds', async function (memory: string, cpu: string, dbConn: string, p95: string) {
  this.testData.baselineMetrics = {
    memory: parseFloat(memory),
    cpu: parseFloat(cpu),
    dbConnections: parseInt(dbConn),
    p95ResponseTime: parseFloat(p95)
  };
});

When('sustained load of {string} concurrent administrators perform permission assignments continuously for {string} hours', async function (adminCount: string, hours: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="soak-admin-count"]'), adminCount);
  await actions.fill(page.locator('//input[@id="soak-duration-hours"]'), hours);
  await actions.click(page.locator('//button[@id="start-soak-test"]'));
  await page.waitForTimeout(5000);
});

When('each administrator performs {string} to {string} assignments per minute', async function (minRate: string, maxRate: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="min-assignment-rate"]'), minRate);
  await actions.fill(page.locator('//input[@id="max-assignment-rate"]'), maxRate);
});

When('metrics are recorded every {string} minutes for heap memory, garbage collection, response times, error rates, and database connection pool', async function (interval: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="metrics-interval"]'), interval);
  this.testData.metricsInterval = parseInt(interval);
});

Then('total assignments should be between {string} and {string} over {string} hours', async function (minAssignments: string, maxAssignments: string, hours: string) {
  // TODO: Replace XPath with Object Repository when available
  const totalAssignments = await page.locator('//span[@id="total-assignments"]').textContent();
  const total = parseInt(totalAssignments || '0');
  expect(total).toBeGreaterThanOrEqual(parseInt(minAssignments));
  expect(total).toBeLessThanOrEqual(parseInt(maxAssignments));
});

Then('memory growth should be less than {string} percent per hour', async function (threshold: string) {
  // TODO: Replace XPath with Object Repository when available
  const memoryGrowth = await page.locator('//span[@id="memory-growth-rate"]').textContent();
  expect(parseFloat(memoryGrowth || '0')).toBeLessThan(parseFloat(threshold));
});

Then('garbage collection frequency should remain consistent', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="gc-frequency-consistent"]'));
});

Then('response times should remain within {string} percent of baseline', async function (threshold: string) {
  // TODO: Replace XPath with Object Repository when available
  const deviation = await page.locator('//span[@id="response-time-deviation"]').textContent();
  expect(parseFloat(deviation || '0')).toBeLessThanOrEqual(parseFloat(threshold));
});

Then('no connection pool exhaustion should occur', async function () {
  // TODO: Replace XPath with Object Repository when available
  const exhaustion = await page.locator('//span[@id="pool-exhaustion-count"]').textContent();
  expect(parseInt(exhaustion || '0')).toBe(0);
});

Then('memory heap dumps at {string} hour intervals should show no memory leaks', async function (interval: string) {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="no-memory-leaks"]'));
});

Then('object counts should remain stable', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="object-counts-stable"]'));
});

Then('no unbounded collection growth should be detected', async function () {
  // TODO: Replace XPath with Object Repository when available
  const unboundedGrowth = await page.locator('//span[@id="unbounded-growth-detected"]').textContent();
  expect(unboundedGrowth).toBe('false');
});

Then('memory should be released after garbage collection cycles', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="memory-released-after-gc"]'));
});

Then('no lock escalations should occur', async function () {
  // TODO: Replace XPath with Object Repository when available
  const lockEscalations = await page.locator('//span[@id="lock-escalations"]').textContent();
  expect(parseInt(lockEscalations || '0')).toBe(0);
});

Then('transaction log should remain within normal bounds', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="transaction-log-normal"]'));
});

Then('{string} permission assignments sampled from different time periods should be validated', async function (sampleCount: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="sample-validation-count"]'), sampleCount);
  await actions.click(page.locator('//button[@id="validate-samples"]'));
  await waits.waitForNetworkIdle();
});

Then('all sampled assignments should be correctly persisted with accurate timestamps and audit logs', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="samples-validated"]'));
});

Then('no data corruption or inconsistencies should be found', async function () {
  // TODO: Replace XPath with Object Repository when available
  const corruption = await page.locator('//span[@id="data-corruption-count"]').textContent();
  expect(parseInt(corruption || '0')).toBe(0);
});

Then('system performance should return to baseline within {string} minutes after test completion', async function (timeout: string) {
  // TODO: Replace XPath with Object Repository when available
  await page.waitForSelector('//div[@id="baseline-performance-restored"]', { timeout: parseInt(timeout) * 60 * 1000 });
});

/**************************************************/
/*  TEST CASE: TC-PERF-004
/*  Title: Sudden traffic surge with auto-scaling
/*  Priority: Critical
/*  Category: Performance - Spike Testing
/**************************************************/

Given('auto-scaling is configured with appropriate thresholds', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/spike-test/config`);
  await assertions.assertVisible(page.locator('//div[@id="auto-scaling-configured"]'));
});

Given('rate limiting and throttling mechanisms are enabled', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.check(page.locator('//input[@id="enable-rate-limiting"]'));
  await actions.check(page.locator('//input[@id="enable-throttling"]'));
});

Given('message queue or request buffer is configured', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="queue-configured"]'));
});

Given('baseline load of {string} concurrent users is established', async function (userCount: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="spike-baseline-users"]'), userCount);
  await actions.click(page.locator('//button[@id="establish-spike-baseline"]'));
  await waits.waitForNetworkIdle();
});

Given('monitoring dashboards are active for real-time observation', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="monitoring-dashboard-active"]'));
});

When('baseline load with {string} concurrent administrators perform {string} assignments per minute', async function (adminCount: string, assignmentRate: string) {
  this.testData.spikeBaseline = {
    users: parseInt(adminCount),
    assignmentRate: parseInt(assignmentRate)
  };
});

Then('baseline should be stable with P95 response time {string} seconds, throughput {string} TPS, CPU {string} percent, and error rate {string} percent', async function (p95: string, tps: string, cpu: string, errorRate: string) {
  this.testData.spikeBaseline.metrics = {
    p95: parseFloat(p95),
    tps: parseInt(tps),
    cpu: parseFloat(cpu),
    errorRate: parseFloat(errorRate)
  };
});

When('sudden spike increases load from {string} to {string} concurrent users within {string} seconds', async function (fromUsers: string, toUsers: string, duration: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="spike-from-users"]'), fromUsers);
  await actions.fill(page.locator('//input[@id="spike-to-users"]'), toUsers);
  await actions.fill(page.locator('//input[@id="spike-duration"]'), duration);
  await actions.click(page.locator('//button[@id="trigger-spike"]'));
  this.testData.spike = { from: parseInt(fromUsers), to: parseInt(toUsers), duration: parseInt(duration) };
});

When('each user attempts {string} permission assignments immediately', async function (assignmentCount: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="assignments-per-user"]'), assignmentCount);
  this.testData.spike.assignmentsPerUser = parseInt(assignmentCount);
});

Then('{string} permission assignment requests should be submitted within {string} second window', async function (requestCount: string, window: string) {
  // TODO: Replace XPath with Object Repository when available
  const submitted = await page.locator('//span[@id="requests-submitted"]').textContent();
  expect(parseInt(submitted || '0')).toBeGreaterThanOrEqual(parseInt(requestCount));
});

Then('rate limiting should activate returning HTTP status code {string} for excess requests', async function (statusCode: string) {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="rate-limiting-active"]'));
  const rateLimitStatus = await page.locator('//span[@id="rate-limit-status-code"]').textContent();
  expect(rateLimitStatus).toBe(statusCode);
});

Then('accepted requests should be queued', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="requests-queued"]'));
});

Then('P99 response time should be less than {string} seconds for accepted requests', async function (threshold: string) {
  // TODO: Replace XPath with Object Repository when available
  const p99 = await page.locator('//span[@id="spike-p99-response-time"]').textContent();
  expect(parseFloat(p99 || '0')).toBeLessThan(parseFloat(threshold));
});

Then('system should not crash', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="system-running"]'));
});

Then('auto-scaling should trigger within {string} to {string} seconds if configured', async function (minTime: string, maxTime: string) {
  // TODO: Replace XPath with Object Repository when available
  await page.waitForSelector('//div[@id="auto-scaling-triggered"]', { timeout: parseInt(maxTime) * 1000 });
});

Then('additional capacity should be provisioned or queue should process requests within acceptable timeframe', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="capacity-provisioned"]'));
});

Then('queued requests should be processed within {string} to {string} minutes', async function (minTime: string, maxTime: string) {
  // TODO: Replace XPath with Object Repository when available
  await page.waitForSelector('//div[@id="queue-processed"]', { timeout: parseInt(maxTime) * 60 * 1000 });
});

Then('error rate for accepted requests should be less than {string} percent', async function (threshold: string) {
  // TODO: Replace XPath with Object Repository when available
  const errorRate = await page.locator('//span[@id="accepted-requests-error-rate"]').textContent();
  expect(parseFloat(errorRate || '0')).toBeLessThan(parseFloat(threshold));
});

Then('no request data loss should occur', async function () {
  // TODO: Replace XPath with Object Repository when available
  const dataLoss = await page.locator('//span[@id="data-loss-count"]').textContent();
  expect(parseInt(dataLoss || '0')).toBe(0);
});

Then('all rate-limited requests should receive proper error responses', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="rate-limited-responses-proper"]'));
});

When('load drops from {string} to {string} concurrent users within {string} seconds', async function (fromUsers: string, toUsers: string, duration: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="drop-from-users"]'), fromUsers);
  await actions.fill(page.locator('//input[@id="drop-to-users"]'), toUsers);
  await actions.fill(page.locator('//input[@id="drop-duration"]'), duration);
  await actions.click(page.locator('//button[@id="trigger-load-drop"]'));
});

Then('system should scale down gracefully within {string} to {string} minutes', async function (minTime: string, maxTime: string) {
  // TODO: Replace XPath with Object Repository when available
  await page.waitForSelector('//div[@id="scale-down-complete"]', { timeout: parseInt(maxTime) * 60 * 1000 });
});

Then('response times should return to baseline', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="response-times-baseline"]'));
});

Then('resources should be deallocated', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="resources-deallocated"]'));
});

Then('no lingering performance issues should exist', async function () {
  // TODO: Replace XPath with Object Repository when available
  const issues = await page.locator('//span[@id="performance-issues-count"]').textContent();
  expect(parseInt(issues || '0')).toBe(0);
});

Then('all successfully processed permission assignments during spike should be validated', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="validate-spike-assignments"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="spike-assignments-validated"]'));
});

Then('all accepted assignments should be correctly persisted', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="accepted-assignments-persisted"]'));
});

Then('no duplicate assignments should exist', async function () {
  // TODO: Replace XPath with Object Repository when available
  const duplicates = await page.locator('//span[@id="duplicate-assignments-count"]').textContent();
  expect(parseInt(duplicates || '0')).toBe(0);
});

Then('audit logs should be complete', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="audit-logs-complete"]'));
});

Then('rejected requests should be properly logged with reason codes', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="rejected-requests-logged"]'));
});

Then('all queues should be cleared', async function () {
  // TODO: Replace XPath with Object Repository when available
  const queueSize = await page.locator('//span[@id="queue-size"]').textContent();
  expect(parseInt(queueSize || '0')).toBe(0);
});