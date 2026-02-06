import { Given, When, Then, Before, After } from '@cucumber/cucumber';
import { Page, Browser, BrowserContext, chromium, expect } from '@playwright/test';
import { BasePage } from '../pages/BasePage';
import { HomePage } from '../pages/HomePage';
import { GenericActions } from '../utils/GenericActions';
import { AssertionHelpers } from '../utils/AssertionHelpers';
import { WaitHelpers } from '../utils/WaitHelpers';

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
    performanceMetrics: {
      clientValidationP95: 100,
      serverValidationP95: 500,
      serverValidationP99: 1000,
      minThroughput: 50,
      maxErrorRate: 0.1,
      maxCpuUtilization: 70,
      maxDbPoolCapacity: 80
    },
    loadConfig: {
      baselineUsers: 100,
      rampUpMinutes: 2,
      steadyStateMinutes: 8,
      totalDurationMinutes: 10
    },
    stressConfig: {
      startUsers: 100,
      incrementUsers: 50,
      incrementIntervalMinutes: 3,
      breakingPointP95: 2000,
      breakingPointErrorRate: 5
    },
    soakConfig: {
      sustainedUsers: 75,
      durationHours: 4,
      metricsIntervalMinutes: 15,
      maxResponseVariance: 10
    },
    spikeConfig: {
      baselineUsers: 20,
      spikeUsers: 300,
      spikeTimeSeconds: 30,
      autoScaleTriggerSeconds: 60,
      instanceProvisionMinutes: 5,
      peakDurationMinutes: 10
    }
  };
  
  this.performanceResults = {
    responseTimesP50: [],
    responseTimesP95: [],
    responseTimesP99: [],
    throughput: [],
    errorRate: [],
    cpuUtilization: [],
    memoryUsage: [],
    dbPoolUsage: [],
    timestamps: []
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

/**************************************************/
/*  BACKGROUND STEPS - ALL TEST CASES
/*  Category: Setup
/**************************************************/

Given('test environment with validation features is deployed and accessible', async function () {
  await actions.navigateTo(process.env.TEST_ENV_URL || 'https://validation-test.example.com');
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="validation-system"]'));
});

Given('monitoring tools are configured for response time, CPU, and memory metrics', async function () {
  await actions.navigateTo(`${process.env.MONITORING_URL || 'https://monitoring.example.com'}/dashboard`);
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="metrics-dashboard"]'));
  await assertions.assertVisible(page.locator('//div[@id="response-time-chart"]'));
  await assertions.assertVisible(page.locator('//div[@id="cpu-metrics"]'));
  await assertions.assertVisible(page.locator('//div[@id="memory-metrics"]'));
});

Given('test data set with valid and invalid input combinations is prepared', async function () {
  this.testDataSet = {
    validInputs: [
      { field: 'email', value: 'test@example.com' },
      { field: 'phone', value: '+1234567890' },
      { field: 'zipcode', value: '12345' }
    ],
    invalidInputs: [
      { field: 'email', value: 'invalid-email' },
      { field: 'phone', value: '123' },
      { field: 'zipcode', value: 'ABCDE' }
    ]
  };
});

/**************************************************/
/*  TEST CASE: TC-PERF-001
/*  Title: Validation performance under concurrent user load
/*  Priority: Critical
/*  Category: Performance - Load Testing
/**************************************************/

Given('load testing tool is configured with JMeter or K6 or Gatling', async function () {
  await actions.navigateTo(`${process.env.LOAD_TEST_URL || 'https://loadtest.example.com'}/configure`);
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//select[@id="load-tool-selector"]'));
  await actions.selectByText(page.locator('//select[@id="load-tool-selector"]'), 'K6');
  await waits.waitForNetworkIdle();
});

Given('baseline performance metrics are established for single-user scenario', async function () {
  await actions.click(page.locator('//button[@id="run-baseline-test"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="baseline-results"]'));
  
  const baselineP95 = await page.locator('//span[@id="baseline-p95"]').textContent();
  this.baselineMetrics = {
    p95ResponseTime: parseFloat(baselineP95 || '0'),
    timestamp: new Date().toISOString()
  };
});

When('load test is configured to simulate {int} concurrent users submitting forms with mixed valid and invalid inputs over {int} minutes', async function (users: number, duration: number) {
  await actions.fill(page.locator('//input[@id="concurrent-users"]'), users.toString());
  await actions.fill(page.locator('//input[@id="test-duration-minutes"]'), duration.toString());
  await actions.check(page.locator('//input[@id="mixed-input-mode"]'));
  await waits.waitForNetworkIdle();
});

When('load test script is configured with ramp-up period of {int} minutes and steady state of {int} minutes', async function (rampUp: number, steadyState: number) {
  await actions.fill(page.locator('//input[@id="ramp-up-minutes"]'), rampUp.toString());
  await actions.fill(page.locator('//input[@id="steady-state-minutes"]'), steadyState.toString());
  await waits.waitForNetworkIdle();
});

When('load test is executed', async function () {
  await actions.click(page.locator('//button[@id="execute-load-test"]'));
  await waits.waitForVisible(page.locator('//div[@id="test-in-progress"]'));
  
  const testDuration = this.testData.loadConfig.totalDurationMinutes * 60 * 1000;
  await page.waitForTimeout(testDuration);
  
  await waits.waitForVisible(page.locator('//div[@id="test-completed"]'));
  await waits.waitForNetworkIdle();
});

Then('client-side validation should respond within {int} milliseconds at P95 for all field validations', async function (maxMs: number) {
  const clientP95Element = page.locator('//span[@id="client-validation-p95"]');
  await waits.waitForVisible(clientP95Element);
  const clientP95 = parseFloat(await clientP95Element.textContent() || '0');
  expect(clientP95).toBeLessThanOrEqual(maxMs);
});

Then('server-side validation should complete within {int} milliseconds at P95', async function (maxMs: number) {
  const serverP95Element = page.locator('//span[@id="server-validation-p95"]');
  await waits.waitForVisible(serverP95Element);
  const serverP95 = parseFloat(await serverP95Element.textContent() || '0');
  expect(serverP95).toBeLessThanOrEqual(maxMs);
});

Then('server-side validation should complete within {int} milliseconds at P99', async function (maxMs: number) {
  const serverP99Element = page.locator('//span[@id="server-validation-p99"]');
  await waits.waitForVisible(serverP99Element);
  const serverP99 = parseFloat(await serverP99Element.textContent() || '0');
  expect(serverP99).toBeLessThanOrEqual(maxMs);
});

Then('throughput should be minimum {int} transactions per second', async function (minTps: number) {
  const throughputElement = page.locator('//span[@id="throughput-tps"]');
  await waits.waitForVisible(throughputElement);
  const throughput = parseFloat(await throughputElement.textContent() || '0');
  expect(throughput).toBeGreaterThanOrEqual(minTps);
});

Then('error rate should remain below {float} percent', async function (maxErrorRate: number) {
  const errorRateElement = page.locator('//span[@id="error-rate-percent"]');
  await waits.waitForVisible(errorRateElement);
  const errorRate = parseFloat(await errorRateElement.textContent() || '0');
  expect(errorRate).toBeLessThan(maxErrorRate);
});

Then('all validation rules should execute correctly with {int} percent accuracy', async function (accuracy: number) {
  const accuracyElement = page.locator('//span[@id="validation-accuracy"]');
  await waits.waitForVisible(accuracyElement);
  const actualAccuracy = parseFloat(await accuracyElement.textContent() || '0');
  expect(actualAccuracy).toBeGreaterThanOrEqual(accuracy);
});

Then('no false positives or false negatives should occur', async function () {
  const falsePositivesElement = page.locator('//span[@id="false-positives-count"]');
  const falseNegativesElement = page.locator('//span[@id="false-negatives-count"]');
  
  await waits.waitForVisible(falsePositivesElement);
  await waits.waitForVisible(falseNegativesElement);
  
  const falsePositives = parseInt(await falsePositivesElement.textContent() || '0');
  const falseNegatives = parseInt(await falseNegativesElement.textContent() || '0');
  
  expect(falsePositives).toBe(0);
  expect(falseNegatives).toBe(0);
});

Then('CPU utilization should stay below {int} percent', async function (maxCpu: number) {
  const cpuElement = page.locator('//span[@id="cpu-utilization-percent"]');
  await waits.waitForVisible(cpuElement);
  const cpuUtilization = parseFloat(await cpuElement.textContent() || '0');
  expect(cpuUtilization).toBeLessThan(maxCpu);
});

Then('memory usage should be stable without leaks', async function () {
  await assertions.assertVisible(page.locator('//div[@id="memory-analysis"]'));
  const memoryLeakDetected = await page.locator('//span[@id="memory-leak-detected"]').textContent();
  expect(memoryLeakDetected).toBe('false');
});

Then('database connection pool should be below {int} percent capacity', async function (maxCapacity: number) {
  const dbPoolElement = page.locator('//span[@id="db-pool-usage-percent"]');
  await waits.waitForVisible(dbPoolElement);
  const dbPoolUsage = parseFloat(await dbPoolElement.textContent() || '0');
  expect(dbPoolUsage).toBeLessThan(maxCapacity);
});

Then('all validation responses should be logged and analyzed', async function () {
  await actions.click(page.locator('//button[@id="view-validation-logs"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="validation-logs-table"]'));
  
  const logCount = await page.locator('//table[@id="validation-logs"]//tr').count();
  expect(logCount).toBeGreaterThan(0);
});

Then('performance metrics report should be generated with P50, P95, and P99 response times', async function () {
  await actions.click(page.locator('//button[@id="generate-performance-report"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="performance-report"]'));
  await assertions.assertVisible(page.locator('//span[@id="p50-response-time"]'));
  await assertions.assertVisible(page.locator('//span[@id="p95-response-time"]'));
  await assertions.assertVisible(page.locator('//span[@id="p99-response-time"]'));
});

Then('system should return to idle state with no resource leaks', async function () {
  await page.waitForTimeout(60000);
  
  const cpuElement = page.locator('//span[@id="cpu-utilization-percent"]');
  const memoryElement = page.locator('//span[@id="memory-usage-mb"]');
  
  const cpuIdle = parseFloat(await cpuElement.textContent() || '0');
  const memoryStable = await page.locator('//span[@id="memory-stable"]').textContent();
  
  expect(cpuIdle).toBeLessThan(10);
  expect(memoryStable).toBe('true');
});

/**************************************************/
/*  TEST CASE: TC-PERF-002
/*  Title: Validation system breaking point and graceful degradation
/*  Priority: High
/*  Category: Performance - Stress Testing
/**************************************************/

Given('validation system is deployed in test environment', async function () {
  await actions.navigateTo(process.env.TEST_ENV_URL || 'https://validation-test.example.com');
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="validation-system"]'));
});

Given('load testing tool is configured for progressive load increase', async function () {
  await actions.navigateTo(`${process.env.LOAD_TEST_URL || 'https://loadtest.example.com'}/stress-test`);
  await waits.waitForNetworkIdle();
  await actions.selectByText(page.locator('//select[@id="test-type"]'), 'Progressive Stress Test');
  await waits.waitForNetworkIdle();
});

Given('system monitoring and alerting are configured', async function () {
  await actions.navigateTo(`${process.env.MONITORING_URL || 'https://monitoring.example.com'}/alerts`);
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="alert-configuration"]'));
  await actions.check(page.locator('//input[@id="enable-alerts"]'));
});

Given('incident response procedures are documented', async function () {
  await actions.navigateTo(`${process.env.DOCS_URL || 'https://docs.example.com'}/incident-response`);
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="incident-procedures"]'));
});

Given('database and application logs are enabled for detailed diagnostics', async function () {
  await actions.navigateTo(`${process.env.ADMIN_URL || 'https://admin.example.com'}/logging`);
  await waits.waitForNetworkIdle();
  await actions.check(page.locator('//input[@id="enable-debug-logging"]'));
  await actions.check(page.locator('//input[@id="enable-db-query-logging"]'));
  await actions.click(page.locator('//button[@id="apply-logging-config"]'));
  await waits.waitForNetworkIdle();
});

When('load test starts with baseline load of {int} concurrent users', async function (users: number) {
  await actions.fill(page.locator('//input[@id="baseline-users"]'), users.toString());
  await actions.click(page.locator('//button[@id="start-stress-test"]'));
  await waits.waitForVisible(page.locator('//div[@id="stress-test-running"]'));
});

When('load progressively increases by {int} users every {int} minutes until system failure or degradation', async function (increment: number, intervalMinutes: number) {
  await actions.fill(page.locator('//input[@id="user-increment"]'), increment.toString());
  await actions.fill(page.locator('//input[@id="increment-interval-minutes"]'), intervalMinutes.toString());
  await actions.check(page.locator('//input[@id="auto-increment-enabled"]'));
  await waits.waitForNetworkIdle();
  
  this.stressTestConfig = {
    increment: increment,
    intervalMinutes: intervalMinutes,
    startTime: new Date()
  };
});

Then('load should increase systematically through {int}, {int}, {int}, {int}, and {int} plus users', async function (level1: number, level2: number, level3: number, level4: number, level5: number) {
  const expectedLevels = [level1, level2, level3, level4, level5];
  
  for (const level of expectedLevels) {
    await waits.waitForVisible(page.locator(`//div[@id="current-user-load"][contains(text(),'${level}')]`));
    await page.waitForTimeout(3 * 60 * 1000);
  }
});

Then('metrics should be captured at each load level', async function () {
  await assertions.assertVisible(page.locator('//div[@id="load-level-metrics"]'));
  
  const metricsRows = await page.locator('//table[@id="load-metrics"]//tr').count();
  expect(metricsRows).toBeGreaterThan(5);
});

Then('breaking point should be identified when P95 exceeds {int} milliseconds or error rate exceeds {int} percent', async function (maxP95: number, maxErrorRate: number) {
  await waits.waitForVisible(page.locator('//div[@id="breaking-point-detected"]'));
  
  const breakingP95 = parseFloat(await page.locator('//span[@id="breaking-point-p95"]').textContent() || '0');
  const breakingErrorRate = parseFloat(await page.locator('//span[@id="breaking-point-error-rate"]').textContent() || '0');
  
  const breakingPointReached = breakingP95 > maxP95 || breakingErrorRate > maxErrorRate;
  expect(breakingPointReached).toBe(true);
});

Then('response time degradation pattern should be documented', async function () {
  await actions.click(page.locator('//button[@id="export-degradation-pattern"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="degradation-report"]'));
});

Then('system should implement rate limiting or queuing at breaking point', async function () {
  await assertions.assertVisible(page.locator('//div[@id="rate-limiting-active"]'));
  const rateLimitStatus = await page.locator('//span[@id="rate-limit-status"]').textContent();
  expect(rateLimitStatus).toBe('ACTIVE');
});

Then('system should return HTTP {int} or {int} status codes with retry-after headers', async function (status1: number, status2: number) {
  await actions.click(page.locator('//button[@id="view-http-responses"]'));
  await waits.waitForNetworkIdle();
  
  const statusCodes = await page.locator('//div[@id="http-status-codes"]').textContent();
  const hasExpectedStatus = statusCodes?.includes(status1.toString()) || statusCodes?.includes(status2.toString());
  expect(hasExpectedStatus).toBe(true);
});

Then('no system crashes or data corruption should occur', async function () {
  const systemStatus = await page.locator('//span[@id="system-status"]').textContent();
  const dataIntegrity = await page.locator('//span[@id="data-integrity-check"]').textContent();
  
  expect(systemStatus).not.toBe('CRASHED');
  expect(dataIntegrity).toBe('VALID');
});

Then('system behavior should be observed at breaking point for {int} minutes', async function (minutes: number) {
  await page.waitForTimeout(minutes * 60 * 1000);
  await assertions.assertVisible(page.locator('//div[@id="observation-complete"]'));
});

Then('no cascading failures to dependent services should occur', async function () {
  await actions.click(page.locator('//button[@id="check-dependent-services"]'));
  await waits.waitForNetworkIdle();
  
  const dependentServicesStatus = await page.locator('//span[@id="dependent-services-status"]').textContent();
  expect(dependentServicesStatus).toBe('HEALTHY');
});

Then('database connections should be managed properly', async function () {
  const dbConnectionStatus = await page.locator('//span[@id="db-connection-status"]').textContent();
  const activeConnections = parseInt(await page.locator('//span[@id="active-db-connections"]').textContent() || '0');
  
  expect(dbConnectionStatus).toBe('MANAGED');
  expect(activeConnections).toBeGreaterThan(0);
});

Then('circuit breakers should activate if configured', async function () {
  const circuitBreakerElement = page.locator('//span[@id="circuit-breaker-status"]');
  if (await circuitBreakerElement.count() > 0) {
    const status = await circuitBreakerElement.textContent();
    expect(status).toMatch(/OPEN|HALF_OPEN/);
  }
});

When('load is reduced back to normal levels', async function () {
  await actions.click(page.locator('//button[@id="reduce-load"]'));
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator('//div[@id="load-reduction-in-progress"]'));
});

Then('system should recover to normal performance within {int} minutes', async function (minutes: number) {
  await page.waitForTimeout(minutes * 60 * 1000);
  
  const recoveryStatus = await page.locator('//span[@id="recovery-status"]').textContent();
  expect(recoveryStatus).toBe('RECOVERED');
});

Then('response times should return to baseline', async function () {
  const currentP95 = parseFloat(await page.locator('//span[@id="current-p95"]').textContent() || '0');
  const baselineP95 = this.baselineMetrics?.p95ResponseTime || 500;
  
  expect(currentP95).toBeLessThanOrEqual(baselineP95 * 1.1);
});

Then('no residual errors or resource leaks should exist', async function () {
  const errorCount = parseInt(await page.locator('//span[@id="residual-errors"]').textContent() || '0');
  const resourceLeaks = await page.locator('//span[@id="resource-leaks-detected"]').textContent();
  
  expect(errorCount).toBe(0);
  expect(resourceLeaks).toBe('false');
});

Then('breaking point should be documented with specific metrics', async function () {
  await actions.click(page.locator('//button[@id="document-breaking-point"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="breaking-point-documentation"]'));
});

Then('stress test report should be generated with capacity recommendations', async function () {
  await actions.click(page.locator('//button[@id="generate-stress-report"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="stress-test-report"]'));
  await assertions.assertVisible(page.locator('//div[@id="capacity-recommendations"]'));
});

/**************************************************/
/*  TEST CASE: TC-PERF-003
/*  Title: Validation system endurance and memory leak detection
/*  Priority: High
/*  Category: Performance - Soak/Endurance Testing
/**************************************************/

Given('validation system is deployed with monitoring enabled', async function () {
  await actions.navigateTo(process.env.TEST_ENV_URL || 'https://validation-test.example.com');
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="validation-system"]'));
  
  await actions.navigateTo(`${process.env.MONITORING_URL || 'https://monitoring.example.com'}/enable`);
  await actions.check(page.locator('//input[@id="enable-monitoring"]'));
  await waits.waitForNetworkIdle();
});

Given('sustained load test is configured for {int} hour duration minimum', async function (hours: number) {
  await actions.navigateTo(`${process.env.LOAD_TEST_URL || 'https://loadtest.example.com'}/soak-test`);
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="test-duration-hours"]'), hours.toString());
});

Given('memory profiling tools are configured', async function () {
  await actions.navigateTo(`${process.env.PROFILING_URL || 'https://profiling.example.com'}/memory`);
  await waits.waitForNetworkIdle();
  await actions.check(page.locator('//input[@id="enable-memory-profiling"]'));
  await actions.click(page.locator('//button[@id="start-profiling"]'));
  await waits.waitForNetworkIdle();
});

Given('baseline memory and resource metrics are captured', async function () {
  await actions.click(page.locator('//button[@id="capture-baseline-metrics"]'));
  await waits.waitForNetworkIdle();
  
  this.baselineMemory = {
    heapUsed: parseFloat(await page.locator('//span[@id="baseline-heap-used"]').textContent() || '0'),
    heapTotal: parseFloat(await page.locator('//span[@id="baseline-heap-total"]').textContent() || '0'),
    timestamp: new Date().toISOString()
  };
});

Given('sufficient test data for extended test duration is available', async function () {
  await actions.navigateTo(`${process.env.TEST_DATA_URL || 'https://testdata.example.com'}/validate`);
  await waits.waitForNetworkIdle();
  
  const dataSetSize = parseInt(await page.locator('//span[@id="test-data-count"]').textContent() || '0');
  expect(dataSetSize).toBeGreaterThan(10000);
});

When('endurance test is configured with sustained load of {int} concurrent users for {int} hours', async function (users: number, hours: number) {
  await actions.fill(page.locator('//input[@id="sustained-users"]'), users.toString());
  await actions.fill(page.locator('//input[@id="duration-hours"]'), hours.toString());
  await waits.waitForNetworkIdle();
});

When('test is configured with consistent load pattern without ramp-up or ramp-down', async function () {
  await actions.selectByText(page.locator('//select[@id="load-pattern"]'), 'Consistent');
  await actions.check(page.locator('//input[@id="disable-ramp-up"]'));
  await actions.check(page.locator('//input[@id="disable-ramp-down"]'));
  await waits.waitForNetworkIdle();
});

When('continuous form submissions with validation are executed', async function () {
  await actions.click(page.locator('//button[@id="start-endurance-test"]'));
  await waits.waitForVisible(page.locator('//div[@id="endurance-test-running"]'));
});

When('response time trends are monitored throughout test duration', async function () {
  await actions.check(page.locator('//input[@id="enable-trend-monitoring"]'));
  await waits.waitForNetworkIdle();
});

When('P50, P95, and P99 metrics are captured every {int} minutes', async function (intervalMinutes: number) {
  await actions.fill(page.locator('//input[@id="metrics-capture-interval"]'), intervalMinutes.toString());
  await actions.click(page.locator('//button[@id="enable-periodic-capture"]'));
  await waits.waitForNetworkIdle();
});

Then('response times should remain stable throughout entire duration', async function () {
  await assertions.assertVisible(page.locator('//div[@id="response-time-stability"]'));
  const stabilityStatus = await page.locator('//span[@id="stability-status"]').textContent();
  expect(stabilityStatus).toBe('STABLE');
});

Then('client-side validation should be less than {int} milliseconds at P95', async function (maxMs: number) {
  const clientP95 = parseFloat(await page.locator('//span[@id="endurance-client-p95"]').textContent() || '0');
  expect(clientP95).toBeLessThan(maxMs);
});

Then('server-side validation should be less than {int} milliseconds at P95', async function (maxMs: number) {
  const serverP95 = parseFloat(await page.locator('//span[@id="endurance-server-p95"]').textContent() || '0');
  expect(serverP95).toBeLessThan(maxMs);
});

Then('response time variance should be less than {int} percent', async function (maxVariance: number) {
  const variance = parseFloat(await page.locator('//span[@id="response-time-variance"]').textContent() || '0');
  expect(variance).toBeLessThan(maxVariance);
});

Then('memory utilization patterns should be monitored on application servers, database servers, and cache layers', async function () {
  await assertions.assertVisible(page.locator('//div[@id="app-server-memory"]'));
  await assertions.assertVisible(page.locator('//div[@id="db-server-memory"]'));
  await assertions.assertVisible(page.locator('//div[@id="cache-layer-memory"]'));
});

Then('memory usage should remain stable or show controlled growth', async function () {
  const memoryTrend = await page.locator('//span[@id="memory-trend"]').textContent();
  expect(memoryTrend).toMatch(/STABLE|CONTROLLED_GROWTH/);
});

Then('no continuous upward trend indicating memory leaks should occur', async function () {
  const memoryLeakIndicator = await page.locator('//span[@id="memory-leak-indicator"]').textContent();
  expect(memoryLeakIndicator).toBe('NO_LEAK_DETECTED');
});

Then('garbage collection should operate normally', async function () {
  const gcStatus = await page.locator('//span[@id="gc-status"]').textContent();
  const gcPauseTime = parseFloat(await page.locator('//span[@id="gc-pause-time"]').textContent() || '0');
  
  expect(gcStatus).toBe('NORMAL');
  expect(gcPauseTime).toBeLessThan(1000);
});

Then('database connection pool usage should remain within normal operating ranges', async function () {
  const dbPoolUsage = parseFloat(await page.locator('//span[@id="endurance-db-pool-usage"]').textContent() || '0');
  expect(dbPoolUsage).toBeLessThan(80);
});

Then('file handles and thread counts should remain stable', async function () {
  const fileHandles = parseInt(await page.locator('//span[@id="file-handles-count"]').textContent() || '0');
  const threadCount = parseInt(await page.locator('//span[@id="thread-count"]').textContent() || '0');
  
  const fileHandlesTrend = await page.locator('//span[@id="file-handles-trend"]').textContent();
  const threadCountTrend = await page.locator('//span[@id="thread-count-trend"]').textContent();
  
  expect(fileHandlesTrend).toBe('STABLE');
  expect(threadCountTrend).toBe('STABLE');
});

Then('no resource exhaustion should occur', async function () {
  const resourceExhaustion = await page.locator('//span[@id="resource-exhaustion"]').textContent();
  expect(resourceExhaustion).toBe('false');
});

Then('connection pools should maintain healthy state', async function () {
  const poolHealth = await page.locator('//span[@id="connection-pool-health"]').textContent();
  expect(poolHealth).toBe('HEALTHY');
});

Then('validation logic should maintain {int} percent accuracy', async function (accuracy: number) {
  const actualAccuracy = parseFloat(await page.locator('//span[@id="endurance-validation-accuracy"]').textContent() || '0');
  expect(actualAccuracy).toBeGreaterThanOrEqual(accuracy);
});

Then('error messages should remain consistent and clear throughout duration', async function () {
  const errorConsistency = await page.locator('//span[@id="error-message-consistency"]').textContent();
  expect(errorConsistency).toBe('CONSISTENT');
});

Then('no degradation in validation quality should occur', async function () {
  const qualityDegradation = await page.locator('//span[@id="validation-quality-degradation"]').textContent();
  expect(qualityDegradation).toBe('false');
});

Then('logs should be analyzed for errors, warnings, or anomalies', async function () {
  await actions.click(page.locator('//button[@id="analyze-logs"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="log-analysis-results"]'));
});

Then('error rate should remain below {float} percent', async function (maxErrorRate: number) {
  const errorRate = parseFloat(await page.locator('//span[@id="endurance-error-rate"]').textContent() || '0');
  expect(errorRate).toBeLessThan(maxErrorRate);
});

Then('no new error patterns should emerge during extended run', async function () {
  const newErrorPatterns = await page.locator('//span[@id="new-error-patterns"]').textContent();
  expect(newErrorPatterns).toBe('NONE');
});

Then('endurance test report should be generated with trend analysis', async function () {
  await actions.click(page.locator('//button[@id="generate-endurance-report"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="endurance-test-report"]'));
  await assertions.assertVisible(page.locator('//div[@id="trend-analysis"]'));
});

Then('memory analysis report should confirm no leaks detected', async function () {
  await actions.click(page.locator('//button[@id="generate-memory-report"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="memory-analysis-report"]'));
  
  const leakDetected = await page.locator('//span[@id="final-leak-status"]').textContent();
  expect(leakDetected).toBe('NO_LEAKS_DETECTED');
});

/**************************************************/
/*  TEST CASE: TC-PERF-004
/*  Title: Validation system spike load and auto-scaling response
/*  Priority: Critical
/*  Category: Performance - Spike/Auto-scaling Testing
/**************************************************/

Given('validation system is deployed with auto-scaling configured', async function () {
  await actions.navigateTo(process.env.TEST_ENV_URL || 'https://validation-test.example.com');
  await waits.waitForNetworkIdle();
  
  await actions.navigateTo(`${process.env.ADMIN_URL || 'https://admin.example.com'}/autoscaling`);
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="autoscaling-config"]'));
  
  const autoScalingEnabled = await page.locator('//span[@id="autoscaling-enabled"]').textContent();
  expect(autoScalingEnabled).toBe('true');
});

Given('spike test scenario is configured in load testing tool', async function () {
  await actions.navigateTo(`${process.env.LOAD_TEST_URL || 'https://loadtest.example.com'}/spike-test`);
  await waits.waitForNetworkIdle();
  await actions.selectByText(page.locator('//select[@id="test-type"]'), 'Spike Test');
});

Given('auto-scaling policies are defined and enabled', async function () {
  await actions.navigateTo(`${process.env.ADMIN_URL || 'https://admin.example.com'}/scaling-policies`);
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="scaling-policies"]'));
  
  const policiesCount = await page.locator('//table[@id="policies-table"]//tr').count();
  expect(policiesCount).toBeGreaterThan(0);
});

Given('monitoring dashboards are configured for real-time observation', async function () {
  await actions.navigateTo(`${process.env.MONITORING_URL || 'https://monitoring.example.com'}/realtime`);
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="realtime-dashboard"]'));
  await actions.check(page.locator('//input[@id="enable-realtime-refresh"]'));
});

Given('alert thresholds are configured for spike detection', async function () {
  await actions.navigateTo(`${process.env.MONITORING_URL || 'https://monitoring.example.com'}/alerts/spike`);
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="spike-alert-config"]'));
});

When('baseline load of {int} concurrent users runs for {int} minutes', async function (users: number, minutes: number) {
  await actions.fill(page.locator('//input[@id="baseline-users"]'), users.toString());
  await actions.fill(page.locator('//input[@id="baseline-duration-minutes"]'), minutes.toString());
  await actions.click(page.locator('//button[@id="start-baseline-load"]'));
  await waits.waitForVisible(page.locator('//div[@id="baseline-running"]'));
  await page.waitForTimeout(minutes * 60 * 1000);
});

Then('system should operate normally with response time less than {int} milliseconds at P95', async function (maxMs: number) {
  const baselineP95 = parseFloat(await page.locator('//span[@id="baseline-p95-response"]').textContent() || '0');
  expect(baselineP95).toBeLessThan(maxMs);
});

Then('CPU should be less than {int} percent', async function (maxCpu: number) {
  const cpuUsage = parseFloat(await page.locator('//span[@id="baseline-cpu"]').textContent() || '0');
  expect(cpuUsage).toBeLessThan(maxCpu);
});

Then('memory should be stable', async function () {
  const memoryStatus = await page.locator('//span[@id="baseline-memory-status"]').textContent();
  expect(memoryStatus).toBe('STABLE');
});

When('load rapidly increases to {int} concurrent users within {int} seconds', async function (users: number, seconds: number) {
  await actions.fill(page.locator('//input[@id="spike-users"]'), users.toString());
  await actions.fill(page.locator('//input[@id="spike-duration-seconds"]'), seconds.toString());
  await actions.click(page.locator('//button[@id="trigger-spike"]'));
  await waits.waitForVisible(page.locator('//div[@id="spike-in-progress"]'));
});

Then('load spike should be executed successfully', async function () {
  await waits.waitForVisible(page.locator('//div[@id="spike-completed"]'));
  const spikeStatus = await page.locator('//span[@id="spike-execution-status"]').textContent();
  expect(spikeStatus).toBe('SUCCESS');
});

Then('all {int} virtual users should be actively submitting forms with validation requests', async function (users: number) {
  const activeUsers = parseInt(await page.locator('//span[@id="active-virtual-users"]').textContent() || '0');
  expect(activeUsers).toBe(users);
});

Then('auto-scaling should trigger within {int} seconds', async function (seconds: number) {
  await page.waitForTimeout(seconds * 1000);
  const scalingTriggered = await page.locator('//span[@id="autoscaling-triggered"]').textContent();
  expect(scalingTriggered).toBe('true');
});

Then('new instances should be provisioned within {int} to {int} minutes', async function (minMinutes: number, maxMinutes: number) {
  await page.waitForTimeout(maxMinutes * 60 * 1000);
  const newInstances = parseInt(await page.locator('//span[@id="new-instances-count"]').textContent() || '0');
  expect(newInstances).toBeGreaterThan(0);
});

Then('response times may temporarily degrade to less than {int} milliseconds at P95 but remain functional', async function (maxMs: number) {
  const spikeP95 = parseFloat(await page.locator('//span[@id="spike-p95-response"]').textContent() || '0');
  expect(spikeP95).toBeLessThan(maxMs);
});

When('peak load of {int} users is maintained for {int} minutes', async function (users: number, minutes: number) {
  await page.waitForTimeout(minutes * 60 * 1000);
  const currentLoad = parseInt(await page.locator('//span[@id="current-user-load"]').textContent() || '0');
  expect(currentLoad).toBeGreaterThanOrEqual(users * 0.95);
});

Then('system should stabilize after auto-scaling completes', async function () {
  const systemStatus = await page.locator('//span[@id="system-stabilization-status"]').textContent();
  expect(systemStatus).toBe('STABILIZED');
});

Then('response times should return to less than {int} milliseconds at P95', async function (maxMs: number) {
  const stabilizedP95 = parseFloat(await page.locator('//span[@id="stabilized-p95"]').textContent() || '0');
  expect(stabilizedP95).toBeLessThan(maxMs);
});

Then('error rate should be less than {int} percent', async function (maxErrorRate: number) {
  const errorRate = parseFloat(await page.locator('//span[@id="spike-error-rate"]').textContent() || '0');
  expect(errorRate).toBeLessThan(maxErrorRate);
});

Then('throughput should scale proportionally to handle {int} users', async function (users: number) {
  const throughput = parseFloat(await page.locator('//span[@id="scaled-throughput"]').textContent() || '0');
  const expectedMinThroughput = users * 0.5;
  expect(throughput).toBeGreaterThan(expectedMinThroughput);
});

When('load rapidly decreases back to {int} users within {int} seconds', async function (users: number, seconds: number) {
  await actions.click(page.locator('//button[@id="trigger-load-decrease"]'));
  await actions.fill(page.locator('//input[@id="target-users"]'), users.toString());
  await actions.fill(page.locator('//input[@id="decrease-duration-seconds"]'), seconds.toString());
  await actions.click(page.locator('//button[@id="execute-decrease"]'));
  await waits.waitForNetworkIdle();
});

Then('system should handle rapid load decrease gracefully', async function () {
  const decreaseStatus = await page.locator('//span[@id="load-decrease-status"]').textContent();
  expect(decreaseStatus).toBe('GRACEFUL');
});

Then('no errors should occur during scale-down', async function () {
  const scaleDownErrors = parseInt(await page.locator('//span[@id="scale-down-errors"]').textContent() || '0');
  expect(scaleDownErrors).toBe(0);
});

Then('excess instances should be de-provisioned within {int} to {int} minutes per scale-down policy', async function (minMinutes: number, maxMinutes: number) {
  await page.waitForTimeout(maxMinutes * 60 * 1000);
  const deprovisionedInstances = parseInt(await page.locator('//span[@id="deprovisioned-instances"]').textContent() || '0');
  expect(deprovisionedInstances).toBeGreaterThan(0);
});

Then('no validation errors or data loss should occur during scaling events', async function () {
  const validationErrors = parseInt(await page.locator('//span[@id="scaling-validation-errors"]').textContent() || '0');
  const dataLoss = await page.locator('//span[@id="data-loss-detected"]').textContent();
  
  expect(validationErrors).toBe(0);
  expect(dataLoss).toBe('false');
});

Then('all form submissions should be processed correctly', async function () {
  const processedSubmissions = parseInt(await page.locator('//span[@id="processed-submissions"]').textContent() || '0');
  const totalSubmissions = parseInt(await page.locator('//span[@id="total-submissions"]').textContent() || '0');
  
  expect(processedSubmissions).toBe(totalSubmissions);
});

Then('validation rules should be applied consistently', async function () {
  const consistencyStatus = await page.locator('//span[@id="validation-consistency"]').textContent();
  expect(consistencyStatus).toBe('CONSISTENT');
});

Then('system should return to baseline configuration after scale-down', async function () {
  const instanceCount = parseInt(await page.locator('//span[@id="current-instance-count"]').textContent() || '0');
  const baselineInstances = parseInt(await page.locator('//span[@id="baseline-instance-count"]').textContent() || '0');
  
  expect(instanceCount).toBe(baselineInstances);
});

Then('no orphaned resources or instances should remain', async function () {
  const orphanedResources = parseInt(await page.locator('//span[@id="orphaned-resources"]').textContent() || '0');
  expect(orphanedResources).toBe(0);
});

Then('spike test report should be generated with auto-scaling timeline', async function () {
  await actions.click(page.locator('//button[@id="generate-spike-report"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="spike-test-report"]'));
  await assertions.assertVisible(page.locator('//div[@id="autoscaling-timeline"]'));
});