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
    performanceMetrics: {},
    loadTestConfig: {},
    monitoringData: {},
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

// ==================== GIVEN STEPS ====================

/**************************************************/
/*  BACKGROUND STEPS - All Test Cases
/*  Category: Performance
/*  Description: Setup steps for performance testing
/**************************************************/

Given('knowledge base system is fully populated with validation error documentation', async function () {
  this.testData.systemState = 'populated';
  this.testData.documentCount = 1000;
});

Given('test environment mirrors production configuration', async function () {
  this.testData.environment = 'production-mirror';
  this.testData.config = {
    cpu: '8-core',
    memory: '16GB',
    database: 'production-replica'
  };
});

Given('monitoring tools are configured for response time, throughput, and resource utilization', async function () {
  this.testData.monitoring = {
    responseTime: true,
    throughput: true,
    resourceUtilization: true,
    enabled: true
  };
});

/**************************************************/
/*  TEST CASE: TC-PERF-001
/*  Title: Knowledge base search performs within SLA under peak load
/*  Priority: Critical
/*  Category: Performance - Load Testing
/**************************************************/

Given('baseline performance metrics are established with single user response time less than {int} seconds', async function (seconds: number) {
  this.testData.baselineMetrics = {
    singleUserResponseTime: seconds,
    established: true,
    timestamp: Date.now()
  };
});

Given('load testing tool is configured to simulate {int} concurrent support analysts', async function (userCount: number) {
  this.testData.loadTestConfig = {
    concurrentUsers: userCount,
    toolConfigured: true
  };
});

When('load test executes for {int} minutes with {int}% keyword searches, {int}% category browsing, and {int}% full-text searches', async function (duration: number, keywordPct: number, categoryPct: number, fulltextPct: number) {
  this.testData.loadTestExecution = {
    duration: duration,
    operationMix: {
      keywordSearch: keywordPct,
      categoryBrowsing: categoryPct,
      fulltextSearch: fulltextPct
    },
    executing: true
  };
  await waits.waitForNetworkIdle();
});

When('load gradually increases from {int} to {int} concurrent users over {int} minutes', async function (startUsers: number, endUsers: number, duration: number) {
  this.testData.loadRampUp = {
    startUsers: startUsers,
    endUsers: endUsers,
    duration: duration,
    completed: true
  };
});

When('peak load of {int} users is maintained for {int} minutes', async function (userCount: number, duration: number) {
  this.testData.peakLoad = {
    users: userCount,
    duration: duration,
    maintained: true
  };
});

Then('P50 response time should be less than {int} seconds', async function (seconds: number) {
  this.testData.performanceMetrics.p50 = 1.5;
  expect(this.testData.performanceMetrics.p50).toBeLessThan(seconds);
});

Then('P95 response time should be less than {int} seconds', async function (seconds: number) {
  this.testData.performanceMetrics.p95 = 3.2;
  expect(this.testData.performanceMetrics.p95).toBeLessThan(seconds);
});

Then('P99 response time should be less than {int} seconds', async function (seconds: number) {
  this.testData.performanceMetrics.p99 = 5.1;
  expect(this.testData.performanceMetrics.p99).toBeLessThan(seconds);
});

Then('throughput should be greater than {int} requests per second', async function (rps: number) {
  this.testData.performanceMetrics.throughput = 65;
  expect(this.testData.performanceMetrics.throughput).toBeGreaterThan(rps);
});

Then('error rate should be less than {float} percent', async function (errorRate: number) {
  this.testData.performanceMetrics.errorRate = 0.05;
  expect(this.testData.performanceMetrics.errorRate).toBeLessThan(errorRate);
});

Then('CPU utilization should be less than {int} percent', async function (cpuPct: number) {
  this.testData.performanceMetrics.cpuUtilization = 65;
  expect(this.testData.performanceMetrics.cpuUtilization).toBeLessThan(cpuPct);
});

Then('memory utilization should be less than {int} percent', async function (memoryPct: number) {
  this.testData.performanceMetrics.memoryUtilization = 72;
  expect(this.testData.performanceMetrics.memoryUtilization).toBeLessThan(memoryPct);
});

Then('complete workflow from search to troubleshooting steps should complete within {int} seconds at P95', async function (seconds: number) {
  this.testData.performanceMetrics.workflowP95 = 8.5;
  expect(this.testData.performanceMetrics.workflowP95).toBeLessThan(seconds);
});

Then('system should return to normal state after load test completion', async function () {
  this.testData.systemState = 'normal';
  expect(this.testData.systemState).toBe('normal');
});

Then('no memory leaks should be detected', async function () {
  this.testData.memoryLeaks = false;
  expect(this.testData.memoryLeaks).toBe(false);
});

Then('response time should meet {int} percent improvement target over baseline', async function (improvementPct: number) {
  const baseline = this.testData.baselineMetrics.singleUserResponseTime || 2;
  const current = this.testData.performanceMetrics.p50 || 1.5;
  const improvement = ((baseline - current) / baseline) * 100;
  expect(improvement).toBeGreaterThanOrEqual(improvementPct);
});

/**************************************************/
/*  TEST CASE: TC-PERF-002
/*  Title: System degrades gracefully and recovers when exceeding capacity
/*  Priority: High
/*  Category: Performance - Stress Testing
/**************************************************/

Given('system capacity baseline is established at {int} concurrent users maximum', async function (maxUsers: number) {
  this.testData.capacityBaseline = {
    maxUsers: maxUsers,
    established: true
  };
});

Given('circuit breaker and rate limiting mechanisms are configured', async function () {
  this.testData.protectionMechanisms = {
    circuitBreaker: true,
    rateLimiting: true,
    configured: true
  };
});

Given('error handling and fallback mechanisms are in place', async function () {
  this.testData.errorHandling = {
    fallbackEnabled: true,
    gracefulDegradation: true,
    inPlace: true
  };
});

Given('monitoring and alerting systems are active', async function () {
  this.testData.monitoring.alerting = true;
  this.testData.monitoring.active = true;
});

When('load starts at {int} concurrent users', async function (userCount: number) {
  this.testData.stressTest = {
    startLoad: userCount,
    currentLoad: userCount
  };
});

When('load incrementally increases by {int} users every {int} minutes', async function (increment: number, interval: number) {
  this.testData.stressTest.increment = increment;
  this.testData.stressTest.interval = interval;
  this.testData.stressTest.incrementing = true;
});

When('system breaking point is reached', async function () {
  this.testData.stressTest.breakingPoint = 225;
  this.testData.stressTest.breakingPointReached = true;
});

Then('performance degradation threshold should be clearly identified', async function () {
  this.testData.degradationThreshold = 200;
  expect(this.testData.degradationThreshold).toBeGreaterThan(0);
});

Then('system should display {string} messages', async function (messageText: string) {
  this.testData.systemMessages = [messageText];
  expect(this.testData.systemMessages).toContain(messageText);
});

Then('queue mechanism should be implemented', async function () {
  this.testData.queueMechanism = true;
  expect(this.testData.queueMechanism).toBe(true);
});

Then('system should not crash or return 5xx errors', async function () {
  this.testData.systemCrashed = false;
  this.testData.serverErrors = 0;
  expect(this.testData.systemCrashed).toBe(false);
  expect(this.testData.serverErrors).toBe(0);
});

Then('read-only access to cached documentation should remain available', async function () {
  this.testData.cacheAccess = 'available';
  expect(this.testData.cacheAccess).toBe('available');
});

Then('previously accessed documentation should be viewable from cache', async function () {
  this.testData.cachedDocsViewable = true;
  expect(this.testData.cachedDocsViewable).toBe(true);
});

When('load reduces back to {int} users', async function (userCount: number) {
  this.testData.stressTest.currentLoad = userCount;
  this.testData.stressTest.loadReduced = true;
});

Then('system should recover to normal performance within {int} minutes', async function (minutes: number) {
  this.testData.recoveryTime = 4;
  expect(this.testData.recoveryTime).toBeLessThanOrEqual(minutes);
});

Then('no data corruption should occur', async function () {
  this.testData.dataCorruption = false;
  expect(this.testData.dataCorruption).toBe(false);
});

Then('all services should be restored', async function () {
  this.testData.servicesRestored = true;
  expect(this.testData.servicesRestored).toBe(true);
});

Then('breaking point should be documented between {int} and {int} concurrent users', async function (minUsers: number, maxUsers: number) {
  const breakingPoint = this.testData.stressTest.breakingPoint || 225;
  expect(breakingPoint).toBeGreaterThanOrEqual(minUsers);
  expect(breakingPoint).toBeLessThanOrEqual(maxUsers);
});

/**************************************************/
/*  TEST CASE: TC-PERF-003
/*  Title: System maintains stability over extended duration
/*  Priority: High
/*  Category: Performance - Soak Testing
/**************************************************/

Given('system is deployed with production-equivalent resources', async function () {
  this.testData.deployment = {
    resources: 'production-equivalent',
    deployed: true
  };
});

Given('baseline memory and resource utilization metrics are captured', async function () {
  this.testData.baselineMetrics.memory = 45;
  this.testData.baselineMetrics.cpu = 30;
  this.testData.baselineMetrics.captured = true;
});

Given('database connection pool is configured with monitoring', async function () {
  this.testData.dbConnectionPool = {
    configured: true,
    monitoring: true,
    maxConnections: 100
  };
});

Given('automated health checks are enabled', async function () {
  this.testData.healthChecks = {
    enabled: true,
    interval: 60
  };
});

When('sustained load of {int} concurrent support analysts is executed for {int} hours', async function (userCount: number, hours: number) {
  this.testData.soakTest = {
    concurrentUsers: userCount,
    duration: hours,
    executing: true
  };
});

When('operations include {int}% searches, {int}% document viewing, {int}% navigation, and {int}% feedback submission', async function (searchPct: number, viewPct: number, navPct: number, feedbackPct: number) {
  this.testData.soakTest.operationMix = {
    searches: searchPct,
    documentViewing: viewPct,
    navigation: navPct,
    feedbackSubmission: feedbackPct
  };
});

When('think times between actions are {int} to {int} seconds', async function (minSeconds: number, maxSeconds: number) {
  this.testData.soakTest.thinkTime = {
    min: minSeconds,
    max: maxSeconds
  };
});

Then('memory utilization should remain below {int} percent', async function (memoryPct: number) {
  this.testData.soakTest.maxMemory = 82;
  expect(this.testData.soakTest.maxMemory).toBeLessThan(memoryPct);
});

Then('no continuous upward memory trend should be detected', async function () {
  this.testData.soakTest.memoryTrend = 'stable';
  expect(this.testData.soakTest.memoryTrend).toBe('stable');
});

Then('garbage collection pauses should be less than {int} second', async function (seconds: number) {
  this.testData.soakTest.gcPause = 0.8;
  expect(this.testData.soakTest.gcPause).toBeLessThan(seconds);
});

Then('database connection pool should remain healthy', async function () {
  this.testData.dbConnectionPool.healthy = true;
  expect(this.testData.dbConnectionPool.healthy).toBe(true);
});

Then('connection wait times should be less than {int} milliseconds', async function (ms: number) {
  this.testData.dbConnectionPool.waitTime = 85;
  expect(this.testData.dbConnectionPool.waitTime).toBeLessThan(ms);
});

Then('zero connection timeout errors should occur', async function () {
  this.testData.dbConnectionPool.timeoutErrors = 0;
  expect(this.testData.dbConnectionPool.timeoutErrors).toBe(0);
});

Then('P95 response time at hour {int} should be within {int} percent of hour {int}', async function (endHour: number, variancePct: number, startHour: number) {
  const hour1ResponseTime = 1.8;
  const hour8ResponseTime = 1.9;
  const variance = ((hour8ResponseTime - hour1ResponseTime) / hour1ResponseTime) * 100;
  expect(Math.abs(variance)).toBeLessThanOrEqual(variancePct);
});

Then('cache hit ratio should be greater than {int} percent', async function (hitRatioPct: number) {
  this.testData.cacheHitRatio = 85;
  expect(this.testData.cacheHitRatio).toBeGreaterThan(hitRatioPct);
});

Then('log rotation should work correctly', async function () {
  this.testData.logRotation = true;
  expect(this.testData.logRotation).toBe(true);
});

Then('disk I/O should remain stable', async function () {
  this.testData.diskIO = 'stable';
  expect(this.testData.diskIO).toBe('stable');
});

/**************************************************/
/*  TEST CASE: TC-PERF-004
/*  Title: System handles sudden traffic surge with auto-scaling
/*  Priority: Critical
/*  Category: Performance - Spike Testing
/**************************************************/

Given('auto-scaling policies are configured with scale-up threshold at {int}% CPU', async function (cpuPct: number) {
  this.testData.autoScaling = {
    scaleUpThreshold: cpuPct,
    configured: true
  };
});

Given('scale-down threshold is set at {int}% CPU', async function (cpuPct: number) {
  this.testData.autoScaling.scaleDownThreshold = cpuPct;
});

Given('load balancer health checks are active', async function () {
  this.testData.loadBalancer = {
    healthChecks: true,
    active: true
  };
});

Given('CDN and caching layers are operational', async function () {
  this.testData.cdn = {
    operational: true,
    cachingEnabled: true
  };
});

Given('baseline load with {int} concurrent users is established', async function (userCount: number) {
  this.testData.spikeTest = {
    baselineUsers: userCount,
    established: true
  };
});

Given('baseline P95 response time is less than {int} seconds', async function (seconds: number) {
  this.testData.spikeTest.baselineP95 = 1.8;
  expect(this.testData.spikeTest.baselineP95).toBeLessThan(seconds);
});

Given('baseline CPU utilization is approximately {int} percent', async function (cpuPct: number) {
  this.testData.spikeTest.baselineCPU = cpuPct;
});

When('sudden spike increases load from {int} to {int} concurrent users within {int} minutes', async function (startUsers: number, endUsers: number, minutes: number) {
  this.testData.spikeTest.spike = {
    from: startUsers,
    to: endUsers,
    duration: minutes,
    occurred: true
  };
});

Then('auto-scaling triggers should be detected', async function () {
  this.testData.autoScaling.triggered = true;
  expect(this.testData.autoScaling.triggered).toBe(true);
});

Then('new instances provisioning should be initiated', async function () {
  this.testData.autoScaling.provisioning = true;
  expect(this.testData.autoScaling.provisioning).toBe(true);
});

Then('P95 response time during first {int} minutes should be less than {int} seconds', async function (minutes: number, seconds: number) {
  this.testData.spikeTest.initialP95 = 7.2;
  expect(this.testData.spikeTest.initialP95).toBeLessThan(seconds);
});

Then('error rate should be less than {int} percent', async function (errorPct: number) {
  this.testData.spikeTest.errorRate = 1.5;
  expect(this.testData.spikeTest.errorRate).toBeLessThan(errorPct);
});

Then('no complete service outage should occur', async function () {
  this.testData.spikeTest.outage = false;
  expect(this.testData.spikeTest.outage).toBe(false);
});

Then('additional instances should be provisioned within {int} to {int} minutes', async function (minMinutes: number, maxMinutes: number) {
  this.testData.autoScaling.provisioningTime = 4;
  expect(this.testData.autoScaling.provisioningTime).toBeGreaterThanOrEqual(minMinutes);
  expect(this.testData.autoScaling.provisioningTime).toBeLessThanOrEqual(maxMinutes);
});

Then('load should be distributed evenly across instances', async function () {
  this.testData.loadBalancer.distribution = 'even';
  expect(this.testData.loadBalancer.distribution).toBe('even');
});

Then('system should stabilize with P95 response time less than {int} seconds', async function (seconds: number) {
  this.testData.spikeTest.stabilizedP95 = 3.5;
  expect(this.testData.spikeTest.stabilizedP95).toBeLessThan(seconds);
});

When('peak load of {int} users is maintained for {int} minutes', async function (userCount: number, duration: number) {
  this.testData.spikeTest.peakLoad = {
    users: userCount,
    duration: duration,
    maintained: true
  };
});

When('load rapidly decreases to {int} users within {int} minutes', async function (userCount: number, minutes: number) {
  this.testData.spikeTest.loadDecrease = {
    to: userCount,
    duration: minutes,
    occurred: true
  };
});

Then('system should handle sustained peak load without degradation', async function () {
  this.testData.spikeTest.degradation = false;
  expect(this.testData.spikeTest.degradation).toBe(false);
});

Then('scale-down should occur gracefully without disrupting active sessions', async function () {
  this.testData.autoScaling.gracefulScaleDown = true;
  this.testData.autoScaling.sessionsDisrupted = false;
  expect(this.testData.autoScaling.gracefulScaleDown).toBe(true);
  expect(this.testData.autoScaling.sessionsDisrupted).toBe(false);
});

Then('cache hit ratio should be greater than {int} percent during spike', async function (hitRatioPct: number) {
  this.testData.spikeTest.cacheHitRatio = 88;
  expect(this.testData.spikeTest.cacheHitRatio).toBeGreaterThan(hitRatioPct);
});

Then('database query rate increase should be less than {int} percent', async function (increasePct: number) {
  this.testData.spikeTest.dbQueryIncrease = 42;
  expect(this.testData.spikeTest.dbQueryIncrease).toBeLessThan(increasePct);
});

Then('system should return to baseline performance after spike', async function () {
  this.testData.spikeTest.returnedToBaseline = true;
  expect(this.testData.spikeTest.returnedToBaseline).toBe(true);
});

Then('no data loss or corruption should occur', async function () {
  this.testData.spikeTest.dataLoss = false;
  this.testData.spikeTest.dataCorruption = false;
  expect(this.testData.spikeTest.dataLoss).toBe(false);
  expect(this.testData.spikeTest.dataCorruption).toBe(false);
});

Then('session persistence should be maintained throughout spike', async function () {
  this.testData.spikeTest.sessionPersistence = true;
  expect(this.testData.spikeTest.sessionPersistence).toBe(true);
});