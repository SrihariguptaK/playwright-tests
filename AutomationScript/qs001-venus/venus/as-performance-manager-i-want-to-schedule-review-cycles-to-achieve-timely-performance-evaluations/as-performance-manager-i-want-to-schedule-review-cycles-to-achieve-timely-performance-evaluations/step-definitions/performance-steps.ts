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
      performanceManager: { username: 'perf_manager', password: 'perfpass123' }
    },
    performanceMetrics: {},
    loadTestResults: {},
    systemMetrics: {},
    breakingPoint: {},
    autoScalingMetrics: {}
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
/*  TEST CASE: TC-PERF-001
/*  Title: Validate review cycle scheduling performance under peak concurrent user load
/*  Priority: Critical
/*  Category: Performance - Load Testing
/**************************************************/

Given('performance testing environment is configured with production-like specifications', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(process.env.PERF_TEST_URL || 'https://performance-test.example.com');
  await waits.waitForNetworkIdle();
  const envIndicator = page.locator('//div[@id="environment-indicator"]');
  await assertions.assertVisible(envIndicator);
  await assertions.assertContainsText(envIndicator, 'Performance');
  this.testData.environment = 'performance';
});

Given('monitoring tools are active for system metrics', async function () {
  // TODO: Replace XPath with Object Repository when available
  const monitoringEndpoint = `${process.env.MONITORING_API_URL || 'https://monitoring.example.com'}/api/health`;
  const response = await page.request.get(monitoringEndpoint);
  expect(response.status()).toBe(200);
  const responseBody = await response.json();
  expect(responseBody.status).toBe('active');
  this.testData.monitoringActive = true;
});

Given('test user accounts with Performance Manager role are provisioned', async function () {
  // TODO: Replace XPath with Object Repository when available
  const provisionEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/test-users/provision`;
  const response = await page.request.post(provisionEndpoint, {
    data: {
      role: 'Performance Manager',
      count: 500
    }
  });
  expect(response.status()).toBe(201);
  const responseBody = await response.json();
  this.testData.provisionedUsers = responseBody.users;
  expect(this.testData.provisionedUsers.length).toBeGreaterThanOrEqual(500);
});

Given('review cycles database is populated with {int} existing review cycles', async function (cycleCount: number) {
  // TODO: Replace XPath with Object Repository when available
  const seedEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/review-cycles/seed`;
  const response = await page.request.post(seedEndpoint, {
    data: {
      count: cycleCount
    }
  });
  expect(response.status()).toBe(201);
  const responseBody = await response.json();
  expect(responseBody.seededCount).toBe(cycleCount);
  this.testData.existingCyclesCount = cycleCount;
});

Given('load testing tool is configured and ready', async function () {
  // TODO: Replace XPath with Object Repository when available
  const loadTestConfigEndpoint = `${process.env.LOAD_TEST_URL || 'https://loadtest.example.com'}/api/config`;
  const response = await page.request.get(loadTestConfigEndpoint);
  expect(response.status()).toBe(200);
  const config = await response.json();
  expect(config.status).toBe('ready');
  this.testData.loadTestConfig = config;
});

Given('{int} test user accounts are provisioned', async function (userCount: number) {
  // TODO: Replace XPath with Object Repository when available
  const provisionEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/test-users/provision`;
  const response = await page.request.post(provisionEndpoint, {
    data: {
      role: 'Performance Manager',
      count: userCount
    }
  });
  expect(response.status()).toBe(201);
  const responseBody = await response.json();
  this.testData.provisionedUsers = responseBody.users;
  expect(this.testData.provisionedUsers.length).toBe(userCount);
});

/**************************************************/
/*  TEST CASE: TC-PERF-002
/*  Title: Identify system breaking point and validate graceful degradation
/*  Priority: High
/*  Category: Performance - Stress Testing
/**************************************************/

Given('system is in stable state with normal resource utilization', async function () {
  // TODO: Replace XPath with Object Repository when available
  const metricsEndpoint = `${process.env.MONITORING_API_URL || 'https://monitoring.example.com'}/api/metrics/current`;
  const response = await page.request.get(metricsEndpoint);
  expect(response.status()).toBe(200);
  const metrics = await response.json();
  expect(metrics.cpu).toBeLessThan(50);
  expect(metrics.memory).toBeLessThan(60);
  expect(metrics.status).toBe('stable');
  this.testData.baselineMetrics = metrics;
});

Given('database has {int} existing review cycles for realistic load', async function (cycleCount: number) {
  // TODO: Replace XPath with Object Repository when available
  const seedEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/review-cycles/seed`;
  const response = await page.request.post(seedEndpoint, {
    data: {
      count: cycleCount
    }
  });
  expect(response.status()).toBe(201);
  const responseBody = await response.json();
  expect(responseBody.seededCount).toBe(cycleCount);
  this.testData.existingCyclesCount = cycleCount;
});

Given('auto-scaling is disabled to identify true breaking point', async function () {
  // TODO: Replace XPath with Object Repository when available
  const autoScaleEndpoint = `${process.env.INFRA_API_URL || 'https://infrastructure.example.com'}/api/autoscaling/disable`;
  const response = await page.request.post(autoScaleEndpoint);
  expect(response.status()).toBe(200);
  const responseBody = await response.json();
  expect(responseBody.autoScalingEnabled).toBe(false);
  this.testData.autoScalingDisabled = true;
});

Given('circuit breakers and rate limiters are configured', async function () {
  // TODO: Replace XPath with Object Repository when available
  const circuitBreakerEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/config/circuit-breaker`;
  const rateLimiterEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/config/rate-limiter`;
  
  const cbResponse = await page.request.get(circuitBreakerEndpoint);
  const rlResponse = await page.request.get(rateLimiterEndpoint);
  
  expect(cbResponse.status()).toBe(200);
  expect(rlResponse.status()).toBe(200);
  
  const cbConfig = await cbResponse.json();
  const rlConfig = await rlResponse.json();
  
  expect(cbConfig.enabled).toBe(true);
  expect(rlConfig.enabled).toBe(true);
  
  this.testData.circuitBreakerConfig = cbConfig;
  this.testData.rateLimiterConfig = rlConfig;
});

Given('alerting and monitoring systems are active', async function () {
  // TODO: Replace XPath with Object Repository when available
  const alertingEndpoint = `${process.env.MONITORING_API_URL || 'https://monitoring.example.com'}/api/alerting/status`;
  const response = await page.request.get(alertingEndpoint);
  expect(response.status()).toBe(200);
  const status = await response.json();
  expect(status.active).toBe(true);
  this.testData.alertingActive = true;
});

Given('backup and rollback procedures are documented and ready', async function () {
  // TODO: Replace XPath with Object Repository when available
  const backupEndpoint = `${process.env.INFRA_API_URL || 'https://infrastructure.example.com'}/api/backup/status`;
  const response = await page.request.get(backupEndpoint);
  expect(response.status()).toBe(200);
  const backupStatus = await response.json();
  expect(backupStatus.ready).toBe(true);
  expect(backupStatus.lastBackup).toBeDefined();
  this.testData.backupReady = true;
});

/**************************************************/
/*  TEST CASE: TC-PERF-003
/*  Title: Validate system handling of sudden traffic spike with auto-scaling
/*  Priority: Critical
/*  Category: Performance - Spike Testing
/**************************************************/

Given('auto-scaling policies are configured and enabled', async function () {
  // TODO: Replace XPath with Object Repository when available
  const autoScaleEndpoint = `${process.env.INFRA_API_URL || 'https://infrastructure.example.com'}/api/autoscaling/config`;
  const response = await page.request.get(autoScaleEndpoint);
  expect(response.status()).toBe(200);
  const config = await response.json();
  expect(config.enabled).toBe(true);
  this.testData.autoScalingConfig = config;
});

Given('scale up threshold is set at {int} percent CPU utilization', async function (threshold: number) {
  // TODO: Replace XPath with Object Repository when available
  const thresholdEndpoint = `${process.env.INFRA_API_URL || 'https://infrastructure.example.com'}/api/autoscaling/threshold/scale-up`;
  const response = await page.request.get(thresholdEndpoint);
  expect(response.status()).toBe(200);
  const config = await response.json();
  expect(config.cpuThreshold).toBe(threshold);
  this.testData.scaleUpThreshold = threshold;
});

Given('scale down threshold is set at {int} percent CPU utilization', async function (threshold: number) {
  // TODO: Replace XPath with Object Repository when available
  const thresholdEndpoint = `${process.env.INFRA_API_URL || 'https://infrastructure.example.com'}/api/autoscaling/threshold/scale-down`;
  const response = await page.request.get(thresholdEndpoint);
  expect(response.status()).toBe(200);
  const config = await response.json();
  expect(config.cpuThreshold).toBe(threshold);
  this.testData.scaleDownThreshold = threshold;
});

Given('cloud infrastructure has capacity for horizontal scaling up to {int} instances', async function (maxInstances: number) {
  // TODO: Replace XPath with Object Repository when available
  const capacityEndpoint = `${process.env.INFRA_API_URL || 'https://infrastructure.example.com'}/api/capacity`;
  const response = await page.request.get(capacityEndpoint);
  expect(response.status()).toBe(200);
  const capacity = await response.json();
  expect(capacity.maxInstances).toBeGreaterThanOrEqual(maxInstances);
  this.testData.maxInstances = maxInstances;
});

Given('load balancer is configured and health checks are active', async function () {
  // TODO: Replace XPath with Object Repository when available
  const lbEndpoint = `${process.env.INFRA_API_URL || 'https://infrastructure.example.com'}/api/load-balancer/status`;
  const response = await page.request.get(lbEndpoint);
  expect(response.status()).toBe(200);
  const lbStatus = await response.json();
  expect(lbStatus.configured).toBe(true);
  expect(lbStatus.healthChecksActive).toBe(true);
  this.testData.loadBalancerActive = true;
});

Given('database connection pooling is optimized for burst traffic', async function () {
  // TODO: Replace XPath with Object Repository when available
  const dbPoolEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/database/pool/config`;
  const response = await page.request.get(dbPoolEndpoint);
  expect(response.status()).toBe(200);
  const poolConfig = await response.json();
  expect(poolConfig.maxConnections).toBeGreaterThanOrEqual(200);
  expect(poolConfig.burstOptimized).toBe(true);
  this.testData.dbPoolConfig = poolConfig;
});

Given('caching layer is operational', async function () {
  // TODO: Replace XPath with Object Repository when available
  const cacheEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/cache/status`;
  const response = await page.request.get(cacheEndpoint);
  expect(response.status()).toBe(200);
  const cacheStatus = await response.json();
  expect(cacheStatus.operational).toBe(true);
  this.testData.cacheOperational = true;
});

// ==================== WHEN STEPS ====================

When('load test is configured to simulate {int} concurrent Performance Managers with {int} second ramp-up time', async function (userCount: number, rampUpTime: number) {
  // TODO: Replace XPath with Object Repository when available
  const loadTestEndpoint = `${process.env.LOAD_TEST_URL || 'https://loadtest.example.com'}/api/test/configure`;
  const response = await page.request.post(loadTestEndpoint, {
    data: {
      concurrentUsers: userCount,
      rampUpTime: rampUpTime,
      userRole: 'Performance Manager'
    }
  });
  expect(response.status()).toBe(200);
  const config = await response.json();
  this.testData.loadTestConfig = config;
  this.testData.concurrentUsers = userCount;
  this.testData.rampUpTime = rampUpTime;
});

When('each user navigates to review cycle management page', async function () {
  // TODO: Replace XPath with Object Repository when available
  const navigationEndpoint = `${process.env.LOAD_TEST_URL || 'https://loadtest.example.com'}/api/test/add-step`;
  const response = await page.request.post(navigationEndpoint, {
    data: {
      stepType: 'navigation',
      url: '/review-cycles/management',
      waitForNetworkIdle: true
    }
  });
  expect(response.status()).toBe(200);
  this.testData.loadTestSteps = this.testData.loadTestSteps || [];
  this.testData.loadTestSteps.push('navigate_to_management_page');
});

When('each user selects review frequency from available options', async function () {
  // TODO: Replace XPath with Object Repository when available
  const stepEndpoint = `${process.env.LOAD_TEST_URL || 'https://loadtest.example.com'}/api/test/add-step`;
  const response = await page.request.post(stepEndpoint, {
    data: {
      stepType: 'select',
      selector: '//select[@id="review-frequency"]',
      optionStrategy: 'random'
    }
  });
  expect(response.status()).toBe(200);
  this.testData.loadTestSteps = this.testData.loadTestSteps || [];
  this.testData.loadTestSteps.push('select_review_frequency');
});

When('each user saves schedule via POST {string} endpoint', async function (endpoint: string) {
  // TODO: Replace XPath with Object Repository when available
  const stepEndpoint = `${process.env.LOAD_TEST_URL || 'https://loadtest.example.com'}/api/test/add-step`;
  const response = await page.request.post(stepEndpoint, {
    data: {
      stepType: 'api_call',
      method: 'POST',
      endpoint: endpoint,
      captureMetrics: true
    }
  });
  expect(response.status()).toBe(200);
  this.testData.loadTestSteps = this.testData.loadTestSteps || [];
  this.testData.loadTestSteps.push('save_schedule_api_call');
  this.testData.apiEndpoint = endpoint;
});

When('load test executes for {int} minutes sustained duration', async function (durationMinutes: number) {
  // TODO: Replace XPath with Object Repository when available
  const executeEndpoint = `${process.env.LOAD_TEST_URL || 'https://loadtest.example.com'}/api/test/execute`;
  const response = await page.request.post(executeEndpoint, {
    data: {
      duration: durationMinutes * 60,
      captureMetrics: true
    },
    timeout: (durationMinutes * 60 * 1000) + 60000
  });
  expect(response.status()).toBe(200);
  const results = await response.json();
  this.testData.loadTestResults = results;
  this.testData.testDuration = durationMinutes;
});

When('stress test starts with {int} concurrent users', async function (initialUsers: number) {
  // TODO: Replace XPath with Object Repository when available
  const stressTestEndpoint = `${process.env.LOAD_TEST_URL || 'https://loadtest.example.com'}/api/stress-test/start`;
  const response = await page.request.post(stressTestEndpoint, {
    data: {
      initialUsers: initialUsers,
      testType: 'stress'
    }
  });
  expect(response.status()).toBe(200);
  const testSession = await response.json();
  this.testData.stressTestSession = testSession;
  this.testData.currentUserLoad = initialUsers;
});

When('user load increases by {int} users every {int} minutes incrementally', async function (userIncrement: number, intervalMinutes: number) {
  // TODO: Replace XPath with Object Repository when available
  const incrementEndpoint = `${process.env.LOAD_TEST_URL || 'https://loadtest.example.com'}/api/stress-test/configure-increment`;
  const response = await page.request.post(incrementEndpoint, {
    data: {
      sessionId: this.testData.stressTestSession.id,
      userIncrement: userIncrement,
      intervalMinutes: intervalMinutes
    }
  });
  expect(response.status()).toBe(200);
  this.testData.userIncrement = userIncrement;
  this.testData.incrementInterval = intervalMinutes;
});

When('response times, error rates, and system resources are monitored at each load increment', async function () {
  // TODO: Replace XPath with Object Repository when available
  const monitorEndpoint = `${process.env.LOAD_TEST_URL || 'https://loadtest.example.com'}/api/stress-test/enable-monitoring`;
  const response = await page.request.post(monitorEndpoint, {
    data: {
      sessionId: this.testData.stressTestSession.id,
      captureMetrics: ['responseTime', 'errorRate', 'cpu', 'memory', 'connections']
    }
  });
  expect(response.status()).toBe(200);
  this.testData.monitoringEnabled = true;
});

When('load generation is stopped', async function () {
  // TODO: Replace XPath with Object Repository when available
  const stopEndpoint = `${process.env.LOAD_TEST_URL || 'https://loadtest.example.com'}/api/stress-test/stop`;
  const response = await page.request.post(stopEndpoint, {
    data: {
      sessionId: this.testData.stressTestSession.id
    }
  });
  expect(response.status()).toBe(200);
  const finalResults = await response.json();
  this.testData.stressTestResults = finalResults;
  this.testData.loadGenerationStopped = true;
});

When('baseline load with {int} concurrent users is established for {int} minutes', async function (baselineUsers: number, durationMinutes: number) {
  // TODO: Replace XPath with Object Repository when available
  const baselineEndpoint = `${process.env.LOAD_TEST_URL || 'https://loadtest.example.com'}/api/spike-test/establish-baseline`;
  const response = await page.request.post(baselineEndpoint, {
    data: {
      users: baselineUsers,
      duration: durationMinutes * 60
    },
    timeout: (durationMinutes * 60 * 1000) + 30000
  });
  expect(response.status()).toBe(200);
  const baselineMetrics = await response.json();
  this.testData.baselineMetrics = baselineMetrics;
  this.testData.baselineUsers = baselineUsers;
});

When('sudden spike to {int} concurrent users occurs within {int} seconds', async function (spikeUsers: number, spikeTime: number) {
  // TODO: Replace XPath with Object Repository when available
  const spikeEndpoint = `${process.env.LOAD_TEST_URL || 'https://loadtest.example.com'}/api/spike-test/execute-spike`;
  const response = await page.request.post(spikeEndpoint, {
    data: {
      targetUsers: spikeUsers,
      spikeTime: spikeTime
    },
    timeout: (spikeTime * 1000) + 30000
  });
  expect(response.status()).toBe(200);
  const spikeResults = await response.json();
  this.testData.spikeResults = spikeResults;
  this.testData.spikeUsers = spikeUsers;
  this.testData.spikeTime = spikeTime;
});

When('spike load is maintained for {int} minutes', async function (durationMinutes: number) {
  // TODO: Replace XPath with Object Repository when available
  const maintainEndpoint = `${process.env.LOAD_TEST_URL || 'https://loadtest.example.com'}/api/spike-test/maintain-load`;
  const response = await page.request.post(maintainEndpoint, {
    data: {
      duration: durationMinutes * 60
    },
    timeout: (durationMinutes * 60 * 1000) + 30000
  });
  expect(response.status()).toBe(200);
  const sustainedMetrics = await response.json();
  this.testData.sustainedSpikeMetrics = sustainedMetrics;
});

When('load rapidly decreases back to {int} users within {int} seconds', async function (targetUsers: number, decreaseTime: number) {
  // TODO: Replace XPath with Object Repository when available
  const decreaseEndpoint = `${process.env.LOAD_TEST_URL || 'https://loadtest.example.com'}/api/spike-test/decrease-load`;
  const response = await page.request.post(decreaseEndpoint, {
    data: {
      targetUsers: targetUsers,
      decreaseTime: decreaseTime
    },
    timeout: (decreaseTime * 1000) + 30000
  });
  expect(response.status()).toBe(200);
  const decreaseResults = await response.json();
  this.testData.decreaseResults = decreaseResults;
});

// ==================== THEN STEPS ====================

Then('all {int} users should complete workflow without errors', async function (userCount: number) {
  const results = this.testData.loadTestResults;
  expect(results.completedUsers).toBe(userCount);
  expect(results.failedUsers).toBe(0);
  expect(results.totalErrors).toBe(0);
});

Then('page load P50 response time should be less than or equal to {float} seconds', async function (threshold: number) {
  const results = this.testData.loadTestResults;
  const p50ResponseTime = results.metrics.pageLoad.p50 / 1000;
  expect(p50ResponseTime).toBeLessThanOrEqual(threshold);
  this.testData.performanceMetrics = this.testData.performanceMetrics || {};
  this.testData.performanceMetrics.pageLoadP50 = p50ResponseTime;
});

Then('page load P95 response time should be less than or equal to {float} seconds', async function (threshold: number) {
  const results = this.testData.loadTestResults;
  const p95ResponseTime = results.metrics.pageLoad.p95 / 1000;
  expect(p95ResponseTime).toBeLessThanOrEqual(threshold);
  this.testData.performanceMetrics = this.testData.performanceMetrics || {};
  this.testData.performanceMetrics.pageLoadP95 = p95ResponseTime;
});

Then('page load P99 response time should be less than or equal to {float} seconds', async function (threshold: number) {
  const results = this.testData.loadTestResults;
  const p99ResponseTime = results.metrics.pageLoad.p99 / 1000;
  expect(p99ResponseTime).toBeLessThanOrEqual(threshold);
  this.testData.performanceMetrics = this.testData.performanceMetrics || {};
  this.testData.performanceMetrics.pageLoadP99 = p99ResponseTime;
});

Then('API POST P50 response time should be less than or equal to {int} milliseconds', async function (threshold: number) {
  const results = this.testData.loadTestResults;
  const p50ApiResponseTime = results.metrics.apiPost.p50;
  expect(p50ApiResponseTime).toBeLessThanOrEqual(threshold);
  this.testData.performanceMetrics = this.testData.performanceMetrics || {};
  this.testData.performanceMetrics.apiPostP50 = p50ApiResponseTime;
});

Then('API POST P95 response time should be less than or equal to {float} seconds', async function (threshold: number) {
  const results = this.testData.loadTestResults;
  const p95ApiResponseTime = results.metrics.apiPost.p95 / 1000;
  expect(p95ApiResponseTime).toBeLessThanOrEqual(threshold);
  this.testData.performanceMetrics = this.testData.performanceMetrics || {};
  this.testData.performanceMetrics.apiPostP95 = p95ApiResponseTime;
});

Then('API POST P99 response time should be less than or equal to {float} seconds', async function (threshold: number) {
  const results = this.testData.loadTestResults;
  const p99ApiResponseTime = results.metrics.apiPost.p99 / 1000;
  expect(p99ApiResponseTime).toBeLessThanOrEqual(threshold);
  this.testData.performanceMetrics = this.testData.performanceMetrics || {};
  this.testData.performanceMetrics.apiPostP99 = p99ApiResponseTime;
});

Then('throughput should be greater than or equal to {int} transactions per second', async function (threshold: number) {
  const results = this.testData.loadTestResults;
  const throughput = results.metrics.throughput;
  expect(throughput).toBeGreaterThanOrEqual(threshold);
  this.testData.performanceMetrics = this.testData.performanceMetrics || {};
  this.testData.performanceMetrics.throughput = throughput;
});

Then('error rate should be less than {float} percent', async function (threshold: number) {
  const results = this.testData.loadTestResults;
  const errorRate = results.metrics.errorRate;
  expect(errorRate).toBeLessThan(threshold);
  this.testData.performanceMetrics = this.testData.performanceMetrics || {};
  this.testData.performanceMetrics.errorRate = errorRate;
});

Then('HTTP 200 success rate should be greater than {float} percent', async function (threshold: number) {
  const results = this.testData.loadTestResults;
  const successRate = results.metrics.http200Rate;
  expect(successRate).toBeGreaterThan(threshold);
  this.testData.performanceMetrics = this.testData.performanceMetrics || {};
  this.testData.performanceMetrics.successRate = successRate;
});

Then('CPU utilization should be less than {int} percent', async function (threshold: number) {
  const results = this.testData.loadTestResults;
  const cpuUtilization = results.metrics.system.cpu;
  expect(cpuUtilization).toBeLessThan(threshold);
  this.testData.systemMetrics = this.testData.systemMetrics || {};
  this.testData.systemMetrics.cpu = cpuUtilization;
});

Then('memory utilization should be less than {int} percent', async function (threshold: number) {
  const results = this.testData.loadTestResults;
  const memoryUtilization = results.metrics.system.memory;
  expect(memoryUtilization).toBeLessThan(threshold);
  this.testData.systemMetrics = this.testData.systemMetrics || {};
  this.testData.systemMetrics.memory = memoryUtilization;
});

Then('database connection pool should be less than {int} percent capacity', async function (threshold: number) {
  const results = this.testData.loadTestResults;
  const dbPoolUtilization = results.metrics.database.connectionPoolUtilization;
  expect(dbPoolUtilization).toBeLessThan(threshold);
  this.testData.systemMetrics = this.testData.systemMetrics || {};
  this.testData.systemMetrics.dbPoolUtilization = dbPoolUtilization;
});

Then('no connection timeouts should occur', async function () {
  const results = this.testData.loadTestResults;
  const connectionTimeouts = results.metrics.database.connectionTimeouts;
  expect(connectionTimeouts).toBe(0);
});

Then('zero overlapping review cycles should be detected in database', async function () {
  // TODO: Replace XPath with Object Repository when available
  const validationEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/review-cycles/validate/overlaps`;
  const response = await page.request.get(validationEndpoint);
  expect(response.status()).toBe(200);
  const validation = await response.json();
  expect(validation.overlappingCycles).toBe(0);
});

Then('all validation rules should be enforced', async function () {
  // TODO: Replace XPath with Object Repository when available
  const validationEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/review-cycles/validate/rules`;
  const response = await page.request.get(validationEndpoint);
  expect(response.status()).toBe(200);
  const validation = await response.json();
  expect(validation.allRulesEnforced).toBe(true);
  expect(validation.violationCount).toBe(0);
});

Then('{int} percent data consistency should be maintained', async function (expectedConsistency: number) {
  // TODO: Replace XPath with Object Repository when available
  const consistencyEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/review-cycles/validate/consistency`;
  const response = await page.request.get(consistencyEndpoint);
  expect(response.status()).toBe(200);
  const consistency = await response.json();
  expect(consistency.consistencyPercentage).toBe(expectedConsistency);
});

Then('all scheduled review cycles should be persisted correctly in database', async function () {
  // TODO: Replace XPath with Object Repository when available
  const persistenceEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/review-cycles/validate/persistence`;
  const response = await page.request.get(persistenceEndpoint);
  expect(response.status()).toBe(200);
  const validation = await response.json();
  expect(validation.allPersisted).toBe(true);
  expect(validation.missingRecords).toBe(0);
});

Then('no orphaned or corrupted records should exist', async function () {
  // TODO: Replace XPath with Object Repository when available
  const integrityEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/review-cycles/validate/integrity`;
  const response = await page.request.get(integrityEndpoint);
  expect(response.status()).toBe(200);
  const integrity = await response.json();
  expect(integrity.orphanedRecords).toBe(0);
  expect(integrity.corruptedRecords).toBe(0);
});

Then('system should return to idle state with normal resource utilization', async function () {
  // TODO: Replace XPath with Object Repository when available
  await page.waitForTimeout(30000);
  const metricsEndpoint = `${process.env.MONITORING_API_URL || 'https://monitoring.example.com'}/api/metrics/current`;
  const response = await page.request.get(metricsEndpoint);
  expect(response.status()).toBe(200);
  const metrics = await response.json();
  expect(metrics.cpu).toBeLessThan(50);
  expect(metrics.memory).toBeLessThan(60);
  expect(metrics.status).toBe('idle');
});

Then('application logs should contain no errors or warnings related to performance', async function () {
  // TODO: Replace XPath with Object Repository when available
  const logsEndpoint = `${process.env.MONITORING_API_URL || 'https://monitoring.example.com'}/api/logs/search`;
  const response = await page.request.post(logsEndpoint, {
    data: {
      level: ['ERROR', 'WARNING'],
      category: 'performance',
      timeRange: 'last_test_execution'
    }
  });
  expect(response.status()).toBe(200);
  const logs = await response.json();
  expect(logs.count).toBe(0);
});

Then('load generator should successfully ramp up users in incremental steps', async function () {
  const results = this.testData.stressTestResults;
  expect(results.rampUpSuccessful).toBe(true);
  expect(results.incrementSteps).toBeGreaterThan(0);
});

Then('metrics should be captured at each increment showing progressive degradation pattern', async function () {
  const results = this.testData.stressTestResults;
  expect(results.metricsPerIncrement).toBeDefined();
  expect(results.metricsPerIncrement.length).toBeGreaterThan(0);
  
  let previousResponseTime = 0;
  for (const metric of results.metricsPerIncrement) {
    expect(metric.responseTime).toBeGreaterThanOrEqual(previousResponseTime);
    previousResponseTime = metric.responseTime;
  }
});

Then('breaking point should be identified where response time exceeds {int} seconds or error rate exceeds {int} percent', async function (responseThreshold: number, errorThreshold: number) {
  const results = this.testData.stressTestResults;
  expect(results.breakingPoint).toBeDefined();
  const breakingPoint = results.breakingPoint;
  
  const exceedsResponseTime = breakingPoint.responseTime > responseThreshold;
  const exceedsErrorRate = breakingPoint.errorRate > errorThreshold;
  
  expect(exceedsResponseTime || exceedsErrorRate).toBe(true);
  this.testData.breakingPoint = breakingPoint;
});

Then('breaking point should be within expected range of {int} to {int} concurrent users', async function (minUsers: number, maxUsers: number) {
  const breakingPoint = this.testData.breakingPoint;
  expect(breakingPoint.concurrentUsers).toBeGreaterThanOrEqual(minUsers);
  expect(breakingPoint.concurrentUsers).toBeLessThanOrEqual(maxUsers);
});

Then('system should exhibit predictable degradation pattern', async function () {
  const results = this.testData.stressTestResults;
  expect(results.degradationPattern).toBe('predictable');
  expect(results.suddenDrops).toBe(0);
});

Then('rate limiter should activate with HTTP 429 responses', async function () {
  const results = this.testData.stressTestResults;
  expect(results.http429Count).toBeGreaterThan(0);
  expect(results.rateLimiterActivated).toBe(true);
});

Then('queue depth should increase but not overflow', async function () {
  const results = this.testData.stressTestResults;
  expect(results.maxQueueDepth).toBeGreaterThan(0);
  expect(results.queueOverflow).toBe(false);
});

Then('users should receive {string} messages instead of crashes', async function (expectedMessage: string) {
  const results = this.testData.stressTestResults;
  expect(results.gracefulDegradationMessages).toContain(expectedMessage);
  expect(results.systemCrashes).toBe(0);
});

Then('system should recover to normal state within {int} minutes', async function (recoveryMinutes: number) {
  const results = this.testData.stressTestResults;
  expect(results.recoveryTime).toBeLessThanOrEqual(recoveryMinutes * 60);
  expect(results.recoveredToNormal).toBe(true);
});

Then('all queued requests should be processed', async function () {
  const results = this.testData.stressTestResults;
  expect(results.queuedRequests).toBe(results.processedRequests);
  expect(results.unprocessedRequests).toBe(0);
});

Then('no data loss or corruption should occur', async function () {
  // TODO: Replace XPath with Object Repository when available
  const integrityEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/review-cycles/validate/integrity`;
  const response = await page.request.get(integrityEndpoint);
  expect(response.status()).toBe(200);
  const integrity = await response.json();
  expect(integrity.dataLoss).toBe(false);
  expect(integrity.corruption).toBe(false);
});

Then('resource utilization should return to baseline', async function () {
  // TODO: Replace XPath with Object Repository when available
  const metricsEndpoint = `${process.env.MONITORING_API_URL || 'https://monitoring.example.com'}/api/metrics/current`;
  const response = await page.request.get(metricsEndpoint);
  expect(response.status()).toBe(200);
  const currentMetrics = await response.json();
  const baselineMetrics = this.testData.baselineMetrics;
  
  expect(Math.abs(currentMetrics.cpu - baselineMetrics.cpu)).toBeLessThan(10);
  expect(Math.abs(currentMetrics.memory - baselineMetrics.memory)).toBeLessThan(10);
});

Then('no deadlocks should be detected', async function () {
  // TODO: Replace XPath with Object Repository when available
  const deadlockEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/database/deadlocks`;
  const response = await page.request.get(deadlockEndpoint);
  expect(response.status()).toBe(200);
  const deadlocks = await response.json();
  expect(deadlocks.count).toBe(0);
});

Then('all transactions should be completed or rolled back properly', async function () {
  // TODO: Replace XPath with Object Repository when available
  const transactionEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/database/transactions/status`;
  const response = await page.request.get(transactionEndpoint);
  expect(response.status()).toBe(200);
  const transactions = await response.json();
  expect(transactions.pendingTransactions).toBe(0);
  expect(transactions.orphanedTransactions).toBe(0);
});

Then('database consistency checks should pass', async function () {
  // TODO: Replace XPath with Object Repository when available
  const consistencyEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/database/consistency-check`;
  const response = await page.request.post(consistencyEndpoint);
  expect(response.status()).toBe(200);
  const consistencyCheck = await response.json();
  expect(consistencyCheck.passed).toBe(true);
  expect(consistencyCheck.issues).toHaveLength(0);
});

Then('system should be fully operational and responsive', async function () {
  // TODO: Replace XPath with Object Repository when available
  const healthEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/health`;
  const response = await page.request.get(healthEndpoint);
  expect(response.status()).toBe(200);
  const health = await response.json();
  expect(health.status).toBe('healthy');
  expect(health.responsive).toBe(true);
});

Then('all scheduled review cycles during test should be either completed or properly failed with rollback', async function () {
  // TODO: Replace XPath with Object Repository when available
  const cyclesEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/review-cycles/test-execution-status`;
  const response = await page.request.get(cyclesEndpoint);
  expect(response.status()).toBe(200);
  const cycleStatus = await response.json();
  expect(cycleStatus.inProgressCount).toBe(0);
  expect(cycleStatus.completedCount + cycleStatus.rolledBackCount).toBe(cycleStatus.totalCount);
});

Then('no memory leaks or resource exhaustion should be detected', async function () {
  // TODO: Replace XPath with Object Repository when available
  const resourceEndpoint = `${process.env.MONITORING_API_URL || 'https://monitoring.example.com'}/api/resources/analysis`;
  const response = await page.request.get(resourceEndpoint);
  expect(response.status()).toBe(200);
  const analysis = await response.json();
  expect(analysis.memoryLeaks).toBe(false);
  expect(analysis.resourceExhaustion).toBe(false);
});

Then('breaking point threshold should be documented for capacity planning', async function () {
  const breakingPoint = this.testData.breakingPoint;
  expect(breakingPoint).toBeDefined();
  expect(breakingPoint.concurrentUsers).toBeGreaterThan(0);
  expect(breakingPoint.responseTime).toBeGreaterThan(0);
  expect(breakingPoint.errorRate).toBeGreaterThan(0);
  
  console.log('Breaking Point Documentation:', JSON.stringify(breakingPoint, null, 2));
});

Then('system should operate normally with P95 response time less than {float} seconds', async function (threshold: number) {
  const baselineMetrics = this.testData.baselineMetrics;
  const p95ResponseTime = baselineMetrics.responseTime.p95 / 1000;
  expect(p95ResponseTime).toBeLessThan(threshold);
});

Then('CPU utilization should be approximately {int} percent', async function (expectedCpu: number) {
  const baselineMetrics = this.testData.baselineMetrics;
  const cpuUtilization = baselineMetrics.cpu;
  expect(Math.abs(cpuUtilization - expectedCpu)).toBeLessThan(10);
});

Then('{int} application instances should be running', async function (expectedInstances: number) {
  // TODO: Replace XPath with Object Repository when available
  const instancesEndpoint = `${process.env.INFRA_API_URL || 'https://infrastructure.example.com'}/api/instances/count`;
  const response = await page.request.get(instancesEndpoint);
  expect(response.status()).toBe(200);
  const instances = await response.json();
  expect(instances.count).toBe(expectedInstances);
  this.testData.currentInstances = expectedInstances;
});

Then('load generator should successfully create spike from {int} to {int} users in {int} seconds', async function (fromUsers: number, toUsers: number, spikeTime: number) {
  const spikeResults = this.testData.spikeResults;
  expect(spikeResults.spikeSuccessful).toBe(true);
  expect(spikeResults.startUsers).toBe(fromUsers);
  expect(spikeResults.endUsers).toBe(toUsers);
  expect(spikeResults.actualSpikeTime).toBeLessThanOrEqual(spikeTime + 5);
});

Then('initial response time spike to {int} to {int} seconds should be acceptable', async function (minResponseTime: number, maxResponseTime: number) {
  const spikeResults = this.testData.spikeResults;
  const initialResponseTime = spikeResults.initialResponseTime / 1000;
  expect(initialResponseTime).toBeGreaterThanOrEqual(minResponseTime);
  expect(initialResponseTime).toBeLessThanOrEqual(maxResponseTime);
});

Then('error rate should remain less than {int} percent', async function (threshold: number) {
  const spikeResults = this.testData.spikeResults;
  const errorRate = spikeResults.errorRate;
  expect(errorRate).toBeLessThan(threshold);
});

Then('no HTTP 500 errors should occur', async function () {
  const spikeResults = this.testData.spikeResults;
  expect(spikeResults.http500Count).toBe(0);
});

Then('auto-scaling should trigger within {int} seconds', async function (threshold: number) {
  const spikeResults = this.testData.spikeResults;
  expect(spikeResults.autoScalingTriggerTime).toBeLessThanOrEqual(threshold);
  expect(spikeResults.autoScalingTriggered).toBe(true);
});

Then('additional instances should provision within {int} seconds', async function (threshold: number) {
  const spikeResults = this.testData.spikeResults;
  expect(spikeResults.instanceProvisionTime).toBeLessThanOrEqual(threshold);
});

Then('system should scale to {int} to {int} instances', async function (minInstances: number, maxInstances: number) {
  const spikeResults = this.testData.spikeResults;
  const scaledInstances = spikeResults.scaledInstanceCount;
  expect(scaledInstances).toBeGreaterThanOrEqual(minInstances);
  expect(scaledInstances).toBeLessThanOrEqual(maxInstances);
  this.testData.scaledInstances = scaledInstances;
});

Then('response times should stabilize to P95 less than {float} seconds within {int} minutes', async function (threshold: number, stabilizationMinutes: number) {
  const spikeResults = this.testData.spikeResults;
  expect(spikeResults.stabilizationTime).toBeLessThanOrEqual(stabilizationMinutes * 60);
  const stabilizedP95 = spikeResults.stabilizedP95 / 1000;
  expect(stabilizedP95).toBeLessThan(threshold);
});

Then('throughput should increase to greater than {int} transactions per second', async function (threshold: number) {
  const spikeResults = this.testData.spikeResults;
  const throughput = spikeResults.throughput;
  expect(throughput).toBeGreaterThan(threshold);
});

Then('response times should remain stable with P95 less than {float} seconds', async function (threshold: number) {
  const sustainedMetrics = this.testData.sustainedSpikeMetrics;
  const p95ResponseTime = sustainedMetrics.responseTime.p95 / 1000;
  expect(p95ResponseTime).toBeLessThan(threshold);
});

Then('P99 response time should be less than {float} seconds', async function (threshold: number) {
  const sustainedMetrics = this.testData.sustainedSpikeMetrics;
  const p99ResponseTime = sustainedMetrics.responseTime.p99 / 1000;
  expect(p99ResponseTime).toBeLessThan(threshold);
});

Then('CPU per instance should be less than {int} percent', async function (threshold: number) {
  const sustainedMetrics = this.testData.sustainedSpikeMetrics;
  const cpuPerInstance = sustainedMetrics.cpuPerInstance;
  expect(cpuPerInstance).toBeLessThan(threshold);
});

Then('no database connection exhaustion should occur', async function () {
  const sustainedMetrics = this.testData.sustainedSpikeMetrics;
  expect(sustainedMetrics.databaseConnectionExhaustion).toBe(false);
  expect(sustainedMetrics.connectionPoolUtilization).toBeLessThan(95);
});

Then('system should handle rapid decrease gracefully', async function () {
  const decreaseResults = this.testData.decreaseResults;
  expect(decreaseResults.gracefulDecrease).toBe(true);
  expect(decreaseResults.errors).toBe(0);
});

Then('auto-scaling should initiate scale-down after {int} minute cooldown', async function (cooldownMinutes: number) {
  const decreaseResults = this.testData.decreaseResults;
  expect(decreaseResults.scaleDownInitiated).toBe(true);
  expect(decreaseResults.cooldownTime).toBeGreaterThanOrEqual(cooldownMinutes * 60);
});

Then('instances should reduce to {int} to {int}', async function (minInstances: number, maxInstances: number) {
  const decreaseResults = this.testData.decreaseResults;
  const finalInstances = decreaseResults.finalInstanceCount;
  expect(finalInstances).toBeGreaterThanOrEqual(minInstances);
  expect(finalInstances).toBeLessThanOrEqual(maxInstances);
});

Then('no in-flight requests should be dropped', async function () {
  const decreaseResults = this.testData.decreaseResults;
  expect(decreaseResults.droppedRequests).toBe(0);
});

Then('zero duplicate review cycles should be created', async function () {
  // TODO: Replace XPath with Object Repository when available
  const duplicateEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/review-cycles/validate/duplicates`;
  const response = await page.request.get(duplicateEndpoint);
  expect(response.status()).toBe(200);
  const validation = await response.json();
  expect(validation.duplicateCount).toBe(0);
});

Then('all validation rules should be enforced during spike', async function () {
  // TODO: Replace XPath with Object Repository when available
  const validationEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/review-cycles/validate/rules`;
  const response = await page.request.get(validationEndpoint);
  expect(response.status()).toBe(200);
  const validation = await response.json();
  expect(validation.allRulesEnforced).toBe(true);
  expect(validation.violationsDuringSpike).toBe(0);
});

Then('no overlapping cycles should exist', async function () {
  // TODO: Replace XPath with Object Repository when available
  const overlapEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/review-cycles/validate/overlaps`;
  const response = await page.request.get(overlapEndpoint);
  expect(response.status()).toBe(200);
  const validation = await response.json();
  expect(validation.overlappingCycles).toBe(0);
});

Then('system should return to baseline performance with {int} instances', async function (expectedInstances: number) {
  // TODO: Replace XPath with Object Repository when available
  await page.waitForTimeout(60000);
  const instancesEndpoint = `${process.env.INFRA_API_URL || 'https://infrastructure.example.com'}/api/instances/count`;
  const response = await page.request.get(instancesEndpoint);
  expect(response.status()).toBe(200);
  const instances = await response.json();
  expect(instances.count).toBe(expectedInstances);
  
  const metricsEndpoint = `${process.env.MONITORING_API_URL || 'https://monitoring.example.com'}/api/metrics/current`;
  const metricsResponse = await page.request.get(metricsEndpoint);
  expect(metricsResponse.status()).toBe(200);
  const metrics = await metricsResponse.json();
  expect(metrics.status).toBe('baseline');
});

Then('all review cycles scheduled during spike should be valid and persisted', async function () {
  // TODO: Replace XPath with Object Repository when available
  const validationEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/review-cycles/validate/spike-cycles`;
  const response = await page.request.get(validationEndpoint);
  expect(response.status()).toBe(200);
  const validation = await response.json();
  expect(validation.allValid).toBe(true);
  expect(validation.allPersisted).toBe(true);
  expect(validation.invalidCount).toBe(0);
});

Then('no orphaned resources or zombie instances should remain', async function () {
  // TODO: Replace XPath with Object Repository when available
  const resourceEndpoint = `${process.env.INFRA_API_URL || 'https://infrastructure.example.com'}/api/resources/orphaned`;
  const response = await page.request.get(resourceEndpoint);
  expect(response.status()).toBe(200);
  const resources = await response.json();
  expect(resources.orphanedResources).toBe(0);
  expect(resources.zombieInstances).toBe(0);
});

Then('auto-scaling metrics and logs should be captured for analysis', async function () {
  // TODO: Replace XPath with Object Repository when available
  const metricsEndpoint = `${process.env.INFRA_API_URL || 'https://infrastructure.example.com'}/api/autoscaling/metrics`;
  const response = await page.request.get(metricsEndpoint);
  expect(response.status()).toBe(200);
  const metrics = await response.json();
  expect(metrics.captured).toBe(true);
  expect(metrics.events).toBeGreaterThan(0);
  this.testData.autoScalingMetrics = metrics;
});

Then('cache hit ratio and effectiveness during spike should be documented', async function () {
  // TODO: Replace XPath with Object Repository when available
  const cacheEndpoint = `${process.env.API_BASE_URL || 'https://api.example.com'}/api/cache/metrics`;
  const response = await page.request.get(cacheEndpoint);
  expect(response.status()).toBe(200);
  const cacheMetrics = await response.json();
  expect(cacheMetrics.hitRatio).toBeDefined();
  expect(cacheMetrics.effectiveness).toBeDefined();
  
  console.log('Cache Metrics During Spike:', JSON.stringify(cacheMetrics, null, 2));
  this.testData.cacheMetrics = cacheMetrics;
});