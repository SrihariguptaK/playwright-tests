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
    loadTestResults: {},
    systemState: {},
    alertMetrics: {}
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
/*  Title: Alert generation and dispatch under peak concurrent load
/*  Priority: Critical
/*  Category: Performance - Load Testing
/**************************************************/

Given('attendance database is populated with active user records', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/database-setup`);
  await waits.waitForNetworkIdle();
  const statusXPath = '//div[@id="database-status"]';
  await assertions.assertVisible(page.locator(statusXPath));
});

Given('alert dispatch service is operational', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/services`);
  await waits.waitForNetworkIdle();
  const serviceStatusXPath = '//div[@id="alert-dispatch-service-status"]';
  await assertions.assertContainsText(page.locator(serviceStatusXPath), 'operational');
});

Given('monitoring tools are configured to track performance metrics', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/monitoring`);
  await waits.waitForNetworkIdle();
  const monitoringConfigXPath = '//div[@id="monitoring-configuration"]';
  await assertions.assertVisible(page.locator(monitoringConfigXPath));
});

Given('test environment mirrors production capacity', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/environment-config`);
  await waits.waitForNetworkIdle();
  const envStatusXPath = '//div[@id="environment-status"]';
  await assertions.assertContainsText(page.locator(envStatusXPath), 'production-mirror');
});

Given('attendance database contains {int} active user records', async function (recordCount: number) {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/database-setup`);
  await waits.waitForNetworkIdle();
  const recordCountInputXPath = '//input[@id="record-count"]';
  await actions.fill(page.locator(recordCountInputXPath), recordCount.toString());
  const generateButtonXPath = '//button[@id="generate-records"]';
  await actions.click(page.locator(generateButtonXPath));
  await waits.waitForNetworkIdle();
  this.testData.recordCount = recordCount;
});

Given('monitoring tools track {string} response times', async function (metricsType: string) {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/monitoring`);
  await waits.waitForNetworkIdle();
  const metricsInputXPath = '//input[@id="metrics-type"]';
  await actions.fill(page.locator(metricsInputXPath), metricsType);
  const enableButtonXPath = '//button[@id="enable-metrics"]';
  await actions.click(page.locator(enableButtonXPath));
  await waits.waitForNetworkIdle();
  this.testData.metricsType = metricsType;
});

Given('baseline metrics are established for normal load', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/performance/baseline`);
  await waits.waitForNetworkIdle();
  const establishButtonXPath = '//button[@id="establish-baseline"]';
  await actions.click(page.locator(establishButtonXPath));
  await waits.waitForNetworkIdle();
  const baselineStatusXPath = '//div[@id="baseline-status"]';
  await assertions.assertContainsText(page.locator(baselineStatusXPath), 'established');
});

/**************************************************/
/*  TEST CASE: TC-PERF-002
/*  Title: System breaking point identification and graceful degradation validation
/*  Priority: High
/*  Category: Performance - Stress Testing
/**************************************************/

Given('system is operating at baseline performance', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/system-status`);
  await waits.waitForNetworkIdle();
  const performanceStatusXPath = '//div[@id="performance-status"]';
  await assertions.assertContainsText(page.locator(performanceStatusXPath), 'baseline');
});

Given('circuit breakers and rate limiters are configured', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/resilience-config`);
  await waits.waitForNetworkIdle();
  const circuitBreakerXPath = '//div[@id="circuit-breaker-status"]';
  const rateLimiterXPath = '//div[@id="rate-limiter-status"]';
  await assertions.assertContainsText(page.locator(circuitBreakerXPath), 'configured');
  await assertions.assertContainsText(page.locator(rateLimiterXPath), 'configured');
});

Given('database backup is completed', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/database-backup`);
  await waits.waitForNetworkIdle();
  const backupButtonXPath = '//button[@id="create-backup"]';
  await actions.click(page.locator(backupButtonXPath));
  await waits.waitForNetworkIdle();
  const backupStatusXPath = '//div[@id="backup-status"]';
  await assertions.assertContainsText(page.locator(backupStatusXPath), 'completed');
});

Given('monitoring and alerting systems are active', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/monitoring`);
  await waits.waitForNetworkIdle();
  const monitoringStatusXPath = '//div[@id="monitoring-status"]';
  const alertingStatusXPath = '//div[@id="alerting-status"]';
  await assertions.assertContainsText(page.locator(monitoringStatusXPath), 'active');
  await assertions.assertContainsText(page.locator(alertingStatusXPath), 'active');
});

Given('rollback procedures are documented and ready', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/rollback-procedures`);
  await waits.waitForNetworkIdle();
  const proceduresStatusXPath = '//div[@id="rollback-procedures-status"]';
  await assertions.assertContainsText(page.locator(proceduresStatusXPath), 'ready');
});

/**************************************************/
/*  TEST CASE: TC-PERF-003
/*  Title: System stability validation during 24-hour continuous operation
/*  Priority: High
/*  Category: Performance - Endurance Testing
/**************************************************/

Given('system is at baseline with all services restarted', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/services`);
  await waits.waitForNetworkIdle();
  const restartButtonXPath = '//button[@id="restart-all-services"]';
  await actions.click(page.locator(restartButtonXPath));
  await waits.waitForNetworkIdle();
  const servicesStatusXPath = '//div[@id="services-status"]';
  await assertions.assertContainsText(page.locator(servicesStatusXPath), 'running');
});

Given('memory profiling tools are configured', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/profiling`);
  await waits.waitForNetworkIdle();
  const memoryProfilingXPath = '//div[@id="memory-profiling-status"]';
  await assertions.assertContainsText(page.locator(memoryProfilingXPath), 'configured');
});

Given('disk space monitoring is enabled', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/monitoring`);
  await waits.waitForNetworkIdle();
  const diskMonitoringXPath = '//input[@id="disk-monitoring-enabled"]';
  await actions.check(page.locator(diskMonitoringXPath));
  await waits.waitForNetworkIdle();
});

Given('database maintenance jobs are scheduled appropriately', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/database-maintenance`);
  await waits.waitForNetworkIdle();
  const maintenanceStatusXPath = '//div[@id="maintenance-schedule-status"]';
  await assertions.assertContainsText(page.locator(maintenanceStatusXPath), 'scheduled');
});

Given('{int} hour test window is allocated', async function (hours: number) {
  this.testData.testWindowHours = hours;
  await actions.navigateTo(`${process.env.BASE_URL}/admin/test-configuration`);
  await waits.waitForNetworkIdle();
  const testWindowInputXPath = '//input[@id="test-window-hours"]';
  await actions.fill(page.locator(testWindowInputXPath), hours.toString());
});

/**************************************************/
/*  TEST CASE: TC-PERF-004
/*  Title: System response to sudden traffic surge during mass anomaly event
/*  Priority: Critical
/*  Category: Performance - Spike Testing
/**************************************************/

Given('auto-scaling policies are configured and enabled', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/auto-scaling`);
  await waits.waitForNetworkIdle();
  const autoScalingStatusXPath = '//div[@id="auto-scaling-status"]';
  await assertions.assertContainsText(page.locator(autoScalingStatusXPath), 'enabled');
});

Given('message queue system is operational with capacity monitoring', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/message-queue`);
  await waits.waitForNetworkIdle();
  const queueStatusXPath = '//div[@id="message-queue-status"]';
  await assertions.assertContainsText(page.locator(queueStatusXPath), 'operational');
});

Given('baseline load of {int} concurrent users is established', async function (userCount: number) {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/load-test`);
  await waits.waitForNetworkIdle();
  const baselineUsersXPath = '//input[@id="baseline-users"]';
  await actions.fill(page.locator(baselineUsersXPath), userCount.toString());
  const establishButtonXPath = '//button[@id="establish-baseline-load"]';
  await actions.click(page.locator(establishButtonXPath));
  await waits.waitForNetworkIdle();
  this.testData.baselineUsers = userCount;
});

Given('alert prioritization rules are configured', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/alert-prioritization`);
  await waits.waitForNetworkIdle();
  const prioritizationStatusXPath = '//div[@id="prioritization-status"]';
  await assertions.assertContainsText(page.locator(prioritizationStatusXPath), 'configured');
});

Given('cloud infrastructure scaling limits are verified', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/infrastructure`);
  await waits.waitForNetworkIdle();
  const scalingLimitsXPath = '//div[@id="scaling-limits-status"]';
  await assertions.assertContainsText(page.locator(scalingLimitsXPath), 'verified');
});

// ==================== WHEN STEPS ====================

When('load test simulates {int} concurrent users with attendance anomalies', async function (userCount: number) {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/load-test`);
  await waits.waitForNetworkIdle();
  const concurrentUsersXPath = '//input[@id="concurrent-users"]';
  await actions.fill(page.locator(concurrentUsersXPath), userCount.toString());
  this.testData.concurrentUsers = userCount;
});

When('load test executes for {int} minutes with ramp-up from {int} to {int} users over {int} minutes', async function (duration: number, startUsers: number, endUsers: number, rampUpTime: number) {
  const durationInputXPath = '//input[@id="test-duration"]';
  const startUsersXPath = '//input[@id="start-users"]';
  const endUsersXPath = '//input[@id="end-users"]';
  const rampUpXPath = '//input[@id="ramp-up-time"]';
  
  await actions.fill(page.locator(durationInputXPath), duration.toString());
  await actions.fill(page.locator(startUsersXPath), startUsers.toString());
  await actions.fill(page.locator(endUsersXPath), endUsers.toString());
  await actions.fill(page.locator(rampUpXPath), rampUpTime.toString());
  
  const startTestButtonXPath = '//button[@id="start-load-test"]';
  await actions.click(page.locator(startTestButtonXPath));
  await waits.waitForNetworkIdle();
  
  this.testData.loadTestConfig = { duration, startUsers, endUsers, rampUpTime };
});

When('peak load is sustained for {int} minutes', async function (sustainMinutes: number) {
  this.testData.sustainedLoadMinutes = sustainMinutes;
  const sustainInputXPath = '//input[@id="sustained-load-minutes"]';
  await actions.fill(page.locator(sustainInputXPath), sustainMinutes.toString());
});

When('load ramps down after sustained period', async function () {
  const rampDownButtonXPath = '//button[@id="ramp-down"]';
  await actions.click(page.locator(rampDownButtonXPath));
  await waits.waitForNetworkIdle();
});

When('stress test starts at {int} concurrent anomaly detections', async function (startLoad: number) {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/stress-test`);
  await waits.waitForNetworkIdle();
  const startLoadXPath = '//input[@id="start-load"]';
  await actions.fill(page.locator(startLoadXPath), startLoad.toString());
  this.testData.stressTestStartLoad = startLoad;
});

When('load increases by {int} users every {int} minutes until system failure or response time exceeds {int} seconds', async function (increment: number, intervalMinutes: number, thresholdSeconds: number) {
  const incrementXPath = '//input[@id="load-increment"]';
  const intervalXPath = '//input[@id="increment-interval"]';
  const thresholdXPath = '//input[@id="response-time-threshold"]';
  
  await actions.fill(page.locator(incrementXPath), increment.toString());
  await actions.fill(page.locator(intervalXPath), intervalMinutes.toString());
  await actions.fill(page.locator(thresholdXPath), thresholdSeconds.toString());
  
  const startStressTestXPath = '//button[@id="start-stress-test"]';
  await actions.click(page.locator(startStressTestXPath));
  await waits.waitForNetworkIdle();
  
  this.testData.stressTestConfig = { increment, intervalMinutes, thresholdSeconds };
});

When('error rates and response times are monitored at each load increment', async function () {
  const monitoringPanelXPath = '//div[@id="monitoring-panel"]';
  await assertions.assertVisible(page.locator(monitoringPanelXPath));
  const errorRateXPath = '//div[@id="error-rate-monitor"]';
  const responseTimeXPath = '//div[@id="response-time-monitor"]';
  await assertions.assertVisible(page.locator(errorRateXPath));
  await assertions.assertVisible(page.locator(responseTimeXPath));
});

When('system behavior is observed at {string} concurrent users', async function (userLevels: string) {
  this.testData.observedUserLevels = userLevels.split(',').map(level => level.trim());
  const observationConfigXPath = '//input[@id="observation-levels"]';
  await actions.fill(page.locator(observationConfigXPath), userLevels);
});

When('endurance test is configured with sustained load of {int} concurrent users', async function (sustainedLoad: number) {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/endurance-test`);
  await waits.waitForNetworkIdle();
  const sustainedLoadXPath = '//input[@id="sustained-load"]';
  await actions.fill(page.locator(sustainedLoadXPath), sustainedLoad.toString());
  this.testData.sustainedLoad = sustainedLoad;
});

When('test includes realistic daily attendance patterns with morning spike {string}', async function (timeRange: string) {
  const morningSpikePatternsXPath = '//input[@id="morning-spike-pattern"]';
  await actions.fill(page.locator(morningSpikePatternsXPath), timeRange);
  this.testData.morningSpike = timeRange;
});

When('test includes lunch period spike {string}', async function (timeRange: string) {
  const lunchSpikePatternsXPath = '//input[@id="lunch-spike-pattern"]';
  await actions.fill(page.locator(lunchSpikePatternsXPath), timeRange);
  this.testData.lunchSpike = timeRange;
});

When('test includes evening spike {string}', async function (timeRange: string) {
  const eveningSpikePatternsXPath = '//input[@id="evening-spike-pattern"]';
  await actions.fill(page.locator(eveningSpikePatternsXPath), timeRange);
  this.testData.eveningSpike = timeRange;
});

When('{int} hour soak test executes continuously generating attendance anomalies', async function (hours: number) {
  const soakTestDurationXPath = '//input[@id="soak-test-duration"]';
  await actions.fill(page.locator(soakTestDurationXPath), hours.toString());
  const startSoakTestXPath = '//button[@id="start-soak-test"]';
  await actions.click(page.locator(startSoakTestXPath));
  await waits.waitForNetworkIdle();
  this.testData.soakTestDuration = hours;
});

When('memory utilization is monitored every {int} minutes', async function (intervalMinutes: number) {
  const memoryMonitorIntervalXPath = '//input[@id="memory-monitor-interval"]';
  await actions.fill(page.locator(memoryMonitorIntervalXPath), intervalMinutes.toString());
  const enableMemoryMonitorXPath = '//button[@id="enable-memory-monitoring"]';
  await actions.click(page.locator(enableMemoryMonitorXPath));
  await waits.waitForNetworkIdle();
});

When('heap size, garbage collection frequency, and memory growth trends are tracked', async function () {
  const heapTrackingXPath = '//input[@id="heap-tracking-enabled"]';
  const gcTrackingXPath = '//input[@id="gc-tracking-enabled"]';
  const memoryGrowthXPath = '//input[@id="memory-growth-tracking-enabled"]';
  
  await actions.check(page.locator(heapTrackingXPath));
  await actions.check(page.locator(gcTrackingXPath));
  await actions.check(page.locator(memoryGrowthXPath));
  await waits.waitForNetworkIdle();
});

When('response times are compared between hour {int}, hour {int}, and hour {int}', async function (hour1: number, hour2: number, hour3: number) {
  this.testData.comparisonHours = [hour1, hour2, hour3];
  const comparisonConfigXPath = '//input[@id="response-time-comparison-hours"]';
  await actions.fill(page.locator(comparisonConfigXPath), `${hour1},${hour2},${hour3}`);
});

When('database connection pool and thread pool utilization are monitored', async function () {
  const dbPoolMonitorXPath = '//input[@id="db-pool-monitoring-enabled"]';
  const threadPoolMonitorXPath = '//input[@id="thread-pool-monitoring-enabled"]';
  
  await actions.check(page.locator(dbPoolMonitorXPath));
  await actions.check(page.locator(threadPoolMonitorXPath));
  await waits.waitForNetworkIdle();
});

When('disk I/O and log file growth are tracked', async function () {
  const diskIOTrackingXPath = '//input[@id="disk-io-tracking-enabled"]';
  const logGrowthTrackingXPath = '//input[@id="log-growth-tracking-enabled"]';
  
  await actions.check(page.locator(diskIOTrackingXPath));
  await actions.check(page.locator(logGrowthTrackingXPath));
  await waits.waitForNetworkIdle();
});

When('alert delivery is verified at beginning, middle, and end of test period', async function () {
  this.testData.alertVerificationPoints = ['beginning', 'middle', 'end'];
  const verificationConfigXPath = '//input[@id="alert-verification-points"]';
  await actions.fill(page.locator(verificationConfigXPath), 'beginning,middle,end');
});

When('baseline load of {int} concurrent users generates normal attendance anomaly patterns', async function (baselineUsers: number) {
  const baselineLoadXPath = '//input[@id="baseline-load"]';
  await actions.fill(page.locator(baselineLoadXPath), baselineUsers.toString());
  const generatePatternsXPath = '//button[@id="generate-normal-patterns"]';
  await actions.click(page.locator(generatePatternsXPath));
  await waits.waitForNetworkIdle();
});

When('system is operating at baseline with stable performance metrics', async function () {
  const performanceMetricsXPath = '//div[@id="performance-metrics"]';
  await assertions.assertVisible(page.locator(performanceMetricsXPath));
  const stabilityStatusXPath = '//div[@id="stability-status"]';
  await assertions.assertContainsText(page.locator(stabilityStatusXPath), 'stable');
});

When('sudden spike to {int} concurrent users occurs within {int} seconds', async function (spikeUsers: number, spikeSeconds: number) {
  const spikeUsersXPath = '//input[@id="spike-users"]';
  const spikeTimeXPath = '//input[@id="spike-time-seconds"]';
  
  await actions.fill(page.locator(spikeUsersXPath), spikeUsers.toString());
  await actions.fill(page.locator(spikeTimeXPath), spikeSeconds.toString());
  
  const triggerSpikeXPath = '//button[@id="trigger-spike"]';
  await actions.click(page.locator(triggerSpikeXPath));
  await waits.waitForNetworkIdle();
  
  this.testData.spikeConfig = { spikeUsers, spikeSeconds };
});

When('spike simulates mass attendance anomaly event', async function () {
  const massAnomalySimulationXPath = '//input[@id="mass-anomaly-simulation-enabled"]';
  await actions.check(page.locator(massAnomalySimulationXPath));
  await waits.waitForNetworkIdle();
});

When('auto-scaling response time and instance provisioning are monitored', async function () {
  const autoScalingMonitorXPath = '//input[@id="auto-scaling-monitoring-enabled"]';
  const instanceProvisioningMonitorXPath = '//input[@id="instance-provisioning-monitoring-enabled"]';
  
  await actions.check(page.locator(autoScalingMonitorXPath));
  await actions.check(page.locator(instanceProvisioningMonitorXPath));
  await waits.waitForNetworkIdle();
});

When('load balancer behavior is monitored during spike', async function () {
  const loadBalancerMonitorXPath = '//input[@id="load-balancer-monitoring-enabled"]';
  await actions.check(page.locator(loadBalancerMonitorXPath));
  await waits.waitForNetworkIdle();
});

When('alert processing queue depth and delivery success rate are measured', async function () {
  const queueDepthMonitorXPath = '//input[@id="queue-depth-monitoring-enabled"]';
  const deliverySuccessMonitorXPath = '//input[@id="delivery-success-monitoring-enabled"]';
  
  await actions.check(page.locator(queueDepthMonitorXPath));
  await actions.check(page.locator(deliverySuccessMonitorXPath));
  await waits.waitForNetworkIdle();
});

When('spike load is sustained for {int} minutes', async function (sustainMinutes: number) {
  this.testData.spikeSustainMinutes = sustainMinutes;
  const sustainSpikeXPath = '//input[@id="spike-sustain-minutes"]';
  await actions.fill(page.locator(sustainSpikeXPath), sustainMinutes.toString());
});

When('load rapidly decreases back to {int} users within {int} minutes', async function (targetUsers: number, decreaseMinutes: number) {
  const targetUsersXPath = '//input[@id="ramp-down-target-users"]';
  const decreaseTimeXPath = '//input[@id="ramp-down-time-minutes"]';
  
  await actions.fill(page.locator(targetUsersXPath), targetUsers.toString());
  await actions.fill(page.locator(decreaseTimeXPath), decreaseMinutes.toString());
  
  const rampDownXPath = '//button[@id="execute-ramp-down"]';
  await actions.click(page.locator(rampDownXPath));
  await waits.waitForNetworkIdle();
});

When('load generation is stopped', async function () {
  const stopLoadXPath = '//button[@id="stop-load-generation"]';
  await actions.click(page.locator(stopLoadXPath));
  await waits.waitForNetworkIdle();
});

// ==================== THEN STEPS ====================

Then('system should process all anomaly detections without errors', async function () {
  const errorCountXPath = '//div[@id="error-count"]';
  await assertions.assertContainsText(page.locator(errorCountXPath), '0');
});

Then('API endpoint {string} P50 response time should be less than {int} milliseconds', async function (endpoint: string, maxMs: number) {
  const p50MetricXPath = `//div[@id="p50-response-time-${endpoint.replace(/\//g, '-')}"]`;
  const p50Value = await page.locator(p50MetricXPath).textContent();
  const p50Number = parseInt(p50Value?.replace(/\D/g, '') || '0');
  expect(p50Number).toBeLessThan(maxMs);
});

Then('API endpoint {string} P95 response time should be less than {int} milliseconds', async function (endpoint: string, maxMs: number) {
  const p95MetricXPath = `//div[@id="p95-response-time-${endpoint.replace(/\//g, '-')}"]`;
  const p95Value = await page.locator(p95MetricXPath).textContent();
  const p95Number = parseInt(p95Value?.replace(/\D/g, '') || '0');
  expect(p95Number).toBeLessThan(maxMs);
});

Then('API endpoint {string} P99 response time should be less than {int} milliseconds', async function (endpoint: string, maxMs: number) {
  const p99MetricXPath = `//div[@id="p99-response-time-${endpoint.replace(/\//g, '-')}"]`;
  const p99Value = await page.locator(p99MetricXPath).textContent();
  const p99Number = parseInt(p99Value?.replace(/\D/g, '') || '0');
  expect(p99Number).toBeLessThan(maxMs);
});

Then('throughput should be greater than or equal to {int} transactions per second', async function (minTps: number) {
  const throughputXPath = '//div[@id="throughput-tps"]';
  const throughputValue = await page.locator(throughputXPath).textContent();
  const throughputNumber = parseFloat(throughputValue?.replace(/\D/g, '') || '0');
  expect(throughputNumber).toBeGreaterThanOrEqual(minTps);
});

Then('error rate should be less than {float} percent', async function (maxErrorRate: number) {
  const errorRateXPath = '//div[@id="error-rate-percent"]';
  const errorRateValue = await page.locator(errorRateXPath).textContent();
  const errorRateNumber = parseFloat(errorRateValue?.replace(/[^\d.]/g, '') || '0');
  expect(errorRateNumber).toBeLessThan(maxErrorRate);
});

Then('{int} percent of alerts should be dispatched within {int} minutes', async function (percentage: number, maxMinutes: number) {
  const alertDispatchMetricXPath = `//div[@id="alert-dispatch-p${percentage}"]`;
  const dispatchTimeValue = await page.locator(alertDispatchMetricXPath).textContent();
  const dispatchMinutes = parseFloat(dispatchTimeValue?.replace(/\D/g, '') || '0');
  expect(dispatchMinutes).toBeLessThanOrEqual(maxMinutes);
});

Then('CPU utilization should be less than {int} percent', async function (maxCpu: number) {
  const cpuUtilizationXPath = '//div[@id="cpu-utilization-percent"]';
  const cpuValue = await page.locator(cpuUtilizationXPath).textContent();
  const cpuNumber = parseFloat(cpuValue?.replace(/\D/g, '') || '0');
  expect(cpuNumber).toBeLessThan(maxCpu);
});

Then('memory usage should be less than {int} percent', async function (maxMemory: number) {
  const memoryUsageXPath = '//div[@id="memory-usage-percent"]';
  const memoryValue = await page.locator(memoryUsageXPath).textContent();
  const memoryNumber = parseFloat(memoryValue?.replace(/\D/g, '') || '0');
  expect(memoryNumber).toBeLessThan(maxMemory);
});

Then('database connections should be less than {int} percent of pool', async function (maxPoolPercent: number) {
  const dbConnectionsXPath = '//div[@id="db-connections-pool-percent"]';
  const connectionsValue = await page.locator(dbConnectionsXPath).textContent();
  const connectionsNumber = parseFloat(connectionsValue?.replace(/\D/g, '') || '0');
  expect(connectionsNumber).toBeLessThan(maxPoolPercent);
});

Then('no resource exhaustion should occur', async function () {
  const resourceStatusXPath = '//div[@id="resource-exhaustion-status"]';
  await assertions.assertContainsText(page.locator(resourceStatusXPath), 'none');
});

Then('all alerts should be successfully delivered to intended recipients', async function () {
  const alertDeliveryStatusXPath = '//div[@id="alert-delivery-status"]';
  await assertions.assertContainsText(page.locator(alertDeliveryStatusXPath), 'all-delivered');
});

Then('system should return to baseline resource utilization', async function () {
  const resourceUtilizationXPath = '//div[@id="resource-utilization-status"]';
  await assertions.assertContainsText(page.locator(resourceUtilizationXPath), 'baseline');
});

Then('no data loss or corruption should exist in attendance database', async function () {
  const dataIntegrityXPath = '//div[@id="data-integrity-status"]';
  await assertions.assertContainsText(page.locator(dataIntegrityXPath), 'intact');
});

Then('alert history should be accurately recorded', async function () {
  const alertHistoryXPath = '//div[@id="alert-history-status"]';
  await assertions.assertContainsText(page.locator(alertHistoryXPath), 'accurate');
});

Then('system should continue processing requests during load increase', async function () {
  const processingStatusXPath = '//div[@id="request-processing-status"]';
  await assertions.assertContainsText(page.locator(processingStatusXPath), 'active');
});

Then('breaking point should be identified when error rate exceeds {int} percent or P95 response time exceeds {int} seconds', async function (errorThreshold: number, responseThreshold: number) {
  const breakingPointXPath = '//div[@id="breaking-point-identified"]';
  await assertions.assertVisible(page.locator(breakingPointXPath));
  this.testData.breakingPointCriteria = { errorThreshold, responseThreshold };
});

Then('system should implement rate limiting at approximately {int} users', async function (userThreshold: number) {
  const rateLimitingXPath = '//div[@id="rate-limiting-active"]';
  await assertions.assertVisible(page.locator(rateLimitingXPath));
  this.testData.rateLimitingThreshold = userThreshold;
});

Then('circuit breakers should activate appropriately', async function () {
  const circuitBreakerStatusXPath = '//div[@id="circuit-breaker-status"]';
  await assertions.assertContainsText(page.locator(circuitBreakerStatusXPath), 'activated');
});

Then('meaningful error messages should be returned to users', async function () {
  const errorMessagesXPath = '//div[@id="error-messages"]';
  await assertions.assertVisible(page.locator(errorMessagesXPath));
});

Then('no system crashes should occur', async function () {
  const systemStatusXPath = '//div[@id="system-status"]';
  await assertions.assertContainsText(page.locator(systemStatusXPath), 'running');
});

Then('system should recover to normal operation within {int} minutes', async function (maxRecoveryMinutes: number) {
  const recoveryTimeXPath = '//div[@id="recovery-time-minutes"]';
  const recoveryValue = await page.locator(recoveryTimeXPath).textContent();
  const recoveryMinutes = parseFloat(recoveryValue?.replace(/\D/g, '') || '0');
  expect(recoveryMinutes).toBeLessThanOrEqual(maxRecoveryMinutes);
});

Then('queued alerts should be processed in order', async function () {
  const queueProcessingXPath = '//div[@id="queue-processing-order"]';
  await assertions.assertContainsText(page.locator(queueProcessingXPath), 'fifo');
});

Then('no alerts should be lost', async function () {
  const alertLossXPath = '//div[@id="alert-loss-count"]';
  await assertions.assertContainsText(page.locator(alertLossXPath), '0');
});

Then('all anomaly records should be accurately stored', async function () {
  const recordAccuracyXPath = '//div[@id="anomaly-record-accuracy"]';
  await assertions.assertContainsText(page.locator(recordAccuracyXPath), 'accurate');
});

Then('alert history should be complete', async function () {
  const historyCompletenessXPath = '//div[@id="alert-history-completeness"]';
  await assertions.assertContainsText(page.locator(historyCompletenessXPath), 'complete');
});

Then('no data corruption should be detected', async function () {
  const dataCorruptionXPath = '//div[@id="data-corruption-status"]';
  await assertions.assertContainsText(page.locator(dataCorruptionXPath), 'none');
});

Then('breaking point should be documented with specific metrics', async function () {
  const breakingPointDocsXPath = '//div[@id="breaking-point-documentation"]';
  await assertions.assertVisible(page.locator(breakingPointDocsXPath));
});

Then('capacity planning recommendations should be generated', async function () {
  const capacityRecommendationsXPath = '//div[@id="capacity-recommendations"]';
  await assertions.assertVisible(page.locator(capacityRecommendationsXPath));
});

Then('test should run continuously for {int} hours without manual intervention', async function (hours: number) {
  const continuousRunXPath = '//div[@id="continuous-run-status"]';
  await assertions.assertContainsText(page.locator(continuousRunXPath), 'completed');
  this.testData.continuousRunHours = hours;
});

Then('memory usage should remain stable with no upward trend', async function () {
  const memoryTrendXPath = '//div[@id="memory-trend"]';
  await assertions.assertContainsText(page.locator(memoryTrendXPath), 'stable');
});

Then('heap size should fluctuate within normal range', async function () {
  const heapFluctuationXPath = '//div[@id="heap-fluctuation-status"]';
  await assertions.assertContainsText(page.locator(heapFluctuationXPath), 'normal');
});

Then('garbage collection frequency should be consistent', async function () {
  const gcFrequencyXPath = '//div[@id="gc-frequency-status"]';
  await assertions.assertContainsText(page.locator(gcFrequencyXPath), 'consistent');
});

Then('memory growth should be less than {int} percent over {int} hours', async function (maxGrowth: number, hours: number) {
  const memoryGrowthXPath = '//div[@id="memory-growth-percent"]';
  const growthValue = await page.locator(memoryGrowthXPath).textContent();
  const growthNumber = parseFloat(growthValue?.replace(/\D/g, '') || '0');
  expect(growthNumber).toBeLessThan(maxGrowth);
});

Then('response time degradation should be less than {int} percent between hour {int} and hour {int}', async function (maxDegradation: number, startHour: number, endHour: number) {
  const degradationXPath = '//div[@id="response-time-degradation-percent"]';
  const degradationValue = await page.locator(degradationXPath).textContent();
  const degradationNumber = parseFloat(degradationValue?.replace(/\D/g, '') || '0');
  expect(degradationNumber).toBeLessThan(maxDegradation);
});

Then('P95 response time should remain under {int} milliseconds throughout test', async function (maxMs: number) {
  const p95ThroughoutXPath = '//div[@id="p95-throughout-test"]';
  const p95Value = await page.locator(p95ThroughoutXPath).textContent();
  const p95Number = parseInt(p95Value?.replace(/\D/g, '') || '0');
  expect(p95Number).toBeLessThan(maxMs);
});

Then('no progressive performance degradation should occur', async function () {
  const degradationStatusXPath = '//div[@id="progressive-degradation-status"]';
  await assertions.assertContainsText(page.locator(degradationStatusXPath), 'none');
});

Then('connection pools should remain stable with no connection leaks', async function () {
  const connectionLeaksXPath = '//div[@id="connection-leaks-status"]';
  await assertions.assertContainsText(page.locator(connectionLeaksXPath), 'none');
});

Then('thread pools should remain healthy', async function () {
  const threadPoolHealthXPath = '//div[@id="thread-pool-health"]';
  await assertions.assertContainsText(page.locator(threadPoolHealthXPath), 'healthy');
});

Then('disk I/O should be consistent', async function () {
  const diskIOStatusXPath = '//div[@id="disk-io-consistency"]';
  await assertions.assertContainsText(page.locator(diskIOStatusXPath), 'consistent');
});

Then('log rotation should function properly', async function () {
  const logRotationXPath = '//div[@id="log-rotation-status"]';
  await assertions.assertContainsText(page.locator(logRotationXPath), 'functioning');
});

Then('alert delivery rate should be consistent throughout {int} hours', async function (hours: number) {
  const deliveryRateXPath = '//div[@id="alert-delivery-rate-consistency"]';
  await assertions.assertContainsText(page.locator(deliveryRateXPath), 'consistent');
});

Then('{int} percent of alerts should be delivered within {int} minute SLA at all measurement points', async function (percentage: number, slaMinutes: number) {
  const slaComplianceXPath = `//div[@id="sla-compliance-p${percentage}"]`;
  await assertions.assertContainsText(page.locator(slaComplianceXPath), 'met');
});

Then('system should remain operational after {int} hour test', async function (hours: number) {
  const operationalStatusXPath = '//div[@id="operational-status"]';
  await assertions.assertContainsText(page.locator(operationalStatusXPath), 'operational');
});

Then('no memory leaks should be identified', async function () {
  const memoryLeaksXPath = '//div[@id="memory-leaks-status"]';
  await assertions.assertContainsText(page.locator(memoryLeaksXPath), 'none');
});

Then('all alerts should be processed and delivered successfully', async function () {
  const alertProcessingXPath = '//div[@id="alert-processing-status"]';
  await assertions.assertContainsText(page.locator(alertProcessingXPath), 'all-successful');
});

Then('load should increase from {int} to {int} users in under {int} seconds', async function (startUsers: number, endUsers: number, maxSeconds: number) {
  const spikeTimeXPath = '//div[@id="spike-time-seconds"]';
  const spikeValue = await page.locator(spikeTimeXPath).textContent();
  const spikeSeconds = parseFloat(spikeValue?.replace(/\D/g, '') || '0');
  expect(spikeSeconds).toBeLessThan(maxSeconds);
});

Then('auto-scaling should trigger within {int} minutes', async function (maxMinutes: number) {
  const autoScalingTriggerXPath = '//div[@id="auto-scaling-trigger-time"]';
  const triggerValue = await page.locator(autoScalingTriggerXPath).textContent();
  const triggerMinutes = parseFloat(triggerValue?.replace(/\D/g, '') || '0');
  expect(triggerMinutes).toBeLessThanOrEqual(maxMinutes);
});

Then('new instances should be provisioned within {int} minutes', async function (maxMinutes: number) {
  const provisioningTimeXPath = '//div[@id="instance-provisioning-time"]';
  const provisionValue = await page.locator(provisioningTimeXPath).textContent();
  const provisionMinutes = parseFloat(provisionValue?.replace(/\D/g, '') || '0');
  expect(provisionMinutes).toBeLessThanOrEqual(maxMinutes);
});

Then('load balancer should distribute traffic effectively', async function () {
  const loadBalancerXPath = '//div[@id="load-balancer-distribution"]';
  await assertions.assertContainsText(page.locator(loadBalancerXPath), 'effective');
});

Then('no service interruption should occur', async function () {
  const serviceInterruptionXPath = '//div[@id="service-interruption-status"]';
  await assertions.assertContainsText(page.locator(serviceInterruptionXPath), 'none');
});

Then('message queue should absorb spike without overflow', async function () {
  const queueOverflowXPath = '//div[@id="queue-overflow-status"]';
  await assertions.assertContainsText(page.locator(queueOverflowXPath), 'none');
});

Then('queue depth should peak but remain manageable', async function () {
  const queueDepthXPath = '//div[@id="queue-depth-status"]';
  await assertions.assertContainsText(page.locator(queueDepthXPath), 'manageable');
});

Then('{int} percent of alerts should be delivered within {int} minutes during spike', async function (percentage: number, maxMinutes: number) {
  const spikeDeliveryXPath = `//div[@id="spike-alert-delivery-p${percentage}"]`;
  const deliveryValue = await page.locator(spikeDeliveryXPath).textContent();
  const deliveryMinutes = parseFloat(deliveryValue?.replace(/\D/g, '') || '0');
  expect(deliveryMinutes).toBeLessThanOrEqual(maxMinutes);
});

Then('system should maintain stability during sustained spike', async function () {
  const stabilityXPath = '//div[@id="sustained-spike-stability"]';
  await assertions.assertContainsText(page.locator(stabilityXPath), 'stable');
});

Then('graceful scale-down should occur after load decrease', async function () {
  const scaleDownXPath = '//div[@id="scale-down-status"]';
  await assertions.assertContainsText(page.locator(scaleDownXPath), 'graceful');
});

Then('no resource thrashing should occur', async function () {
  const resourceThrashingXPath = '//div[@id="resource-thrashing-status"]';
  await assertions.assertContainsText(page.locator(resourceThrashingXPath), 'none');
});

Then('all alerts should be delivered within {int} minutes post-spike', async function (maxMinutes: number) {
  const postSpikeDeliveryXPath = '//div[@id="post-spike-delivery-time"]';
  const deliveryValue = await page.locator(postSpikeDeliveryXPath).textContent();
  const deliveryMinutes = parseFloat(deliveryValue?.replace(/\D/g, '') || '0');
  expect(deliveryMinutes).toBeLessThanOrEqual(maxMinutes);
});

Then('critical alerts should be prioritized', async function () {
  const prioritizationXPath = '//div[@id="alert-prioritization-status"]';
  await assertions.assertContainsText(page.locator(prioritizationXPath), 'active');
});

Then('system should return to baseline performance within {int} minutes of load decrease', async function (maxMinutes: number) {
  const baselineReturnXPath = '//div[@id="baseline-return-time"]';
  const returnValue = await page.locator(baselineReturnXPath).textContent();
  const returnMinutes = parseFloat(returnValue?.replace(/\D/g, '') || '0');
  expect(returnMinutes).toBeLessThanOrEqual(maxMinutes);
});

Then('no alerts should be lost or duplicated', async function () {
  const alertIntegrityXPath = '//div[@id="alert-integrity-status"]';
  await assertions.assertContainsText(page.locator(alertIntegrityXPath), 'intact');
});

Then('performance metrics should return to normal', async function () {
  const metricsStatusXPath = '//div[@id="performance-metrics-status"]';
  await assertions.assertContainsText(page.locator(metricsStatusXPath), 'normal');
});