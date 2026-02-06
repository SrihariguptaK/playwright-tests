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
    steadyState: {},
    circuitBreaker: { state: 'closed' },
    validationResults: [],
    failureCount: 0,
    successCount: 0
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
/*  TEST CASE: TC-REL-001
/*  Title: Validation service maintains resilience during database connection failure
/*  Priority: Critical
/*  Category: Reliability - Chaos Engineering
/**************************************************/

Given('validation service is operational with client-side and server-side validation enabled', async function () {
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000');
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="validation-service-status"]'));
  this.testData.serviceStatus = 'operational';
});

Given('database connection monitoring is configured', async function () {
  await assertions.assertVisible(page.locator('//div[@id="db-connection-monitor"]'));
  this.testData.dbMonitoring = true;
});

Given('circuit breaker pattern is implemented for database calls', async function () {
  await assertions.assertVisible(page.locator('//div[@id="circuit-breaker-status"]'));
  this.testData.circuitBreaker.enabled = true;
});

Given('baseline validation response time is established at less than {int} milliseconds', async function (maxTime: number) {
  this.testData.baselineResponseTime = maxTime;
  this.testData.metrics.baselineTime = maxTime;
});

/**************************************************/
/*  TEST CASE: TC-REL-002
/*  Title: Validation service handles network latency with retry logic
/*  Priority: High
/*  Category: Reliability - Network Latency
/**************************************************/

Given('validation API endpoints are accessible and responding normally', async function () {
  await assertions.assertVisible(page.locator('//div[@id="api-endpoints-status"]'));
  this.testData.apiStatus = 'accessible';
});

Given('network latency baseline is established at less than {int} milliseconds', async function (latency: number) {
  this.testData.networkLatencyBaseline = latency;
});

Given('client timeout is configured to {int} seconds', async function (timeout: number) {
  this.testData.clientTimeout = timeout;
});

Given('server timeout is configured to {int} seconds', async function (timeout: number) {
  this.testData.serverTimeout = timeout;
});

Given('retry policy is configured with exponential backoff', async function () {
  await assertions.assertVisible(page.locator('//div[@id="retry-policy-config"]'));
  this.testData.retryPolicy = { enabled: true, type: 'exponential' };
});

/**************************************************/
/*  TEST CASE: TC-REL-003
/*  Title: Validation service gracefully degrades when external dependencies fail
/*  Priority: Critical
/*  Category: Reliability - Fallback
/**************************************************/

Given('external email verification service is integrated', async function () {
  await assertions.assertVisible(page.locator('//div[@id="email-verification-service"]'));
  this.testData.externalServices = this.testData.externalServices || {};
  this.testData.externalServices.emailVerification = 'integrated';
});

Given('external address validation service is integrated', async function () {
  await assertions.assertVisible(page.locator('//div[@id="address-validation-service"]'));
  this.testData.externalServices.addressValidation = 'integrated';
});

Given('local fallback validation rules are configured', async function () {
  await assertions.assertVisible(page.locator('//div[@id="fallback-rules-config"]'));
  this.testData.fallbackRules = true;
});

Given('cache layer is operational with {int} hour TTL for validation results', async function (ttl: number) {
  await assertions.assertVisible(page.locator('//div[@id="cache-layer-status"]'));
  this.testData.cacheTTL = ttl;
});

Given('circuit breaker is configured for external service calls with failure threshold of {int} failures in {int} seconds', async function (failures: number, seconds: number) {
  this.testData.circuitBreaker.failureThreshold = failures;
  this.testData.circuitBreaker.timeWindow = seconds;
});

/**************************************************/
/*  TEST CASE: TC-REL-004
/*  Title: Circuit breaker state transitions and retry policy under load
/*  Priority: High
/*  Category: Reliability - Circuit Breaker
/**************************************************/

Given('circuit breaker is configured with failure threshold of {int} percent', async function (threshold: number) {
  this.testData.circuitBreaker.failureThresholdPercent = threshold;
});

Given('circuit breaker is configured with minimum {int} requests', async function (minRequests: number) {
  this.testData.circuitBreaker.minRequests = minRequests;
});

Given('circuit breaker is configured with timeout of {int} seconds', async function (timeout: number) {
  this.testData.circuitBreaker.timeout = timeout;
});

Given('retry policy is configured with max {int} retries', async function (maxRetries: number) {
  this.testData.retryPolicy = this.testData.retryPolicy || {};
  this.testData.retryPolicy.maxRetries = maxRetries;
});

Given('retry policy is configured with exponential backoff at {int} second, {int} seconds, and {int} seconds', async function (delay1: number, delay2: number, delay3: number) {
  this.testData.retryPolicy.backoffDelays = [delay1, delay2, delay3];
});

Given('load testing environment is prepared with {int} concurrent users', async function (users: number) {
  this.testData.loadTest = { concurrentUsers: users };
});

Given('monitoring dashboards are configured for circuit breaker metrics', async function () {
  await assertions.assertVisible(page.locator('//div[@id="monitoring-dashboard"]'));
  this.testData.monitoring = true;
});

// ==================== WHEN STEPS ====================

When('user submits {int} valid and invalid form inputs to establish steady state', async function (count: number) {
  for (let i = 0; i < count; i++) {
    const isValid = i % 2 === 0;
    const testValue = isValid ? `valid-input-${i}` : '';
    await actions.fill(page.locator('//input[@id="validation-test-field"]'), testValue);
    await actions.click(page.locator('//button[@id="validate"]'));
    await waits.waitForNetworkIdle();
  }
  this.testData.steadyStateSubmissions = count;
});

When('database connection failure is injected using chaos engineering tool', async function () {
  await actions.click(page.locator('//button[@id="inject-db-failure"]'));
  await waits.waitForNetworkIdle();
  this.testData.chaosInjection = { type: 'database', status: 'injected' };
});

When('user submits form inputs with required fields validation', async function () {
  await actions.fill(page.locator('//input[@id="required-field"]'), 'test-value');
  await actions.click(page.locator('//button[@id="validate-required"]'));
  await waits.waitForNetworkIdle();
});

When('user submits form inputs with format validation', async function () {
  await actions.fill(page.locator('//input[@id="format-field"]'), 'test@example.com');
  await actions.click(page.locator('//button[@id="validate-format"]'));
  await waits.waitForNetworkIdle();
});

When('user submits form inputs with length constraints validation', async function () {
  await actions.fill(page.locator('//input[@id="length-field"]'), 'test-length-value');
  await actions.click(page.locator('//button[@id="validate-length"]'));
  await waits.waitForNetworkIdle();
});

When('system behavior is monitored for {int} minutes during failure state', async function (minutes: number) {
  this.testData.monitoringDuration = minutes;
  await page.waitForTimeout(minutes * 60 * 1000);
});

When('user attempts {int} form submissions during failure period', async function (attempts: number) {
  for (let i = 0; i < attempts; i++) {
    await actions.fill(page.locator('//input[@id="validation-test-field"]'), `test-${i}`);
    await actions.click(page.locator('//button[@id="validate"]'));
    await waits.waitForNetworkIdle();
  }
  this.testData.failurePeriodAttempts = attempts;
});

When('database connection is restored', async function () {
  await actions.click(page.locator('//button[@id="restore-db-connection"]'));
  await waits.waitForNetworkIdle();
  this.testData.chaosInjection.status = 'restored';
});

When('data integrity is verified for all submissions during failure period', async function () {
  await actions.click(page.locator('//button[@id="verify-data-integrity"]'));
  await waits.waitForNetworkIdle();
});

When('hypothesis is defined as {string}', async function (hypothesis: string) {
  this.testData.hypothesis = hypothesis;
});

When('steady state metrics are measured for validation success rate', async function () {
  const successRate = await page.locator('//div[@id="success-rate-metric"]').textContent();
  this.testData.steadyState.successRate = parseFloat(successRate || '0');
});

When('steady state metrics are measured for P95 response time', async function () {
  const p95Time = await page.locator('//div[@id="p95-response-time"]').textContent();
  this.testData.steadyState.p95ResponseTime = parseFloat(p95Time || '0');
});

When('steady state metrics are measured for error rate', async function () {
  const errorRate = await page.locator('//div[@id="error-rate-metric"]').textContent();
  this.testData.steadyState.errorRate = parseFloat(errorRate || '0');
});

When('steady state metrics are measured for user abandonment rate', async function () {
  const abandonmentRate = await page.locator('//div[@id="abandonment-rate"]').textContent();
  this.testData.steadyState.abandonmentRate = parseFloat(abandonmentRate || '0');
});

When('{int} milliseconds network latency is injected on validation API endpoints for test user segment', async function (latency: number) {
  await actions.fill(page.locator('//input[@id="latency-injection-value"]'), latency.toString());
  await actions.click(page.locator('//button[@id="inject-latency"]'));
  await waits.waitForNetworkIdle();
  this.testData.injectedLatency = latency;
});

When('user submits {int} form validations during latency injection period', async function (count: number) {
  for (let i = 0; i < count; i++) {
    await actions.fill(page.locator('//input[@id="validation-test-field"]'), `latency-test-${i}`);
    await actions.click(page.locator('//button[@id="validate"]'));
    await waits.waitForNetworkIdle();
  }
  this.testData.latencyTestSubmissions = count;
});

When('validation success rate is measured during latency injection', async function () {
  const successRate = await page.locator('//div[@id="current-success-rate"]').textContent();
  this.testData.metrics.latencySuccessRate = parseFloat(successRate || '0');
});

When('total response time including retries is measured', async function () {
  const responseTime = await page.locator('//div[@id="total-response-time"]').textContent();
  this.testData.metrics.totalResponseTime = parseFloat(responseTime || '0');
});

When('user experience metrics are measured', async function () {
  const uxScore = await page.locator('//div[@id="ux-metrics-score"]').textContent();
  this.testData.metrics.uxScore = parseFloat(uxScore || '0');
});

When('latency injection is removed', async function () {
  await actions.click(page.locator('//button[@id="remove-latency-injection"]'));
  await waits.waitForNetworkIdle();
  this.testData.injectedLatency = 0;
});

When('user submits {int} validations requiring external service calls to establish baseline', async function (count: number) {
  for (let i = 0; i < count; i++) {
    await actions.fill(page.locator('//input[@id="email-field"]'), `test${i}@example.com`);
    await actions.click(page.locator('//button[@id="validate-email"]'));
    await waits.waitForNetworkIdle();
  }
  this.testData.externalServiceBaseline = count;
});

When('external email verification API failure is simulated by blocking API endpoint', async function () {
  await actions.click(page.locator('//button[@id="block-email-api"]'));
  await waits.waitForNetworkIdle();
  this.testData.externalServices.emailVerification = 'blocked';
});

When('user submits {int} email validation requests during external service outage', async function (count: number) {
  for (let i = 0; i < count; i++) {
    await actions.fill(page.locator('//input[@id="email-field"]'), `outage-test${i}@example.com`);
    await actions.click(page.locator('//button[@id="validate-email"]'));
    await waits.waitForNetworkIdle();
  }
  this.testData.outageValidations = count;
});

When('user submits previously validated emails that are in cache', async function () {
  await actions.fill(page.locator('//input[@id="email-field"]'), 'cached@example.com');
  await actions.click(page.locator('//button[@id="validate-email"]'));
  await waits.waitForNetworkIdle();
});

When('user submits {int} address validation requests with external service down', async function (count: number) {
  for (let i = 0; i < count; i++) {
    await actions.fill(page.locator('//input[@id="address-field"]'), `${i} Test Street`);
    await actions.click(page.locator('//button[@id="validate-address"]'));
    await waits.waitForNetworkIdle();
  }
  this.testData.addressValidations = count;
});

When('external services are restored', async function () {
  await actions.click(page.locator('//button[@id="restore-external-services"]'));
  await waits.waitForNetworkIdle();
  this.testData.externalServices.emailVerification = 'restored';
  this.testData.externalServices.addressValidation = 'restored';
});

When('{int} concurrent users submit validation requests at {int} requests per second for {int} minutes', async function (users: number, rps: number, minutes: number) {
  this.testData.loadTest.users = users;
  this.testData.loadTest.rps = rps;
  this.testData.loadTest.duration = minutes;
  await actions.click(page.locator('//button[@id="start-load-test"]'));
  await page.waitForTimeout(minutes * 60 * 1000);
});

When('intermittent failures are introduced in validation service with {int} percent failure rate', async function (failureRate: number) {
  await actions.fill(page.locator('//input[@id="failure-rate"]'), failureRate.toString());
  await actions.click(page.locator('//button[@id="inject-failures"]'));
  await waits.waitForNetworkIdle();
  this.testData.injectedFailureRate = failureRate;
});

When('system behavior is monitored in open state for {int} seconds under continued load', async function (seconds: number) {
  await page.waitForTimeout(seconds * 1000);
  this.testData.openStateMonitoring = seconds;
});

When('circuit breaker timeout of {int} seconds elapses', async function (timeout: number) {
  await page.waitForTimeout(timeout * 1000);
});

When('test requests are submitted with circuit in half-open state and failures still occurring', async function () {
  await actions.fill(page.locator('//input[@id="validation-test-field"]'), 'half-open-test');
  await actions.click(page.locator('//button[@id="validate"]'));
  await waits.waitForNetworkIdle();
});

When('validation service is restored to healthy state', async function () {
  await actions.click(page.locator('//button[@id="restore-service"]'));
  await waits.waitForNetworkIdle();
  this.testData.serviceStatus = 'healthy';
});

When('next half-open transition occurs with successful test request', async function () {
  await page.waitForTimeout(this.testData.circuitBreaker.timeout * 1000);
  await actions.fill(page.locator('//input[@id="validation-test-field"]'), 'success-test');
  await actions.click(page.locator('//button[@id="validate"]'));
  await waits.waitForNetworkIdle();
});

When('single transient failure timeout is introduced during normal operation', async function () {
  await actions.click(page.locator('//button[@id="inject-transient-failure"]'));
  await waits.waitForNetworkIdle();
});

// ==================== THEN STEPS ====================

Then('validation success rate should be {int} percent', async function (expectedRate: number) {
  const successRate = await page.locator('//div[@id="success-rate-metric"]').textContent();
  const actualRate = parseFloat(successRate || '0');
  expect(actualRate).toBeGreaterThanOrEqual(expectedRate);
});

Then('average response time should be less than {int} milliseconds', async function (maxTime: number) {
  const responseTime = await page.locator('//div[@id="avg-response-time"]').textContent();
  const actualTime = parseFloat(responseTime || '0');
  expect(actualTime).toBeLessThan(maxTime);
});

Then('all error messages should display correctly', async function () {
  await assertions.assertVisible(page.locator('//div[@id="error-messages-container"]'));
});

Then('database connection pool should report failure', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="db-connection-status"]'), 'failure');
});

Then('circuit breaker should open within {int} seconds', async function (seconds: number) {
  await page.waitForTimeout(seconds * 1000);
  await assertions.assertContainsText(page.locator('//div[@id="circuit-breaker-state"]'), 'open');
  this.testData.circuitBreaker.state = 'open';
});

Then('client-side validation should continue to function normally', async function () {
  await assertions.assertVisible(page.locator('//div[@id="client-validation-active"]'));
});

Then('server-side validation should return error message {string}', async function (errorMessage: string) {
  await assertions.assertContainsText(page.locator('//div[@id="server-error-message"]'), errorMessage);
});

Then('no 500 errors should be exposed to user', async function () {
  const errorCode = await page.locator('//div[@id="http-status-code"]').textContent();
  expect(errorCode).not.toBe('500');
});

Then('circuit breaker should remain in open state', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="circuit-breaker-state"]'), 'open');
});

Then('client-side validation should block obviously invalid inputs', async function () {
  await assertions.assertVisible(page.locator('//div[@id="client-validation-error"]'));
});

Then('user should receive consistent error messaging', async function () {
  await assertions.assertVisible(page.locator('//div[@id="consistent-error-message"]'));
});

Then('no data loss should occur', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="data-integrity-status"]'), 'no loss');
});

Then('circuit breaker should transition to half-open state within {int} seconds', async function (seconds: number) {
  await page.waitForTimeout(seconds * 1000);
  await assertions.assertContainsText(page.locator('//div[@id="circuit-breaker-state"]'), 'half-open');
  this.testData.circuitBreaker.state = 'half-open';
});

Then('successful validation request should close circuit breaker', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="circuit-breaker-state"]'), 'closed');
  this.testData.circuitBreaker.state = 'closed';
});

Then('full functionality should be restored within {int} seconds', async function (seconds: number) {
  await page.waitForTimeout(seconds * 1000);
  await assertions.assertContainsText(page.locator('//div[@id="service-status"]'), 'fully operational');
});

Then('no corrupted validation records should exist', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="data-corruption-check"]'), 'no corruption');
});

Then('all failed submissions should be properly logged for retry', async function () {
  await assertions.assertVisible(page.locator('//div[@id="failed-submissions-log"]'));
});

Then('transaction rollback should be successful for incomplete operations', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="rollback-status"]'), 'successful');
});

Then('system should return to steady state with {int} percent validation functionality', async function (percentage: number) {
  const functionality = await page.locator('//div[@id="functionality-percentage"]').textContent();
  const actualPercentage = parseFloat(functionality || '0');
  expect(actualPercentage).toBeGreaterThanOrEqual(percentage);
});

Then('circuit breaker should be in closed state', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="circuit-breaker-state"]'), 'closed');
});

Then('all monitoring alerts should be cleared', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="monitoring-alerts"]'), 'cleared');
});

Then('hypothesis should be documented with measurable success criteria', async function () {
  await assertions.assertVisible(page.locator('//div[@id="hypothesis-documentation"]'));
});

Then('blast radius should be limited to test user segment of {int} percent of traffic', async function (percentage: number) {
  const blastRadius = await page.locator('//div[@id="blast-radius-percentage"]').textContent();
  const actualPercentage = parseFloat(blastRadius || '0');
  expect(actualPercentage).toBeLessThanOrEqual(percentage);
});

Then('baseline should show {float} percent success rate', async function (expectedRate: number) {
  expect(this.testData.steadyState.successRate).toBeGreaterThanOrEqual(expectedRate);
});

Then('baseline should show P95 response time of {int} milliseconds', async function (expectedTime: number) {
  expect(this.testData.steadyState.p95ResponseTime).toBeLessThanOrEqual(expectedTime);
});

Then('baseline should show error rate less than {float} percent', async function (maxErrorRate: number) {
  expect(this.testData.steadyState.errorRate).toBeLessThan(maxErrorRate);
});

Then('baseline should show abandonment rate less than {int} percent', async function (maxAbandonmentRate: number) {
  expect(this.testData.steadyState.abandonmentRate).toBeLessThan(maxAbandonmentRate);
});

Then('latency injection should be confirmed via network monitoring', async function () {
  await assertions.assertVisible(page.locator('//div[@id="latency-injection-confirmed"]'));
});

Then('injection should affect only designated test segment', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="injection-scope"]'), 'test segment only');
});

Then('client-side loading indicators should display immediately', async function () {
  await assertions.assertVisible(page.locator('//div[@id="loading-indicator"]'));
});

Then('retry logic should activate after first timeout of {int} seconds', async function (timeout: number) {
  await page.waitForTimeout(timeout * 1000);
  await assertions.assertVisible(page.locator('//div[@id="retry-attempt-1"]'));
});

Then('exponential backoff should be applied at {int} seconds interval', async function (interval: number) {
  await page.waitForTimeout(interval * 1000);
  await assertions.assertVisible(page.locator('//div[@id="exponential-backoff-active"]'));
});

Then('users should see {string} message with progress indicator', async function (message: string) {
  await assertions.assertContainsText(page.locator('//div[@id="user-message"]'), message);
  await assertions.assertVisible(page.locator('//div[@id="progress-indicator"]'));
});

Then('success rate should be greater than or equal to {int} percent', async function (minRate: number) {
  expect(this.testData.metrics.latencySuccessRate).toBeGreaterThanOrEqual(minRate);
});

Then('P95 response time should be less than {int} seconds with retries', async function (maxTime: number) {
  const p95Time = this.testData.metrics.totalResponseTime / 1000;
  expect(p95Time).toBeLessThan(maxTime);
});

Then('error messages should be clear when max retries exceeded', async function () {
  await assertions.assertVisible(page.locator('//div[@id="max-retries-error"]'));
});

Then('no client-side crashes or hangs should occur', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="client-stability"]'), 'stable');
});

Then('system should return to steady state within {int} minutes', async function (minutes: number) {
  await page.waitForTimeout(minutes * 60 * 1000);
  await assertions.assertContainsText(page.locator('//div[@id="system-state"]'), 'steady');
});

Then('success rate should return to {float} percent', async function (expectedRate: number) {
  const successRate = await page.locator('//div[@id="success-rate-metric"]').textContent();
  const actualRate = parseFloat(successRate || '0');
  expect(actualRate).toBeGreaterThanOrEqual(expectedRate);
});

Then('P95 response time should return to {int} milliseconds', async function (expectedTime: number) {
  const p95Time = await page.locator('//div[@id="p95-response-time"]').textContent();
  const actualTime = parseFloat(p95Time || '0');
  expect(actualTime).toBeLessThanOrEqual(expectedTime);
});

Then('no residual performance degradation should exist', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="performance-status"]'), 'no degradation');
});

Then('retry queue should be cleared', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="retry-queue-status"]'), 'cleared');
});

Then('cache hit rate should be {int} percent', async function (expectedRate: number) {
  const cacheHitRate = await page.locator('//div[@id="cache-hit-rate"]').textContent();
  const actualRate = parseFloat(cacheHitRate || '0');
  expect(actualRate).toBeGreaterThanOrEqual(expectedRate);
});

Then('external service call success rate should be {int} percent', async function (expectedRate: number) {
  const successRate = await page.locator('//div[@id="external-service-success-rate"]').textContent();
  const actualRate = parseFloat(successRate || '0');
  expect(actualRate).toBeGreaterThanOrEqual(expectedRate);
});

Then('external service should return errors', async function () {
  await assertions.assertVisible(page.locator('//div[@id="external-service-error"]'));
});

Then('circuit breaker should open after {int} consecutive failures within {int} seconds', async function (failures: number, seconds: number) {
  await page.waitForTimeout(seconds * 1000);
  await assertions.assertContainsText(page.locator('//div[@id="circuit-breaker-state"]'), 'open');
});

Then('monitoring alerts should be triggered', async function () {
  await assertions.assertVisible(page.locator('//div[@id="monitoring-alert-triggered"]'));
});

Then('system should fall back to local regex-based email validation', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="validation-method"]'), 'local regex');
});

Then('validation should complete successfully with warning message {string}', async function (warningMessage: string) {
  await assertions.assertContainsText(page.locator('//div[@id="warning-message"]'), warningMessage);
});

Then('response time should be less than {int} milliseconds', async function (maxTime: number) {
  const responseTime = await page.locator('//div[@id="response-time"]').textContent();
  const actualTime = parseFloat(responseTime || '0');
  expect(actualTime).toBeLessThan(maxTime);
});

Then('cache should serve validation results successfully', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="cache-status"]'), 'serving');
});

Then('no external service calls should be attempted', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="external-calls-count"]'), '0');
});

Then('cache hit rate should be {int} percent for cached entries', async function (expectedRate: number) {
  const cacheHitRate = await page.locator('//div[@id="cache-hit-rate-cached"]').textContent();
  const actualRate = parseFloat(cacheHitRate || '0');
  expect(actualRate).toBe(expectedRate);
});

Then('system should use fallback validation with basic format check', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="fallback-validation-type"]'), 'basic format');
});

Then('system should use fallback validation with required fields check', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="fallback-validation-type"]'), 'required fields');
});

Then('user workflow should not be blocked', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="workflow-status"]'), 'not blocked');
});

Then('informational message {string} should be displayed', async function (message: string) {
  await assertions.assertContainsText(page.locator('//div[@id="informational-message"]'), message);
});

Then('validation should be marked as {string} in database', async function (status: string) {
  await assertions.assertContainsText(page.locator('//div[@id="validation-db-status"]'), status);
});

Then('circuit breaker should transition to half-open state after {int} seconds', async function (seconds: number) {
  await page.waitForTimeout(seconds * 1000);
  await assertions.assertContainsText(page.locator('//div[@id="circuit-breaker-state"]'), 'half-open');
});

Then('successful test request should close circuit breaker', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="circuit-breaker-state"]'), 'closed');
});

Then('previously unverified validations should be queued for re-verification', async function () {
  await assertions.assertVisible(page.locator('//div[@id="re-verification-queue"]'));
});

Then('full service should be restored within {int} seconds', async function (seconds: number) {
  await page.waitForTimeout(seconds * 1000);
  await assertions.assertContainsText(page.locator('//div[@id="service-status"]'), 'fully restored');
});

Then('cache should be refreshed with latest validation results', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="cache-refresh-status"]'), 'refreshed');
});

Then('unverified entries should be re-processed and updated', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="unverified-entries-status"]'), 're-processed');
});

Then('success rate should be {int} percent', async function (expectedRate: number) {
  const successRate = await page.locator('//div[@id="success-rate-metric"]').textContent();
  const actualRate = parseFloat(successRate || '0');
  expect(actualRate).toBeGreaterThanOrEqual(expectedRate);
});

Then('zero circuit breaker trips should occur', async function () {
  const trips = await page.locator('//div[@id="circuit-breaker-trips"]').textContent();
  expect(parseInt(trips || '0')).toBe(0);
});

Then('circuit breaker should detect failure threshold exceeded', async function () {
  await assertions.assertVisible(page.locator('//div[@id="failure-threshold-exceeded"]'));
});

Then('circuit breaker should transition to open state within {int} seconds', async function (seconds: number) {
  await page.waitForTimeout(seconds * 1000);
  await assertions.assertContainsText(page.locator('//div[@id="circuit-breaker-state"]'), 'open');
});

Then('fast-fail responses should be returned immediately without calling failing service', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="response-type"]'), 'fast-fail');
});

Then('all requests should fail fast with circuit open error', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="error-type"]'), 'circuit open');
});

Then('retry logic should NOT be activated for circuit-open failures', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="retry-status"]'), 'not activated');
});

Then('system should be protected from overload', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="overload-protection"]'), 'active');
});

Then('circuit breaker should automatically transition to half-open state', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="circuit-breaker-state"]'), 'half-open');
});

Then('single test request should be allowed through to validation service', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="test-request-status"]'), 'allowed');
});

Then('circuit should immediately reopen for another {int} seconds if test request fails', async function (seconds: number) {
  await assertions.assertContainsText(page.locator('//div[@id="circuit-breaker-state"]'), 'open');
  this.testData.circuitBreaker.reopenDuration = seconds;
});

Then('retry logic should activate with exponential backoff for transient errors', async function () {
  await assertions.assertVisible(page.locator('//div[@id="exponential-backoff-active"]'));
});

Then('max {int} retry attempts should occur before final failure', async function (maxRetries: number) {
  const retryCount = await page.locator('//div[@id="retry-count"]').textContent();
  expect(parseInt(retryCount || '0')).toBeLessThanOrEqual(maxRetries);
});

Then('full traffic should resume', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="traffic-status"]'), 'full');
});

Then('MTTR from failure injection to full recovery should be less than {int} seconds', async function (maxSeconds: number) {
  const mttr = await page.locator('//div[@id="mttr-metric"]').textContent();
  const actualMTTR = parseFloat(mttr || '0');
  expect(actualMTTR).toBeLessThan(maxSeconds);
});

Then('request should be retried with {int} second delay for first retry', async function (delay: number) {
  await page.waitForTimeout(delay * 1000);
  await assertions.assertVisible(page.locator('//div[@id="retry-attempt-1"]'));
});

Then('request should be retried with {int} seconds delay for second retry if first fails', async function (delay: number) {
  await page.waitForTimeout(delay * 1000);
  await assertions.assertVisible(page.locator('//div[@id="retry-attempt-2"]'));
});

Then('request should be retried with {int} seconds delay for final retry if second fails', async function (delay: number) {
  await page.waitForTimeout(delay * 1000);
  await assertions.assertVisible(page.locator('//div[@id="retry-attempt-3"]'));
});

Then('total max time should be {int} seconds before final failure', async function (maxTime: number) {
  const totalTime = await page.locator('//div[@id="total-retry-time"]').textContent();
  const actualTime = parseFloat(totalTime || '0');
  expect(actualTime).toBeLessThanOrEqual(maxTime);
});

Then('exponential backoff should be confirmed', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="backoff-type"]'), 'exponential');
});

Then('all retry queues should be cleared', async function () {
  await assertions.assertContainsText(page.locator('//div[@id="retry-queue-status"]'), 'cleared');
});

Then('load testing should be stopped and resources released', async function () {
  await actions.click(page.locator('//button[@id="stop-load-test"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertContainsText(page.locator('//div[@id="load-test-status"]'), 'stopped');
});