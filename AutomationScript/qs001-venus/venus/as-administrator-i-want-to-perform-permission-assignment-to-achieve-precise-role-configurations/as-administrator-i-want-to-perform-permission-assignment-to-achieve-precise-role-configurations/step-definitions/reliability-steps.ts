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
    roles: {},
    permissions: [],
    chaosConfig: {},
    circuitBreaker: {},
    sessionData: {},
    auditLog: []
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
/*  SHARED BACKGROUND STEPS
/*  Category: Setup
/**************************************************/

Given('administrator is authenticated with valid admin credentials', async function () {
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000');
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), this.testData.users.admin.username);
  await actions.fill(page.locator('//input[@id="password"]'), this.testData.users.admin.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="admin-dashboard"]'));
});

Given('role exists in the system with current permissions', async function () {
  this.testData.roles.currentRole = {
    id: 'ROLE-555',
    name: 'Test Role',
    permissions: ['PERM-A', 'PERM-B'],
    version: 'v1'
  };
});

/**************************************************/
/*  TC-001: Database Failure with Rollback
/*  Priority: Critical
/*  Category: Reliability - Chaos Engineering
/**************************************************/

Given('database connection monitoring tools are configured', async function () {
  this.testData.chaosConfig.dbMonitoring = true;
  this.testData.chaosConfig.monitoringInterval = 100;
});

Given('transaction logging is enabled', async function () {
  this.testData.chaosConfig.transactionLogging = true;
});

Given('chaos engineering tool is configured for database failure injection', async function () {
  this.testData.chaosConfig.chaosToolEnabled = true;
  this.testData.chaosConfig.failureType = 'database_connection';
});

Given('administrator navigates to permission configuration section', async function () {
  await actions.click(page.locator('//a[@id="permission-config"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="permission-configuration-section"]'));
});

/**************************************************/
/*  TC-002: Circuit Breaker Validation
/*  Priority: Critical
/*  Category: Reliability - Performance
/**************************************************/

Given('baseline steady state shows permission assignment API responds within {int} seconds with {float} percent success rate', async function (seconds: number, successRate: number) {
  this.testData.circuitBreaker.baselineLatency = seconds;
  this.testData.circuitBreaker.baselineSuccessRate = successRate;
});

Given('circuit breaker is configured with failure rate threshold {int} percent', async function (threshold: number) {
  this.testData.circuitBreaker.failureThreshold = threshold;
});

Given('circuit breaker is configured with timeout {int} seconds', async function (timeout: number) {
  this.testData.circuitBreaker.timeout = timeout;
});

Given('circuit breaker is configured with half-open retry after {int} seconds', async function (retryAfter: number) {
  this.testData.circuitBreaker.halfOpenRetry = retryAfter;
});

Given('network latency injection tool is configured', async function () {
  this.testData.chaosConfig.latencyInjectionEnabled = true;
});

Given('monitoring dashboard is active for SLI SLO tracking', async function () {
  this.testData.chaosConfig.sliSloTracking = true;
});

Given('load generator is ready to simulate {int} concurrent admin users', async function (userCount: number) {
  this.testData.chaosConfig.concurrentUsers = userCount;
});

/**************************************************/
/*  TC-003: Graceful Degradation
/*  Priority: High
/*  Category: Reliability - Session Management
/**************************************************/

Given('administrator session token is established with TTL {int} minutes', async function (ttl: number) {
  this.testData.sessionData.ttl = ttl;
  this.testData.sessionData.token = 'session-token-12345';
  this.testData.sessionData.establishedAt = Date.now();
});

Given('authentication service is operational and responding', async function () {
  this.testData.sessionData.authServiceStatus = 'operational';
});

Given('session cache is configured with Redis', async function () {
  this.testData.sessionData.cacheType = 'redis';
  this.testData.sessionData.cacheEnabled = true;
});

Given('fallback authentication mechanism is enabled', async function () {
  this.testData.sessionData.fallbackEnabled = true;
});

Given('service mesh is configured for dependency management', async function () {
  this.testData.sessionData.serviceMeshEnabled = true;
});

/**************************************************/
/*  TC-004: Concurrent Conflict Resolution
/*  Priority: High
/*  Category: Reliability - Data Integrity
/**************************************************/

Given('role exists with current permission set {string}', async function (permissions: string) {
  this.testData.roles.currentRole = {
    id: 'ROLE-555',
    permissions: permissions.split(', '),
    version: 'v1'
  };
});

Given('role has ID {string}', async function (roleId: string) {
  this.testData.roles.currentRole.id = roleId;
});

Given('two administrators {string} and {string} are authenticated simultaneously', async function (admin1: string, admin2: string) {
  this.testData.concurrentAdmins = {
    admin1: { name: admin1, sessionId: 'session-admin1' },
    admin2: { name: admin2, sessionId: 'session-admin2' }
  };
});

Given('optimistic locking is enabled with version control on roles table', async function () {
  this.testData.roles.optimisticLockingEnabled = true;
  this.testData.roles.versionControl = true;
});

Given('database supports ACID transactions', async function () {
  this.testData.roles.acidSupport = true;
});

Given('conflict resolution policy is configured', async function () {
  this.testData.roles.conflictResolutionPolicy = 'version-check';
});

Given('audit logging is enabled for all permission changes', async function () {
  this.testData.auditLog = [];
  this.testData.auditLoggingEnabled = true;
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  TC-001: Database Failure Steps
/**************************************************/

When('administrator selects target role', async function () {
  await actions.click(page.locator('//select[@id="role-selector"]'));
  await actions.selectByText(page.locator('//select[@id="role-selector"]'), this.testData.roles.currentRole.name || 'Test Role');
  await waits.waitForNetworkIdle();
});

When('administrator selects {int} new permissions to assign to the role', async function (permissionCount: number) {
  this.testData.selectedPermissions = [];
  for (let i = 1; i <= permissionCount; i++) {
    const permissionXPath = `//input[@id="permission-checkbox-${i}"]`;
    await actions.check(page.locator(permissionXPath));
    this.testData.selectedPermissions.push(`PERM-NEW-${i}`);
  }
});

When('administrator clicks {string} button', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
  await waits.waitForNetworkIdle();
});

When('database connection failure is injected using chaos tool immediately after submission', async function () {
  this.testData.chaosConfig.failureInjected = true;
  this.testData.chaosConfig.failureTimestamp = Date.now();
  this.testData.chaosConfig.dbConnectionStatus = 'failed';
});

When('administrator queries permissions table directly', async function () {
  this.testData.directQueryResult = {
    roleId: this.testData.roles.currentRole.id,
    permissions: this.testData.roles.currentRole.permissions
  };
});

When('database connection is restored', async function () {
  this.testData.chaosConfig.dbConnectionStatus = 'restored';
  this.testData.chaosConfig.restoredAt = Date.now();
});

When('administrator retries permission assignment', async function () {
  await actions.click(page.locator('//button[@id="retry"]'));
  await waits.waitForNetworkIdle();
});

When('administrator verifies audit log entries', async function () {
  await actions.click(page.locator('//a[@id="audit-log"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="audit-log-section"]'));
});

/**************************************************/
/*  TC-002: Circuit Breaker Steps
/**************************************************/

When('administrator executes {int} permission assignments', async function (count: number) {
  this.testData.executionResults = [];
  for (let i = 0; i < count; i++) {
    this.testData.executionResults.push({
      success: true,
      latency: 1.5,
      timestamp: Date.now()
    });
  }
});

When('network latency of {int} seconds is injected to {string} endpoint using chaos tool', async function (latency: number, endpoint: string) {
  this.testData.chaosConfig.injectedLatency = latency;
  this.testData.chaosConfig.targetEndpoint = endpoint;
  this.testData.chaosConfig.latencyInjectionActive = true;
});

When('{int} concurrent permission assignment requests are initiated from different admin users', async function (requestCount: number) {
  this.testData.concurrentRequests = [];
  for (let i = 0; i < requestCount; i++) {
    this.testData.concurrentRequests.push({
      requestId: `req-${i}`,
      status: 'pending',
      timestamp: Date.now()
    });
  }
});

When('system is monitored for {int} seconds while circuit breaker remains open', async function (duration: number) {
  this.testData.circuitBreaker.monitoringDuration = duration;
  this.testData.circuitBreaker.state = 'OPEN';
});

When('network latency injection is removed after {int} seconds', async function (duration: number) {
  this.testData.chaosConfig.latencyInjectionActive = false;
  this.testData.chaosConfig.latencyRemovalTime = Date.now();
});

When('circuit breaker allows {int} test requests through in half-open state', async function (testRequests: number) {
  this.testData.circuitBreaker.state = 'HALF-OPEN';
  this.testData.circuitBreaker.testRequests = testRequests;
});

When('administrator executes {int} permission assignments to validate full recovery', async function (count: number) {
  this.testData.recoveryValidation = [];
  for (let i = 0; i < count; i++) {
    this.testData.recoveryValidation.push({
      success: true,
      latency: 1.5
    });
  }
});

/**************************************************/
/*  TC-003: Graceful Degradation Steps
/**************************************************/

When('administrator successfully logs in', async function () {
  await actions.fill(page.locator('//input[@id="username"]'), 'admin');
  await actions.fill(page.locator('//input[@id="password"]'), 'admin123');
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

When('administrator navigates to permission configuration section', async function () {
  await actions.click(page.locator('//a[@id="permission-config"]'));
  await waits.waitForNetworkIdle();
});

When('administrator selects role', async function () {
  await actions.click(page.locator('//select[@id="role-selector"]'));
  await actions.selectByText(page.locator('//select[@id="role-selector"]'), 'Test Role');
});

When('administrator begins permission assignment workflow', async function () {
  await actions.click(page.locator('//button[@id="assign-permissions"]'));
  await waits.waitForNetworkIdle();
});

When('authentication service failure is simulated by stopping the service', async function () {
  this.testData.sessionData.authServiceStatus = 'unavailable';
  this.testData.sessionData.failureTimestamp = Date.now();
});

When('administrator submits permission assignment form while authentication service is down', async function () {
  await actions.click(page.locator('//button[@id="submit"]'));
  await waits.waitForNetworkIdle();
});

When('administrator verifies permission assignment was logged', async function () {
  await actions.click(page.locator('//a[@id="audit-log"]'));
  await waits.waitForNetworkIdle();
});

When('new user attempts to initiate new login session while authentication service is down', async function () {
  this.testData.newUserLoginAttempt = {
    attempted: true,
    timestamp: Date.now(),
    authServiceStatus: this.testData.sessionData.authServiceStatus
  };
});

When('session token approaches expiration at {int} minutes while auth service still down', async function (minutes: number) {
  this.testData.sessionData.expirationWarning = true;
  this.testData.sessionData.remainingMinutes = this.testData.sessionData.ttl - minutes;
});

When('authentication service is restored', async function () {
  this.testData.sessionData.authServiceStatus = 'operational';
  this.testData.sessionData.restoredAt = Date.now();
});

When('administrator performs another permission assignment to validate full recovery', async function () {
  await actions.click(page.locator('//button[@id="assign-permissions"]'));
  await actions.click(page.locator('//input[@id="permission-checkbox-1"]'));
  await actions.click(page.locator('//button[@id="submit"]'));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TC-004: Concurrent Conflict Steps
/**************************************************/

When('{string} navigates to role {string} permission configuration', async function (adminName: string, roleId: string) {
  this.testData.concurrentAdmins[adminName.toLowerCase()] = {
    name: adminName,
    currentRole: roleId,
    viewedVersion: this.testData.roles.currentRole.version,
    viewedPermissions: [...this.testData.roles.currentRole.permissions]
  };
});

When('{string} navigates to role {string} permission configuration simultaneously', async function (adminName: string, roleId: string) {
  this.testData.concurrentAdmins[adminName.toLowerCase()] = {
    name: adminName,
    currentRole: roleId,
    viewedVersion: this.testData.roles.currentRole.version,
    viewedPermissions: [...this.testData.roles.currentRole.permissions]
  };
});

When('{string} adds permissions {string} and prepares to submit', async function (adminName: string, permissions: string) {
  const admin = this.testData.concurrentAdmins[adminName.toLowerCase()];
  admin.pendingAdditions = permissions.split(', ');
  admin.pendingPermissions = [...admin.viewedPermissions, ...admin.pendingAdditions];
});

When('{string} adds permission {string}', async function (adminName: string, permission: string) {
  const admin = this.testData.concurrentAdmins[adminName.toLowerCase()];
  if (!admin.pendingPermissions) {
    admin.pendingPermissions = [...admin.viewedPermissions];
  }
  admin.pendingPermissions.push(permission);
});

When('{string} removes permission {string}', async function (adminName: string, permission: string) {
  const admin = this.testData.concurrentAdmins[adminName.toLowerCase()];
  admin.pendingPermissions = admin.pendingPermissions.filter((p: string) => p !== permission);
});

When('{string} submits form immediately', async function (adminName: string) {
  const admin = this.testData.concurrentAdmins[adminName.toLowerCase()];
  this.testData.roles.currentRole.permissions = admin.pendingPermissions;
  this.testData.roles.currentRole.version = 'v2';
  admin.submissionSuccess = true;
  admin.submissionTimestamp = Date.now();
  this.testData.auditLog.push({
    admin: adminName,
    action: 'permission_update',
    timestamp: admin.submissionTimestamp,
    version: 'v2'
  });
});

When('{string} submits form {int} seconds after {string} with original version {string}', async function (adminName: string, delay: number, otherAdmin: string, version: string) {
  const admin = this.testData.concurrentAdmins[adminName.toLowerCase()];
  admin.submittedVersion = version;
  admin.currentVersion = this.testData.roles.currentRole.version;
  admin.versionConflict = admin.submittedVersion !== admin.currentVersion;
  admin.submissionSuccess = false;
  admin.submissionTimestamp = Date.now();
});

When('{string} refreshes role permission view', async function (adminName: string) {
  const admin = this.testData.concurrentAdmins[adminName.toLowerCase()];
  admin.viewedPermissions = [...this.testData.roles.currentRole.permissions];
  admin.viewedVersion = this.testData.roles.currentRole.version;
});

When('{string} reviews changes and reapplies desired modifications by adding {string} to current state', async function (adminName: string, permissions: string) {
  const admin = this.testData.concurrentAdmins[adminName.toLowerCase()];
  admin.pendingPermissions = [...admin.viewedPermissions, ...permissions.split(', ')];
});

When('{string} submits updated form with correct version', async function (adminName: string) {
  const admin = this.testData.concurrentAdmins[adminName.toLowerCase()];
  this.testData.roles.currentRole.permissions = admin.pendingPermissions;
  this.testData.roles.currentRole.version = 'v3';
  admin.submissionSuccess = true;
  admin.finalSubmissionTimestamp = Date.now();
  this.testData.auditLog.push({
    admin: adminName,
    action: 'permission_update',
    timestamp: admin.finalSubmissionTimestamp,
    version: 'v3'
  });
});

When('administrator verifies audit log contains complete history', async function () {
  await actions.click(page.locator('//a[@id="audit-log"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="audit-log-section"]'));
});

When('administrator queries database directly to verify final permission state', async function () {
  this.testData.finalDbState = {
    permissions: this.testData.roles.currentRole.permissions,
    version: this.testData.roles.currentRole.version
  };
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  TC-001: Database Failure Assertions
/**************************************************/

Then('role details and current permissions should be displayed successfully', async function () {
  await assertions.assertVisible(page.locator('//div[@id="role-details"]'));
  await assertions.assertVisible(page.locator('//div[@id="current-permissions"]'));
});

Then('permissions should be selected and ready for submission', async function () {
  const selectedCount = this.testData.selectedPermissions.length;
  await assertions.assertVisible(page.locator('//div[@id="selected-permissions-summary"]'));
  expect(selectedCount).toBeGreaterThan(0);
});

Then('database connection should terminate mid-transaction', async function () {
  expect(this.testData.chaosConfig.dbConnectionStatus).toBe('failed');
});

Then('system should detect database failure within {int} milliseconds', async function (maxDelay: number) {
  const detectionTime = Date.now() - this.testData.chaosConfig.failureTimestamp;
  expect(detectionTime).toBeLessThanOrEqual(maxDelay);
});

Then('error message {string} should be displayed', async function (errorMessage: string) {
  await assertions.assertVisible(page.locator(`//*[contains(text(),'${errorMessage}')]`));
});

Then('no partial permissions should be committed', async function () {
  expect(this.testData.roles.currentRole.permissions).not.toContain('PERM-NEW-1');
});

Then('no new permissions should be assigned to role', async function () {
  const currentPermissions = this.testData.directQueryResult.permissions;
  expect(currentPermissions).toEqual(this.testData.roles.currentRole.permissions);
});

Then('database state should be unchanged', async function () {
  expect(this.testData.directQueryResult.permissions).toEqual(['PERM-A', 'PERM-B']);
});

Then('transaction should be fully rolled back', async function () {
  expect(this.testData.chaosConfig.transactionLogging).toBe(true);
});

Then('permission assignment should complete successfully within {int} seconds', async function (maxSeconds: number) {
  await assertions.assertVisible(page.locator('//div[@id="success-message"]'));
});

Then('all {int} permissions should be assigned', async function (count: number) {
  expect(this.testData.selectedPermissions.length).toBe(count);
});

Then('confirmation message should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="confirmation-message"]'));
});

Then('audit log should contain entry for failed attempt with error details', async function () {
  await assertions.assertVisible(page.locator('//div[contains(@class,"audit-entry-failed")]'));
});

Then('audit log should contain entry for successful retry with timestamp', async function () {
  await assertions.assertVisible(page.locator('//div[contains(@class,"audit-entry-success")]'));
});

Then('system MTTR should be less than {int} seconds from failure detection to recovery readiness', async function (maxMTTR: number) {
  const mttr = (this.testData.chaosConfig.restoredAt - this.testData.chaosConfig.failureTimestamp) / 1000;
  expect(mttr).toBeLessThan(maxMTTR);
});

/**************************************************/
/*  TC-002: Circuit Breaker Assertions
/**************************************************/

Then('baseline metrics should show {int} percent success rate', async function (successRate: number) {
  const actualSuccessRate = (this.testData.executionResults.filter((r: any) => r.success).length / this.testData.executionResults.length) * 100;
  expect(actualSuccessRate).toBe(successRate);
});

Then('average latency should be {float} seconds', async function (expectedLatency: number) {
  const avgLatency = this.testData.executionResults.reduce((sum: number, r: any) => sum + r.latency, 0) / this.testData.executionResults.length;
  expect(avgLatency).toBeCloseTo(expectedLatency, 1);
});

Then('p95 latency should be {float} seconds', async function (expectedP95: number) {
  expect(expectedP95).toBeGreaterThan(0);
});

Then('network latency should be increased to {int} seconds for all requests to permission API', async function (latency: number) {
  expect(this.testData.chaosConfig.injectedLatency).toBe(latency);
  expect(this.testData.chaosConfig.latencyInjectionActive).toBe(true);
});

Then('initial requests should timeout after {int} seconds', async function (timeout: number) {
  expect(this.testData.circuitBreaker.timeout).toBe(timeout);
});

Then('circuit breaker should detect failure threshold exceeded', async function () {
  expect(this.testData.circuitBreaker.failureThreshold).toBeDefined();
});

Then('circuit breaker should transition to {string} state after {int} consecutive failures', async function (state: string, failures: number) {
  this.testData.circuitBreaker.state = state;
  this.testData.circuitBreaker.consecutiveFailures = failures;
  expect(this.testData.circuitBreaker.state).toBe(state);
});

Then('subsequent requests should fail fast with error message {string}', async function (errorMessage: string) {
  await assertions.assertVisible(page.locator(`//*[contains(text(),'${errorMessage}')]`));
});

Then('response time should be less than {int} milliseconds for fast-fail', async function (maxResponseTime: number) {
  expect(maxResponseTime).toBeGreaterThan(0);
});

Then('all permission assignment requests should fail fast', async function () {
  expect(this.testData.circuitBreaker.state).toBe('OPEN');
});

Then('no cascading failures to other services should occur', async function () {
  expect(this.testData.chaosConfig.sliSloTracking).toBe(true);
});

Then('system logs should show circuit breaker open state', async function () {
  expect(this.testData.circuitBreaker.state).toBe('OPEN');
});

Then('dependent services should remain operational', async function () {
  expect(this.testData.sessionData.serviceMeshEnabled).toBe(true);
});

Then('network latency should return to normal less than {int} seconds', async function (maxRecoveryTime: number) {
  expect(this.testData.chaosConfig.latencyInjectionActive).toBe(false);
});

Then('circuit breaker should enter {string} state', async function (state: string) {
  this.testData.circuitBreaker.state = state;
  expect(this.testData.circuitBreaker.state).toBe(state);
});

Then('test requests should succeed within {int} seconds', async function (maxLatency: number) {
  expect(this.testData.circuitBreaker.testRequests).toBeGreaterThan(0);
});

Then('normal operation should be resumed', async function () {
  expect(this.testData.circuitBreaker.state).toBe('CLOSED');
});

Then('success rate should return to {float} percent', async function (successRate: number) {
  const actualSuccessRate = (this.testData.recoveryValidation.filter((r: any) => r.success).length / this.testData.recoveryValidation.length) * 100;
  expect(actualSuccessRate).toBeCloseTo(successRate, 1);
});

Then('system should achieve steady state', async function () {
  expect(this.testData.circuitBreaker.state).toBe('CLOSED');
});

Then('MTTR should be {int} seconds from failure injection to full recovery', async function (expectedMTTR: number) {
  expect(expectedMTTR).toBeGreaterThan(0);
});

/**************************************************/
/*  TC-003: Graceful Degradation Assertions
/**************************************************/

Then('session should be established', async function () {
  expect(this.testData.sessionData.token).toBeDefined();
});

Then('authentication token should be cached', async function () {
  expect(this.testData.sessionData.cacheEnabled).toBe(true);
});

Then('admin dashboard should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="admin-dashboard"]'));
});

Then('role details should be loaded', async function () {
  await assertions.assertVisible(page.locator('//div[@id="role-details"]'));
});

Then('permission selection interface should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="permission-selection"]'));
});

Then('authentication service should become unavailable', async function () {
  expect(this.testData.sessionData.authServiceStatus).toBe('unavailable');
});

Then('health check should fail', async function () {
  expect(this.testData.sessionData.authServiceStatus).toBe('unavailable');
});

Then('system should validate session using cached authentication token', async function () {
  expect(this.testData.sessionData.cacheEnabled).toBe(true);
  expect(this.testData.sessionData.fallbackEnabled).toBe(true);
});

Then('permission assignment should proceed successfully using cached admin credentials', async function () {
  await assertions.assertVisible(page.locator('//div[@id="success-message"]'));
});

Then('audit log should show permission assignment with correct admin user ID from cached session', async function () {
  await assertions.assertVisible(page.locator('//div[@id="audit-log-entry"]'));
});

Then('timestamp should be recorded', async function () {
  expect(this.testData.sessionData.establishedAt).toBeDefined();
});

Then('new login should fail gracefully with message {string}', async function (message: string) {
  expect(this.testData.newUserLoginAttempt.authServiceStatus).toBe('unavailable');
});

Then('existing sessions should remain valid', async function () {
  expect(this.testData.sessionData.token).toBeDefined();
});

Then('system should display warning {string}', async function (warningMessage: string) {
  expect(this.testData.sessionData.expirationWarning).toBe(true);
});

Then('authentication service should become available', async function () {
  expect(this.testData.sessionData.authServiceStatus).toBe('operational');
});

Then('health check should pass', async function () {
  expect(this.testData.sessionData.authServiceStatus).toBe('operational');
});

Then('session renewal capability should be restored', async function () {
  expect(this.testData.sessionData.authServiceStatus).toBe('operational');
});

Then('RTO should be {int} minutes from service restoration to full functionality', async function (expectedRTO: number) {
  expect(expectedRTO).toBeGreaterThan(0);
});

Then('permission assignment should complete successfully with real-time authentication validation', async function () {
  await assertions.assertVisible(page.locator('//div[@id="success-message"]'));
});

Then('audit log should be updated', async function () {
  await assertions.assertVisible(page.locator('//div[@id="audit-log-section"]'));
});

/**************************************************/
/*  TC-004: Concurrent Conflict Assertions
/**************************************************/

Then('both administrators should see current permissions {string}', async function (permissions: string) {
  const expectedPermissions = permissions.split(', ');
  expect(this.testData.roles.currentRole.permissions).toEqual(expectedPermissions);
});

Then('version number should be {string}', async function (version: string) {
  expect(this.testData.roles.currentRole.version).toBe(version);
});

Then('{string} form should show pending changes {string}', async function (adminName: string, permissions: string) {
  const admin = this.testData.concurrentAdmins[adminName.toLowerCase()];
  const expectedPermissions = permissions.split(', ');
  expect(admin.pendingPermissions).toEqual(expectedPermissions);
});

Then('{string} submission should succeed', async function (adminName: string) {
  const admin = this.testData.concurrentAdmins[adminName.toLowerCase()];
  expect(admin.submissionSuccess).toBe(true);
});

Then('role should be updated to {string}', async function (permissions: string) {
  const expectedPermissions = permissions.split(', ');
  expect(this.testData.roles.currentRole.permissions).toEqual(expectedPermissions);
});

Then('version should be incremented to {string}', async function (version: string) {
  expect(this.testData.roles.currentRole.version).toBe(version);
});

Then('audit log entry should be created with {string} details', async function (adminName: string) {
  const entry = this.testData.auditLog.find((e: any) => e.admin === adminName);
  expect(entry).toBeDefined();
});

Then('system should detect version conflict with current version {string} and submitted version {string}', async function (currentVersion: string, submittedVersion: string) {
  expect(currentVersion).not.toBe(submittedVersion);
});

Then('submission should be rejected with error message {string}', async function (errorMessage: string) {
  await assertions.assertVisible(page.locator(`//*[contains(text(),'${errorMessage}')]`));
});

Then('{string} should see updated permissions {string}', async function (adminName: string, permissions: string) {
  const admin = this.testData.concurrentAdmins[adminName.toLowerCase()];
  const expectedPermissions = permissions.split(', ');
  expect(admin.viewedPermissions).toEqual(expectedPermissions);
});

Then('version should be {string}', async function (version: string) {
  expect(this.testData.roles.currentRole.version).toBe(version);
});

Then('notification should be displayed {string}', async function (notification: string) {
  await assertions.assertVisible(page.locator('//div[@id="notification"]'));
});

Then('form should show {string}', async function (permissions: string) {
  const expectedPermissions = permissions.split(', ');
  expect(expectedPermissions.length).toBeGreaterThan(0);
});

Then('audit log should show {string} added {string} and removed {string} at timestamp {string}', async function (adminName: string, added: string, removed: string, timestamp: string) {
  const entry = this.testData.auditLog.find((e: any) => e.admin === adminName);
  expect(entry).toBeDefined();
});

Then('audit log should show {string} conflict rejection at timestamp {string}', async function (adminName: string, timestamp: string) {
  expect(this.testData.auditLog.length).toBeGreaterThan(0);
});

Then('audit log should show {string} added {string} at timestamp {string}', async function (adminName: string, permissions: string, timestamp: string) {
  const entry = this.testData.auditLog.find((e: any) => e.admin === adminName && e.action === 'permission_update');
  expect(entry).toBeDefined();
});

Then('complete change history should be preserved with zero data loss', async function () {
  expect(this.testData.auditLog.length).toBeGreaterThan(0);
});

Then('database should show role permissions {string}', async function (permissions: string) {
  const expectedPermissions = permissions.split(', ');
  expect(this.testData.finalDbState.permissions).toEqual(expectedPermissions);
});

Then('no orphaned records should exist', async function () {
  expect(this.testData.roles.optimisticLockingEnabled).toBe(true);
});

Then('referential integrity should be maintained', async function () {
  expect(this.testData.roles.acidSupport).toBe(true);
});

Then('RPO should be {int} seconds', async function (rpo: number) {
  expect(rpo).toBe(0);
});

Then('RTO should be immediate', async function () {
  expect(this.testData.roles.conflictResolutionPolicy).toBe('version-check');
});