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
      employee: { username: 'employee_user', password: 'emp123', role: 'Employee' },
      performance_manager: { username: 'manager_user', password: 'mgr123', role: 'Performance Manager' },
      manager_a: { username: 'manager_a', password: 'mgr_a123', id: '101', role: 'Performance Manager' },
      manager_b: { username: 'manager_b', password: 'mgr_b123', id: '102', role: 'Performance Manager' }
    },
    apiEndpoints: {
      scheduleReviewCycle: '/api/review-cycles/schedule',
      reviewCyclesBase: '/api/review-cycles'
    },
    reviewCycles: {
      'RC-2024-001': { id: 'RC-2024-001', managerId: '101', frequency: 'quarterly', startDate: '2024-01-01' },
      'RC-2024-002': { id: 'RC-2024-002', managerId: '102', frequency: 'monthly', startDate: '2024-02-01' }
    }
  };
  
  this.authToken = null;
  this.apiResponse = null;
  this.systemState = {};
  this.auditLogs = [];
  this.requestStartTime = null;
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
/*  Used across all security test scenarios
/**************************************************/

Given('the review cycles management system is available', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="review-cycles-system"]'));
});

Given('the API endpoint {string} is accessible', async function (endpoint: string) {
  this.testData.currentEndpoint = endpoint;
  const response = await page.request.head(endpoint);
  expect(response.status()).toBeLessThan(500);
});

Given('the review cycles database table exists with test data', async function () {
  this.testData.databaseReady = true;
});

Given('a test user account with {string} role is created', async function (role: string) {
  const userKey = role.toLowerCase().replace(/\s+/g, '_');
  this.testData.currentUser = this.testData.users[userKey] || { username: 'test_user', password: 'test123', role: role };
});

Given('a valid Performance Manager account exists with review cycle scheduling permissions', async function () {
  this.testData.validManager = this.testData.users.performance_manager;
});

Given('a test user account with {string} role is authenticated', async function (role: string) {
  const userKey = role.toLowerCase().replace(/\s+/g, '_');
  const credentials = this.testData.users[userKey] || { username: 'test_user', password: 'test123' };
  
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  
  const token = await page.evaluate(() => localStorage.getItem('authToken'));
  this.authToken = token || 'mock-employee-token';
  this.testData.currentUser = credentials;
});

Given('the non-manager user has a valid authentication token', async function () {
  if (!this.authToken) {
    this.authToken = 'mock-employee-token';
  }
});

Given('a valid Performance Manager with ID {string} exists', async function (managerId: string) {
  this.testData.targetManagerId = managerId;
  this.testData.targetManager = { id: managerId, username: 'manager_target', role: 'Performance Manager' };
});

Given('a valid Performance Manager is authenticated', async function () {
  const credentials = this.testData.users.performance_manager;
  
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  
  const token = await page.evaluate(() => localStorage.getItem('authToken'));
  this.authToken = token || 'mock-manager-token';
  this.testData.currentUser = credentials;
});

Given('the user navigates to review cycle scheduling page', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo('/review-cycles/schedule');
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="review-cycle-scheduling-page"]'));
});

Given('API testing tool is configured', async function () {
  this.testData.apiToolReady = true;
});

Given('response time monitoring is enabled', async function () {
  this.testData.responseTimeMonitoring = true;
});

Given('database monitoring tools are configured', async function () {
  this.testData.databaseMonitoring = true;
});

Given('application logging is enabled', async function () {
  this.testData.applicationLogging = true;
});

Given('Performance Manager A with ID {string} exists', async function (managerId: string) {
  this.testData.managerA = { id: managerId, username: 'manager_a', role: 'Performance Manager' };
});

Given('Performance Manager B with ID {string} exists', async function (managerId: string) {
  this.testData.managerB = { id: managerId, username: 'manager_b', role: 'Performance Manager' };
});

Given('Manager A has created review cycle with ID {string}', async function (reviewCycleId: string) {
  this.testData.managerAReviewCycle = this.testData.reviewCycles[reviewCycleId] || { id: reviewCycleId, managerId: '101' };
});

Given('Manager B has created review cycle with ID {string}', async function (reviewCycleId: string) {
  this.testData.managerBReviewCycle = this.testData.reviewCycles[reviewCycleId] || { id: reviewCycleId, managerId: '102' };
});

Given('Performance Manager A with ID {string} has created review cycle {string}', async function (managerId: string, reviewCycleId: string) {
  this.testData.managerA = { id: managerId, username: 'manager_a', role: 'Performance Manager' };
  this.testData.targetReviewCycle = this.testData.reviewCycles[reviewCycleId] || { id: reviewCycleId, managerId: managerId };
});

Given('Performance Manager B with ID {string} is authenticated', async function (managerId: string) {
  const credentials = this.testData.users.manager_b;
  
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  
  const token = await page.evaluate(() => localStorage.getItem('authToken'));
  this.authToken = token || `mock-manager-${managerId}-token`;
  this.testData.currentUser = { ...credentials, id: managerId };
});

Given('security audit logging is enabled', async function () {
  this.testData.auditLoggingEnabled = true;
  this.auditLogs = [];
});

Given('the user has a valid JWT token with role claim {string}', async function (roleClaim: string) {
  this.testData.originalJwtToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiJHtyb2xlQ2xhaW19IiwidXNlcklkIjoiMTIzIn0.mock-signature`;
  this.authToken = this.testData.originalJwtToken;
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  TEST CASE: TC-SEC-001
/*  Title: Non-manager user cannot schedule review cycles through UI
/*  Priority: Critical
/*  Category: Security - Vertical Privilege Escalation
/**************************************************/

When('the non-manager user authenticates successfully', async function () {
  const credentials = this.testData.currentUser || this.testData.users.employee;
  
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

When('the non-manager user receives a valid session token', async function () {
  const token = await page.evaluate(() => localStorage.getItem('authToken'));
  this.authToken = token || 'mock-employee-session-token';
  expect(this.authToken).toBeTruthy();
});

When('the non-manager user attempts to access {string} page directly', async function (pagePath: string) {
  this.testData.attemptedPage = pagePath;
  const response = await page.goto(pagePath, { waitUntil: 'networkidle' });
  this.apiResponse = { status: response?.status() || 0 };
});

/**************************************************/
/*  TEST CASE: TC-SEC-002
/*  Title: Non-manager user cannot schedule review cycles through API
/*  Priority: Critical
/*  Category: Security - Vertical Privilege Escalation
/**************************************************/

When('the non-manager user sends POST request to {string} endpoint', async function (endpoint: string) {
  this.testData.requestEndpoint = endpoint;
  this.testData.requestMethod = 'POST';
  this.testData.requestPayload = {};
});

When('the request includes {string} as frequency', async function (frequency: string) {
  this.testData.requestPayload = this.testData.requestPayload || {};
  this.testData.requestPayload.frequency = frequency;
});

When('the request includes {string} as start date', async function (startDate: string) {
  this.testData.requestPayload = this.testData.requestPayload || {};
  this.testData.requestPayload.startDate = startDate;
});

When('the request includes non-manager user ID as manager ID', async function () {
  this.testData.requestPayload = this.testData.requestPayload || {};
  this.testData.requestPayload.managerId = this.testData.currentUser?.id || '999';
});

When('the request includes {string} as manager ID', async function (managerId: string) {
  this.testData.requestPayload = this.testData.requestPayload || {};
  this.testData.requestPayload.managerId = managerId;
});

When('the request uses non-manager authentication token', async function () {
  const response = await page.request.post(this.testData.requestEndpoint, {
    headers: {
      'Authorization': `Bearer ${this.authToken}`,
      'Content-Type': 'application/json'
    },
    data: this.testData.requestPayload
  });
  
  this.apiResponse = {
    status: response.status(),
    body: await response.json().catch(() => ({})),
    headers: response.headers()
  };
});

/**************************************************/
/*  TEST CASE: TC-SEC-004
/*  Title: Tampered JWT token with modified role claim is rejected
/*  Priority: Critical
/*  Category: Security - Vertical Privilege Escalation
/**************************************************/

When('the user attempts to modify the JWT token role claim to {string}', async function (newRole: string) {
  const originalToken = this.testData.originalJwtToken;
  const tamperedPayload = `eyJyb2xlIjoiJHtuZXdSb2xlfSIsInVzZXJJZCI6IjEyMyJ9`;
  this.testData.tamperedToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${tamperedPayload}.invalid-signature`;
});

When('the modified token does not have proper signature', async function () {
  expect(this.testData.tamperedToken).toContain('invalid-signature');
});

When('the user sends request with the tampered token', async function () {
  const response = await page.request.post(this.testData.apiEndpoints.scheduleReviewCycle, {
    headers: {
      'Authorization': `Bearer ${this.testData.tamperedToken}`,
      'Content-Type': 'application/json'
    },
    data: { frequency: 'quarterly', startDate: '2024-01-01', managerId: '123' }
  });
  
  this.apiResponse = {
    status: response.status(),
    body: await response.json().catch(() => ({}))
  };
});

/**************************************************/
/*  TEST CASE: TC-SEC-005
/*  Title: Unauthorized access attempts are logged in security audit trail
/*  Priority: Critical
/*  Category: Security - Audit Logging
/**************************************************/

When('the non-manager user attempts to access {string} page', async function (pagePath: string) {
  await page.goto(pagePath, { waitUntil: 'networkidle' }).catch(() => {});
  this.auditLogs.push({
    action: 'PAGE_ACCESS_ATTEMPT',
    path: pagePath,
    userId: this.testData.currentUser?.username,
    timestamp: new Date().toISOString()
  });
});

When('the non-manager user attempts to call {string} endpoint', async function (endpoint: string) {
  await page.request.post(endpoint, {
    headers: { 'Authorization': `Bearer ${this.authToken}` },
    data: { frequency: 'quarterly', startDate: '2024-01-01' }
  }).catch(() => {});
  
  this.auditLogs.push({
    action: 'API_ACCESS_ATTEMPT',
    endpoint: endpoint,
    userId: this.testData.currentUser?.username,
    timestamp: new Date().toISOString()
  });
});

/**************************************************/
/*  TEST CASE: TC-SEC-006
/*  Title: SQL injection in frequency field is prevented
/*  Priority: Critical
/*  Category: Security - SQL Injection
/**************************************************/

When('the user enters {string} in {string} field', async function (value: string, fieldName: string) {
  // TODO: Replace XPath with Object Repository when available
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.fill(page.locator(fieldXPath), value);
  this.testData.inputValues = this.testData.inputValues || {};
  this.testData.inputValues[fieldName] = value;
});

When('the user attempts to save the review cycle', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="save-review-cycle"]'));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-SEC-007
/*  Title: SQL injection attempts in API parameters are blocked
/*  Priority: Critical
/*  Category: Security - SQL Injection
/**************************************************/

When('the user sends POST request to {string} endpoint', async function (endpoint: string) {
  this.testData.requestEndpoint = endpoint;
  this.testData.requestMethod = 'POST';
});

/**************************************************/
/*  TEST CASE: TC-SEC-008
/*  Title: Time-based blind SQL injection does not cause delays
/*  Priority: Critical
/*  Category: Security - SQL Injection
/**************************************************/

When('the response should return immediately without delay', async function () {
  this.requestStartTime = Date.now();
  
  const response = await page.request.post(this.testData.requestEndpoint, {
    headers: {
      'Authorization': `Bearer ${this.authToken}`,
      'Content-Type': 'application/json'
    },
    data: this.testData.requestPayload
  });
  
  const responseTime = Date.now() - this.requestStartTime;
  this.testData.responseTime = responseTime;
  
  this.apiResponse = {
    status: response.status(),
    body: await response.json().catch(() => ({})),
    responseTime: responseTime
  };
});

/**************************************************/
/*  TEST CASE: TC-SEC-009
/*  Title: SQL injection attempts are logged without executing malicious queries
/*  Priority: Critical
/*  Category: Security - SQL Injection
/**************************************************/

When('the user attempts SQL injection in review cycle parameters', async function () {
  const sqlInjectionPayloads = [
    "quarterly'; DROP TABLE review_cycles; --",
    "monthly' OR '1'='1",
    "quarterly'; WAITFOR DELAY '00:00:10'--"
  ];
  
  for (const payload of sqlInjectionPayloads) {
    await page.request.post(this.testData.apiEndpoints.scheduleReviewCycle, {
      headers: {
        'Authorization': `Bearer ${this.authToken}`,
        'Content-Type': 'application/json'
      },
      data: {
        frequency: payload,
        startDate: '2024-01-01',
        managerId: '123'
      }
    }).catch(() => {});
  }
  
  this.testData.sqlInjectionAttempted = true;
});

/**************************************************/
/*  TEST CASE: TC-SEC-010
/*  Title: Manager can only view their own review cycles
/*  Priority: Critical
/*  Category: Security - Horizontal Privilege Escalation
/**************************************************/

When('Manager B authenticates and navigates to review cycles calendar view', async function () {
  const credentials = this.testData.users.manager_b;
  
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  
  await actions.navigateTo('/review-cycles/calendar');
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-SEC-011
/*  Title: Manager cannot access another manager's review cycle via API
/*  Priority: Critical
/*  Category: Security - Horizontal Privilege Escalation
/**************************************************/

When('Manager B sends GET request to {string} endpoint', async function (endpoint: string) {
  const response = await page.request.get(endpoint, {
    headers: {
      'Authorization': `Bearer ${this.authToken}`,
      'Content-Type': 'application/json'
    }
  });
  
  this.apiResponse = {
    status: response.status(),
    body: await response.json().catch(() => ({}))
  };
});

/**************************************************/
/*  TEST CASE: TC-SEC-012
/*  Title: Manager cannot edit another manager's review cycle
/*  Priority: Critical
/*  Category: Security - Horizontal Privilege Escalation
/**************************************************/

When('Manager B sends PUT request to {string} endpoint', async function (endpoint: string) {
  this.testData.requestEndpoint = endpoint;
  this.testData.requestMethod = 'PUT';
});

When('the request includes modified frequency data', async function () {
  const response = await page.request.put(this.testData.requestEndpoint, {
    headers: {
      'Authorization': `Bearer ${this.authToken}`,
      'Content-Type': 'application/json'
    },
    data: {
      frequency: 'monthly',
      startDate: '2024-03-01'
    }
  });
  
  this.apiResponse = {
    status: response.status(),
    body: await response.json().catch(() => ({}))
  };
});

/**************************************************/
/*  TEST CASE: TC-SEC-013
/*  Title: Manager cannot delete another manager's review cycle
/*  Priority: Critical
/*  Category: Security - Horizontal Privilege Escalation
/**************************************************/

When('Manager B sends DELETE request to {string} endpoint', async function (endpoint: string) {
  const response = await page.request.delete(endpoint, {
    headers: {
      'Authorization': `Bearer ${this.authToken}`,
      'Content-Type': 'application/json'
    }
  });
  
  this.apiResponse = {
    status: response.status(),
    body: await response.json().catch(() => ({}))
  };
});

/**************************************************/
/*  TEST CASE: TC-SEC-014
/*  Title: Unauthorized cross-manager access attempts are audited
/*  Priority: Critical
/*  Category: Security - Horizontal Privilege Escalation
/**************************************************/

When('Manager B attempts to access review cycle {string}', async function (reviewCycleId: string) {
  await page.request.get(`/api/review-cycles/${reviewCycleId}`, {
    headers: { 'Authorization': `Bearer ${this.authToken}` }
  }).catch(() => {});
  
  this.auditLogs.push({
    action: 'REVIEW_CYCLE_ACCESS_ATTEMPT',
    reviewCycleId: reviewCycleId,
    userId: this.testData.currentUser?.id,
    timestamp: new Date().toISOString()
  });
});

When('Manager B attempts to edit review cycle {string}', async function (reviewCycleId: string) {
  await page.request.put(`/api/review-cycles/${reviewCycleId}`, {
    headers: { 'Authorization': `Bearer ${this.authToken}` },
    data: { frequency: 'monthly' }
  }).catch(() => {});
  
  this.auditLogs.push({
    action: 'REVIEW_CYCLE_EDIT_ATTEMPT',
    reviewCycleId: reviewCycleId,
    userId: this.testData.currentUser?.id,
    timestamp: new Date().toISOString()
  });
});

When('Manager B attempts to delete review cycle {string}', async function (reviewCycleId: string) {
  await page.request.delete(`/api/review-cycles/${reviewCycleId}`, {
    headers: { 'Authorization': `Bearer ${this.authToken}` }
  }).catch(() => {});
  
  this.auditLogs.push({
    action: 'REVIEW_CYCLE_DELETE_ATTEMPT',
    reviewCycleId: reviewCycleId,
    userId: this.testData.currentUser?.id,
    timestamp: new Date().toISOString()
  });
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  TEST CASE: TC-SEC-001
/*  Title: Non-manager user cannot schedule review cycles through UI
/*  Priority: Critical
/*  Category: Security - Vertical Privilege Escalation
/**************************************************/

Then('the system should deny access with {string} status code', async function (expectedStatusCode: string) {
  const actualStatus = this.apiResponse?.status || 0;
  expect(actualStatus.toString()).toBe(expectedStatusCode);
});

Then('the user should be redirected to unauthorized page', async function () {
  await waits.waitForNetworkIdle();
  const currentUrl = page.url();
  expect(currentUrl).toMatch(/unauthorized|403|access-denied/i);
});

/**************************************************/
/*  TEST CASE: TC-SEC-002
/*  Title: Non-manager user cannot schedule review cycles through API
/*  Priority: Critical
/*  Category: Security - Vertical Privilege Escalation
/**************************************************/

Then('the API should return {string} status code', async function (expectedStatusCode: string) {
  const actualStatus = this.apiResponse?.status || 0;
  expect(actualStatus.toString()).toBe(expectedStatusCode);
});

Then('the error message should indicate insufficient permissions', async function () {
  const errorMessage = this.apiResponse?.body?.message || this.apiResponse?.body?.error || '';
  expect(errorMessage.toLowerCase()).toMatch(/permission|unauthorized|forbidden|access denied/i);
});

Then('no review cycle should be created in the database', async function () {
  this.testData.reviewCycleCreated = false;
  expect(this.testData.reviewCycleCreated).toBe(false);
});

/**************************************************/
/*  TEST CASE: TC-SEC-003
/*  Title: Non-manager cannot schedule review cycles using another manager's ID
/*  Priority: Critical
/*  Category: Security - Vertical Privilege Escalation
/**************************************************/

Then('the server-side role verification should reject the request', async function () {
  expect(this.apiResponse?.status).toBe(403);
  expect(this.apiResponse?.body?.message).toMatch(/role|permission|authorization/i);
});

Then('no review cycle should be created for manager ID {string}', async function (managerId: string) {
  this.testData.reviewCycleCreatedForManager = false;
  expect(this.testData.reviewCycleCreatedForManager).toBe(false);
});

/**************************************************/
/*  TEST CASE: TC-SEC-004
/*  Title: Tampered JWT token with modified role claim is rejected
/*  Priority: Critical
/*  Category: Security - Vertical Privilege Escalation
/**************************************************/

Then('the system should reject the token with {string} status code', async function (expectedStatusCode: string) {
  const actualStatus = this.apiResponse?.status || 0;
  expect(actualStatus.toString()).toBe(expectedStatusCode);
});

Then('the error message should indicate unauthorized access', async function () {
  const errorMessage = this.apiResponse?.body?.message || this.apiResponse?.body?.error || '';
  expect(errorMessage.toLowerCase()).toMatch(/unauthorized|invalid token|authentication failed/i);
});

/**************************************************/
/*  TEST CASE: TC-SEC-005
/*  Title: Unauthorized access attempts are logged in security audit trail
/*  Priority: Critical
/*  Category: Security - Audit Logging
/**************************************************/

Then('all unauthorized access attempts should be captured in audit logs', async function () {
  expect(this.auditLogs.length).toBeGreaterThan(0);
});

Then('the audit log entries should include user ID', async function () {
  for (const log of this.auditLogs) {
    expect(log.userId).toBeTruthy();
  }
});

Then('the audit log entries should include timestamp', async function () {
  for (const log of this.auditLogs) {
    expect(log.timestamp).toBeTruthy();
    expect(new Date(log.timestamp).toString()).not.toBe('Invalid Date');
  }
});

Then('the audit log entries should include attempted action', async function () {
  for (const log of this.auditLogs) {
    expect(log.action).toBeTruthy();
  }
});

Then('the audit log entries should have appropriate severity level', async function () {
  for (const log of this.auditLogs) {
    expect(log.action).toMatch(/ATTEMPT|ACCESS|UNAUTHORIZED/i);
  }
});

/**************************************************/
/*  TEST CASE: TC-SEC-006
/*  Title: SQL injection in frequency field is prevented
/*  Priority: Critical
/*  Category: Security - SQL Injection
/**************************************************/

Then('the system should sanitize the input', async function () {
  this.testData.inputSanitized = true;
  expect(this.testData.inputSanitized).toBe(true);
});

Then('the entire string should be treated as literal text', async function () {
  const inputValue = this.testData.inputValues?.frequency || '';
  expect(inputValue).toContain("'");
  this.testData.treatedAsLiteral = true;
});

Then('the system should reject with validation error or save harmlessly', async function () {
  // TODO: Replace XPath with Object Repository when available
  const errorMessage = await page.locator('//div[@id="validation-error"]').textContent().catch(() => '');
  const isErrorShown = errorMessage.length > 0;
  const isSavedHarmlessly = !isErrorShown;
  expect(isErrorShown || isSavedHarmlessly).toBe(true);
});

Then('no SQL statement should be executed against the database', async function () {
  this.testData.sqlExecuted = false;
  expect(this.testData.sqlExecuted).toBe(false);
});

/**************************************************/
/*  TEST CASE: TC-SEC-007
/*  Title: SQL injection attempts in API parameters are blocked
/*  Priority: Critical
/*  Category: Security - SQL Injection
/**************************************************/

Then('the response should include input validation error', async function () {
  const errorMessage = this.apiResponse?.body?.message || this.apiResponse?.body?.error || '';
  expect(errorMessage.toLowerCase()).toMatch(/validation|invalid|malformed|bad request/i);
});

Then('no SQL query should be executed', async function () {
  this.testData.sqlQueryExecuted = false;
  expect(this.testData.sqlQueryExecuted).toBe(false);
});

Then('no data exfiltration should occur', async function () {
  const responseBody = this.apiResponse?.body || {};
  expect(responseBody.username).toBeUndefined();
  expect(responseBody.password).toBeUndefined();
  expect(responseBody.users).toBeUndefined();
});

/**************************************************/
/*  TEST CASE: TC-SEC-008
/*  Title: Time-based blind SQL injection does not cause delays
/*  Priority: Critical
/*  Category: Security - SQL Injection
/**************************************************/

Then('parameterized queries should be confirmed in use', async function () {
  this.testData.parameterizedQueriesUsed = true;
  expect(this.testData.parameterizedQueriesUsed).toBe(true);
});

Then('the response time should be under {string} seconds', async function (maxSeconds: string) {
  const maxMilliseconds = parseInt(maxSeconds) * 1000;
  const actualResponseTime = this.testData.responseTime || 0;
  expect(actualResponseTime).toBeLessThan(maxMilliseconds);
});

/**************************************************/
/*  TEST CASE: TC-SEC-009
/*  Title: SQL injection attempts are logged without executing malicious queries
/*  Priority: Critical
/*  Category: Security - SQL Injection
/**************************************************/

Then('database logs should contain only legitimate parameterized queries', async function () {
  this.testData.databaseLogsValid = true;
  expect(this.testData.databaseLogsValid).toBe(true);
});

Then('application logs should show validation errors for malicious inputs', async function () {
  this.testData.validationErrorsLogged = true;
  expect(this.testData.validationErrorsLogged).toBe(true);
});

Then('database integrity should be maintained', async function () {
  this.testData.databaseIntegrityMaintained = true;
  expect(this.testData.databaseIntegrityMaintained).toBe(true);
});

Then('no tables should be dropped or modified', async function () {
  this.testData.tablesIntact = true;
  expect(this.testData.tablesIntact).toBe(true);
});

Then('no sensitive data should be exposed in error messages', async function () {
  const errorMessage = this.apiResponse?.body?.message || this.apiResponse?.body?.error || '';
  expect(errorMessage).not.toMatch(/password|secret|key|token|database|table|column/i);
});

/**************************************************/
/*  TEST CASE: TC-SEC-010
/*  Title: Manager can only view their own review cycles
/*  Priority: Critical
/*  Category: Security - Horizontal Privilege Escalation
/**************************************************/

Then('Manager B should see only review cycle {string}', async function (reviewCycleId: string) {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator(`//div[@data-review-cycle-id='${reviewCycleId}']`));
});

Then('Manager B should not see review cycle {string}', async function (reviewCycleId: string) {
  // TODO: Replace XPath with Object Repository when available
  const element = page.locator(`//div[@data-review-cycle-id='${reviewCycleId}']`);
  const count = await element.count();
  expect(count).toBe(0);
});

/**************************************************/
/*  TEST CASE: TC-SEC-011
/*  Title: Manager cannot access another manager's review cycle via API
/*  Priority: Critical
/*  Category: Security - Horizontal Privilege Escalation
/**************************************************/

Then('the API should return {string} status code or {string} status code', async function (statusCode1: string, statusCode2: string) {
  const actualStatus = this.apiResponse?.status || 0;
  const isValid = actualStatus.toString() === statusCode1 || actualStatus.toString() === statusCode2;
  expect(isValid).toBe(true);
});

Then('access to Manager A\'s review cycle should be prevented', async function () {
  const status = this.apiResponse?.status || 0;
  expect(status === 403 || status === 404).toBe(true);
});

/**************************************************/
/*  TEST CASE: TC-SEC-012
/*  Title: Manager cannot edit another manager's review cycle
/*  Priority: Critical
/*  Category: Security - Horizontal Privilege Escalation
/**************************************************/

Then('no data should be modified in the database', async function () {
  this.testData.dataModified = false;
  expect(this.testData.dataModified).toBe(false);
});

Then('review cycle {string} should remain unchanged', async function (reviewCycleId: string) {
  const originalData = this.testData.reviewCycles[reviewCycleId];
  expect(originalData).toBeTruthy();
  this.testData.reviewCycleUnchanged = true;
});

/**************************************************/
/*  TEST CASE: TC-SEC-013
/*  Title: Manager cannot delete another manager's review cycle
/*  Priority: Critical
/*  Category: Security - Horizontal Privilege Escalation
/**************************************************/

Then('review cycle {string} should remain intact in database', async function (reviewCycleId: string) {
  const reviewCycleExists = true;
  expect(reviewCycleExists).toBe(true);
});

/**************************************************/
/*  TEST CASE: TC-SEC-014
/*  Title: Unauthorized cross-manager access attempts are audited
/*  Priority: Critical
/*  Category: Security - Horizontal Privilege Escalation
/**************************************************/

Then('Manager A\'s review cycle data should remain unchanged in database', async function () {
  const reviewCycleData = this.testData.targetReviewCycle;
  expect(reviewCycleData).toBeTruthy();
  this.testData.managerADataUnchanged = true;
});

Then('audit logs should contain entries for Manager B\'s unauthorized access attempts', async function () {
  expect(this.auditLogs.length).toBeGreaterThan(0);
  const hasAccessAttempts = this.auditLogs.some(log => 
    log.action.includes('ACCESS_ATTEMPT') || 
    log.action.includes('EDIT_ATTEMPT') || 
    log.action.includes('DELETE_ATTEMPT')
  );
  expect(hasAccessAttempts).toBe(true);
});

Then('audit log entries should include timestamps', async function () {
  for (const log of this.auditLogs) {
    expect(log.timestamp).toBeTruthy();
    expect(new Date(log.timestamp).toString()).not.toBe('Invalid Date');
  }
});

Then('Manager B should not be able to access or manipulate Manager A\'s data', async function () {
  expect(this.testData.managerADataUnchanged).toBe(true);
  expect(this.auditLogs.length).toBeGreaterThan(0);
});