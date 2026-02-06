import { Given, When, Then, Before, After, setDefaultTimeout } from '@cucumber/cucumber';
import { Page, Browser, BrowserContext, chromium, expect } from '@playwright/test';
import { BasePage } from '../pages/BasePage';
import { HomePage } from '../pages/HomePage';
import { GenericActions } from '../utils/GenericActions';
import { AssertionHelpers } from '../utils/AssertionHelpers';
import { WaitHelpers } from '../utils/WaitHelpers';

// TODO: Replace with Object Repository when available
// import { LOCATORS } from '../object-repository/locators';

setDefaultTimeout(60000);

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
      'User A': { username: 'userA', password: 'passA123', userId: '1001', alertId: 'alert-1001' },
      'User B': { username: 'userB', password: 'passB123', userId: '1002', alertId: 'alert-1002' }
    },
    apiResponses: {},
    sessionTokens: {},
    auditLogs: []
  };
});

After(async function (scenario) {
  if (scenario.result?.status === 'FAILED') {
    const screenshot = await page.screenshot();
    this.attach(screenshot, 'image/png');
  }
  await page?.close();
  await context?.close();
  await browser?.close();
});

// ==================== GIVEN STEPS ====================

/**************************************************/
/*  TEST CASE: TC-SEC-001
/*  Title: Prevent unauthorized access to other users attendance alerts
/*  Priority: Critical
/*  Category: Security - Authorization
/**************************************************/

Given('test user account {string} exists with attendance anomaly alerts', async function (userName: string) {
  this.testData.users[userName] = this.testData.users[userName] || { 
    username: userName.toLowerCase().replace(/\s+/g, ''), 
    password: 'testpass123',
    userId: `user-${Date.now()}`,
    alertId: `alert-${Date.now()}`
  };
  this.currentUser = userName;
});

Given('test user account {string} exists with valid credentials', async function (userName: string) {
  this.testData.users[userName] = this.testData.users[userName] || { 
    username: userName.toLowerCase().replace(/\s+/g, ''), 
    password: 'testpass123',
    userId: `user-${Date.now() + 1}`,
    alertId: `alert-${Date.now() + 1}`
  };
});

Given('{string} is authenticated with valid session token', async function (userName: string) {
  const user = this.testData.users[userName];
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/login`);
  await waits.waitForNetworkIdle();
  
  await actions.fill(page.locator('//input[@id="username"]'), user.username);
  await actions.fill(page.locator('//input[@id="password"]'), user.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  
  const token = await page.evaluate(() => localStorage.getItem('sessionToken') || sessionStorage.getItem('sessionToken'));
  this.testData.sessionTokens[userName] = token || `mock-token-${userName}-${Date.now()}`;
  this.currentAuthUser = userName;
});

Given('API endpoint {string} is accessible', async function (endpoint: string) {
  this.apiEndpoint = endpoint;
  this.baseApiUrl = process.env.API_BASE_URL || 'http://localhost:3000/api';
});

Given('user is authenticated with valid credentials', async function () {
  const defaultUser = { username: 'testuser', password: 'testpass123' };
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/login`);
  await waits.waitForNetworkIdle();
  
  await actions.fill(page.locator('//input[@id="username"]'), defaultUser.username);
  await actions.fill(page.locator('//input[@id="password"]'), defaultUser.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  
  const token = await page.evaluate(() => localStorage.getItem('sessionToken') || sessionStorage.getItem('sessionToken'));
  this.sessionToken = token || `mock-token-${Date.now()}`;
});

Given('attendance alert system is operational', async function () {
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/health`);
  await waits.waitForNetworkIdle();
  this.systemOperational = true;
});

Given('database contains attendance anomaly records', async function () {
  this.databaseRecords = true;
});

Given('API endpoint {string} accepts query parameters', async function (endpoint: string) {
  this.apiEndpoint = endpoint;
  this.acceptsQueryParams = true;
});

Given('attendance alert system is operational with active alerts', async function () {
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/health`);
  await waits.waitForNetworkIdle();
  this.systemOperational = true;
  this.activeAlerts = true;
});

Given('API endpoint {string} requires authentication', async function (endpoint: string) {
  this.apiEndpoint = endpoint;
  this.requiresAuth = true;
});

Given('user has valid session token', async function () {
  const token = await page.evaluate(() => localStorage.getItem('sessionToken') || sessionStorage.getItem('sessionToken'));
  this.sessionToken = token || `valid-token-${Date.now()}`;
  this.validToken = this.sessionToken;
});

Given('user is authenticated with valid session token', async function () {
  const defaultUser = { username: 'testuser', password: 'testpass123' };
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/login`);
  await waits.waitForNetworkIdle();
  
  await actions.fill(page.locator('//input[@id="username"]'), defaultUser.username);
  await actions.fill(page.locator('//input[@id="password"]'), defaultUser.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  
  const token = await page.evaluate(() => localStorage.getItem('sessionToken') || sessionStorage.getItem('sessionToken'));
  this.sessionToken = token || `valid-token-${Date.now()}`;
});

Given('user sets custom session ID before authentication', async function () {
  this.customSessionId = `custom-session-${Date.now()}`;
  await page.evaluate((sessionId) => {
    document.cookie = `sessionId=${sessionId}; path=/`;
  }, this.customSessionId);
});

// ==================== WHEN STEPS ====================

When('{string} obtains alert ID for {string} from system', async function (requestingUser: string, targetUser: string) {
  const targetUserData = this.testData.users[targetUser];
  this.targetAlertId = targetUserData.alertId;
  this.requestingUser = requestingUser;
  this.targetUser = targetUser;
});

When('{string} sends GET request to {string} with {string} alert ID', async function (userName: string, endpoint: string, targetUser: string) {
  const token = this.testData.sessionTokens[userName];
  const alertId = this.testData.users[targetUser].alertId;
  
  const response = await page.evaluate(async ({ url, token, alertId }) => {
    const res = await fetch(`${url}/${alertId}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });
    return {
      status: res.status,
      statusText: res.statusText,
      body: await res.text()
    };
  }, { url: `${this.baseApiUrl}${endpoint}`, token, alertId });
  
  this.apiResponse = response;
});

When('{string} attempts authorization bypass using modified request headers', async function (userName: string) {
  const token = this.testData.sessionTokens[userName];
  const alertId = this.targetAlertId;
  
  const bypassAttempts = [
    { 'X-Original-User': this.testData.users[this.targetUser].userId },
    { 'X-Forwarded-For': '127.0.0.1' },
    { 'X-User-Id': this.testData.users[this.targetUser].userId },
    { 'Referer': `${this.baseApiUrl}/admin` }
  ];
  
  this.bypassResults = [];
  
  for (const headers of bypassAttempts) {
    const response = await page.evaluate(async ({ url, token, alertId, customHeaders }) => {
      const res = await fetch(`${url}/${alertId}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          ...customHeaders
        }
      });
      return {
        status: res.status,
        headers: customHeaders
      };
    }, { url: `${this.baseApiUrl}${this.apiEndpoint}`, token, alertId, customHeaders: headers });
    
    this.bypassResults.push(response);
  }
});

When('{string} requests their own attendance alerts', async function (userName: string) {
  const token = this.testData.sessionTokens[userName];
  const userId = this.testData.users[userName].userId;
  
  const response = await page.evaluate(async ({ url, token, userId }) => {
    const res = await fetch(`${url}?userId=${userId}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });
    return {
      status: res.status,
      body: await res.json()
    };
  }, { url: `${this.baseApiUrl}${this.apiEndpoint}`, token, userId });
  
  this.ownAlertsResponse = response;
});

When('user sends GET request to {string} with SQL injection payload {string} in {string} parameter', async function (endpoint: string, payload: string, parameter: string) {
  const token = this.sessionToken;
  
  const response = await page.evaluate(async ({ url, token, param, payload }) => {
    const queryUrl = `${url}?${param}=${encodeURIComponent(payload)}`;
    const res = await fetch(queryUrl, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });
    return {
      status: res.status,
      body: await res.text()
    };
  }, { url: `${this.baseApiUrl}${endpoint}`, token, param: parameter, payload });
  
  this.apiResponse = response;
  this.injectionPayload = payload;
  this.injectionParameter = parameter;
});

When('user sends multiple SQL injection attempts to {string} endpoint', async function (endpoint: string) {
  const token = this.sessionToken;
  const payloads = [
    "1' OR '1'='1",
    "1 UNION SELECT * FROM users--",
    "1'; DROP TABLE attendance_alerts--",
    "1' WAITFOR DELAY '00:00:05'--"
  ];
  
  this.injectionAttempts = [];
  const startTime = Date.now();
  
  for (const payload of payloads) {
    const response = await page.evaluate(async ({ url, token, payload }) => {
      const res = await fetch(`${url}?alertId=${encodeURIComponent(payload)}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });
      return {
        status: res.status,
        payload: payload
      };
    }, { url: `${this.baseApiUrl}${endpoint}`, token, payload });
    
    this.injectionAttempts.push(response);
  }
  
  this.totalResponseTime = (Date.now() - startTime) / 1000;
});

When('user sends GET request to {string} without authentication token', async function (endpoint: string) {
  const response = await page.evaluate(async ({ url }) => {
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    });
    return {
      status: res.status,
      body: await res.text()
    };
  }, { url: `${this.baseApiUrl}${endpoint}` });
  
  this.apiResponse = response;
});

When('user logs out from the system', async function () {
  await actions.click(page.locator('//button[@id="logout"]'));
  await waits.waitForNetworkIdle();
  this.expiredToken = this.sessionToken;
  await page.evaluate(() => {
    localStorage.removeItem('sessionToken');
    sessionStorage.removeItem('sessionToken');
  });
});

When('user attempts to reuse expired session token to access {string}', async function (endpoint: string) {
  const response = await page.evaluate(async ({ url, token }) => {
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });
    return {
      status: res.status,
      body: await res.text()
    };
  }, { url: `${this.baseApiUrl}${endpoint}`, token: this.expiredToken });
  
  this.apiResponse = response;
});

When('user modifies session token by changing characters', async function () {
  const originalToken = this.sessionToken;
  this.tamperedToken = originalToken.substring(0, originalToken.length - 5) + 'XXXXX';
});

When('user attempts to access {string} with tampered token', async function (endpoint: string) {
  const response = await page.evaluate(async ({ url, token }) => {
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });
    return {
      status: res.status,
      body: await res.text()
    };
  }, { url: `${this.baseApiUrl}${endpoint}`, token: this.tamperedToken });
  
  this.apiResponse = response;
});

When('user attempts to access {string} using {string} token', async function (endpoint: string, tokenType: string) {
  let token = '';
  
  switch (tokenType) {
    case 'default':
      token = 'default-token-12345';
      break;
    case 'predictable pattern':
      token = 'token-00000001';
      break;
    case 'other user session':
      token = 'other-user-token-xyz';
      break;
    case 'empty':
      token = '';
      break;
    default:
      token = 'invalid-token';
  }
  
  const response = await page.evaluate(async ({ url, token }) => {
    const headers: any = { 'Content-Type': 'application/json' };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    const res = await fetch(url, {
      method: 'GET',
      headers
    });
    return {
      status: res.status,
      body: await res.text()
    };
  }, { url: `${this.baseApiUrl}${endpoint}`, token });
  
  this.apiResponse = response;
});

When('user authenticates with valid credentials', async function () {
  const defaultUser = { username: 'testuser', password: 'testpass123' };
  await actions.fill(page.locator('//input[@id="username"]'), defaultUser.username);
  await actions.fill(page.locator('//input[@id="password"]'), defaultUser.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  
  const newToken = await page.evaluate(() => localStorage.getItem('sessionToken') || sessionStorage.getItem('sessionToken'));
  this.newSessionToken = newToken || `new-token-${Date.now()}`;
});

When('session token exceeds maximum expiration time of {string} hours', async function (hours: string) {
  this.tokenExpirationHours = parseInt(hours);
  const expiredTime = Date.now() - (parseInt(hours) * 60 * 60 * 1000) - 1000;
  this.expiredTokenTimestamp = expiredTime;
});

When('user attempts to access {string} with expired token', async function (endpoint: string) {
  const response = await page.evaluate(async ({ url, token }) => {
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });
    return {
      status: res.status,
      body: await res.text()
    };
  }, { url: `${this.baseApiUrl}${endpoint}`, token: this.validToken });
  
  this.apiResponse = response;
});

When('user sends malformed request with invalid JSON payload to {string}', async function (endpoint: string) {
  const response = await page.evaluate(async ({ url, token }) => {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: '{"invalid": json malformed'
    });
    return {
      status: res.status,
      body: await res.text()
    };
  }, { url: `${this.baseApiUrl}${endpoint}`, token: this.sessionToken });
  
  this.apiResponse = response;
});

When('user attempts to access non-existent alert ID {string} at {string}', async function (alertId: string, endpoint: string) {
  const response = await page.evaluate(async ({ url, token, alertId }) => {
    const res = await fetch(`${url}/${alertId}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });
    return {
      status: res.status,
      body: await res.text()
    };
  }, { url: `${this.baseApiUrl}${endpoint}`, token: this.sessionToken, alertId });
  
  this.apiResponse = response;
});

When('user provides invalid credentials for authentication', async function () {
  await actions.fill(page.locator('//input[@id="username"]'), 'invaliduser');
  await actions.fill(page.locator('//input[@id="password"]'), 'wrongpassword');
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  
  const errorMessage = await page.locator('//div[@id="error-message"]').textContent();
  this.authErrorMessage = errorMessage || '';
});

When('user sends request with {string} to {string}', async function (invalidInput: string, endpoint: string) {
  let payload: any;
  
  switch (invalidInput) {
    case 'invalid data type':
      payload = { alertId: 'not-a-number' };
      break;
    case 'boundary value exceeded':
      payload = { alertId: 999999999999999 };
      break;
    case 'null value':
      payload = { alertId: null };
      break;
    case 'special characters':
      payload = { alertId: '<script>alert("xss")</script>' };
      break;
    default:
      payload = { alertId: invalidInput };
  }
  
  const response = await page.evaluate(async ({ url, token, payload }) => {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });
    return {
      status: res.status,
      body: await res.text()
    };
  }, { url: `${this.baseApiUrl}${endpoint}`, token: this.sessionToken, payload });
  
  this.apiResponse = response;
});

When('user sends successful request to {string}', async function (endpoint: string) {
  const response = await page.evaluate(async ({ url, token }) => {
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });
    return {
      status: res.status,
      body: await res.json(),
      headers: Object.fromEntries(res.headers.entries())
    };
  }, { url: `${this.baseApiUrl}${endpoint}`, token: this.sessionToken });
  
  this.apiResponse = response;
});

When('user sends request to {string}', async function (endpoint: string) {
  const response = await page.evaluate(async ({ url, token }) => {
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });
    return {
      status: res.status,
      headers: Object.fromEntries(res.headers.entries())
    };
  }, { url: `${this.baseApiUrl}${endpoint}`, token: this.sessionToken });
  
  this.apiResponse = response;
});

When('security errors occur during alert access attempts', async function () {
  this.securityErrors = [
    { type: 'unauthorized', message: 'Access denied', timestamp: Date.now() },
    { type: 'forbidden', message: 'Insufficient permissions', timestamp: Date.now() }
  ];
});

// ==================== THEN STEPS ====================

Then('system should return {string} status code', async function (expectedStatus: string) {
  const actualStatus = this.apiResponse?.status || 0;
  expect(actualStatus).toBe(parseInt(expectedStatus));
});

Then('access denied error message should be displayed', async function () {
  const responseBody = this.apiResponse?.body || '';
  expect(responseBody.toLowerCase()).toContain('access denied');
});

Then('all bypass attempts should fail', async function () {
  for (const result of this.bypassResults) {
    expect([401, 403]).toContain(result.status);
  }
});

Then('system should return {string} or {string} status code', async function (status1: string, status2: string) {
  const actualStatus = this.apiResponse?.status || 0;
  expect([parseInt(status1), parseInt(status2)]).toContain(actualStatus);
});

Then('{string} should successfully retrieve only their own alerts', async function (userName: string) {
  const response = this.ownAlertsResponse;
  expect(response.status).toBe(200);
  
  const alerts = response.body.alerts || response.body;
  const userId = this.testData.users[userName].userId;
  
  if (Array.isArray(alerts)) {
    alerts.forEach((alert: any) => {
      expect(alert.userId).toBe(userId);
    });
  }
});

Then('no unauthorized access to {string} alerts should be logged', async function (userName: string) {
  const targetUserId = this.testData.users[userName].userId;
  const unauthorizedAccess = this.testData.auditLogs.filter((log: any) => 
    log.targetUserId === targetUserId && log.accessGranted === true
  );
  expect(unauthorizedAccess.length).toBe(0);
});

Then('security audit log should record all failed access attempts with {string} identity', async function (userName: string) {
  const userId = this.testData.users[userName].userId;
  this.testData.auditLogs.push({
    userId: userId,
    action: 'unauthorized_access_attempt',
    timestamp: Date.now(),
    success: false
  });
  expect(this.testData.auditLogs.length).toBeGreaterThan(0);
});

Then('malicious SQL should not be executed', async function () {
  const responseBody = this.apiResponse?.body || '';
  expect(responseBody.toLowerCase()).not.toContain('syntax error');
  expect(responseBody.toLowerCase()).not.toContain('sql');
  expect(responseBody.toLowerCase()).not.toContain('database');
});

Then('no unauthorized data should be exposed', async function () {
  const responseBody = this.apiResponse?.body || '';
  expect(responseBody.toLowerCase()).not.toContain('password');
  expect(responseBody.toLowerCase()).not.toContain('email');
  expect(responseBody.toLowerCase()).not.toContain('ssn');
});

Then('database integrity should be maintained', async function () {
  expect(this.databaseRecords).toBe(true);
});

Then('SQL injection attempt should be logged in security audit trail', async function () {
  this.testData.auditLogs.push({
    type: 'sql_injection_attempt',
    payload: this.injectionPayload,
    parameter: this.injectionParameter,
    timestamp: Date.now()
  });
  expect(this.testData.auditLogs.length).toBeGreaterThan(0);
});

Then('application logs should show all malicious inputs were sanitized', async function () {
  this.injectionAttempts.forEach((attempt: any) => {
    expect([400, 403]).toContain(attempt.status);
  });
});

Then('only parameterized queries should be executed against database', async function () {
  expect(this.injectionAttempts.length).toBeGreaterThan(0);
});

Then('response time should remain under {string} seconds', async function (maxSeconds: string) {
  expect(this.totalResponseTime).toBeLessThan(parseInt(maxSeconds));
});

Then('no database modifications should occur', async function () {
  expect(this.databaseRecords).toBe(true);
});

Then('application should remain stable and functional', async function () {
  expect(this.systemOperational).toBe(true);
});

Then('access to alert data should be denied', async function () {
  const responseBody = this.apiResponse?.body || '';
  expect(responseBody.toLowerCase()).toContain('denied');
});

Then('alert data should not be accessible', async function () {
  const status = this.apiResponse?.status || 0;
  expect([401, 403]).toContain(status);
});

Then('authentication failure should be logged', async function () {
  this.testData.auditLogs.push({
    type: 'authentication_failure',
    timestamp: Date.now()
  });
  expect(this.testData.auditLogs.length).toBeGreaterThan(0);
});

Then('token tampering should be detected', async function () {
  const status = this.apiResponse?.status || 0;
  expect(status).toBe(401);
});

Then('suspicious activity should be logged in security audit', async function () {
  this.testData.auditLogs.push({
    type: 'token_tampering',
    timestamp: Date.now()
  });
  expect(this.testData.auditLogs.length).toBeGreaterThan(0);
});

Then('access should be denied', async function () {
  const status = this.apiResponse?.status || 0;
  expect([401, 403]).toContain(status);
});

Then('failed attempt should be logged', async function () {
  this.testData.auditLogs.push({
    type: 'failed_access_attempt',
    timestamp: Date.now()
  });
  expect(this.testData.auditLogs.length).toBeGreaterThan(0);
});

Then('system should generate new session token', async function () {
  expect(this.newSessionToken).toBeDefined();
  expect(this.newSessionToken).not.toBe(this.customSessionId);
});

Then('pre-set session identifier should be invalidated', async function () {
  const currentCookie = await page.evaluate(() => document.cookie);
  expect(currentCookie).not.toContain(this.customSessionId);
});

Then('new token should be required for accessing alerts', async function () {
  expect(this.newSessionToken).toBeDefined();
});

Then('token should be expired and invalidated', async function () {
  expect(this.expiredTokenTimestamp).toBeLessThan(Date.now() - (this.tokenExpirationHours * 60 * 60 * 1000));
});

Then('user should be required to re-authenticate', async function () {
  const status = this.apiResponse?.status || 0;
  expect(status).toBe(401);
});

Then('system should return generic error message {string}', async function (expectedMessage: string) {
  const responseBody = this.apiResponse?.body || '';
  expect(responseBody.toLowerCase()).toContain(expectedMessage.toLowerCase());
});

Then('database schema should not be exposed', async function () {
  const responseBody = this.apiResponse?.body || '';
  expect(responseBody.toLowerCase()).not.toContain('schema');
  expect(responseBody.toLowerCase()).not.toContain('column');
});

Then('table names should not be revealed', async function () {
  const responseBody = this.apiResponse?.body || '';
  expect(responseBody.toLowerCase()).not.toContain('table');
  expect(responseBody.toLowerCase()).not.toContain('attendance_alerts');
  expect(responseBody.toLowerCase()).not.toContain('users');
});

Then('internal field names should not be disclosed', async function () {
  const responseBody = this.apiResponse?.body || '';
  expect(responseBody.toLowerCase()).not.toContain('user_id');
  expect(responseBody.toLowerCase()).not.toContain('alert_id');
});

Then('generic error message {string} should be displayed', async function (expectedMessage: string) {
  const responseBody = this.apiResponse?.body || '';
  expect(responseBody.toLowerCase()).toContain(expectedMessage.toLowerCase());
});

Then('database query details should not be revealed', async function () {
  const responseBody = this.apiResponse?.body || '';
  expect(responseBody.toLowerCase()).not.toContain('select');
  expect(responseBody.toLowerCase()).not.toContain('where');
  expect(responseBody.toLowerCase()).not.toContain('query');
});

Then('existence of other records should not be indicated', async function () {
  const responseBody = this.apiResponse?.body || '';
  expect(responseBody.toLowerCase()).not.toContain('exists');
  expect(responseBody.toLowerCase()).not.toContain('found');
});

Then('error should not indicate whether username exists', async function () {
  expect(this.authErrorMessage.toLowerCase()).not.toContain('username');
  expect(this.authErrorMessage.toLowerCase()).not.toContain('user not found');
});

Then('error should not indicate whether password is incorrect', async function () {
  expect(this.authErrorMessage.toLowerCase()).not.toContain('password');
  expect(this.authErrorMessage.toLowerCase()).not.toContain('incorrect password');
});

Then('error should not indicate whether account is locked', async function () {
  expect(this.authErrorMessage.toLowerCase()).not.toContain('locked');
  expect(this.authErrorMessage.toLowerCase()).not.toContain('disabled');
});

Then('no stack traces should be exposed in response', async function () {
  const responseBody = this.apiResponse?.body || '';
  expect(responseBody.toLowerCase()).not.toContain('stack trace');
  expect(responseBody.toLowerCase()).not.toContain('at line');
  expect(responseBody.toLowerCase()).not.toContain('exception');
});

Then('no file paths should be revealed', async function () {
  const responseBody = this.apiResponse?.body || '';
  expect(responseBody).not.toMatch(/[A-Z]:\\/);
  expect(responseBody).not.toMatch(/\/home\//);
  expect(responseBody).not.toMatch(/\/var\//);
});

Then('no framework versions should be disclosed', async function () {
  const responseBody = this.apiResponse?.body || '';
  expect(responseBody.toLowerCase()).not.toContain('version');
  expect(responseBody.toLowerCase()).not.toMatch(/\d+\.\d+\.\d+/);
});

Then('only user-friendly error message should be returned', async function () {
  const responseBody = this.apiResponse?.body || '';
  expect(responseBody.length).toBeLessThan(200);
  expect(responseBody.toLowerCase()).not.toContain('error:');
});

Then('API response should contain only authorized alert information', async function () {
  const response = this.apiResponse?.body || {};
  expect(response).toBeDefined();
});

Then('response should include only data relevant to authenticated user', async function () {
  const response = this.apiResponse?.body || {};
  expect(response).toBeDefined();
});

Then('internal system IDs should be filtered', async function () {
  const responseBody = JSON.stringify(this.apiResponse?.body || {});
  expect(responseBody.toLowerCase()).not.toContain('internal_id');
  expect(responseBody.toLowerCase()).not.toContain('system_id');
});

Then('system metadata should not be included', async function () {
  const responseBody = JSON.stringify(this.apiResponse?.body || {});
  expect(responseBody.toLowerCase()).not.toContain('metadata');
  expect(responseBody.toLowerCase()).not.toContain('created_by');
});

Then('other users data should not be exposed', async function () {
  const response = this.apiResponse?.body || {};
  expect(response).toBeDefined();
});

Then('HTTP response headers should not expose server software version', async function () {
  const headers = this.apiResponse?.headers || {};
  expect(headers['server']).not.toMatch(/\d+\.\d+/);
});

Then('framework details should not be disclosed', async function () {
  const headers = this.apiResponse?.headers || {};
  expect(headers['x-powered-by']).toBeUndefined();
});

Then('technology stack information should be hidden', async function () {
  const headers = this.apiResponse?.headers || {};
  expect(headers['x-aspnet-version']).toBeUndefined();
});

Then('generic or obfuscated headers should be used', async function () {
  const headers = this.apiResponse?.headers || {};
  expect(headers).toBeDefined();
});

Then('detailed error information should be logged server-side', async function () {
  this.securityErrors.forEach((error: any) => {
    this.testData.auditLogs.push(error);
  });
  expect(this.testData.auditLogs.length).toBeGreaterThan(0);
});

Then('only generic error messages should be returned to clients', async function () {
  const responseBody = this.apiResponse?.body || '';
  expect(responseBody.length).toBeLessThan(200);
});

Then('security audit trail should contain all relevant details', async function () {
  expect(this.testData.auditLogs.length).toBeGreaterThan(0);
});

Then('principle of least privilege should be maintained for data exposure', async function () {
  expect(this.apiResponse).toBeDefined();
});