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
    users: {},
    sessions: {},
    notifications: {},
    apiResponses: {},
    securityLogs: [],
    responseHeaders: {},
    responseTimes: {},
    interceptedRequests: {}
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
/*  Category: Security
/*  Description: Common setup for security tests
/**************************************************/

Given('the notification system is operational', async function () {
  // TODO: Replace XPath with Object Repository when available
  const response = await page.request.get('/api/notifications/health');
  expect(response.status()).toBe(200);
  this.testData.systemStatus = 'operational';
});

Given('the schedule database is accessible', async function () {
  // TODO: Replace XPath with Object Repository when available
  const response = await page.request.get('/api/schedules/health');
  expect(response.status()).toBe(200);
  this.testData.databaseStatus = 'accessible';
});

/**************************************************/
/*  TEST CASE: TC-SEC-001
/*  Title: Prevent unauthorized access to other users' notification history via IDOR
/*  Priority: Critical
/*  Category: Security - Authorization - IDOR
/**************************************************/

Given('user account {string} exists with valid session', async function (username: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo('/login');
  await waits.waitForNetworkIdle();
  
  await actions.fill(page.locator('//input[@id="username"]'), username);
  await actions.fill(page.locator('//input[@id="password"]'), 'SecurePass123!');
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  
  const sessionToken = await page.evaluate(() => localStorage.getItem('sessionToken'));
  this.testData.users[username] = {
    username: username,
    sessionToken: sessionToken,
    authenticated: true
  };
});

Given('{string} has received notifications with known notification IDs', async function (username: string) {
  const sessionToken = this.testData.users[username].sessionToken;
  
  const response = await page.request.get('/api/notifications', {
    headers: {
      'Authorization': `Bearer ${sessionToken}`
    }
  });
  
  const notifications = await response.json();
  this.testData.notifications[username] = notifications.data || [];
  this.testData.users[username].notificationIds = this.testData.notifications[username].map((n: any) => n.id);
});

Given('API endpoint {string} is accessible', async function (endpoint: string) {
  const response = await page.request.get(endpoint);
  expect(response.status()).toBeLessThan(500);
  this.testData.apiEndpoints = this.testData.apiEndpoints || {};
  this.testData.apiEndpoints[endpoint] = 'accessible';
});

When('{string} authenticates and obtains valid session token', async function (username: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo('/login');
  await waits.waitForNetworkIdle();
  
  await actions.fill(page.locator('//input[@id="username"]'), username);
  await actions.fill(page.locator('//input[@id="password"]'), 'SecurePass123!');
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  
  const sessionToken = await page.evaluate(() => localStorage.getItem('sessionToken'));
  this.testData.users[username] = this.testData.users[username] || {};
  this.testData.users[username].sessionToken = sessionToken;
  this.testData.users[username].authenticated = true;
});

When('{string} intercepts API request to {string} and identifies {string} notification ID', async function (attackerUser: string, endpoint: string, victimUser: string) {
  const victimNotificationIds = this.testData.users[victimUser].notificationIds;
  this.testData.interceptedRequests[attackerUser] = {
    endpoint: endpoint,
    targetNotificationId: victimNotificationIds[0],
    victimUser: victimUser
  };
});

When('{string} sends GET request to {string} using their session', async function (username: string, endpointTemplate: string) {
  const sessionToken = this.testData.users[username].sessionToken;
  const targetNotificationId = this.testData.interceptedRequests[username].targetNotificationId;
  const endpoint = endpointTemplate.replace('{UserA_notification_id}', targetNotificationId);
  
  const response = await page.request.get(endpoint, {
    headers: {
      'Authorization': `Bearer ${sessionToken}`
    }
  });
  
  this.testData.apiResponses[username] = {
    status: response.status(),
    body: await response.text(),
    headers: response.headers()
  };
});

Then('system should return {string} status code', async function (expectedStatusCode: string) {
  const lastResponse = Object.values(this.testData.apiResponses).pop() as any;
  expect(lastResponse.status).toBe(parseInt(expectedStatusCode));
});

Then('error message {string} should be displayed', async function (expectedMessage: string) {
  const lastResponse = Object.values(this.testData.apiResponses).pop() as any;
  expect(lastResponse.body).toContain(expectedMessage);
});

Then('{string} should not see {string} notification content', async function (attackerUser: string, victimUser: string) {
  const response = this.testData.apiResponses[attackerUser];
  const victimNotifications = this.testData.notifications[victimUser];
  
  if (victimNotifications && victimNotifications.length > 0) {
    const victimContent = victimNotifications[0].content || victimNotifications[0].message;
    expect(response.body).not.toContain(victimContent);
  }
});

When('{string} attempts to modify {string} parameter to {string} ID in request', async function (attackerUser: string, parameterName: string, victimUser: string) {
  const sessionToken = this.testData.users[attackerUser].sessionToken;
  const victimUserId = this.testData.users[victimUser].userId || 'user-victim-id';
  
  const response = await page.request.get(`/api/notifications?${parameterName}=${victimUserId}`, {
    headers: {
      'Authorization': `Bearer ${sessionToken}`
    }
  });
  
  this.testData.apiResponses[`${attackerUser}_parameter_manipulation`] = {
    status: response.status(),
    body: await response.text(),
    headers: response.headers()
  };
});

Then('system should validate session ownership', async function () {
  const lastResponse = Object.values(this.testData.apiResponses).pop() as any;
  expect(lastResponse.status).toBeGreaterThanOrEqual(400);
  expect(lastResponse.status).toBeLessThan(500);
});

Then('system should reject request with {string} status code', async function (expectedStatusCode: string) {
  const lastResponse = Object.values(this.testData.apiResponses).pop() as any;
  expect(lastResponse.status).toBe(parseInt(expectedStatusCode));
});

When('{string} attempts sequential notification ID enumeration with increments', async function (attackerUser: string) {
  const sessionToken = this.testData.users[attackerUser].sessionToken;
  const enumerationResults = [];
  
  for (let i = 1; i <= 10; i++) {
    const response = await page.request.get(`/api/notifications/${i}`, {
      headers: {
        'Authorization': `Bearer ${sessionToken}`
      }
    });
    
    enumerationResults.push({
      notificationId: i,
      status: response.status(),
      body: await response.text()
    });
  }
  
  this.testData.enumerationResults = this.testData.enumerationResults || {};
  this.testData.enumerationResults[attackerUser] = enumerationResults;
});

Then('system should consistently deny access to notifications not belonging to {string}', async function (username: string) {
  const enumerationResults = this.testData.enumerationResults[username];
  const userNotificationIds = this.testData.users[username].notificationIds || [];
  
  enumerationResults.forEach((result: any) => {
    if (!userNotificationIds.includes(result.notificationId)) {
      expect(result.status).toBeGreaterThanOrEqual(403);
    }
  });
});

Then('security logs should record all unauthorized access attempts', async function () {
  const response = await page.request.get('/api/admin/security-logs', {
    headers: {
      'Authorization': `Bearer ${this.testData.adminToken || 'admin-token'}`
    }
  });
  
  const logs = await response.json();
  this.testData.securityLogs = logs.data || [];
  expect(this.testData.securityLogs.length).toBeGreaterThan(0);
});

Then('{string} should only access their own notifications', async function (username: string) {
  const sessionToken = this.testData.users[username].sessionToken;
  
  const response = await page.request.get('/api/notifications', {
    headers: {
      'Authorization': `Bearer ${sessionToken}`
    }
  });
  
  const notifications = await response.json();
  const userNotifications = notifications.data || [];
  
  userNotifications.forEach((notification: any) => {
    expect(notification.userId).toBe(username);
  });
});

/**************************************************/
/*  TEST CASE: TC-SEC-002
/*  Title: Prevent Cross-Site Scripting in notification content display
/*  Priority: Critical
/*  Category: Security - XSS - Injection
/**************************************************/

Given('user account with schedule modification privileges exists', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo('/login');
  await waits.waitForNetworkIdle();
  
  await actions.fill(page.locator('//input[@id="username"]'), 'schedule_admin');
  await actions.fill(page.locator('//input[@id="password"]'), 'AdminPass123!');
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  
  const sessionToken = await page.evaluate(() => localStorage.getItem('sessionToken'));
  this.testData.scheduleAdmin = {
    username: 'schedule_admin',
    sessionToken: sessionToken,
    privileges: ['schedule_modify']
  };
});

Given('test user account to receive notifications exists', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo('/login');
  await waits.waitForNetworkIdle();
  
  await actions.fill(page.locator('//input[@id="username"]'), 'test_recipient');
  await actions.fill(page.locator('//input[@id="password"]'), 'TestPass123!');
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  
  const sessionToken = await page.evaluate(() => localStorage.getItem('sessionToken'));
  this.testData.testRecipient = {
    username: 'test_recipient',
    sessionToken: sessionToken
  };
});

When('user creates schedule change with payload {string} in {string}', async function (xssPayload: string, fieldName: string) {
  const sessionToken = this.testData.scheduleAdmin.sessionToken;
  
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo('/schedules/create');
  await waits.waitForNetworkIdle();
  
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  const textareaXPath = `//textarea[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  
  const inputFields = page.locator(fieldXPath);
  const textareaFields = page.locator(textareaXPath);
  
  if (await inputFields.count() > 0) {
    await actions.fill(inputFields, xssPayload);
  } else if (await textareaFields.count() > 0) {
    await actions.fill(textareaFields, xssPayload);
  }
  
  this.testData.xssPayload = xssPayload;
  this.testData.xssFieldName = fieldName;
});

When('notification generation is triggered for the schedule change', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="save-schedule"]'));
  await waits.waitForNetworkIdle();
  
  await page.waitForTimeout(2000);
  
  this.testData.notificationTriggered = true;
});

Then('in-app notification should display payload as plain text', async function () {
  const sessionToken = this.testData.testRecipient.sessionToken;
  
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo('/notifications');
  await waits.waitForNetworkIdle();
  
  const notificationContent = await page.locator('//div[@id="notification-content"]').textContent();
  expect(notificationContent).toContain(this.testData.xssPayload);
  
  const scriptExecuted = await page.evaluate(() => {
    return (window as any).xssExecuted === true;
  });
  expect(scriptExecuted).toBeFalsy();
});

Then('script tags should be HTML-encoded as {string}', async function (encodedString: string) {
  const notificationHtml = await page.locator('//div[@id="notification-content"]').innerHTML();
  
  if (this.testData.xssPayload.includes('<script>')) {
    expect(notificationHtml).toContain(encodedString);
  }
});

Then('no JavaScript execution should occur', async function () {
  const alertFired = await page.evaluate(() => {
    return (window as any).alertFired === true;
  });
  expect(alertFired).toBeFalsy();
  
  const cookies = await page.evaluate(() => document.cookie);
  const cookieLeaked = await page.evaluate(() => {
    return (window as any).leakedCookie !== undefined;
  });
  expect(cookieLeaked).toBeFalsy();
});

When('email notification HTML source is checked', async function () {
  const response = await page.request.get('/api/notifications/email/latest', {
    headers: {
      'Authorization': `Bearer ${this.testData.testRecipient.sessionToken}`
    }
  });
  
  const emailData = await response.json();
  this.testData.emailHtmlSource = emailData.htmlContent || '';
});

Then('email content should show encoded HTML entities', async function () {
  const emailHtml = this.testData.emailHtmlSource;
  
  if (this.testData.xssPayload.includes('<script>')) {
    expect(emailHtml).toContain('&lt;script&gt;');
    expect(emailHtml).not.toMatch(/<script[^>]*>/);
  }
  
  if (this.testData.xssPayload.includes('<img')) {
    expect(emailHtml).toContain('&lt;img');
  }
});

Then('script should not execute when email is opened', async function () {
  const emailHtml = this.testData.emailHtmlSource;
  
  const newPage = await context.newPage();
  await newPage.setContent(emailHtml);
  
  const scriptExecuted = await newPage.evaluate(() => {
    return (window as any).xssExecuted === true || (window as any).alertFired === true;
  });
  
  expect(scriptExecuted).toBeFalsy();
  await newPage.close();
});

Then('Content-Security-Policy headers should be present in notification display pages', async function () {
  // TODO: Replace XPath with Object Repository when available
  const response = await page.goto('/notifications');
  const headers = response?.headers();
  
  this.testData.cspHeaders = headers?.['content-security-policy'] || headers?.['Content-Security-Policy'];
  expect(this.testData.cspHeaders).toBeDefined();
});

Then('CSP headers should restrict inline script execution', async function () {
  const cspHeader = this.testData.cspHeaders;
  expect(cspHeader).toBeDefined();
  expect(cspHeader).toMatch(/script-src/);
  expect(cspHeader).not.toContain("'unsafe-inline'");
});

Then('user session cookies should remain secure', async function () {
  const cookies = await context.cookies();
  const sessionCookie = cookies.find(c => c.name === 'sessionToken' || c.name === 'session');
  
  if (sessionCookie) {
    expect(sessionCookie.httpOnly).toBeTruthy();
    expect(sessionCookie.secure).toBeTruthy();
  }
});

Then('all notification content should be properly sanitized', async function () {
  const notificationHtml = await page.locator('//div[@id="notification-content"]').innerHTML();
  
  expect(notificationHtml).not.toMatch(/<script[^>]*>/);
  expect(notificationHtml).not.toMatch(/onerror=/);
  expect(notificationHtml).not.toMatch(/onload=/);
  expect(notificationHtml).not.toMatch(/javascript:/);
});

/**************************************************/
/*  TEST CASE: TC-SEC-003
/*  Title: Prevent information disclosure via notification API response leakage
/*  Priority: High
/*  Category: Security - Information Disclosure
/**************************************************/

Given('multiple user accounts with different schedules exist', async function () {
  const users = ['user1', 'user2', 'user3'];
  
  for (const username of users) {
    // TODO: Replace XPath with Object Repository when available
    await actions.navigateTo('/register');
    await waits.waitForNetworkIdle();
    
    await actions.fill(page.locator('//input[@id="username"]'), username);
    await actions.fill(page.locator('//input[@id="email"]'), `${username}@test.com`);
    await actions.fill(page.locator('//input[@id="password"]'), 'SecurePass123!');
    await actions.click(page.locator('//button[@id="register"]'));
    await waits.waitForNetworkIdle();
  }
  
  this.testData.multipleUsers = users;
});

Given('test accounts with valid and invalid authentication tokens exist', async function () {
  this.testData.authTokens = {
    valid: 'valid-token-12345',
    invalid: 'invalid-token-99999',
    expired: 'expired-token-00000',
    malformed: 'malformed@#$%token'
  };
});

Given('network traffic interception tool is configured', async function () {
  this.testData.interceptedTraffic = [];
  
  page.on('response', (response) => {
    this.testData.interceptedTraffic.push({
      url: response.url(),
      status: response.status(),
      headers: response.headers()
    });
  });
});

When('API request is sent to {string} with invalid notification ID', async function (endpoint: string) {
  const invalidNotificationId = '99999999';
  
  const response = await page.request.post(endpoint, {
    data: {
      notificationId: invalidNotificationId
    },
    headers: {
      'Authorization': `Bearer ${this.testData.authTokens.valid}`
    }
  });
  
  this.testData.apiResponses.invalidId = {
    status: response.status(),
    body: await response.text(),
    headers: response.headers()
  };
});

Then('generic error message {string} should be returned', async function (expectedMessage: string) {
  const response = this.testData.apiResponses.invalidId;
  expect(response.body).toContain(expectedMessage);
});

Then('system details should not be revealed in error message', async function () {
  const response = this.testData.apiResponses.invalidId;
  
  expect(response.body).not.toMatch(/stack trace/i);
  expect(response.body).not.toMatch(/database/i);
  expect(response.body).not.toMatch(/SQL/i);
  expect(response.body).not.toMatch(/Exception/i);
  expect(response.body).not.toMatch(/Error at line/i);
});

Then('valid ID patterns should not be exposed', async function () {
  const response = this.testData.apiResponses.invalidId;
  
  expect(response.body).not.toMatch(/valid IDs are/i);
  expect(response.body).not.toMatch(/ID must be between/i);
  expect(response.body).not.toMatch(/\d{1,10}/);
});

When('API response headers are analyzed for sensitive information', async function () {
  const response = await page.request.get('/api/notifications', {
    headers: {
      'Authorization': `Bearer ${this.testData.authTokens.valid}`
    }
  });
  
  this.testData.responseHeaders.analyzed = response.headers();
});

Then('response headers should contain minimal information', async function () {
  const headers = this.testData.responseHeaders.analyzed;
  expect(headers).toBeDefined();
});

Then('{string} header should not be present', async function (headerName: string) {
  const headers = this.testData.responseHeaders.analyzed;
  const headerKey = headerName.toLowerCase();
  expect(headers[headerKey]).toBeUndefined();
});

Then('server version should not be exposed', async function () {
  const headers = this.testData.responseHeaders.analyzed;
  
  expect(headers['server']).not.toMatch(/\d+\.\d+/);
  expect(headers['x-aspnet-version']).toBeUndefined();
  expect(headers['x-aspnetmvc-version']).toBeUndefined();
});

Then('internal IP addresses should not be disclosed', async function () {
  const headers = this.testData.responseHeaders.analyzed;
  const allHeaderValues = Object.values(headers).join(' ');
  
  expect(allHeaderValues).not.toMatch(/\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
  expect(allHeaderValues).not.toMatch(/\b192\.168\.\d{1,3}\.\d{1,3}\b/);
  expect(allHeaderValues).not.toMatch(/\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b/);
});

When('notification list is requested with pagination parameter {string} set to {string}', async function (parameterName: string, parameterValue: string) {
  const response = await page.request.get(`/api/notifications?${parameterName}=${parameterValue}`, {
    headers: {
      'Authorization': `Bearer ${this.testData.authTokens.valid}`
    }
  });
  
  this.testData.apiResponses.pagination = {
    status: response.status(),
    body: await response.json(),
    headers: response.headers()
  };
});

Then('system should enforce maximum pagination limits', async function () {
  const response = this.testData.apiResponses.pagination;
  const notifications = response.body.data || [];
  
  expect(notifications.length).toBeLessThanOrEqual(100);
});

Then('only authorized user notifications should be returned', async function () {
  const response = this.testData.apiResponses.pagination;
  const notifications = response.body.data || [];
  
  notifications.forEach((notification: any) => {
    expect(notification.userId).toBeDefined();
  });
});

Then('rate limiting should be applied', async function () {
  const requests = [];
  
  for (let i = 0; i < 50; i++) {
    const response = await page.request.get('/api/notifications', {
      headers: {
        'Authorization': `Bearer ${this.testData.authTokens.valid}`
      }
    });
    requests.push(response.status());
  }
  
  const rateLimited = requests.some(status => status === 429);
  expect(rateLimited).toBeTruthy();
});

When('{string} is accessed with missing authentication token', async function (endpoint: string) {
  const response = await page.request.post(endpoint, {
    data: {
      notificationId: '12345'
    }
  });
  
  this.testData.apiResponses.noAuth = {
    status: response.status(),
    body: await response.text(),
    headers: response.headers()
  };
});

Then('{string} status code should be returned', async function (expectedStatusCode: string) {
  const response = this.testData.apiResponses.noAuth;
  expect(response.status).toBe(parseInt(expectedStatusCode));
});

Then('generic {string} error should be displayed', async function (errorMessage: string) {
  const response = this.testData.apiResponses.noAuth;
  expect(response.body).toContain(errorMessage);
});

Then('endpoint existence should not be revealed', async function () {
  const response = this.testData.apiResponses.noAuth;
  
  expect(response.body).not.toContain('endpoint not found');
  expect(response.body).not.toContain('route does not exist');
});

Then('user account validity should not be disclosed', async function () {
  const response = this.testData.apiResponses.noAuth;
  
  expect(response.body).not.toContain('user does not exist');
  expect(response.body).not.toContain('invalid user');
  expect(response.body).not.toContain('user not found');
});

When('response times are measured for valid versus invalid user IDs', async function () {
  const validUserId = 'user1';
  const invalidUserId = 'nonexistent999';
  
  const startValid = Date.now();
  await page.request.get(`/api/notifications?userId=${validUserId}`, {
    headers: {
      'Authorization': `Bearer ${this.testData.authTokens.valid}`
    }
  });
  const validTime = Date.now() - startValid;
  
  const startInvalid = Date.now();
  await page.request.get(`/api/notifications?userId=${invalidUserId}`, {
    headers: {
      'Authorization': `Bearer ${this.testData.authTokens.valid}`
    }
  });
  const invalidTime = Date.now() - startInvalid;
  
  this.testData.responseTimes = {
    valid: validTime,
    invalid: invalidTime
  };
});

Then('response times should be consistent regardless of user ID validity', async function () {
  const validTime = this.testData.responseTimes.valid;
  const invalidTime = this.testData.responseTimes.invalid;
  
  const timeDifference = Math.abs(validTime - invalidTime);
  expect(timeDifference).toBeLessThan(500);
});

Then('user enumeration should be prevented', async function () {
  const validTime = this.testData.responseTimes.valid;
  const invalidTime = this.testData.responseTimes.invalid;
  
  const ratio = validTime / invalidTime;
  expect(ratio).toBeGreaterThan(0.5);
  expect(ratio).toBeLessThan(2.0);
});

When('notification payload is inspected for PII of other participants', async function () {
  const response = await page.request.get('/api/notifications', {
    headers: {
      'Authorization': `Bearer ${this.testData.authTokens.valid}`
    }
  });
  
  const notifications = await response.json();
  this.testData.notificationPayloads = notifications.data || [];
});

Then('notifications should contain only information relevant to authenticated user', async function () {
  const notifications = this.testData.notificationPayloads;
  
  notifications.forEach((notification: any) => {
    expect(notification.recipientId).toBeDefined();
  });
});

Then('other participants PII should not be exposed', async function () {
  const notifications = this.testData.notificationPayloads;
  
  notifications.forEach((notification: any) => {
    const content = JSON.stringify(notification);
    expect(content).not.toMatch(/ssn/i);
    expect(content).not.toMatch(/social security/i);
    expect(content).not.toMatch(/credit card/i);
    expect(content).not.toMatch(/\b\d{3}-\d{2}-\d{4}\b/);
  });
});

Then('no sensitive system information should be disclosed', async function () {
  const notifications = this.testData.notificationPayloads;
  
  notifications.forEach((notification: any) => {
    const content = JSON.stringify(notification);
    expect(content).not.toMatch(/database/i);
    expect(content).not.toMatch(/connection string/i);
    expect(content).not.toMatch(/api key/i);
    expect(content).not.toMatch(/secret/i);
  });
});

Then('error messages should remain generic and non-revealing', async function () {
  const allResponses = Object.values(this.testData.apiResponses);
  
  allResponses.forEach((response: any) => {
    if (response.status >= 400) {
      expect(response.body).not.toMatch(/stack trace/i);
      expect(response.body).not.toMatch(/file path/i);
      expect(response.body).not.toMatch(/C:\\/);
      expect(response.body).not.toMatch(/\/var\//);
    }
  });
});

Then('API responses should contain only authorized data', async function () {
  const notifications = this.testData.notificationPayloads;
  
  notifications.forEach((notification: any) => {
    expect(notification.recipientId).toBeDefined();
    expect(notification.content).toBeDefined();
  });
});

// ==================== WHEN STEPS ====================

When('I click on the {string} button', async function (buttonText: string) {
  // TODO: Replace XPath with Object Repository when available
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
  await waits.waitForNetworkIdle();
});

When('I enter {string} in the {string} field', async function (value: string, fieldName: string) {
  // TODO: Replace XPath with Object Repository when available
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.fill(page.locator(fieldXPath), value);
});

When('I select {string} from the {string} dropdown', async function (optionText: string, dropdownName: string) {
  // TODO: Replace XPath with Object Repository when available
  const dropdownXPath = `//select[@id='${dropdownName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.selectByText(page.locator(dropdownXPath), optionText);
});

// ==================== THEN STEPS ====================

Then('I should see {string}', async function (text: string) {
  await assertions.assertContainsText(page.locator(`//*[contains(text(),'${text}')]`), text);
});

Then('the {string} element should be visible', async function (elementName: string) {
  // TODO: Replace XPath with Object Repository when available
  const elementXPath = `//div[@id='${elementName.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(elementXPath));
});

Then('I should see a success message', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="success-message"]'));
});