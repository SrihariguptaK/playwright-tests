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
      'User A': { username: 'userA', password: 'testpass123', email: 'usera@test.com' },
      'User B': { username: 'userB', password: 'testpass456', email: 'userb@test.com' },
      admin: { username: 'admin', password: 'admin123', email: 'admin@test.com' }
    },
    apiEndpoints: {
      notifications: '/api/notifications/send',
      notificationView: '/api/notifications/view'
    },
    capturedData: {
      notificationIds: {},
      apiRequests: [],
      securityLogs: []
    }
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
/*  TEST CASE: TC-SEC-001
/*  Title: Prevent unauthorized access to other users' notifications through IDOR vulnerability
/*  Priority: Critical
/*  Category: Security - IDOR
/**************************************************/

// ==================== GIVEN STEPS ====================

Given('user account {string} exists in the system', async function (userName: string) {
  const userCredentials = this.testData?.users?.[userName] || { username: userName.toLowerCase().replace(/\s+/g, ''), password: 'testpass123' };
  this.testData.users[userName] = userCredentials;
  
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000');
  await waits.waitForNetworkIdle();
  
  await actions.fill(page.locator('//input[@id="username"]'), userCredentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), userCredentials.password);
  await actions.click(page.locator('//button[@id="register"]'));
  await waits.waitForNetworkIdle();
});

Given('both users have active schedules with recent changes', async function () {
  for (const userName of ['User A', 'User B']) {
    const userCredentials = this.testData?.users?.[userName];
    
    // TODO: Replace XPath with Object Repository when available
    await actions.fill(page.locator('//input[@id="username"]'), userCredentials.username);
    await actions.fill(page.locator('//input[@id="password"]'), userCredentials.password);
    await actions.click(page.locator('//button[@id="login"]'));
    await waits.waitForNetworkIdle();
    
    await actions.click(page.locator('//button[@id="create-schedule"]'));
    await actions.fill(page.locator('//input[@id="schedule-title"]'), `${userName} Schedule`);
    await actions.fill(page.locator('//textarea[@id="schedule-description"]'), `Active schedule for ${userName}`);
    await actions.click(page.locator('//button[@id="save-schedule"]'));
    await waits.waitForNetworkIdle();
    
    await actions.click(page.locator('//button[@id="logout"]'));
    await waits.waitForNetworkIdle();
  }
});

Given('both users are authenticated', async function () {
  this.testData.authenticatedUsers = ['User A', 'User B'];
});

Given('notification IDs are observable in API requests', async function () {
  await page.route('**/api/notifications/**', async (route) => {
    const request = route.request();
    this.testData.capturedData.apiRequests.push({
      url: request.url(),
      method: request.method(),
      headers: request.headers(),
      postData: request.postData()
    });
    await route.continue();
  });
});

Given('notification API endpoint {string} is accessible', async function (endpoint: string) {
  this.testData.apiEndpoint = endpoint;
  const response = await page.request.get(`${process.env.BASE_URL}${endpoint}`, { failOnStatusCode: false });
  this.testData.endpointAccessible = response.status() !== 404;
});

Given('valid user account exists with active schedule', async function () {
  const userCredentials = this.testData?.users?.admin;
  
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000');
  await waits.waitForNetworkIdle();
  
  await actions.fill(page.locator('//input[@id="username"]'), userCredentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), userCredentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  
  await actions.click(page.locator('//button[@id="create-schedule"]'));
  await actions.fill(page.locator('//input[@id="schedule-title"]'), 'Active Schedule');
  await actions.click(page.locator('//button[@id="save-schedule"]'));
  await waits.waitForNetworkIdle();
  
  await actions.click(page.locator('//button[@id="logout"]'));
  await waits.waitForNetworkIdle();
});

Given('authentication mechanism is implemented', async function () {
  this.testData.authenticationEnabled = true;
});

Given('test environment allows API testing tools', async function () {
  this.testData.apiTestingEnabled = true;
});

Given('user account with permission to create schedule entries exists', async function () {
  const userCredentials = { username: 'scheduleuser', password: 'testpass123', email: 'scheduleuser@test.com' };
  this.testData.users['scheduleuser'] = userCredentials;
  
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000');
  await waits.waitForNetworkIdle();
  
  await actions.fill(page.locator('//input[@id="username"]'), userCredentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), userCredentials.password);
  await actions.click(page.locator('//button[@id="register"]'));
  await waits.waitForNetworkIdle();
});

Given('notification system is active and configured for email and in-app alerts', async function () {
  this.testData.notificationSystemActive = true;
  this.testData.notificationChannels = ['email', 'in-app'];
});

Given('test environment allows schedule modification', async function () {
  this.testData.scheduleModificationEnabled = true;
});

Given('user has access to view rendered notifications in both formats', async function () {
  this.testData.notificationViewAccess = ['email', 'in-app'];
});

Given('notification system is active and configured', async function () {
  this.testData.notificationSystemActive = true;
});

/**************************************************/
/*  TEST CASE: TC-SEC-002
/*  Title: Enforce proper authentication on notification API endpoint
/*  Priority: Critical
/*  Category: Security - Authentication
/**************************************************/

/**************************************************/
/*  TEST CASE: TC-SEC-003
/*  Title: Protect notification system against XSS injection attacks
/*  Priority: Critical
/*  Category: Security - XSS
/**************************************************/

// ==================== WHEN STEPS ====================

When('{string} logs in to the system', async function (userName: string) {
  const userCredentials = this.testData?.users?.[userName];
  
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000');
  await waits.waitForNetworkIdle();
  
  await actions.fill(page.locator('//input[@id="username"]'), userCredentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), userCredentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  
  this.testData.currentUser = userName;
});

When('{string} triggers a schedule change to generate a notification', async function (userName: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="my-schedules"]'));
  await waits.waitForNetworkIdle();
  
  const scheduleLocator = page.locator(`//div[contains(text(),'${userName} Schedule')]`);
  await actions.click(scheduleLocator);
  await waits.waitForNetworkIdle();
  
  await actions.click(page.locator('//button[@id="edit-schedule"]'));
  await actions.fill(page.locator('//input[@id="schedule-title"]'), `${userName} Schedule - Updated`);
  await actions.click(page.locator('//button[@id="save-schedule"]'));
  await waits.waitForNetworkIdle();
});

When('user captures the API request to {string} endpoint', async function (endpoint: string) {
  const capturedRequests = this.testData.capturedData.apiRequests.filter((req: any) => req.url.includes(endpoint));
  this.testData.capturedEndpointRequests = capturedRequests;
});

When('{string} attempts to access {string} notification by manipulating notification ID parameter', async function (currentUser: string, targetUser: string) {
  const targetNotificationId = this.testData.capturedData.notificationIds[targetUser];
  
  const response = await page.request.get(`${process.env.BASE_URL}/api/notifications/${targetNotificationId}`, {
    failOnStatusCode: false,
    headers: {
      'Authorization': `Bearer ${this.testData.authToken}`
    }
  });
  
  this.testData.unauthorizedAccessResponse = {
    status: response.status(),
    body: await response.text()
  };
});

When('user attempts sequential notification ID enumeration', async function () {
  const enumerationResults = [];
  
  for (let i = 1; i <= 10; i++) {
    const response = await page.request.get(`${process.env.BASE_URL}/api/notifications/${i}`, {
      failOnStatusCode: false,
      headers: {
        'Authorization': `Bearer ${this.testData.authToken}`
      }
    });
    
    enumerationResults.push({
      notificationId: i,
      status: response.status()
    });
  }
  
  this.testData.enumerationResults = enumerationResults;
});

When('user verifies notification content in email and in-app alerts', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="notifications"]'));
  await waits.waitForNetworkIdle();
  
  const notificationContent = await page.locator('//div[@id="notification-content"]').textContent();
  this.testData.inAppNotificationContent = notificationContent;
  
  const emailNotificationLocator = page.locator('//div[@id="email-preview"]');
  if (await emailNotificationLocator.count() > 0) {
    this.testData.emailNotificationContent = await emailNotificationLocator.textContent();
  }
});

When('user attempts to access {string} endpoint without authentication credentials', async function (endpoint: string) {
  const response = await page.request.post(`${process.env.BASE_URL}${endpoint}`, {
    failOnStatusCode: false,
    data: {
      userId: 'testuser',
      message: 'Test notification'
    }
  });
  
  this.testData.unauthenticatedResponse = {
    status: response.status(),
    body: await response.text()
  };
});

When('user attempts to access the endpoint with expired authentication token', async function () {
  const expiredToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.expired';
  
  const response = await page.request.post(`${process.env.BASE_URL}${this.testData.apiEndpoint}`, {
    failOnStatusCode: false,
    headers: {
      'Authorization': `Bearer ${expiredToken}`
    },
    data: {
      userId: 'testuser',
      message: 'Test notification'
    }
  });
  
  this.testData.expiredTokenResponse = {
    status: response.status(),
    body: await response.text()
  };
});

When('user attempts to access the endpoint with malformed authentication token', async function () {
  const malformedToken = 'malformed.token.value';
  
  const response = await page.request.post(`${process.env.BASE_URL}${this.testData.apiEndpoint}`, {
    failOnStatusCode: false,
    headers: {
      'Authorization': `Bearer ${malformedToken}`
    },
    data: {
      userId: 'testuser',
      message: 'Test notification'
    }
  });
  
  this.testData.malformedTokenResponse = {
    status: response.status(),
    body: await response.text()
  };
});

When('user attempts to replay valid authentication token from previous session after logout', async function () {
  const previousToken = this.testData.authToken;
  
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="logout"]'));
  await waits.waitForNetworkIdle();
  
  const response = await page.request.post(`${process.env.BASE_URL}${this.testData.apiEndpoint}`, {
    failOnStatusCode: false,
    headers: {
      'Authorization': `Bearer ${previousToken}`
    },
    data: {
      userId: 'testuser',
      message: 'Test notification'
    }
  });
  
  this.testData.replayTokenResponse = {
    status: response.status(),
    body: await response.text()
  };
});

When('user attempts authentication bypass by manipulating request headers', async function () {
  const bypassAttempts = [];
  
  const bypassHeaders = [
    { 'X-Forwarded-For': '127.0.0.1' },
    { 'X-Original-URL': '/admin' },
    { 'X-Rewrite-URL': '/admin' },
    { 'X-Custom-IP-Authorization': '127.0.0.1' },
    { 'Authorization': 'Bearer null' }
  ];
  
  for (const headers of bypassHeaders) {
    const response = await page.request.post(`${process.env.BASE_URL}${this.testData.apiEndpoint}`, {
      failOnStatusCode: false,
      headers: headers,
      data: {
        userId: 'testuser',
        message: 'Test notification'
      }
    });
    
    bypassAttempts.push({
      headers: headers,
      status: response.status()
    });
  }
  
  this.testData.bypassAttempts = bypassAttempts;
});

When('user verifies notification viewing endpoints require authentication', async function () {
  const response = await page.request.get(`${process.env.BASE_URL}/api/notifications/view`, {
    failOnStatusCode: false
  });
  
  this.testData.notificationViewAuthCheck = {
    status: response.status()
  };
});

When('user creates schedule entry with {string} in {string} field', async function (payload: string, fieldName: string) {
  // TODO: Replace XPath with Object Repository when available
  const userCredentials = this.testData?.users?.scheduleuser;
  
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000');
  await waits.waitForNetworkIdle();
  
  await actions.fill(page.locator('//input[@id="username"]'), userCredentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), userCredentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  
  await actions.click(page.locator('//button[@id="create-schedule"]'));
  await waits.waitForNetworkIdle();
  
  const fieldXPath = `//input[@id='schedule-${fieldName.toLowerCase()}'] | //textarea[@id='schedule-${fieldName.toLowerCase()}']`;
  await actions.fill(page.locator(fieldXPath), payload);
  
  this.testData.xssPayload = payload;
  this.testData.xssField = fieldName;
});

When('user modifies the schedule entry to trigger a notification', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="save-schedule"]'));
  await waits.waitForNetworkIdle();
  
  await actions.click(page.locator('//button[@id="edit-schedule"]'));
  await actions.fill(page.locator('//input[@id="schedule-title"]'), 'Updated Schedule');
  await actions.click(page.locator('//button[@id="save-schedule"]'));
  await waits.waitForNetworkIdle();
});

When('user observes the email notification content', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="email-notifications"]'));
  await waits.waitForNetworkIdle();
  
  const emailContent = await page.locator('//div[@id="email-notification-preview"]').innerHTML();
  this.testData.emailNotificationHtml = emailContent;
});

When('user views the in-app notification', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="notifications"]'));
  await waits.waitForNetworkIdle();
  
  const inAppContent = await page.locator('//div[@id="notification-content"]').innerHTML();
  this.testData.inAppNotificationHtml = inAppContent;
});

When('user verifies notification API responses include security headers', async function () {
  const response = await page.request.get(`${process.env.BASE_URL}/api/notifications/list`, {
    failOnStatusCode: false,
    headers: {
      'Authorization': `Bearer ${this.testData.authToken}`
    }
  });
  
  this.testData.securityHeaders = {
    contentType: response.headers()['content-type'],
    xContentTypeOptions: response.headers()['x-content-type-options'],
    xXssProtection: response.headers()['x-xss-protection'],
    allHeaders: response.headers()
  };
});

When('{string} views the notification', async function (userName: string) {
  const userCredentials = this.testData?.users?.[userName];
  
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000');
  await waits.waitForNetworkIdle();
  
  await actions.fill(page.locator('//input[@id="username"]'), userCredentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), userCredentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  
  await actions.click(page.locator('//button[@id="notifications"]'));
  await waits.waitForNetworkIdle();
  
  const notificationContent = await page.locator('//div[@id="notification-content"]').innerHTML();
  this.testData.viewedNotificationContent = notificationContent;
});

// ==================== THEN STEPS ====================

Then('{string} should receive notification with unique notification ID', async function (userName: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="notifications"]'));
  await waits.waitForNetworkIdle();
  
  const notificationIdElement = page.locator('//div[@data-notification-id]');
  await assertions.assertVisible(notificationIdElement);
  
  const notificationId = await notificationIdElement.getAttribute('data-notification-id');
  this.testData.capturedData.notificationIds[userName] = notificationId;
  
  expect(notificationId).toBeTruthy();
  expect(notificationId).not.toBe('');
});

Then('API request structure should be documented showing notification ID parameter', async function () {
  const capturedRequests = this.testData.capturedEndpointRequests;
  expect(capturedRequests.length).toBeGreaterThan(0);
  
  const notificationRequest = capturedRequests[0];
  expect(notificationRequest.url).toContain('/api/notifications');
});

Then('{string} should receive notification with different notification ID', async function (userName: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="notifications"]'));
  await waits.waitForNetworkIdle();
  
  const notificationIdElement = page.locator('//div[@data-notification-id]');
  await assertions.assertVisible(notificationIdElement);
  
  const notificationId = await notificationIdElement.getAttribute('data-notification-id');
  this.testData.capturedData.notificationIds[userName] = notificationId;
  
  const previousUserNotificationId = this.testData.capturedData.notificationIds['User A'];
  expect(notificationId).not.toBe(previousUserNotificationId);
});

Then('system should return {string} status code', async function (expectedStatusCode: string) {
  const actualStatusCode = this.testData.unauthorizedAccessResponse?.status || 
                          this.testData.unauthenticatedResponse?.status ||
                          this.testData.expiredTokenResponse?.status ||
                          this.testData.malformedTokenResponse?.status ||
                          this.testData.replayTokenResponse?.status;
  
  expect(actualStatusCode).toBe(parseInt(expectedStatusCode));
});

Then('unauthorized access should be prevented', async function () {
  const statusCode = this.testData.unauthorizedAccessResponse?.status;
  expect(statusCode).toBe(403);
});

Then('all unauthorized access attempts should be blocked with proper error codes', async function () {
  const enumerationResults = this.testData.enumerationResults;
  
  for (const result of enumerationResults) {
    expect([401, 403, 404]).toContain(result.status);
  }
});

Then('security events should be logged in audit trail', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/security-logs`);
  await waits.waitForNetworkIdle();
  
  const securityLogEntries = page.locator('//div[@class="security-log-entry"]');
  const logCount = await securityLogEntries.count();
  
  expect(logCount).toBeGreaterThan(0);
});

Then('notification should contain only authenticated user\'s own schedule information', async function () {
  const notificationContent = this.testData.inAppNotificationContent;
  const currentUser = this.testData.currentUser;
  
  expect(notificationContent).toContain(currentUser);
});

Then('no data leakage from other users should be present', async function () {
  const notificationContent = this.testData.inAppNotificationContent;
  const currentUser = this.testData.currentUser;
  const otherUsers = Object.keys(this.testData.users).filter(user => user !== currentUser);
  
  for (const otherUser of otherUsers) {
    expect(notificationContent).not.toContain(otherUser);
  }
});

Then('all unauthorized access attempts should be logged in security audit trail', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/audit-trail`);
  await waits.waitForNetworkIdle();
  
  const auditLogEntries = page.locator('//div[@class="audit-log-entry"]');
  const logCount = await auditLogEntries.count();
  
  expect(logCount).toBeGreaterThan(0);
  
  const unauthorizedAccessLogs = page.locator('//div[contains(@class, "audit-log-entry") and contains(text(), "Unauthorized")]');
  const unauthorizedLogCount = await unauthorizedAccessLogs.count();
  
  expect(unauthorizedLogCount).toBeGreaterThan(0);
});

Then('no sensitive information from other users should be exposed', async function () {
  const notificationContent = this.testData.inAppNotificationContent || this.testData.emailNotificationContent;
  const currentUser = this.testData.currentUser;
  const otherUsers = Object.keys(this.testData.users).filter(user => user !== currentUser);
  
  for (const otherUser of otherUsers) {
    const otherUserData = this.testData.users[otherUser];
    expect(notificationContent).not.toContain(otherUserData.email);
    expect(notificationContent).not.toContain(otherUserData.username);
  }
});

Then('user sessions should remain valid and unaffected', async function () {
  // TODO: Replace XPath with Object Repository when available
  const userProfileButton = page.locator('//button[@id="user-profile"]');
  await assertions.assertVisible(userProfileButton);
  
  await actions.click(userProfileButton);
  await waits.waitForNetworkIdle();
  
  const sessionStatus = page.locator('//div[@id="session-status"]');
  await assertions.assertContainsText(sessionStatus, 'Active');
});

Then('access to the endpoint should be denied', async function () {
  const statusCode = this.testData.unauthenticatedResponse?.status;
  expect(statusCode).toBe(401);
});

Then('error message should indicate token expiration', async function () {
  const responseBody = this.testData.expiredTokenResponse?.body;
  expect(responseBody).toMatch(/expired|invalid|token/i);
});

Then('invalid token attempt should be logged as security event', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/security-logs`);
  await waits.waitForNetworkIdle();
  
  const invalidTokenLogs = page.locator('//div[contains(@class, "security-log-entry") and contains(text(), "Invalid token")]');
  const logCount = await invalidTokenLogs.count();
  
  expect(logCount).toBeGreaterThan(0);
});

Then('system should reject the token', async function () {
  const statusCode = this.testData.replayTokenResponse?.status;
  expect(statusCode).toBe(401);
});

Then('token invalidation on logout should be confirmed', async function () {
  const statusCode = this.testData.replayTokenResponse?.status;
  expect(statusCode).toBe(401);
  
  const responseBody = this.testData.replayTokenResponse?.body;
  expect(responseBody).toMatch(/invalid|unauthorized|expired/i);
});

Then('all bypass attempts should fail with {string} status code', async function (expectedStatusCode: string) {
  const bypassAttempts = this.testData.bypassAttempts;
  
  for (const attempt of bypassAttempts) {
    expect(attempt.status).toBe(parseInt(expectedStatusCode));
  }
});

Then('only authenticated users should view their own notifications', async function () {
  const statusCode = this.testData.notificationViewAuthCheck?.status;
  expect(statusCode).toBe(401);
});

Then('cross-user access should be prevented', async function () {
  const statusCode = this.testData.unauthorizedAccessResponse?.status;
  expect(statusCode).toBe(403);
});

Then('all unauthorized access attempts should be logged with timestamps and source IPs', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/security-logs`);
  await waits.waitForNetworkIdle();
  
  const logEntries = page.locator('//div[@class="security-log-entry"]');
  const firstLogEntry = logEntries.first();
  
  await assertions.assertVisible(firstLogEntry);
  
  const logContent = await firstLogEntry.textContent();
  expect(logContent).toMatch(/\d{4}-\d{2}-\d{2}/);
  expect(logContent).toMatch(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/);
});

Then('no notifications should be sent or accessed without valid authentication', async function () {
  const unauthenticatedStatusCode = this.testData.unauthenticatedResponse?.status;
  expect(unauthenticatedStatusCode).toBe(401);
});

Then('system security posture should remain intact', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/system-health`);
  await waits.waitForNetworkIdle();
  
  const securityStatus = page.locator('//div[@id="security-status"]');
  await assertions.assertContainsText(securityStatus, 'Secure');
});

Then('system should accept the input and store the schedule entry', async function () {
  // TODO: Replace XPath with Object Repository when available
  const successMessage = page.locator('//div[@id="success-message"]');
  await assertions.assertVisible(successMessage);
});

Then('email notification should display sanitized content', async function () {
  const emailHtml = this.testData.emailNotificationHtml;
  const payload = this.testData.xssPayload;
  
  expect(emailHtml).not.toContain('<script>');
  expect(emailHtml).not.toContain('onerror=');
  expect(emailHtml).not.toContain('onload=');
  expect(emailHtml).not.toContain('javascript:');
});

Then('script tags should be encoded or stripped', async function () {
  const emailHtml = this.testData.emailNotificationHtml;
  
  expect(emailHtml).not.toContain('<script>');
  expect(emailHtml).not.toContain('</script>');
});

Then('script should not execute', async function () {
  const alertDialogPromise = page.waitForEvent('dialog', { timeout: 2000 }).catch(() => null);
  const dialog = await alertDialogPromise;
  
  expect(dialog).toBeNull();
});

Then('in-app notification should render safe content without executing JavaScript', async function () {
  const inAppHtml = this.testData.inAppNotificationHtml;
  
  expect(inAppHtml).not.toContain('<script>');
  expect(inAppHtml).not.toContain('onerror=');
  expect(inAppHtml).not.toContain('onload=');
});

Then('no alert popup should appear', async function () {
  const alertDialogPromise = page.waitForEvent('dialog', { timeout: 2000 }).catch(() => null);
  const dialog = await alertDialogPromise;
  
  expect(dialog).toBeNull();
});

Then('notification should be properly sanitized in the UI', async function () {
  const inAppHtml = this.testData.inAppNotificationHtml;
  const payload = this.testData.xssPayload;
  
  expect(inAppHtml).not.toContain('<script>');
  expect(inAppHtml).not.toContain('<iframe');
  expect(inAppHtml).not.toContain('javascript:');
});

Then('{string} header should be {string}', async function (headerName: string, expectedValue: string) {
  const headers = this.testData.securityHeaders;
  const headerKey = headerName.toLowerCase().replace(/-/g, '');
  
  if (headerName === 'Content-Type') {
    expect(headers.contentType).toContain(expectedValue);
  } else if (headerName === 'X-Content-Type-Options') {
    expect(headers.xContentTypeOptions).toBe(expectedValue);
  } else if (headerName === 'X-XSS-Protection') {
    expect(headers.xXssProtection).toBeTruthy();
  }
});

Then('{string} header should be present', async function (headerName: string) {
  const headers = this.testData.securityHeaders;
  const headerKey = headerName.toLowerCase();
  
  expect(headers.allHeaders[headerKey]).toBeTruthy();
});

Then('all security headers should prevent MIME-type sniffing', async function () {
  const headers = this.testData.securityHeaders;
  expect(headers.xContentTypeOptions).toBe('nosniff');
});

Then('no malicious scripts should be executed in any notification context', async function () {
  const alertDialogPromise = page.waitForEvent('dialog', { timeout: 2000 }).catch(() => null);
  const dialog = await alertDialogPromise;
  
  expect(dialog).toBeNull();
  
  const emailHtml = this.testData.emailNotificationHtml;
  const inAppHtml = this.testData.inAppNotificationHtml;
  
  expect(emailHtml).not.toContain('<script>');
  expect(inAppHtml).not.toContain('<script>');
});

Then('schedule data should remain intact with sanitized content', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="my-schedules"]'));
  await waits.waitForNetworkIdle();
  
  const scheduleContent = page.locator('//div[@class="schedule-content"]');
  await assertions.assertVisible(scheduleContent);
  
  const content = await scheduleContent.textContent();
  expect(content).toBeTruthy();
});

Then('security logs should capture input validation events', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(`${process.env.BASE_URL}/admin/security-logs`);
  await waits.waitForNetworkIdle();
  
  const validationLogs = page.locator('//div[contains(@class, "security-log-entry") and contains(text(), "Input validation")]');
  const logCount = await validationLogs.count();
  
  expect(logCount).toBeGreaterThan(0);
});

Then('{string} should receive sanitized notification', async function (userName: string) {
  const notificationContent = this.testData.viewedNotificationContent;
  
  expect(notificationContent).not.toContain('<script>');
  expect(notificationContent).not.toContain('onerror=');
  expect(notificationContent).not.toContain('onload=');
});

Then('no script execution should occur', async function () {
  const alertDialogPromise = page.waitForEvent('dialog', { timeout: 2000 }).catch(() => null);
  const dialog = await alertDialogPromise;
  
  expect(dialog).toBeNull();
});

Then('stored XSS protection should be confirmed', async function () {
  const notificationContent = this.testData.viewedNotificationContent;
  
  expect(notificationContent).not.toContain('<script>');
  expect(notificationContent).not.toContain('javascript:');
  expect(notificationContent).not.toContain('onerror=');
  
  const alertDialogPromise = page.waitForEvent('dialog', { timeout: 2000 }).catch(() => null);
  const dialog = await alertDialogPromise;
  
  expect(dialog).toBeNull();
});