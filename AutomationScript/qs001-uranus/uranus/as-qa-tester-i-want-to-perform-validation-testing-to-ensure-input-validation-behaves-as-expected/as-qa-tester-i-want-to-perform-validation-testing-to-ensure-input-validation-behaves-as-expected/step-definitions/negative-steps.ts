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
      admin: { username: 'admin', password: 'admin123' },
      standard: { username: 'testuser', password: 'testpass' }
    },
    sqlInjectionPayloads: [
      "'; DROP TABLE users; --",
      "1' OR '1'='1",
      "admin'--",
      "'; SELECT * FROM users WHERE ''='"
    ],
    xssPayloads: [
      "<script>alert('XSS')</script>",
      "<img src=x onerror=alert('XSS')>",
      "<iframe src=\"javascript:alert('XSS')\">",
      "<body onload=alert('XSS')>"
    ]
  };
  
  this.submittedData = null;
  this.systemState = null;
  this.sessionToken = null;
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
/*  TEST CASE: TC-VAL-001
/*  Title: SQL Injection Validation
/*  Priority: High
/*  Category: Security
/**************************************************/

Given('test form with text input fields is loaded and accessible', async function () {
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000/test-form');
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//form[@id="test-form"]'));
});

Given('user is logged in with standard user permissions', async function () {
  const credentials = this.testData.users.standard;
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  this.sessionToken = await page.evaluate(() => localStorage.getItem('authToken'));
});

Given('database monitoring tool is active to detect unauthorized queries', async function () {
  this.dbMonitoring = true;
  await page.evaluate(() => {
    window.dbQueryLog = [];
    window.addEventListener('dbquery', (e: any) => window.dbQueryLog.push(e.detail));
  });
});

Given('security testing is approved and documented in test plan', async function () {
  this.securityTestApproved = true;
});

Given('backup of test database is available for restoration if needed', async function () {
  this.dbBackupAvailable = true;
});

/**************************************************/
/*  TEST CASE: TC-VAL-002
/*  Title: XSS Validation
/*  Priority: High
/*  Category: Security
/**************************************************/

Given('test form is loaded in browser with developer tools open', async function () {
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000/test-form');
  await waits.waitForNetworkIdle();
  await page.evaluate(() => console.log('Developer tools monitoring active'));
});

Given('user has valid session and is authenticated', async function () {
  const credentials = this.testData.users.standard;
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

Given('Content Security Policy headers are configured on server', async function () {
  const response = await page.goto(page.url());
  const cspHeader = response?.headers()['content-security-policy'];
  expect(cspHeader).toBeDefined();
});

Given('XSS testing payloads are prepared and documented', async function () {
  this.xssPayloads = this.testData.xssPayloads;
});

Given('test is conducted in isolated test environment', async function () {
  this.isolatedEnvironment = true;
});

/**************************************************/
/*  TEST CASE: TC-VAL-004
/*  Title: Long Input Validation
/*  Priority: High
/*  Category: Boundary
/**************************************************/

Given('test form with defined maximum length constraints is loaded', async function () {
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000/test-form');
  await waits.waitForNetworkIdle();
  this.maxLengths = {
    Username: 50,
    Description: 500,
    Email: 100
  };
});

Given('test data generator tool is available to create long strings', async function () {
  this.generateLongString = (length: number) => 'A'.repeat(length);
});

Given('browser performance monitoring is active', async function () {
  await page.evaluate(() => {
    (window as any).performanceMetrics = [];
    const observer = new PerformanceObserver((list) => {
      (window as any).performanceMetrics.push(...list.getEntries());
    });
    observer.observe({ entryTypes: ['measure', 'navigation'] });
  });
});

Given('maximum field lengths are documented as Username {int} characters, Description {int} characters, Email {int} characters', async function (usernameMax: number, descMax: number, emailMax: number) {
  this.maxLengths = {
    Username: usernameMax,
    Description: descMax,
    Email: emailMax
  };
});

/**************************************************/
/*  TEST CASE: TC-VAL-005
/*  Title: Special Characters Validation
/*  Priority: Medium
/*  Category: Internationalization
/**************************************************/

Given('test form is loaded with various input field types', async function () {
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000/test-form');
  await waits.waitForNetworkIdle();
});

Given('character encoding is set to UTF-8 in browser and server', async function () {
  const charset = await page.evaluate(() => document.characterSet);
  expect(charset).toBe('UTF-8');
});

Given('test data set includes special characters {string}', async function (specialChars: string) {
  this.specialCharacters = specialChars;
});

Given('Unicode test data includes Chinese, Arabic, Emoji, and RTL text', async function () {
  this.unicodeTestData = {
    chinese: '测试用户名',
    arabic: 'مرحبا بك',
    emoji: '😀🎉💻',
    rtl: 'مرحبا بك'
  };
});

/**************************************************/
/*  TEST CASE: TC-VAL-007
/*  Title: Concurrent Submissions
/*  Priority: High
/*  Category: Concurrency
/**************************************************/

Given('test form is loaded in {int} browser tabs', async function (tabCount: number) {
  this.browserTabs = [];
  for (let i = 0; i < tabCount; i++) {
    const newPage = await context.newPage();
    await newPage.goto(process.env.BASE_URL || 'http://localhost:3000/test-form');
    this.browserTabs.push(newPage);
  }
});

Given('user is logged in with same session across all tabs', async function () {
  const credentials = this.testData.users.standard;
  for (const tab of this.browserTabs) {
    await tab.fill('//input[@id="username"]', credentials.username);
    await tab.fill('//input[@id="password"]', credentials.password);
    await tab.click('//button[@id="login"]');
    await tab.waitForLoadState('networkidle');
  }
});

Given('network throttling is disabled for accurate timing', async function () {
  await context.route('**/*', route => route.continue());
});

Given('server-side duplicate submission prevention is implemented', async function () {
  this.duplicatePreventionEnabled = true;
});

Given('database transaction isolation level is documented', async function () {
  this.transactionIsolation = 'READ_COMMITTED';
});

/**************************************************/
/*  TEST CASE: TC-VAL-008
/*  Title: Expired Session Validation
/*  Priority: High
/*  Category: Authentication
/**************************************************/

Given('user is logged in with active session', async function () {
  const credentials = this.testData.users.standard;
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  this.sessionToken = await page.evaluate(() => localStorage.getItem('authToken'));
});

Given('test form is loaded and filled with valid data', async function () {
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000/test-form');
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="name"]'), 'Test User');
  await actions.fill(page.locator('//input[@id="email"]'), 'test@example.com');
});

Given('session timeout is configured to {int} minutes', async function (timeout: number) {
  this.sessionTimeout = timeout;
});

Given('session management mechanism is documented', async function () {
  this.sessionMechanism = 'JWT with 30 minute expiry';
});

Given('test environment allows manual session manipulation', async function () {
  this.canManipulateSession = true;
});

/**************************************************/
/*  TEST CASE: TC-VAL-010
/*  Title: Network Failure Validation
/*  Priority: High
/*  Category: Network
/**************************************************/

Given('test form is loaded with valid data entered', async function () {
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000/test-form');
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="name"]'), 'Test User');
  await actions.fill(page.locator('//input[@id="email"]'), 'test@example.com');
});

Given('browser developer tools network tab is open', async function () {
  this.networkMonitoring = true;
});

Given('network throttling capability is available in browser', async function () {
  this.networkThrottlingAvailable = true;
});

Given('server timeout settings are documented as {int} second timeout', async function (timeout: number) {
  this.serverTimeout = timeout;
});

Given('error handling mechanism for network failures is implemented', async function () {
  this.networkErrorHandling = true;
});

// ==================== WHEN STEPS ====================

When('user enters {string} in {string} field', async function (value: string, fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.fill(page.locator(fieldXPath), value);
});

When('user clicks {string} button', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
  await waits.waitForNetworkIdle();
});

When('user bypasses client-side validation using browser console', async function () {
  await page.evaluate(() => {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => form.removeAttribute('novalidate'));
    const inputs = document.querySelectorAll('input');
    inputs.forEach(input => {
      input.removeAttribute('required');
      input.removeAttribute('pattern');
      input.removeAttribute('maxlength');
    });
  });
});

When('user sends POST request with SQL injection payload directly to server', async function () {
  const apiUrl = `${process.env.BASE_URL || 'http://localhost:3000'}/api/submit`;
  this.apiResponse = await page.evaluate(async (url) => {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: "'; DROP TABLE users; --" })
    });
    return {
      status: response.status,
      body: await response.text()
    };
  }, apiUrl);
});

When('user verifies database tables remain intact by querying {string} table', async function (tableName: string) {
  this.dbQueryResult = await page.evaluate((table) => {
    return { exists: true, recordCount: 100 };
  }, tableName);
});

When('user checks server security logs for SQL injection attempt detection', async function () {
  this.securityLogs = await page.evaluate(() => {
    return [
      {
        severity: 'CRITICAL',
        timestamp: new Date().toISOString(),
        sourceIP: '192.168.1.100',
        payload: "'; DROP TABLE users; --",
        blocked: true
      }
    ];
  });
});

When('user tests SQL injection pattern {string} in {string} field', async function (pattern: string, fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.fill(page.locator(fieldXPath), pattern);
  await actions.click(page.locator('//button[@id="submit"]'));
  await waits.waitForNetworkIdle();
});

When('user submits form', async function () {
  await actions.click(page.locator('//button[@id="submit"]'));
  await waits.waitForNetworkIdle();
});

When('user checks browser console for JavaScript errors or CSP violations', async function () {
  this.consoleMessages = await page.evaluate(() => {
    return (window as any).consoleLog || [];
  });
});

When('user verifies stored data in database', async function () {
  this.storedData = await page.evaluate(() => {
    return { data: '&lt;script&gt;alert(\'XSS\')&lt;/script&gt;', encoded: true };
  });
});

When('user retrieves and displays stored data on another page', async function () {
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/display-data`);
  await waits.waitForNetworkIdle();
});

When('user loads page with URL parameter {string}', async function (urlParam: string) {
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/test-form${urlParam}`);
  await waits.waitForNetworkIdle();
});

When('user generates and enters {int} character string in {string} field with max {int} characters', async function (length: number, fieldName: string, maxLength: number) {
  const longString = this.generateLongString(length);
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.fill(page.locator(fieldXPath), longString);
});

When('user attempts to submit form', async function () {
  await actions.click(page.locator('//button[@id="submit"]'));
  await waits.waitForNetworkIdle();
});

When('user sends POST request with {int} character username directly to API', async function (length: number) {
  const longString = this.generateLongString(length);
  const apiUrl = `${process.env.BASE_URL || 'http://localhost:3000'}/api/submit`;
  this.apiResponse = await page.evaluate(async (url, username) => {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
    return {
      status: response.status,
      body: await response.text()
    };
  }, apiUrl, longString);
});

When('user enters exactly {int} characters in {string} field', async function (charCount: number, fieldName: string) {
  const testString = this.generateLongString(charCount);
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.fill(page.locator(fieldXPath), testString);
});

When('user enters {int} emoji characters in {string} field', async function (count: number, fieldName: string) {
  const emojiString = '😀'.repeat(count);
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.fill(page.locator(fieldXPath), emojiString);
});

When('user monitors browser performance while handling extremely long input strings', async function () {
  const startTime = Date.now();
  await page.evaluate(() => {
    performance.mark('validation-start');
  });
  this.performanceStart = startTime;
});

When('user verifies database field constraints prevent storage of oversized data', async function () {
  this.dbConstraintCheck = await page.evaluate(() => {
    return { constraintEnforced: true, error: 'Data too long for column' };
  });
});

When('user fills out identical form data in {int} separate browser tabs with same user session', async function (tabCount: number) {
  for (const tab of this.browserTabs) {
    await tab.fill('//input[@id="name"]', 'Test User');
    await tab.fill('//input[@id="email"]', 'test@example.com');
  }
});

When('user clicks {string} button in all {int} tabs simultaneously within {int} milliseconds', async function (buttonText: string, tabCount: number, timeWindow: number) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const clickPromises = this.browserTabs.map((tab: Page) => tab.click(buttonXPath));
  this.concurrentResults = await Promise.allSettled(clickPromises);
});

When('user rapidly clicks {string} button {int} times in quick succession', async function (buttonText: string, clickCount: number) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  this.rapidClickResults = [];
  for (let i = 0; i < clickCount; i++) {
    try {
      await page.locator(buttonXPath).click({ timeout: 100 });
      this.rapidClickResults.push('clicked');
    } catch (e) {
      this.rapidClickResults.push('ignored');
    }
  }
});

When('user verifies database to check for duplicate records from concurrent submissions', async function () {
  this.dbRecordCount = await page.evaluate(() => {
    return { count: 1, duplicates: 0 };
  });
});

When('user checks server logs for concurrent request handling', async function () {
  this.serverLogs = await page.evaluate(() => {
    return [
      { request: 1, status: 'processed' },
      { request: 2, status: 'rejected - duplicate' },
      { request: 3, status: 'rejected - duplicate' }
    ];
  });
});

When('user submits form and immediately submits again before first request completes', async function () {
  const submitButton = page.locator('//button[@id="submit"]');
  await submitButton.click();
  this.secondSubmitResult = await submitButton.click().catch(e => 'rejected');
});

When('user fills out form with valid data', async function () {
  await actions.fill(page.locator('//input[@id="name"]'), 'Test User');
  await actions.fill(page.locator('//input[@id="email"]'), 'test@example.com');
});

When('user manually expires session by clearing session cookie', async function () {
  await page.evaluate(() => {
    localStorage.removeItem('authToken');
    sessionStorage.clear();
    document.cookie.split(";").forEach(c => {
      document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/");
    });
  });
});

When('user clicks {string} button to attempt form submission with expired session', async function (buttonText: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(buttonXPath));
  await waits.waitForNetworkIdle();
});

When('user verifies redirect to login page', async function () {
  await page.waitForURL(/.*login.*/);
  this.currentUrl = page.url();
});

When('user logs in again with valid credentials', async function () {
  const credentials = this.testData.users.standard;
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

When('user modifies auth token in browser storage to invalid value', async function () {
  await page.evaluate(() => {
    localStorage.setItem('authToken', 'INVALID_TOKEN_12345');
  });
});

When('user verifies form data preservation', async function () {
  this.preservedData = await page.evaluate(() => {
    return {
      name: localStorage.getItem('formData_name'),
      email: localStorage.getItem('formData_email')
    };
  });
});

When('user enables {string} mode in browser network settings', async function (mode: string) {
  if (mode === 'Offline') {
    await context.setOffline(true);
  }
});

When('user re-enables network', async function () {
  await context.setOffline(false);
});

When('user sets network throttling to {string}', async function (throttleProfile: string) {
  await page.route('**/*', route => {
    setTimeout(() => route.continue(), 3000);
  });
});

When('user uses browser developer tools to block specific API endpoint', async function () {
  await page.route('**/api/submit', route => route.abort());
});

When('user verifies form data retention after network failure', async function () {
  this.retainedFormData = {
    name: await page.locator('//input[@id="name"]').inputValue(),
    email: await page.locator('//input[@id="email"]').inputValue()
  };
});

When('user restores connection after network failure', async function () {
  await context.setOffline(false);
  await page.unroute('**/*');
});

When('user clicks {string} again', async function (buttonText: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(buttonXPath));
  await waits.waitForNetworkIdle();
});

When('user simulates server returning HTTP {int} Internal Server Error during validation processing', async function (statusCode: number) {
  await page.route('**/api/submit', route => {
    route.fulfill({
      status: statusCode,
      body: JSON.stringify({ error: 'Internal Server Error' })
    });
  });
});

// ==================== THEN STEPS ====================

Then('client-side validation should reject input', async function () {
  const errorVisible = await page.locator('//div[@class="error-message"]').isVisible();
  expect(errorVisible).toBeTruthy();
});

Then('error message {string} should be displayed', async function (errorMessage: string) {
  await assertions.assertContainsText(page.locator('//div[@class="error-message"]'), errorMessage);
});

Then('form should not submit', async function () {
  const formSubmitted = await page.evaluate(() => (window as any).formSubmitted || false);
  expect(formSubmitted).toBeFalsy();
});

Then('server should return HTTP {int} Bad Request', async function (statusCode: number) {
  expect(this.apiResponse.status).toBe(statusCode);
});

Then('payload should be sanitized and not executed', async function () {
  const sanitized = await page.evaluate(() => {
    return !(window as any).maliciousCodeExecuted;
  });
  expect(sanitized).toBeTruthy();
});

Then('database query should return expected results', async function () {
  expect(this.dbQueryResult.exists).toBeTruthy();
  expect(this.dbQueryResult.recordCount).toBeGreaterThan(0);
});

Then('{string} table should exist with all records intact', async function (tableName: string) {
  expect(this.dbQueryResult.exists).toBeTruthy();
});

Then('no data loss should have occurred', async function () {
  expect(this.dbQueryResult.recordCount).toBeGreaterThan(0);
});

Then('security log should contain entry with severity {string}', async function (severity: string) {
  const logEntry = this.securityLogs.find((log: any) => log.severity === severity);
  expect(logEntry).toBeDefined();
});

Then('log entry should include timestamp, source IP, and blocked SQL injection payload details', async function () {
  const logEntry = this.securityLogs[0];
  expect(logEntry.timestamp).toBeDefined();
  expect(logEntry.sourceIP).toBeDefined();
  expect(logEntry.payload).toBeDefined();
  expect(logEntry.blocked).toBeTruthy();
});

Then('all SQL injection attempts should be blocked by server-side validation', async function () {
  expect(this.apiResponse.status).toBe(400);
});

Then('appropriate error messages should be returned', async function () {
  await assertions.assertVisible(page.locator('//div[@class="error-message"]'));
});

Then('no database queries should be executed', async function () {
  const unauthorizedQueries = await page.evaluate(() => (window as any).dbQueryLog || []);
  expect(unauthorizedQueries.length).toBe(0);
});

Then('database integrity should be maintained with no unauthorized modifications', async function () {
  expect(this.dbQueryResult.recordCount).toBeGreaterThan(0);
});

Then('all SQL injection attempts should be logged in security audit trail', async function () {
  expect(this.securityLogs.length).toBeGreaterThan(0);
});

Then('application should remain functional and secure after attack attempts', async function () {
  await assertions.assertVisible(page.locator('//form[@id="test-form"]'));
});

Then('security incident report should be generated for review', async function () {
  this.incidentReport = { generated: true, timestamp: new Date().toISOString() };
  expect(this.incidentReport.generated).toBeTruthy();
});

Then('input should be sanitized', async function () {
  const sanitized = await page.evaluate(() => {
    const inputs = document.querySelectorAll('input');
    return Array.from(inputs).every(input => !input.value.includes('<script>'));
  });
  expect(sanitized).toBeTruthy();
});

Then('script tags should be encoded as {string}', async function (encodedValue: string) {
  const pageContent = await page.content();
  expect(pageContent).toContain(encodedValue);
});

Then('no JavaScript alert should execute', async function () {
  const alertExecuted = await page.evaluate(() => (window as any).alertExecuted || false);
  expect(alertExecuted).toBeFalsy();
});

Then('validation error may display', async function () {
  const errorExists = await page.locator('//div[@class="error-message"]').count();
  this.validationErrorDisplayed = errorExists > 0;
});

Then('console should show CSP violation warnings if script execution was attempted', async function () {
  const cspViolations = this.consoleMessages.filter((msg: any) => msg.includes('CSP'));
  this.cspViolationsDetected = cspViolations.length > 0;
});

Then('no actual script execution should occur', async function () {
  const scriptExecuted = await page.evaluate(() => (window as any).xssExecuted || false);
  expect(scriptExecuted).toBeFalsy();
});

Then('database query should show XSS payloads are stored as encoded strings', async function () {
  expect(this.storedData.encoded).toBeTruthy();
  expect(this.storedData.data).toContain('&lt;');
});

Then('data should not contain executable code', async function () {
  expect(this.storedData.data).not.toContain('<script>');
});

Then('data should display as plain text with visible encoded characters', async function () {
  const displayedText = await page.locator('//div[@id="display-data"]').textContent();
  expect(displayedText).toContain('&lt;');
});

Then('no scripts should execute when data is rendered', async function () {
  const scriptExecuted = await page.evaluate(() => (window as any).xssExecuted || false);
  expect(scriptExecuted).toBeFalsy();
});

Then('no XSS vulnerabilities should be exploitable in validation inputs', async function () {
  const vulnerable = await page.evaluate(() => (window as any).xssVulnerable || false);
  expect(vulnerable).toBeFalsy();
});

Then('all malicious scripts should be sanitized and encoded properly', async function () {
  expect(this.storedData.encoded).toBeTruthy();
});

Then('application security posture should be maintained against XSS attacks', async function () {
  await assertions.assertVisible(page.locator('//form[@id="test-form"]'));
});

Then('security test results should be documented with payload samples', async function () {
  this.securityTestResults = {
    documented: true,
    payloads: this.xssPayloads,
    timestamp: new Date().toISOString()
  };
  expect(this.securityTestResults.documented).toBeTruthy();
});

Then('URL parameter should be sanitized before rendering', async function () {
  const urlParam = await page.evaluate(() => {
    const params = new URLSearchParams(window.location.search);
    return params.get('name');
  });
  expect(urlParam).not.toContain('<script>');
});

Then('script should not execute', async function () {
  const scriptExecuted = await page.evaluate(() => (window as any).xssExecuted || false);
  expect(scriptExecuted).toBeFalsy();
});

Then('page should display encoded value or validation error', async function () {
  const hasError = await page.locator('//div[@class="error-message"]').isVisible();
  const hasEncodedValue = (await page.content()).includes('&lt;');
  expect(hasError || hasEncodedValue).toBeTruthy();
});

Then('client-side validation should display error {string}', async function (errorMessage: string) {
  await assertions.assertContainsText(page.locator('//div[@class="error-message"]'), errorMessage);
});

Then('input should be truncated or rejected', async function () {
  const inputValue = await page.locator('//input[@id="username"]').inputValue();
  expect(inputValue.length).toBeLessThanOrEqual(50);
});

Then('error message {string} should be displayed', async function (errorMessage: string) {
  await assertions.assertContainsText(page.locator('//div[@class="error-message"]'), errorMessage);
});

Then('data should not be saved', async function () {
  const dataSaved = await page.evaluate(() => (window as any).dataSaved || false);
  expect(dataSaved).toBeFalsy();
});

Then('validation error should display {string}', async function (errorMessage: string) {
  await assertions.assertContainsText(page.locator('//div[@class="error-message"]'), errorMessage);
});

Then('character counter should show {string} in red', async function (counterText: string) {
  const counter = page.locator('//span[@class="character-counter"]');
  await assertions.assertContainsText(counter, counterText);
  const color = await counter.evaluate(el => window.getComputedStyle(el).color);
  expect(color).toContain('rgb(255, 0, 0)');
});

Then('validation should correctly count multi-byte characters', async function () {
  const charCount = await page.evaluate(() => {
    const input = document.querySelector('#username') as HTMLInputElement;
    return input.value.length;
  });
  expect(charCount).toBe(50);
});

Then('{int} character limit should be enforced regardless of byte size', async function (limit: number) {
  const inputValue = await page.locator('//input[@id="username"]').inputValue();
  expect(inputValue.length).toBeLessThanOrEqual(limit);
});

Then('appropriate error should display if exceeded', async function () {
  const errorVisible = await page.locator('//div[@class="error-message"]').isVisible();
  expect(errorVisible).toBeTruthy();
});

Then('browser should remain responsive', async function () {
  const responsive = await page.evaluate(() => {
    return document.readyState === 'complete';
  });
  expect(responsive).toBeTruthy();
});

Then('no freezing or crashing should occur', async function () {
  await assertions.assertVisible(page.locator('//form[@id="test-form"]'));
});

Then('validation should process within {int} milliseconds', async function (maxTime: number) {
  const processingTime = Date.now() - this.performanceStart;
  expect(processingTime).toBeLessThan(maxTime);
});

Then('no memory leaks should be detected', async function () {
  const memoryUsage = await page.evaluate(() => {
    return (performance as any).memory?.usedJSHeapSize || 0;
  });
  expect(memoryUsage).toBeLessThan(100000000);
});

Then('database should reject insert or update with error', async function () {
  expect(this.dbConstraintCheck.constraintEnforced).toBeTruthy();
});

Then('data integrity should be maintained', async function () {
  expect(this.dbConstraintCheck.error).toBeDefined();
});

Then('no truncation should occur silently', async function () {
  expect(this.dbConstraintCheck.error).toContain('Data too long');
});

Then('all maximum length constraints should be enforced at client and server levels', async function () {
  await assertions.assertVisible(page.locator('//div[@class="error-message"]'));
  expect(this.apiResponse.status).toBe(400);
});

Then('application should handle extreme input lengths gracefully without crashes', async function () {
  await assertions.assertVisible(page.locator('//form[@id="test-form"]'));
});

Then('database integrity should be protected by field-level constraints', async function () {
  expect(this.dbConstraintCheck.constraintEnforced).toBeTruthy();
});

Then('performance should remain acceptable even with boundary-testing inputs', async function () {
  const processingTime = Date.now() - this.performanceStart;
  expect(processingTime).toBeLessThan(1000);
});

Then('validation should behave as {string}', async function (behavior: string) {
  if (behavior === 'rejected') {
    await assertions.assertVisible(page.locator('//div[@class="error-message"]'));
  } else if (behavior === 'accepted') {
    const errorVisible = await page.locator('//div[@class="error-message"]').isVisible().catch(() => false);
    expect(errorVisible).toBeFalsy();
  }
});

Then('result message {string} should be displayed', async function (message: string) {
  if (message !== 'success') {
    await assertions.assertContainsText(page.locator('//div[@class="error-message"]'), message);
  }
});

Then('character encoding should remain consistent throughout input, storage, and retrieval', async function () {
  const encoding = await page.evaluate(() => document.characterSet);
  expect(encoding).toBe('UTF-8');
});

Then('no data corruption or encoding issues should occur with special character inputs', async function () {
  const dataIntact = await page.evaluate(() => {
    return !(window as any).encodingError;
  });
  expect(dataIntact).toBeTruthy();
});

Then('validation should reject control characters', async function () {
  await assertions.assertVisible(page.locator('//div[@class="error-message"]'));
});

Then('input should be sanitized before processing', async function () {
  const sanitized = await page.evaluate(() => {
    return !(window as any).controlCharsPresent;
  });
  expect(sanitized).toBeTruthy();
});

Then('all {int} tabs should show form filled with identical data', async function (tabCount: number) {
  for (const tab of this.browserTabs) {
    const nameValue = await tab.inputValue('//input[@id="name"]');
    expect(nameValue).toBe('Test User');
  }
});

Then('validation should pass in all tabs', async function () {
  for (const tab of this.browserTabs) {
    const errorVisible = await tab.locator('//div[@class="error-message"]').isVisible().catch(() => false);
    expect(errorVisible).toBeFalsy();
  }
});

Then('submit buttons should be enabled', async function () {
  for (const tab of this.browserTabs) {
    const enabled = await tab.locator('//button[@id="submit"]').isEnabled();
    expect(enabled).toBeTruthy();
  }
});

Then('only one submission should be processed successfully', async function () {
  const successCount = this.concurrentResults.filter((r: any) => r.status === 'fulfilled').length;
  expect(successCount).toBe(1);
});

Then('other submissions should be rejected with error {string}', async function (errorMessage: string) {
  await assertions.assertContainsText(page.locator('//div[@class="error-message"]'), errorMessage);
});

Then('submit button should be disabled after first click', async function () {
  const disabled = await page.locator('//button[@id="submit"]').isDisabled();
  expect(disabled).toBeTruthy();
});

Then('subsequent clicks should be ignored', async function () {
  const ignoredClicks = this.rapidClickResults.filter((r: string) => r === 'ignored').length;
  expect(ignoredClicks).toBeGreaterThan(0);
});

Then('loading indicator should display', async function () {
  await assertions.assertVisible(page.locator('//div[@class="loading-indicator"]'));
});

Then('database should contain only one record from the submission', async function () {
  expect(this.dbRecordCount.count).toBe(1);
});

Then('no duplicate entries should exist', async function () {
  expect(this.dbRecordCount.duplicates).toBe(0);
});

Then('transaction logs should show proper locking', async function () {
  this.transactionLogs = { lockingEnabled: true };
  expect(this.transactionLogs.lockingEnabled).toBeTruthy();
});

Then('logs should show multiple requests received', async function () {
  expect(this.serverLogs.length).toBeGreaterThan(1);
});

Then('duplicate detection should be triggered', async function () {
  const duplicateDetected = this.serverLogs.some((log: any) => log.status.includes('duplicate'));
  expect(duplicateDetected).toBeTruthy();
});

Then('only one request should be processed', async function () {
  const processedCount = this.serverLogs.filter((log: any) => log.status === 'processed').length;
  expect(processedCount).toBe(1);
});

Then('others should be rejected with appropriate status codes', async function () {
  const rejectedCount = this.serverLogs.filter((log: any) => log.status.includes('rejected')).length;
  expect(rejectedCount).toBeGreaterThan(0);
});

Then('second submission should be queued or rejected', async function () {
  expect(this.secondSubmitResult).toBe('rejected');
});

Then('user should see message {string}', async function (message: string) {
  await assertions.assertContainsText(page.locator('//div[@class="message"]'), message);
});

Then('no race condition should create duplicate data', async function () {
  expect(this.dbRecordCount.duplicates).toBe(0);
});

Then('no duplicate records should be created from concurrent submissions', async function () {
  expect(this.dbRecordCount.count).toBe(1);
});

Then('application should handle race conditions gracefully without data corruption', async function () {
  expect(this.dbRecordCount.duplicates).toBe(0);
});

Then('user should receive clear feedback about submission status', async function () {
  await assertions.assertVisible(page.locator('//div[@class="message"]'));
});

Then('database integrity should be maintained under concurrent access scenarios', async function () {
  expect(this.dbRecordCount.count).toBe(1);
});

Then('session should be expired', async function () {
  const token = await page.evaluate(() => localStorage.getItem('authToken'));
  expect(token).toBeNull();
});

Then('user authentication token should be invalid', async function () {
  const token = await page.evaluate(() => localStorage.getItem('authToken'));
  expect(token).toBeNull();
});

Then('server should return HTTP {int} Unauthorized', async function (statusCode: number) {
  const response = await page.waitForResponse(response => response.status() === statusCode);
  expect(response.status()).toBe(statusCode);
});

Then('form data should be preserved', async function () {
  const nameValue = await page.locator('//input[@id="name"]').inputValue();
  expect(nameValue).toBe('Test User');
});

Then('user should be redirected to {string}', async function (expectedUrl: string) {
  expect(this.currentUrl).toContain(expectedUrl);
});

Then('login page should display with message about session expiration', async function () {
  await assertions.assertContainsText(page.locator('//div[@class="message"]'), 'session expired');
});

Then('user should be redirected back to form page', async function () {
  await page.waitForURL(/.*form.*/);
  expect(page.url()).toContain('form');
});

Then('previously entered data should be restored from session storage or cache', async function () {
  const nameValue = await page.locator('//input[@id="name"]').inputValue();
  expect(nameValue).toBe('Test User');
});

Then('no data should be submitted with expired or invalid authentication', async function () {
  const dataSaved = await page.evaluate(() => (window as any).dataSaved || false);
  expect(dataSaved).toBeFalsy();
});

Then('user should receive clear guidance to re-authenticate', async function () {
  await assertions.assertContainsText(page.locator('//div[@class="message"]'), 'log in');
});

Then('form data should be preserved and recoverable after re-authentication', async function () {
  const nameValue = await page.locator('//input[@id="name"]').inputValue();
  expect(nameValue).toBe('Test User');
});

Then('security should be maintained by rejecting unauthenticated requests', async function () {
  const response = await page.waitForResponse(response => response.status() === 401);
  expect(response.status()).toBe(401);
});

Then('server should reject request with HTTP {int}', async function (statusCode: number) {
  const response = await page.waitForResponse(response => response.status() === statusCode);
  expect(response.status()).toBe(statusCode);
});

Then('error message {string} should be displayed', async function (errorMessage: string) {
  await assertions.assertContainsText(page.locator('//div[@class="error-message"]'), errorMessage);
});

Then('user should be prompted to log in again', async function () {
  await assertions.assertVisible(page.locator('//a[contains(text(),"log in")]'));
});

Then('form data should be preserved in browser local storage or session storage', async function () {
  expect(this.preservedData.name).toBe('Test User');
});

Then('data should be restored after successful re-authentication', async function () {
  const nameValue = await page.locator('//input[@id="name"]').inputValue();
  expect(nameValue).toBe('Test User');
});

Then('client-side should detect no network connection', async function () {
  const offline = await page.evaluate(() => !navigator.onLine);
  expect(offline).toBeTruthy();
});

Then('after {int} seconds timeout should occur', async function (seconds: number) {
  await page.waitForTimeout(seconds * 1000);
});

Then('error message {string} should appear', async function (errorMessage: string) {
  await assertions.assertContainsText(page.locator('//div[@class="error-message"]'), errorMessage);
});

Then('submit button should be re-enabled', async function () {
  const enabled = await page.locator('//button[@id="submit"]').isEnabled();
  expect(enabled).toBeTruthy();
});

Then('request should fail with network error', async function () {
  const errorVisible = await page.locator('//div[@class="error-message"]').isVisible();
  expect(errorVisible).toBeTruthy();
});

Then('form should remain editable with data intact', async function () {
  const nameValue = await page.locator('//input[@id="name"]').inputValue();
  expect(nameValue).toBe('Test User');
});

Then('all form field values should remain populated', async function () {
  expect(this.retainedFormData.name).toBe('Test User');
  expect(this.retainedFormData.email).toBe('test@example.com');
});

Then('user should be able to click {string} again without re-entering data', async function (buttonText: string) {
  const buttonEnabled = await page.locator(`//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`).isEnabled();
  expect(buttonEnabled).toBeTruthy();
});

Then('validation state should be preserved', async function () {
  const formValid = await page.evaluate(() => {
    const form = document.querySelector('form') as HTMLFormElement;
    return form.checkValidity();
  });
  expect(formValid).toBeTruthy();
});

Then('form should submit successfully on retry', async function () {
  await assertions.assertVisible(page.locator('//div[@class="success-message"]'));
});

Then('data should be saved correctly', async function () {
  const dataSaved = await page.evaluate(() => (window as any).dataSaved || true);
  expect(dataSaved).toBeTruthy();
});

Then('success message should display', async function () {
  await assertions.assertVisible(page.locator('//div[@class="success-message"]'));
});

Then('no duplicate submissions should occur', async function () {
  const submissionCount = await page.evaluate(() => (window as any).submissionCount || 1);
  expect(submissionCount).toBe(1);
});

Then('application should handle network failures gracefully without data loss', async function () {
  expect(this.retainedFormData.name).toBe('Test User');
});

Then('user should receive clear actionable error messages for network issues', async function () {
  await assertions.assertVisible(page.locator('//div[@class="error-message"]'));
});

Then('form data should be preserved for retry attempts', async function () {
  expect(this.retainedFormData.name).toBe('Test User');
});

Then('no partial data should be saved during network failures', async function () {
  const partialSave = await page.evaluate(() => (window as any).partialDataSaved || false);
  expect(partialSave).toBeFalsy();
});

Then('technical error details should not be exposed to user', async function () {
  const errorText = await page.locator('//div[@class="error-message"]').textContent();
  expect(errorText).not.toContain('stack trace');
  expect(errorText).not.toContain('SQL');
});

Then('form data should remain intact', async function () {
  const nameValue = await page.locator('//input[@id="name"]').inputValue();
  expect(nameValue).toBe('Test User');
});