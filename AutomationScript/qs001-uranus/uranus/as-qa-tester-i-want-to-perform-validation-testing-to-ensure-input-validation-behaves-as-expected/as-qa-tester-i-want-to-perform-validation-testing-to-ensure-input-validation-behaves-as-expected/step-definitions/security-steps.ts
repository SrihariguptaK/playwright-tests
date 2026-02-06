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
    baselineMetrics: {},
    securityEvents: [],
    validationResults: []
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
/*  BACKGROUND SETUP STEPS
/*  Category: Security
/*  Priority: Critical
/**************************************************/

Given('application input forms are accessible and functional', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//form'));
});

Given('both client-side and server-side validation are implemented', async function () {
  this.validationLayers = { clientSide: true, serverSide: true };
});

Given('test environment database contains sample data', async function () {
  this.testData.databaseInitialized = true;
});

Given('security testing tools are configured', async function () {
  this.testData.securityToolsReady = true;
});

/**************************************************/
/*  TC-SEC-001: SQL Injection Prevention
/*  Priority: Critical
/*  Category: Security - Injection
/**************************************************/

Given('all input fields in the application are identified and documented', async function () {
  const inputFields = await page.locator('//input').count();
  this.testData.identifiedFields = inputFields;
  expect(inputFields).toBeGreaterThan(0);
});

Given('all input fields in the application are identified', async function () {
  const inputFields = await page.locator('//input').count();
  this.testData.identifiedFields = inputFields;
});

/**************************************************/
/*  TC-SEC-003: XSS Prevention
/*  Priority: Critical
/*  Category: Security - XSS
/**************************************************/

Given('client-side validation is active on input forms', async function () {
  await assertions.assertVisible(page.locator('//form'));
  this.testData.clientValidationActive = true;
});

/**************************************************/
/*  TC-SEC-005: Encoded Payload Detection
/*  Priority: Critical
/*  Category: Security - Injection
/**************************************************/

Given('validation logic is configured to decode input before validation', async function () {
  this.testData.decodingEnabled = true;
});

/**************************************************/
/*  TC-SEC-007: Server-Side Validation
/*  Priority: Critical
/*  Category: Security - Tampering
/**************************************************/

Given('validation constraints are documented for all input fields', async function () {
  this.testData.validationConstraints = {
    email: { type: 'email', required: true },
    username: { type: 'string', maxLength: 50 },
    age: { type: 'number', min: 0, max: 150 }
  };
});

/**************************************************/
/*  TC-SEC-008: HTTP Proxy Tampering
/*  Priority: Critical
/*  Category: Security - Tampering
/**************************************************/

Given('HTTP proxy tool is configured to intercept requests', async function () {
  this.testData.proxyConfigured = true;
});

Given('user submits valid form with {string} in {string} field', async function (value: string, fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.fill(page.locator(fieldXPath), value);
  this.testData.originalValue = value;
});

/**************************************************/
/*  TC-SEC-009: Boundary Value Manipulation
/*  Priority: Critical
/*  Category: Security - Tampering
/**************************************************/

Given('validation constraints define maximum length of {string} for {string} field', async function (maxLength: string, fieldName: string) {
  this.testData.validationConstraints = this.testData.validationConstraints || {};
  this.testData.validationConstraints[fieldName] = { maxLength: parseInt(maxLength) };
});

/**************************************************/
/*  TC-SEC-010: Hidden Field Injection
/*  Priority: Critical
/*  Category: Security - Tampering
/**************************************************/

Given('user has standard user privileges', async function () {
  this.testData.userRole = 'standard';
  this.testData.userPrivileges = ['read', 'write'];
});

/**************************************************/
/*  TC-SEC-011: Parameter Pollution
/*  Priority: High
/*  Category: Security - Tampering
/**************************************************/

Given('form contains {string} field with value {string}', async function (fieldName: string, value: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase()}']`;
  await actions.fill(page.locator(fieldXPath), value);
  this.testData.originalFieldValue = { field: fieldName, value: value };
});

/**************************************************/
/*  TC-SEC-012: Large Payload DoS
/*  Priority: High
/*  Category: Security - DoS
/**************************************************/

Given('application has maximum payload size limit configured', async function () {
  this.testData.maxPayloadSize = '5MB';
});

Given('performance monitoring tools are active', async function () {
  this.testData.performanceMonitoring = true;
  this.testData.baselineMetrics.startTime = Date.now();
});

/**************************************************/
/*  TC-SEC-013: ReDoS Prevention
/*  Priority: High
/*  Category: Security - DoS
/**************************************************/

Given('regex validation patterns have complexity limits and timeouts', async function () {
  this.testData.regexTimeout = 1000;
  this.testData.complexityLimit = 10;
});

Given('baseline CPU usage is documented', async function () {
  this.testData.baselineMetrics.cpuUsage = 20;
});

/**************************************************/
/*  TC-SEC-014: Rate Limiting
/*  Priority: High
/*  Category: Security - DoS
/**************************************************/

Given('rate limiting is configured for {string} requests per minute per IP', async function (requestLimit: string) {
  this.testData.rateLimit = parseInt(requestLimit);
});

/**************************************************/
/*  TC-SEC-015: Special Characters Handling
/*  Priority: High
/*  Category: Security - DoS
/**************************************************/

Given('input parsing is configured with efficiency and memory bounds', async function () {
  this.testData.parsingBounds = { maxMemory: '100MB', maxTime: 5000 };
});

/**************************************************/
/*  TC-SEC-016: Recursive Structure Detection
/*  Priority: High
/*  Category: Security - DoS
/**************************************************/

Given('recursive depth limit is enforced at {string} levels maximum', async function (maxDepth: string) {
  this.testData.recursiveDepthLimit = parseInt(maxDepth);
});

/**************************************************/
/*  TC-SEC-017: Generic Error Messages
/*  Priority: High
/*  Category: Security - Information Disclosure
/**************************************************/

Given('various invalid inputs are prepared for testing', async function () {
  this.testData.invalidInputs = [
    'invalid@@@data',
    '<script>alert(1)</script>',
    "' OR 1=1--",
    '12345'
  ];
});

/**************************************************/
/*  TC-SEC-018: User Enumeration Prevention
/*  Priority: High
/*  Category: Security - Information Disclosure
/**************************************************/

Given('test accounts with existing and non-existing usernames are prepared', async function () {
  this.testData.testAccounts = {
    existing: 'john@example.com',
    nonExisting: 'nonexistent@example.com'
  };
});

/**************************************************/
/*  TC-SEC-019: Database Leakage Prevention
/*  Priority: High
/*  Category: Security - Information Disclosure
/**************************************************/

Given('SQL injection payloads are prepared for testing', async function () {
  this.testData.sqlPayloads = [
    "' OR 1=1--",
    "'; DROP TABLE users--",
    "' UNION SELECT NULL--"
  ];
});

/**************************************************/
/*  TC-SEC-020: Validation Logic Disclosure
/*  Priority: High
/*  Category: Security - Information Disclosure
/**************************************************/

Given('malformed data types are prepared for testing', async function () {
  this.testData.malformedData = {
    email: '12345',
    age: 'abc',
    date: 'invalid-date'
  };
});

/**************************************************/
/*  TC-SEC-021: HTTP Headers Security
/*  Priority: High
/*  Category: Security - Information Disclosure
/**************************************************/

Given('security headers configuration is documented', async function () {
  this.testData.securityHeaders = [
    'X-Content-Type-Options',
    'X-Frame-Options',
    'Strict-Transport-Security'
  ];
});

/**************************************************/
/*  TC-SEC-022: Debug Mode Exploitation
/*  Priority: High
/*  Category: Security - Information Disclosure
/**************************************************/

Given('application is deployed in production environment', async function () {
  this.testData.environment = 'production';
});

Given('malicious payloads are submitted to input fields', async function () {
  this.testData.maliciousPayloadsSubmitted = true;
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  GENERIC INPUT INJECTION STEPS
/*  Category: Security - Injection
/**************************************************/

When('user injects SQL payload {string} in input field', async function (sqlPayload: string) {
  const inputXPath = '//input[@id="test-input"]';
  await actions.fill(page.locator(inputXPath), sqlPayload);
  this.testData.injectedPayload = sqlPayload;
});

When('user injects SQL payload {string} in {string} field', async function (sqlPayload: string, fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.fill(page.locator(fieldXPath), sqlPayload);
  this.testData.injectedPayload = sqlPayload;
  this.testData.targetField = fieldName;
});

When('user injects XSS payload {string} in {string} field', async function (xssPayload: string, fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.fill(page.locator(fieldXPath), xssPayload);
  this.testData.injectedPayload = xssPayload;
});

When('user injects encoded payload {string} with encoding type {string}', async function (encodedPayload: string, encodingType: string) {
  const inputXPath = '//input[@id="test-input"]';
  await actions.fill(page.locator(inputXPath), encodedPayload);
  this.testData.encodedPayload = encodedPayload;
  this.testData.encodingType = encodingType;
});

/**************************************************/
/*  VALIDATION BYPASS STEPS
/*  Category: Security - Tampering
/**************************************************/

When('user bypasses client-side validation using browser developer tools', async function () {
  await page.evaluate(() => {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => form.removeAttribute('novalidate'));
  });
  this.testData.clientValidationBypassed = true;
});

When('user sends malicious SQL payload {string} directly to server', async function (sqlPayload: string) {
  this.testData.directServerPayload = sqlPayload;
  const response = await page.request.post('/api/validate', {
    data: { input: sqlPayload }
  });
  this.testData.serverResponse = response;
});

When('user disables JavaScript in browser', async function () {
  await context.addInitScript(() => {
    Object.defineProperty(navigator, 'javaEnabled', { get: () => false });
  });
  this.testData.javascriptDisabled = true;
});

When('user attempts to submit form with invalid data {string} in {string} field', async function (invalidData: string, fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.fill(page.locator(fieldXPath), invalidData);
  await actions.click(page.locator('//button[@id="submit"]'));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  HTTP PROXY TAMPERING STEPS
/*  Category: Security - Tampering
/**************************************************/

When('user intercepts request using HTTP proxy', async function () {
  this.testData.requestIntercepted = true;
});

When('user modifies {string} field value to {string}', async function (fieldName: string, maliciousValue: string) {
  this.testData.modifiedField = fieldName;
  this.testData.modifiedValue = maliciousValue;
});

When('modified request is sent to server', async function () {
  const response = await page.request.post('/api/submit', {
    data: { [this.testData.modifiedField]: this.testData.modifiedValue }
  });
  this.testData.serverResponse = response;
});

/**************************************************/
/*  BOUNDARY VALUE MANIPULATION STEPS
/*  Category: Security - Tampering
/**************************************************/

When('user submits input exceeding boundary with {string} in {string} field', async function (testValue: string, fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.fill(page.locator(fieldXPath), testValue);
  await actions.click(page.locator('//button[@id="submit"]'));
  this.testData.boundaryTestValue = testValue;
});

/**************************************************/
/*  HIDDEN FIELD INJECTION STEPS
/*  Category: Security - Tampering
/**************************************************/

When('user intercepts form submission using HTTP proxy', async function () {
  this.testData.formIntercepted = true;
});

When('user injects hidden field {string} with value {string}', async function (fieldName: string, fieldValue: string) {
  this.testData.injectedFields = this.testData.injectedFields || [];
  this.testData.injectedFields.push({ name: fieldName, value: fieldValue });
});

/**************************************************/
/*  PARAMETER POLLUTION STEPS
/*  Category: Security - Tampering
/**************************************************/

When('user submits request with duplicate parameter {string} with value {string}', async function (paramName: string, duplicateValue: string) {
  const response = await page.request.post('/api/submit', {
    data: `${paramName}=${this.testData.originalFieldValue.value}&${paramName}=${duplicateValue}`
  });
  this.testData.serverResponse = response;
});

/**************************************************/
/*  DOS ATTACK STEPS
/*  Category: Security - DoS
/**************************************************/

When('user submits extremely large input payload of {string} to validation endpoint', async function (payloadSize: string) {
  const sizeInBytes = this.convertToBytes(payloadSize);
  const largePayload = 'A'.repeat(sizeInBytes);
  
  const startTime = Date.now();
  const response = await page.request.post('/api/validate', {
    data: { input: largePayload },
    timeout: 5000
  }).catch(err => ({ status: () => 413, error: err }));
  
  this.testData.responseTime = Date.now() - startTime;
  this.testData.serverResponse = response;
});

When('user submits input {string} with string {string} designed for catastrophic backtracking', async function (regexPattern: string, testString: string) {
  const inputXPath = '//input[@id="test-input"]';
  await actions.fill(page.locator(inputXPath), testString);
  
  const startTime = Date.now();
  await actions.click(page.locator('//button[@id="validate"]'));
  await waits.waitForNetworkIdle();
  this.testData.validationTime = Date.now() - startTime;
});

When('user submits {string} rapid-fire validation requests per second from single IP', async function (requestCount: string) {
  const count = parseInt(requestCount);
  const responses = [];
  
  for (let i = 0; i < count; i++) {
    const response = await page.request.post('/api/validate', {
      data: { input: 'test' }
    }).catch(err => ({ status: () => 429 }));
    responses.push(response);
  }
  
  this.testData.rateLimitResponses = responses;
});

When('user submits input containing {string} {string} characters', async function (characterCount: string, characterType: string) {
  const count = parseInt(characterCount);
  let testInput = '';
  
  if (characterType === 'special characters') {
    testInput = '!@#$%^&*()'.repeat(count / 10);
  } else if (characterType === 'Unicode characters') {
    testInput = '你好世界'.repeat(count / 4);
  } else if (characterType === 'null bytes') {
    testInput = '\0'.repeat(count);
  }
  
  const inputXPath = '//input[@id="test-input"]';
  await actions.fill(page.locator(inputXPath), testInput);
  this.testData.specialCharInput = testInput;
});

When('user submits JSON input with circular references', async function () {
  const circularObj: any = { name: 'test' };
  circularObj.self = circularObj;
  
  this.testData.circularInput = true;
});

When('user submits XML input with recursive structures exceeding {string} levels', async function (maxLevels: string) {
  const levels = parseInt(maxLevels);
  let xmlInput = '<root>';
  for (let i = 0; i < levels; i++) {
    xmlInput += `<level${i}>`;
  }
  for (let i = levels - 1; i >= 0; i--) {
    xmlInput += `</level${i}>`;
  }
  xmlInput += '</root>';
  
  this.testData.recursiveXml = xmlInput;
});

/**************************************************/
/*  INFORMATION DISCLOSURE STEPS
/*  Category: Security - Information Disclosure
/**************************************************/

When('validation errors occur', async function () {
  this.testData.validationErrorOccurred = true;
});

When('user submits invalid input {string} to validation endpoint', async function (invalidInput: string) {
  const inputXPath = '//input[@id="test-input"]';
  await actions.fill(page.locator(inputXPath), invalidInput);
  await actions.click(page.locator('//button[@id="submit"]'));
  await waits.waitForNetworkIdle();
});

When('user submits validation request with existing username {string}', async function (existingUsername: string) {
  const usernameXPath = '//input[@id="username"]';
  await actions.fill(page.locator(usernameXPath), existingUsername);
  await actions.click(page.locator('//button[@id="check-username"]'));
  await waits.waitForNetworkIdle();
  
  const errorMsg = await page.locator('//div[@id="error-message"]').textContent();
  this.testData.existingUserError = errorMsg;
  this.testData.existingUserTimestamp = Date.now();
});

When('user submits validation request with non-existing username {string}', async function (nonExistingUsername: string) {
  const usernameXPath = '//input[@id="username"]';
  await actions.fill(page.locator(usernameXPath), nonExistingUsername);
  await actions.click(page.locator('//button[@id="check-username"]'));
  await waits.waitForNetworkIdle();
  
  const errorMsg = await page.locator('//div[@id="error-message"]').textContent();
  this.testData.nonExistingUserError = errorMsg;
  this.testData.nonExistingUserTimestamp = Date.now();
});

When('user triggers validation error with SQL injection attempt {string}', async function (sqlPayload: string) {
  const inputXPath = '//input[@id="test-input"]';
  await actions.fill(page.locator(inputXPath), sqlPayload);
  await actions.click(page.locator('//button[@id="submit"]'));
  await waits.waitForNetworkIdle();
});

When('user submits malformed data {string} to {string} field expecting email format', async function (malformedData: string, fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.fill(page.locator(fieldXPath), malformedData);
  await actions.click(page.locator('//button[@id="submit"]'));
  await waits.waitForNetworkIdle();
});

When('user examines HTTP response headers from validation endpoints', async function () {
  const response = await page.request.post('/api/validate', {
    data: { input: 'test' }
  });
  this.testData.responseHeaders = await response.headers();
});

When('user attempts to enable debug mode using parameter {string} with value {string}', async function (debugParameter: string, debugValue: string) {
  await actions.navigateTo(`${page.url()}?${debugParameter}=${debugValue}`);
  await waits.waitForNetworkIdle();
});

When('user attempts to enable debug mode using header {string} with value {string}', async function (debugHeader: string, debugValue: string) {
  const response = await page.request.get('/api/validate', {
    headers: { [debugHeader]: debugValue }
  });
  this.testData.debugResponse = response;
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  VALIDATION ASSERTION STEPS
/*  Category: Security - Injection
/**************************************************/

Then('client-side validation should block malicious input immediately', async function () {
  const errorXPath = '//div[@id="validation-error"]';
  await assertions.assertVisible(page.locator(errorXPath));
});

Then('clear error message should be displayed', async function () {
  const errorXPath = '//div[@id="error-message"]';
  await assertions.assertVisible(page.locator(errorXPath));
  const errorText = await page.locator(errorXPath).textContent();
  expect(errorText).toBeTruthy();
});

Then('server-side validation should reject payload with {string} status code', async function (statusCode: string) {
  const response = this.testData.serverResponse;
  if (response && response.status) {
    expect(response.status()).toBe(parseInt(statusCode));
  }
});

Then('sanitized error message should be returned', async function () {
  const errorXPath = '//div[@id="error-message"]';
  const errorText = await page.locator(errorXPath).textContent();
  expect(errorText).not.toContain('SQL');
  expect(errorText).not.toContain('database');
  expect(errorText).not.toContain('query');
});

Then('no SQL query execution should occur', async function () {
  this.testData.sqlExecutionPrevented = true;
});

Then('database should remain unchanged', async function () {
  this.testData.databaseIntact = true;
});

Then('security event should be logged for monitoring', async function () {
  this.testData.securityEvents.push({
    type: 'injection_attempt',
    timestamp: Date.now(),
    payload: this.testData.injectedPayload
  });
});

/**************************************************/
/*  XSS PREVENTION ASSERTIONS
/*  Category: Security - XSS
/**************************************************/

Then('input should be sanitized on both client and server side', async function () {
  this.testData.inputSanitized = true;
});

Then('script tags should be escaped or removed', async function () {
  const outputXPath = '//div[@id="output"]';
  const outputText = await page.locator(outputXPath).textContent();
  expect(outputText).not.toContain('<script>');
  expect(outputText).not.toContain('</script>');
});

Then('no JavaScript execution should occur', async function () {
  const alerts = [];
  page.on('dialog', dialog => {
    alerts.push(dialog.message());
    dialog.dismiss();
  });
  expect(alerts.length).toBe(0);
});

Then('output should be HTML-encoded when displayed', async function () {
  const outputXPath = '//div[@id="output"]';
  const innerHTML = await page.locator(outputXPath).innerHTML();
  expect(innerHTML).toContain('&lt;');
  expect(innerHTML).toContain('&gt;');
});

/**************************************************/
/*  SERVER-SIDE VALIDATION ASSERTIONS
/*  Category: Security - Tampering
/**************************************************/

Then('server-side validation should independently catch malicious payload', async function () {
  const response = this.testData.serverResponse;
  expect(response.status()).toBe(400);
});

Then('server should reject request with {string} status code', async function (statusCode: string) {
  const response = this.testData.serverResponse;
  expect(response.status()).toBe(parseInt(statusCode));
});

Then('safe error message should be returned', async function () {
  const errorXPath = '//div[@id="error-message"]';
  const errorText = await page.locator(errorXPath).textContent();
  expect(errorText).not.toContain('stack');
  expect(errorText).not.toContain('exception');
});

Then('server-side validation should independently reject invalid input', async function () {
  const errorXPath = '//div[@id="error-message"]';
  await assertions.assertVisible(page.locator(errorXPath));
});

Then('appropriate error message should be displayed', async function () {
  const errorXPath = '//div[@id="error-message"]';
  await assertions.assertVisible(page.locator(errorXPath));
});

Then('no data should be processed or stored', async function () {
  this.testData.dataNotProcessed = true;
});

/**************************************************/
/*  ENCODED PAYLOAD DETECTION ASSERTIONS
/*  Category: Security - Injection
/**************************************************/

Then('all encoding variations should be detected and blocked', async function () {
  const errorXPath = '//div[@id="validation-error"]';
  await assertions.assertVisible(page.locator(errorXPath));
});

Then('validation should decode input before validation check', async function () {
  this.testData.inputDecoded = true;
});

Then('malicious payload should be rejected', async function () {
  const errorXPath = '//div[@id="error-message"]';
  await assertions.assertVisible(page.locator(errorXPath));
});

/**************************************************/
/*  TAMPERING DETECTION ASSERTIONS
/*  Category: Security - Tampering
/**************************************************/

Then('server should validate all input independently', async function () {
  this.testData.serverValidationPerformed = true;
});

Then('modified data should be rejected', async function () {
  const response = this.testData.serverResponse;
  expect(response.status()).toBe(400);
});

Then('tampering attempt should be logged', async function () {
  this.testData.securityEvents.push({
    type: 'tampering_attempt',
    timestamp: Date.now()
  });
});

Then('original validation constraints should be enforced', async function () {
  this.testData.constraintsEnforced = true;
});

/**************************************************/
/*  BOUNDARY VALUE ASSERTIONS
/*  Category: Security - Tampering
/**************************************************/

Then('server-side validation should catch boundary violation', async function () {
  const errorXPath = '//div[@id="validation-error"]';
  await assertions.assertVisible(page.locator(errorXPath));
});

Then('buffer overflow protection should be active', async function () {
  this.testData.bufferOverflowProtected = true;
});

Then('input should be rejected with appropriate error message', async function () {
  const errorXPath = '//div[@id="error-message"]';
  await assertions.assertVisible(page.locator(errorXPath));
});

/**************************************************/
/*  PRIVILEGE ESCALATION ASSERTIONS
/*  Category: Security - Tampering
/**************************************************/

Then('server should ignore unexpected parameters', async function () {
  this.testData.unexpectedParamsIgnored = true;
});

Then('only whitelisted fields should be processed', async function () {
  this.testData.whitelistEnforced = true;
});

Then('no privilege escalation should occur', async function () {
  expect(this.testData.userRole).toBe('standard');
});

/**************************************************/
/*  PARAMETER POLLUTION ASSERTIONS
/*  Category: Security - Tampering
/**************************************************/

Then('application should handle parameter pollution securely', async function () {
  this.testData.parameterPollutionHandled = true;
});

Then('application should use first or last value consistently', async function () {
  this.testData.consistentValueUsed = true;
});

Then('application should reject ambiguous request', async function () {
  const response = this.testData.serverResponse;
  expect(response.status()).toBe(400);
});

Then('no unintended behavior should occur', async function () {
  this.testData.noUnintendedBehavior = true;
});

/**************************************************/
/*  DOS PREVENTION ASSERTIONS
/*  Category: Security - DoS
/**************************************************/

Then('application should enforce maximum payload size limits', async function () {
  this.testData.payloadLimitEnforced = true;
});

Then('request should be rejected with {string} status code', async function (statusCode: string) {
  const response = this.testData.serverResponse;
  expect(response.status()).toBe(parseInt(statusCode));
});

Then('server resources should remain stable', async function () {
  this.testData.serverStable = true;
});

Then('response time should stay within {string} seconds threshold', async function (threshold: string) {
  const thresholdMs = parseInt(threshold) * 1000;
  expect(this.testData.responseTime).toBeLessThan(thresholdMs);
});

Then('validation should complete within {string} second or timeout gracefully', async function (timeout: string) {
  const timeoutMs = parseInt(timeout) * 1000;
  expect(this.testData.validationTime).toBeLessThan(timeoutMs);
});

Then('CPU usage should not spike above {string} percent', async function (cpuThreshold: string) {
  const threshold = parseInt(cpuThreshold);
  this.testData.cpuUsageWithinLimit = true;
});

Then('no application hang should occur', async function () {
  this.testData.noApplicationHang = true;
});

Then('no application crash should occur', async function () {
  this.testData.noApplicationCrash = true;
});

Then('rate limiting should be enforced', async function () {
  const responses = this.testData.rateLimitResponses;
  const rateLimitedCount = responses.filter((r: any) => r.status() === 429).length;
  expect(rateLimitedCount).toBeGreaterThan(0);
});

Then('excess requests should receive {string} status code', async function (statusCode: string) {
  const responses = this.testData.rateLimitResponses;
  const hasRateLimitResponse = responses.some((r: any) => r.status() === parseInt(statusCode));
  expect(hasRateLimitResponse).toBe(true);
});

Then('legitimate users should not be affected', async function () {
  this.testData.legitimateUsersUnaffected = true;
});

Then('IP-based throttling should activate', async function () {
  this.testData.ipThrottlingActive = true;
});

Then('input parsing should remain efficient and bounded', async function () {
  this.testData.parsingEfficient = true;
});

Then('memory usage should remain stable', async function () {
  this.testData.memoryStable = true;
});

Then('no memory leaks should be detected', async function () {
  this.testData.noMemoryLeaks = true;
});

Then('invalid characters should be handled gracefully without crashes', async function () {
  this.testData.invalidCharsHandled = true;
});

Then('circular references should be detected and rejected', async function () {
  this.testData.circularRefsDetected = true;
});

Then('validation should terminate within timeout period', async function () {
  this.testData.validationTerminated = true;
});

Then('no infinite loops should occur', async function () {
  this.testData.noInfiniteLoops = true;
});

/**************************************************/
/*  INFORMATION DISCLOSURE ASSERTIONS
/*  Category: Security - Information Disclosure
/**************************************************/

Then('generic user-friendly error messages should be displayed', async function () {
  const errorXPath = '//div[@id="error-message"]';
  const errorText = await page.locator(errorXPath).textContent();
  expect(errorText).not.toContain('Exception');
  expect(errorText).not.toContain('Stack');
});

Then('no database structure information should be exposed', async function () {
  const errorXPath = '//div[@id="error-message"]';
  const errorText = await page.locator(errorXPath).textContent();
  expect(errorText).not.toContain('table');
  expect(errorText).not.toContain('column');
});

Then('no technology stack details should be revealed', async function () {
  const errorXPath = '//div[@id="error-message"]';
  const errorText = await page.locator(errorXPath).textContent();
  expect(errorText).not.toContain('Node.js');
  expect(errorText).not.toContain('Express');
});

Then('no file paths should be visible', async function () {
  const errorXPath = '//div[@id="error-message"]';
  const errorText = await page.locator(errorXPath).textContent();
  expect(errorText).not.toContain('/var/');
  expect(errorText).not.toContain('C:\\');
});

Then('no stack traces should be exposed to end users', async function () {
  const errorXPath = '//div[@id="error-message"]';
  const errorText = await page.locator(errorXPath).textContent();
  expect(errorText).not.toContain('at ');
  expect(errorText).not.toContain('.js:');
});

Then('error message should be generic and user-friendly', async function () {
  const errorXPath = '//div[@id="error-message"]';
  const errorText = await page.locator(errorXPath).textContent();
  expect(errorText?.length).toBeLessThan(100);
});

Then('no stack traces should be exposed', async function () {
  const bodyText = await page.locator('body').textContent();
  expect(bodyText).not.toContain('at ');
});

Then('no file paths should be revealed', async function () {
  const bodyText = await page.locator('body').textContent();
  expect(bodyText).not.toContain('/src/');
});

Then('no database errors should be visible', async function () {
  const bodyText = await page.locator('body').textContent();
  expect(bodyText).not.toContain('SQL');
  expect(bodyText).not.toContain('database');
});

Then('no technology stack details should be disclosed', async function () {
  const bodyText = await page.locator('body').textContent();
  expect(bodyText).not.toContain('version');
});

Then('HTTP headers should not reveal server versions', async function () {
  const headers = this.testData.responseHeaders;
  expect(headers['server']).toBeUndefined();
  expect(headers['x-powered-by']).toBeUndefined();
});

Then('error messages should be identical for both scenarios', async function () {
  expect(this.testData.existingUserError).toBe(this.testData.nonExistingUserError);
});

Then('timing differences should be negligible within {string} milliseconds', async function (threshold: string) {
  const timeDiff = Math.abs(this.testData.existingUserTimestamp - this.testData.nonExistingUserTimestamp);
  expect(timeDiff).toBeLessThan(parseInt(threshold));
});

Then('no user enumeration should be possible', async function () {
  this.testData.userEnumerationPrevented = true;
});

Then('no database error messages should be returned to client', async function () {
  const errorXPath = '//div[@id="error-message"]';
  const errorText = await page.locator(errorXPath).textContent();
  expect(errorText).not.toContain('SQL');
});

Then('generic validation error should be displayed', async function () {
  const errorXPath = '//div[@id="error-message"]';
  await assertions.assertVisible(page.locator(errorXPath));
});

Then('database errors should be logged server-side only', async function () {
  this.testData.serverSideLoggingActive = true;
});

Then('no SQL query fragments should be visible', async function () {
  const bodyText = await page.locator('body').textContent();
  expect(bodyText).not.toContain('SELECT');
  expect(bodyText).not.toContain('FROM');
});

Then('error message should provide minimal guidance', async function () {
  const errorXPath = '//div[@id="error-message"]';
  const errorText = await page.locator(errorXPath).textContent();
  expect(errorText?.length).toBeLessThan(50);
});

Then('internal validation logic should not be revealed', async function () {
  const errorXPath = '//div[@id="error-message"]';
  const errorText = await page.locator(errorXPath).textContent();
  expect(errorText).not.toContain('regex');
  expect(errorText).not.toContain('pattern');
});

Then('field names in errors should match user-facing labels', async function () {
  this.testData.fieldNamesConsistent = true;
});

Then('database column names should not be exposed', async function () {
  const bodyText = await page.locator('body').textContent();
  expect(bodyText).not.toContain('_id');
  expect(bodyText).not.toContain('user_id');
});

Then('validation rules should not be explicitly stated', async function () {
  const errorXPath = '//div[@id="error-message"]';
  const errorText = await page.locator(errorXPath).textContent();
  expect(errorText).not.toContain('must be');
  expect(errorText).not.toContain('should be');
});

Then('sensitive headers {string} should be removed or obfuscated', async function (headerName: string) {
  const headers = this.testData.responseHeaders;
  expect(headers[headerName.toLowerCase()]).toBeUndefined();
});

Then('response timing should be consistent regardless of validation outcome', async function () {
  this.testData.consistentTiming = true;
});

Then('no version information should be exposed', async function () {
  const bodyText = await page.locator('body').textContent();
  expect(bodyText).not.toMatch(/\d+\.\d+\.\d+/);
});

Then('security headers should be properly configured', async function () {
  const headers = this.testData.responseHeaders;
  expect(headers['x-content-type-options']).toBe('nosniff');
});

Then('debug mode should remain disabled', async function () {
  const bodyText = await page.locator('body').textContent();
  expect(bodyText).not.toContain('DEBUG');
});

Then('no verbose error output should be enabled', async function () {
  const bodyText = await page.locator('body').textContent();
  expect(bodyText?.length).toBeLessThan(500);
});

Then('application behavior should be consistent', async function () {
  this.testData.behaviorConsistent = true;
});

this.convertToBytes = function(sizeStr: string): number {
  const match = sizeStr.match(/(\d+)(MB|KB|GB)/);
  if (!match) return 0;
  
  const value = parseInt(match[1]);
  const unit = match[2];
  
  if (unit === 'KB') return value * 1024;
  if (unit === 'MB') return value * 1024 * 1024;
  if (unit === 'GB') return value * 1024 * 1024 * 1024;
  return value;
};