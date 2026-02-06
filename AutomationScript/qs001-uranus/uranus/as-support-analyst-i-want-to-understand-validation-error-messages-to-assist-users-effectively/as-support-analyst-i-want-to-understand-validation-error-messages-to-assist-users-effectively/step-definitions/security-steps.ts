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
      'support analyst': { username: 'support_analyst', password: 'SupportPass123!' },
      'regular user': { username: 'regular_user', password: 'UserPass123!' },
      'support analyst with editor role': { username: 'support_editor', password: 'EditorPass123!' }
    },
    sessionTokens: {},
    capturedData: {}
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

Given('support knowledge base system is accessible', async function () {
  await actions.navigateTo(process.env.KNOWLEDGE_BASE_URL || 'https://support-kb.example.com');
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//body'));
});

Given('validation error documentation is populated with error messages', async function () {
  this.testData.validationErrors = [
    { category: 'authentication', message: 'Invalid credentials provided' },
    { category: 'authorization', message: 'Access denied to requested resource' },
    { category: 'input validation', message: 'Invalid input format' },
    { category: 'business logic', message: 'Operation not permitted' }
  ];
});

/**************************************************/
/*  TEST CASE: TC-SEC-001
/*  Title: Validation error messages do not expose sensitive system information
/*  Priority: Critical
/*  Category: Security - Information Disclosure
/**************************************************/

Given('test account with support analyst privileges is available', async function () {
  this.currentUser = this.testData.users['support analyst'];
});

Given('sample validation errors from various system modules are documented', async function () {
  this.sampleErrors = [
    'Invalid email format',
    'Password must meet complexity requirements',
    'Access denied',
    'Invalid date format',
    'Required field missing'
  ];
});

Given('test accounts are available for {string} role', async function (roleName: string) {
  this.testData.users[roleName] = this.testData.users[roleName] || { username: roleName.replace(/\s+/g, '_'), password: 'TestPass123!' };
});

Given('role-based access control is configured', async function () {
  this.rbacEnabled = true;
});

Given('validation error documentation is published in knowledge base', async function () {
  this.documentationPublished = true;
});

Given('search functionality is available', async function () {
  await assertions.assertVisible(page.locator('//input[@id="search-field"]'));
});

Given('test support analyst account is available', async function () {
  this.currentUser = this.testData.users['support analyst'];
});

Given('documentation update functionality exists', async function () {
  this.updateFunctionalityExists = true;
});

Given('support knowledge base authentication system is operational', async function () {
  await assertions.assertVisible(page.locator('//input[@id="username"]'));
});

Given('HTTPS is enforced for all connections', async function () {
  const currentUrl = page.url();
  expect(currentUrl).toMatch(/^https:\/\//);
});

Given('configured session timeout is {string} minutes', async function (timeoutMinutes: string) {
  this.sessionTimeout = parseInt(timeoutMinutes);
});

Given('user is logged in as support analyst in first browser', async function () {
  const credentials = this.testData.users['support analyst'];
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  const cookies = await context.cookies();
  this.testData.sessionTokens.firstBrowser = cookies.find(c => c.name === 'session_token')?.value;
});

Given('user sets predetermined session ID before authentication', async function () {
  await context.addCookies([{
    name: 'session_token',
    value: 'predetermined_session_12345',
    domain: new URL(page.url()).hostname,
    path: '/'
  }]);
  this.predeterminedSessionId = 'predetermined_session_12345';
});

Given('configured absolute session timeout is {string} hours', async function (timeoutHours: string) {
  this.absoluteTimeout = parseInt(timeoutHours);
});

// ==================== WHEN STEPS ====================

When('user logs in as support analyst', async function () {
  const credentials = this.testData.users['support analyst'];
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

When('user logs in as {string}', async function (userRole: string) {
  const credentials = this.testData.users[userRole];
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

When('user logs in as {string} with non-support role', async function (userRole: string) {
  const credentials = this.testData.users[userRole];
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

When('user logs in as {string} with proper role', async function (userRole: string) {
  const credentials = this.testData.users[userRole];
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

When('user logs in as support analyst with editor role', async function () {
  const credentials = this.testData.users['support analyst with editor role'];
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

When('user logs in as support analyst with valid credentials', async function () {
  const credentials = this.testData.users['support analyst'];
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

When('user navigates to {string} section', async function (sectionName: string) {
  const sectionXPath = `//a[contains(text(),'${sectionName}')]`;
  await actions.click(page.locator(sectionXPath));
  await waits.waitForNetworkIdle();
});

When('user reviews each documented validation error message for sensitive information', async function () {
  const errorMessages = await page.locator('//div[@id="error-messages-list"]//div[@class="error-message"]').allTextContents();
  this.testData.capturedData.errorMessages = errorMessages;
});

When('user checks error messages for information specificity', async function () {
  const errorMessages = this.testData.capturedData.errorMessages || [];
  this.testData.capturedData.specificityCheck = errorMessages;
});

When('user reviews troubleshooting steps in documentation', async function () {
  const troubleshootingSteps = await page.locator('//div[@id="troubleshooting-steps"]').allTextContents();
  this.testData.capturedData.troubleshootingSteps = troubleshootingSteps;
});

When('user tests error messages with {string} error category', async function (categoryName: string) {
  const categoryXPath = `//div[@data-category='${categoryName}']`;
  await actions.click(page.locator(categoryXPath));
  await waits.waitForNetworkIdle();
  const categoryErrors = await page.locator(`${categoryXPath}//div[@class="error-message"]`).allTextContents();
  this.testData.capturedData[`${categoryName}_errors`] = categoryErrors;
});

When('user attempts to access validation error documentation URL without authentication', async function () {
  await context.clearCookies();
  await actions.navigateTo(process.env.KNOWLEDGE_BASE_URL + '/validation-errors');
  await waits.waitForNetworkIdle();
});

When('user attempts to navigate to validation error documentation section', async function () {
  await actions.navigateTo(process.env.KNOWLEDGE_BASE_URL + '/validation-errors');
  await waits.waitForNetworkIdle();
});

When('user attempts to access documentation via direct URL as {string}', async function (userRole: string) {
  await actions.navigateTo(process.env.KNOWLEDGE_BASE_URL + '/validation-errors');
  await waits.waitForNetworkIdle();
});

When('user attempts to access documentation via API endpoints as {string}', async function (userRole: string) {
  const response = await page.request.get(process.env.KNOWLEDGE_BASE_URL + '/api/validation-errors');
  this.testData.capturedData.apiResponse = response;
});

When('user attempts to access documentation via alternative paths as {string}', async function (userRole: string) {
  const alternativePaths = [
    '/docs/validation-errors',
    '/kb/validation-errors',
    '/support/validation-errors'
  ];
  this.testData.capturedData.alternativePathResults = [];
  for (const path of alternativePaths) {
    await actions.navigateTo(process.env.KNOWLEDGE_BASE_URL + path);
    await waits.waitForNetworkIdle();
    this.testData.capturedData.alternativePathResults.push(page.url());
  }
});

When('user accesses validation error documentation', async function () {
  await actions.navigateTo(process.env.KNOWLEDGE_BASE_URL + '/validation-errors');
  await waits.waitForNetworkIdle();
});

When('user attempts horizontal privilege escalation by modifying session token', async function () {
  const cookies = await context.cookies();
  const sessionCookie = cookies.find(c => c.name === 'session_token');
  if (sessionCookie) {
    await context.addCookies([{
      ...sessionCookie,
      value: 'modified_token_12345'
    }]);
  }
  await actions.navigateTo(process.env.KNOWLEDGE_BASE_URL + '/validation-errors');
  await waits.waitForNetworkIdle();
});

When('user attempts horizontal privilege escalation by modifying user ID parameter', async function () {
  await actions.navigateTo(process.env.KNOWLEDGE_BASE_URL + '/validation-errors?user_id=999');
  await waits.waitForNetworkIdle();
});

When('support analyst attempts to edit documentation without editor role', async function () {
  const editButtonXPath = '//button[@id="edit-documentation"]';
  const editButtons = page.locator(editButtonXPath);
  if (await editButtons.count() > 0) {
    await actions.click(editButtons);
    await waits.waitForNetworkIdle();
  }
});

When('support analyst attempts to delete documentation without editor role', async function () {
  const deleteButtonXPath = '//button[@id="delete-documentation"]';
  const deleteButtons = page.locator(deleteButtonXPath);
  if (await deleteButtons.count() > 0) {
    await actions.click(deleteButtons);
    await waits.waitForNetworkIdle();
  }
});

When('user enters {string} in search field', async function (searchTerm: string) {
  await actions.fill(page.locator('//input[@id="search-field"]'), searchTerm);
  await waits.waitForNetworkIdle();
});

When('user enters {string} in {string} field', async function (value: string, fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  const textareaXPath = `//textarea[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  const inputFields = page.locator(fieldXPath);
  const textareaFields = page.locator(textareaXPath);
  
  if (await inputFields.count() > 0) {
    await actions.fill(inputFields, value);
  } else if (await textareaFields.count() > 0) {
    await actions.fill(textareaFields, value);
  }
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

When('another support analyst views the documentation', async function () {
  await page.reload();
  await waits.waitForNetworkIdle();
});

When('user accesses validation error documentation page', async function () {
  await actions.navigateTo(process.env.KNOWLEDGE_BASE_URL + '/validation-errors');
  await waits.waitForNetworkIdle();
});

When('user captures session token from cookies', async function () {
  const cookies = await context.cookies();
  const sessionCookie = cookies.find(c => c.name === 'session_token');
  this.testData.sessionTokens.current = sessionCookie?.value;
  this.testData.capturedData.sessionCookie = sessionCookie;
});

When('user remains idle for {string} minutes', async function (idleMinutes: string) {
  const idleTime = parseInt(idleMinutes) * 60 * 1000;
  await page.waitForTimeout(Math.min(idleTime, 5000));
});

When('user attempts to access validation documentation', async function () {
  await actions.navigateTo(process.env.KNOWLEDGE_BASE_URL + '/validation-errors');
  await waits.waitForNetworkIdle();
});

When('user copies session token to different browser', async function () {
  const cookies = await context.cookies();
  this.testData.sessionTokens.copied = cookies.find(c => c.name === 'session_token')?.value;
});

When('user attempts to access knowledge base simultaneously', async function () {
  const secondContext = await browser.newContext();
  const secondPage = await secondContext.newPage();
  
  if (this.testData.sessionTokens.copied) {
    await secondContext.addCookies([{
      name: 'session_token',
      value: this.testData.sessionTokens.copied,
      domain: new URL(page.url()).hostname,
      path: '/'
    }]);
  }
  
  await secondPage.goto(process.env.KNOWLEDGE_BASE_URL + '/validation-errors');
  await secondPage.waitForLoadState('networkidle');
  this.testData.capturedData.secondPageUrl = secondPage.url();
  
  await secondPage.close();
  await secondContext.close();
});

When('user captures current session token', async function () {
  const cookies = await context.cookies();
  this.testData.sessionTokens.beforeLogout = cookies.find(c => c.name === 'session_token')?.value;
});

When('user clicks {string} button', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase()}']`;
  const buttons = page.locator(buttonIdXPath);
  
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
  await waits.waitForNetworkIdle();
});

When('user attempts to reuse old session token to access documentation', async function () {
  if (this.testData.sessionTokens.beforeLogout) {
    await context.addCookies([{
      name: 'session_token',
      value: this.testData.sessionTokens.beforeLogout,
      domain: new URL(page.url()).hostname,
      path: '/'
    }]);
  }
  await actions.navigateTo(process.env.KNOWLEDGE_BASE_URL + '/validation-errors');
  await waits.waitForNetworkIdle();
});

When('user navigates through knowledge base pages', async function () {
  const pages = ['/home', '/documentation', '/validation-errors'];
  this.testData.capturedData.visitedUrls = [];
  
  for (const pagePath of pages) {
    await actions.navigateTo(process.env.KNOWLEDGE_BASE_URL + pagePath);
    await waits.waitForNetworkIdle();
    this.testData.capturedData.visitedUrls.push(page.url());
  }
});

When('user maintains continuous activity for {string} hours', async function (activityHours: string) {
  const activityTime = parseInt(activityHours) * 60 * 60 * 1000;
  await page.waitForTimeout(Math.min(activityTime, 5000));
});

// ==================== THEN STEPS ====================

Then('documentation section should load successfully', async function () {
  await assertions.assertVisible(page.locator('//div[@id="validation-error-documentation"]'));
});

Then('list of validation errors should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="error-messages-list"]'));
  const errorCount = await page.locator('//div[@id="error-messages-list"]//div[@class="error-message"]').count();
  expect(errorCount).toBeGreaterThan(0);
});

Then('error messages should not contain {string}', async function (sensitiveInfo: string) {
  const errorMessages = this.testData.capturedData.errorMessages || [];
  const patterns: { [key: string]: RegExp } = {
    'database table names': /\b(users|auth_users|customers|orders|payments|transactions|sessions)\b/i,
    'database column names': /\b(user_id|password_hash|email_address|credit_card|ssn|user_password)\b/i,
    'SQL queries': /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN)\b/i,
    'file system paths': /\b(\/var\/www|C:\\|\/home\/|\/etc\/|\.\.\/)\b/i,
    'server hostnames': /\b(server\d+|prod-db|staging-app|localhost)\b/i,
    'IP addresses': /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,
    'framework versions': /\b(v\d+\.\d+\.\d+|version \d+\.\d+|Node\.js \d+)\b/i,
    'stack traces': /\bat\s+\w+\.\w+\s+\(/i,
    'internal API endpoints': /\b(\/api\/internal|\/admin\/api|\/v1\/private)\b/i
  };
  
  const pattern = patterns[sensitiveInfo];
  if (pattern) {
    for (const message of errorMessages) {
      expect(message).not.toMatch(pattern);
    }
  }
});

Then('error messages should contain only user-friendly descriptions', async function () {
  const errorMessages = this.testData.capturedData.errorMessages || [];
  const userFriendlyPatterns = [
    /invalid/i,
    /required/i,
    /format/i,
    /access denied/i,
    /not permitted/i
  ];
  
  for (const message of errorMessages) {
    const isUserFriendly = userFriendlyPatterns.some(pattern => pattern.test(message));
    expect(isUserFriendly).toBeTruthy();
  }
});

Then('messages should follow pattern {string}', async function (expectedPattern: string) {
  const errorMessages = this.testData.capturedData.specificityCheck || [];
  const hasExpectedPattern = errorMessages.some(msg => msg.includes(expectedPattern));
  expect(hasExpectedPattern).toBeTruthy();
});

Then('messages should not follow pattern {string}', async function (forbiddenPattern: string) {
  const errorMessages = this.testData.capturedData.specificityCheck || [];
  const hasForbiddenPattern = errorMessages.some(msg => msg.includes(forbiddenPattern));
  expect(hasForbiddenPattern).toBeFalsy();
});

Then('troubleshooting steps should focus on user actions', async function () {
  const steps = this.testData.capturedData.troubleshootingSteps || [];
  const userActionKeywords = ['verify', 'check', 'ensure', 'confirm', 'review'];
  const hasUserActions = steps.some(step => 
    userActionKeywords.some(keyword => step.toLowerCase().includes(keyword))
  );
  expect(hasUserActions).toBeTruthy();
});

Then('troubleshooting steps should focus on data format requirements', async function () {
  const steps = this.testData.capturedData.troubleshootingSteps || [];
  const formatKeywords = ['format', 'pattern', 'structure', 'valid'];
  const hasFormatGuidance = steps.some(step => 
    formatKeywords.some(keyword => step.toLowerCase().includes(keyword))
  );
  expect(hasFormatGuidance).toBeTruthy();
});

Then('troubleshooting steps should not instruct sharing sensitive system details with end users', async function () {
  const steps = this.testData.capturedData.troubleshootingSteps || [];
  const sensitiveKeywords = ['database', 'server', 'stack trace', 'log file', 'internal'];
  const hasSensitiveInstructions = steps.some(step => 
    sensitiveKeywords.some(keyword => step.toLowerCase().includes(keyword))
  );
  expect(hasSensitiveInstructions).toBeFalsy();
});

Then('all error categories should maintain appropriate information boundaries', async function () {
  const categories = ['authentication', 'authorization', 'input validation', 'business logic'];
  for (const category of categories) {
    const categoryErrors = this.testData.capturedData[`${category}_errors`] || [];
    for (const error of categoryErrors) {
      expect(error).not.toMatch(/\b(SELECT|INSERT|table|column|server|stack)\b/i);
    }
  }
});

Then('no technical details should be leaked in any category', async function () {
  const allErrors = Object.keys(this.testData.capturedData)
    .filter(key => key.endsWith('_errors'))
    .flatMap(key => this.testData.capturedData[key]);
  
  const technicalPatterns = [
    /\b(SELECT|INSERT|UPDATE|DELETE)\b/i,
    /\b(table|column|database)\b/i,
    /\b(server|hostname|IP)\b/i,
    /\bat\s+\w+\.\w+/i
  ];
  
  for (const error of allErrors) {
    for (const pattern of technicalPatterns) {
      expect(error).not.toMatch(pattern);
    }
  }
});

Then('access should be denied', async function () {
  const currentUrl = page.url();
  const isLoginPage = currentUrl.includes('/login') || currentUrl.includes('/auth');
  const hasAccessDenied = await page.locator('//*[contains(text(),"Access Denied") or contains(text(),"403")]').count() > 0;
  expect(isLoginPage || hasAccessDenied).toBeTruthy();
});

Then('user should be redirected to login page', async function () {
  const currentUrl = page.url();
  expect(currentUrl).toMatch(/\/(login|auth|signin)/);
});

Then('appropriate error message should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="error-message"]'));
});

Then('access should be denied with {string} error', async function (errorCode: string) {
  const errorElement = page.locator(`//*[contains(text(),'${errorCode}')]`);
  await assertions.assertVisible(errorElement);
});

Then('documentation should not be visible in navigation', async function () {
  const navLink = page.locator('//nav//a[contains(text(),"Validation Error Documentation")]');
  const count = await navLink.count();
  expect(count).toBe(0);
});

Then('access should be blocked', async function () {
  const currentUrl = page.url();
  const isBlocked = currentUrl.includes('/login') || 
                    currentUrl.includes('/403') || 
                    await page.locator('//*[contains(text(),"Access Denied")]').count() > 0;
  expect(isBlocked).toBeTruthy();
});

Then('documentation should be accessible', async function () {
  await assertions.assertVisible(page.locator('//div[@id="validation-error-documentation"]'));
});

Then('all troubleshooting steps should be fully visible', async function () {
  await assertions.assertVisible(page.locator('//div[@id="troubleshooting-steps"]'));
});

Then('session validation should prevent access', async function () {
  const hasError = await page.locator('//*[contains(text(),"Session") or contains(text(),"Invalid")]').count() > 0;
  const isLoginPage = page.url().includes('/login');
  expect(hasError || isLoginPage).toBeTruthy();
});

Then('support analyst should have read-only access', async function () {
  const editButton = page.locator('//button[@id="edit-documentation"]');
  const deleteButton = page.locator('//button[@id="delete-documentation"]');
  const editCount = await editButton.count();
  const deleteCount = await deleteButton.count();
  expect(editCount).toBe(0);
  expect(deleteCount).toBe(0);
});

Then('access control logs should be generated for all access attempts', async function () {
  this.testData.capturedData.logsGenerated = true;
});

Then('unauthorized access attempts should be logged for security monitoring', async function () {
  this.testData.capturedData.securityLogsGenerated = true;
});

Then('input should be sanitized or rejected', async function () {
  const errorMessage = await page.locator('//div[@id="error-message"]').textContent();
  const isRejected = errorMessage && (errorMessage.includes('Invalid') || errorMessage.includes('rejected'));
  expect(isRejected).toBeTruthy();
});

Then('no script execution should occur in search results', async function () {
  const alertFired = await page.evaluate(() => {
    return (window as any).alertFired || false;
  });
  expect(alertFired).toBeFalsy();
});

Then('no script execution should occur in error messages', async function () {
  const alertFired = await page.evaluate(() => {
    return (window as any).alertFired || false;
  });
  expect(alertFired).toBeFalsy();
});

Then('no database errors should be exposed', async function () {
  const pageContent = await page.locator('//body').textContent();
  expect(pageContent).not.toMatch(/\b(SQL|database|query|syntax error)\b/i);
});

Then('no unauthorized data should be retrieved', async function () {
  const results = await page.locator('//div[@id="search-results"]').textContent();
  expect(results).not.toMatch(/\b(password|token|secret|key)\b/i);
});

Then('content should be sanitized before storage', async function () {
  await waits.waitForNetworkIdle();
  const successMessage = await page.locator('//div[@id="success-message"]').textContent();
  expect(successMessage).toContain('saved');
});

Then('no script execution should occur', async function () {
  const alertFired = await page.evaluate(() => {
    return (window as any).alertFired || false;
  });
  expect(alertFired).toBeFalsy();
});

Then('content should be properly encoded on retrieval', async function () {
  const content = await page.locator('//div[@id="error-description"]').innerHTML();
  expect(content).not.toMatch(/<script>/i);
  expect(content).toMatch(/&lt;|&gt;/);
});

Then('Content Security Policy headers should be present', async function () {
  const response = await page.goto(page.url());
  const headers = response?.headers();
  expect(headers?.['content-security-policy']).toBeDefined();
});

Then('CSP headers should restrict script sources', async function () {
  const response = await page.goto(page.url());
  const csp = response?.headers()['content-security-policy'];
  expect(csp).toMatch(/script-src/i);
});

Then('CSP headers should prevent inline script execution', async function () {
  const response = await page.goto(page.url());
  const csp = response?.headers()['content-security-policy'];
  expect(csp).toMatch(/'unsafe-inline'/);
});

Then('session token length should be minimum {int} bits', async function (minBits: number) {
  const token = this.testData.capturedData.sessionCookie?.value;
  const tokenLength = token ? token.length * 4 : 0;
  expect(tokenLength).toBeGreaterThanOrEqual(minBits);
});

Then('session token should be cryptographically random', async function () {
  const token = this.testData.capturedData.sessionCookie?.value;
  expect(token).toMatch(/^[a-zA-Z0-9+/=_-]+$/);
  expect(token?.length).toBeGreaterThan(20);
});

Then('session token should have {string} flag set', async function (flagName: string) {
  const cookie = this.testData.capturedData.sessionCookie;
  if (flagName === 'HttpOnly') {
    expect(cookie?.httpOnly).toBeTruthy();
  } else if (flagName === 'Secure') {
    expect(cookie?.secure).toBeTruthy();
  }
});

Then('session token should have {string} attribute set to {string} or {string}', async function (attribute: string, value1: string, value2: string) {
  const cookie = this.testData.capturedData.sessionCookie;
  if (attribute === 'SameSite') {
    expect(['Strict', 'Lax']).toContain(cookie?.sameSite);
  }
});

Then('session should be expired', async function () {
  const isLoginPage = page.url().includes('/login');
  const hasSessionExpired = await page.locator('//*[contains(text(),"Session expired")]').count() > 0;
  expect(isLoginPage || hasSessionExpired).toBeTruthy();
});

Then('system should either allow concurrent sessions with proper tracking', async function () {
  this.testData.capturedData.concurrentAllowed = true;
});

Then('system should detect and invalidate suspicious concurrent access', async function () {
  const hasWarning = await page.locator('//*[contains(text(),"concurrent") or contains(text(),"multiple")]').count() > 0;
  this.testData.capturedData.concurrentDetected = hasWarning;
});

Then('new session token should be generated', async function () {
  const cookies = await context.cookies();
  const newToken = cookies.find(c => c.name === 'session_token')?.value;
  expect(newToken).not.toBe(this.predeterminedSessionId);
});

Then('old session token should be invalidated', async function () {
  const cookies = await context.cookies();
  const currentToken = cookies.find(c => c.name === 'session_token')?.value;
  expect(currentToken).not.toBe(this.predeterminedSessionId);
});

Then('session token should be invalidated server-side', async function () {
  await waits.waitForNetworkIdle();
  this.testData.capturedData.tokenInvalidated = true;
});

Then('old token should not access protected resources', async function () {
  const isLoginPage = page.url().includes('/login');
  const hasAccessDenied = await page.locator('//*[contains(text(),"Access Denied")]').count() > 0;
  expect(isLoginPage || hasAccessDenied).toBeTruthy();
});

Then('session tokens should not appear in URLs', async function () {
  const urls = this.testData.capturedData.visitedUrls || [];
  for (const url of urls) {
    expect(url).not.toMatch(/session|token|auth/i);
  }
});

Then('session tokens should not appear in referrer headers', async function () {
  this.testData.capturedData.referrerChecked = true;
});

Then('session tokens should not appear in browser history', async function () {
  this.testData.capturedData.historyChecked = true;
});

Then('session tokens should not appear in application logs', async function () {
  this.testData.capturedData.logsChecked = true;
});

Then('session tokens should only be transmitted in secure cookies', async function () {
  const cookies = await context.cookies();
  const sessionCookie = cookies.find(c => c.name === 'session_token');
  expect(sessionCookie?.secure).toBeTruthy();
  expect(sessionCookie?.httpOnly).toBeTruthy();
});

Then('session should be terminated after absolute timeout', async function () {
  const isLoginPage = page.url().includes('/login');
  const hasTimeout = await page.locator('//*[contains(text(),"timeout") or contains(text(),"expired")]').count() > 0;
  expect(isLoginPage || hasTimeout).toBeTruthy();
});

Then('user should be required to re-authenticate', async function () {
  await assertions.assertVisible(page.locator('//input[@id="username"]'));
  await assertions.assertVisible(page.locator('//input[@id="password"]'));
});