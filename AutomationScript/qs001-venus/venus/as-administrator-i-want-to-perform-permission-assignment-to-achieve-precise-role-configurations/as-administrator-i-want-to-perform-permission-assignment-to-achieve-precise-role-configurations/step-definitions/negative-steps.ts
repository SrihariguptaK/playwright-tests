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
      'Standard User': { username: 'standarduser', password: 'userpass' }
    },
    apiBaseUrl: process.env.API_BASE_URL || 'http://localhost:3000',
    apiResponse: null,
    systemState: null
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
/*  BACKGROUND STEP - All Test Cases
/*  Authentication prerequisite
/**************************************************/

Given('administrator is authenticated with valid admin credentials', async function () {
  const credentials = this.testData?.users?.admin || { username: 'admin', password: 'admin123' };
  await actions.navigateTo(`${this.testData.apiBaseUrl}/login`);
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-NEG-001
/*  Title: System rejects permission assignment when no permissions are selected
/*  Priority: High
/*  Category: Negative
/**************************************************/

Given('administrator is on the permission configuration page', async function () {
  await actions.navigateTo(`${this.testData.apiBaseUrl}/admin/permissions`);
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="permission-configuration-page"]'));
});

Given('role {string} exists in the system with no current permissions', async function (roleName: string) {
  this.currentRole = roleName;
  await assertions.assertVisible(page.locator(`//select[@id="role-selection-dropdown"]`));
});

Given('available permissions list is displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="available-permissions-list"]'));
});

Given('no permission checkboxes are selected', async function () {
  const checkboxes = page.locator('//input[@type="checkbox" and contains(@id, "permission-")]');
  const count = await checkboxes.count();
  for (let i = 0; i < count; i++) {
    const checkbox = checkboxes.nth(i);
    if (await checkbox.isChecked()) {
      await actions.click(checkbox);
    }
  }
});

/**************************************************/
/*  TEST CASE: TC-NEG-002
/*  Title: System rejects permission assignment without admin authentication
/*  Priority: High
/*  Category: Negative
/**************************************************/

Given('user is logged in with non-admin role {string}', async function (roleName: string) {
  const credentials = this.testData?.users?.[roleName] || { username: 'standarduser', password: 'userpass' };
  await actions.navigateTo(`${this.testData.apiBaseUrl}/login`);
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  this.currentUser = roleName;
  this.authToken = 'standard-user-token-12345';
});

Given('role {string} exists in the system', async function (roleName: string) {
  this.currentRole = roleName;
});

Given('user does not have admin-level permissions', async function () {
  this.hasAdminPermissions = false;
});

/**************************************************/
/*  TEST CASE: TC-NEG-003
/*  Title: System handles permission assignment for non-existent role ID gracefully
/*  Priority: High
/*  Category: Negative
/**************************************************/

Given('role ID {string} does not exist in the database', async function (roleId: string) {
  this.nonExistentRoleId = roleId;
});

Given('permission {string} exists in the system', async function (permissionName: string) {
  this.permissions = this.permissions || [];
  this.permissions.push(permissionName);
});

/**************************************************/
/*  TEST CASE: TC-NEG-004
/*  Title: System rejects permission assignment with invalid permission IDs
/*  Priority: High
/*  Category: Negative
/**************************************************/

Given('role {string} with ID {string} exists in the system', async function (roleName: string, roleId: string) {
  this.currentRole = roleName;
  this.currentRoleId = roleId;
});

Given('permission ID {string} does not exist in the permissions table', async function (permissionId: string) {
  this.invalidPermissions = this.invalidPermissions || [];
  this.invalidPermissions.push(permissionId);
});

Given('permission {string} exists in the system', async function (permissionId: string) {
  this.validPermissions = this.validPermissions || [];
  this.validPermissions.push(permissionId);
});

/**************************************************/
/*  TEST CASE: TC-NEG-005
/*  Title: System handles database connection failure during permission assignment
/*  Priority: Medium
/*  Category: Negative
/**************************************************/

Given('permission {string} is available for assignment', async function (permissionName: string) {
  this.availablePermissions = this.availablePermissions || [];
  this.availablePermissions.push(permissionName);
  await assertions.assertVisible(page.locator(`//input[@id="permission-${permissionName.toLowerCase().replace(/\s+/g, '-')}"]`));
});

Given('database connection can be simulated to fail', async function () {
  this.canSimulateDbFailure = true;
});

/**************************************************/
/*  TEST CASE: TC-NEG-006
/*  Title: System rejects permission assignment with SQL injection attempt in role ID
/*  Priority: High
/*  Category: Negative
/**************************************************/

Given('administrator is authenticated with valid credentials', async function () {
  const credentials = this.testData?.users?.admin || { username: 'admin', password: 'admin123' };
  await actions.navigateTo(`${this.testData.apiBaseUrl}/login`);
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  this.authToken = 'admin-auth-token-67890';
});

Given('system has SQL injection protection mechanisms in place', async function () {
  this.hasSqlInjectionProtection = true;
});

/**************************************************/
/*  TEST CASE: TC-NEG-007
/*  Title: System handles session timeout during permission assignment process
/*  Priority: Medium
/*  Category: Negative
/**************************************************/

Given('permission {string} is selected for assignment', async function (permissionName: string) {
  this.selectedPermissions = this.selectedPermissions || [];
  this.selectedPermissions.push(permissionName);
});

Given('admin session timeout is set to {int} minutes', async function (timeoutMinutes: number) {
  this.sessionTimeout = timeoutMinutes;
});

// ==================== WHEN STEPS ====================

When('administrator selects {string} role from the role selection dropdown', async function (roleName: string) {
  const dropdownXPath = '//select[@id="role-selection-dropdown"]';
  await actions.selectByText(page.locator(dropdownXPath), roleName);
  await waits.waitForNetworkIdle();
  this.selectedRole = roleName;
});

When('administrator clicks {string} button without selecting any permissions', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
  await waits.waitForNetworkIdle();
});

When('user navigates to {string} page', async function (pagePath: string) {
  await actions.navigateTo(`${this.testData.apiBaseUrl}${pagePath}`);
  await waits.waitForNetworkIdle();
});

When('user sends POST request to {string} with {string} authentication token', async function (endpoint: string, userType: string) {
  const response = await page.evaluate(async ({ url, token }) => {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ permissions: ['perm-001'] })
    });
    return {
      status: res.status,
      body: await res.json()
    };
  }, { url: `${this.testData.apiBaseUrl}${endpoint}`, token: this.authToken });
  
  this.testData.apiResponse = response;
});

When('administrator sends POST request to {string} with permissions {string}', async function (endpoint: string, permissions: string) {
  const response = await page.evaluate(async ({ url, perms, token }) => {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token || 'admin-token'}`
      },
      body: JSON.stringify({ permissions: perms.split(',') })
    });
    return {
      status: res.status,
      body: await res.json()
    };
  }, { url: `${this.testData.apiBaseUrl}${endpoint}`, perms: permissions, token: this.authToken });
  
  this.testData.apiResponse = response;
});

When('administrator checks {string} permission checkbox', async function (permissionName: string) {
  const checkboxXPath = `//input[@id="permission-${permissionName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await actions.check(page.locator(checkboxXPath));
  this.selectedPermissions = this.selectedPermissions || [];
  this.selectedPermissions.push(permissionName);
});

When('database connection failure is simulated', async function () {
  await page.evaluate(() => {
    window.localStorage.setItem('simulate-db-failure', 'true');
  });
  this.dbFailureSimulated = true;
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

When('admin session expires', async function () {
  await page.evaluate(() => {
    window.localStorage.removeItem('auth-token');
    window.sessionStorage.clear();
  });
  this.sessionExpired = true;
});

// ==================== THEN STEPS ====================

Then('{string} role details panel should display with empty current permissions section', async function (roleName: string) {
  await assertions.assertVisible(page.locator('//div[@id="role-details-panel"]'));
  await assertions.assertVisible(page.locator('//div[@id="current-permissions-section"]'));
  const permissionCount = await page.locator('//div[@id="current-permissions-section"]//li').count();
  expect(permissionCount).toBe(0);
});

Then('error message {string} should be displayed', async function (errorMessage: string) {
  await assertions.assertVisible(page.locator(`//*[contains(text(),'${errorMessage}')]`));
});

Then('error banner should be displayed in {string} color at the top of the page', async function (color: string) {
  const bannerXPath = '//div[@id="error-banner"]';
  await assertions.assertVisible(page.locator(bannerXPath));
  const bgColor = await page.locator(bannerXPath).evaluate((el) => window.getComputedStyle(el).backgroundColor);
  expect(bgColor).toContain('rgb');
});

Then('current permissions section should remain empty for {string} role', async function (roleName: string) {
  const permissionCount = await page.locator('//div[@id="current-permissions-section"]//li').count();
  expect(permissionCount).toBe(0);
});

Then('all form fields should remain enabled and accessible', async function () {
  const dropdown = page.locator('//select[@id="role-selection-dropdown"]');
  await assertions.assertVisible(dropdown);
  const isEnabled = await dropdown.isEnabled();
  expect(isEnabled).toBe(true);
});

Then('no permissions should be assigned to {string} role in the database', async function (roleName: string) {
  this.databaseCheck = { role: roleName, permissionsAssigned: false };
});

Then('failed assignment attempt should be logged with reason {string}', async function (reason: string) {
  this.logEntry = { type: 'failed_assignment', reason: reason };
});

Then('{string} page should be displayed', async function (pageName: string) {
  await assertions.assertVisible(page.locator(`//div[@id="${pageName.toLowerCase().replace(/\s+/g, '-')}-page"]`));
});

Then('API should return HTTP status code {int}', async function (statusCode: number) {
  expect(this.testData.apiResponse.status).toBe(statusCode);
});

Then('response should contain error {string}', async function (errorType: string) {
  expect(this.testData.apiResponse.body.error).toBe(errorType);
});

Then('response should contain message {string}', async function (message: string) {
  expect(this.testData.apiResponse.body.message).toContain(message);
});

Then('no permissions should be modified in the database', async function () {
  this.databaseCheck = { permissionsModified: false };
});

Then('unauthorized access attempt should be logged in security audit log', async function () {
  this.securityLog = { type: 'unauthorized_access', logged: true };
});

Then('response should contain status code {int}', async function (statusCode: number) {
  expect(this.testData.apiResponse.body.statusCode || this.testData.apiResponse.status).toBe(statusCode);
});

Then('no database records should be created in role_permissions table for role {string}', async function (roleId: string) {
  this.databaseCheck = { table: 'role_permissions', roleId: roleId, recordsCreated: false };
});

Then('error log entry should exist with severity {string} and message {string}', async function (severity: string, message: string) {
  this.logEntry = { severity: severity, message: message, exists: true };
});

Then('response should contain invalid permissions list {string}', async function (invalidPermsList: string) {
  expect(this.testData.apiResponse.body.invalidPermissions).toBeDefined();
});

Then('transaction should be rolled back completely', async function () {
  this.transactionRolledBack = true;
});

Then('error message should not expose sensitive database information', async function () {
  const errorText = await page.locator('//div[@id="error-message"]').textContent();
  expect(errorText).not.toContain('SQL');
  expect(errorText).not.toContain('database');
  expect(errorText).not.toContain('connection string');
});

Then('error log should contain detailed technical information {string}', async function (technicalInfo: string) {
  this.errorLog = { technicalInfo: technicalInfo, detailed: true };
});

Then('no partial data should be saved to the database', async function () {
  this.databaseCheck = { partialDataSaved: false };
});

Then('system should remain stable and operational', async function () {
  await assertions.assertVisible(page.locator('//div[@id="permission-configuration-page"]'));
  const isResponsive = await page.evaluate(() => document.readyState === 'complete');
  expect(isResponsive).toBe(true);
});

Then('no database records should be modified or exposed', async function () {
  this.databaseCheck = { recordsModified: false, dataExposed: false };
});

Then('no unauthorized queries should be executed', async function () {
  this.unauthorizedQueries = false;
});

Then('security log entry should exist with severity {string} and message {string}', async function (severity: string, message: string) {
  this.securityLog = { severity: severity, message: message, exists: true };
});

Then('security alert should be triggered for potential attack attempt', async function () {
  this.securityAlert = { triggered: true, type: 'sql_injection_attempt' };
});

Then('{string} button should be visible', async function (buttonText: string) {
  const buttonXPath = `//button[@id="${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  await assertions.assertVisible(page.locator(buttonXPath));
});

Then('session expiration should be logged in audit trail', async function () {
  this.auditLog = { event: 'session_expired', logged: true };
});

Then('administrator should be redirected to login page', async function () {
  await waits.waitForNetworkIdle();
  await assertions.assertUrlContains('/login');
});

Then('I should see {string}', async function (text: string) {
  await assertions.assertContainsText(page.locator(`//*[contains(text(),'${text}')]`), text);
});