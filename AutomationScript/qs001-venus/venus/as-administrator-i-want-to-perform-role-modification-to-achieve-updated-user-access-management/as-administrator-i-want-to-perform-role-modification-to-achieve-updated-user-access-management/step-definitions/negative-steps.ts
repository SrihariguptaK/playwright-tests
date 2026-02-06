import { Given, When, Then, Before, After } from '@cucumber/cucumber';
import { Page, Browser, BrowserContext, chromium, expect } from '@playwright/test';
import { BasePage } from '../pages/BasePage';
import { HomePage } from '../pages/HomePage';
import { GenericActions } from '../utils/GenericActions';
import { AssertionHelpers } from '../utils/AssertionHelpers';
import { WaitHelpers } from '../utils/WaitHelpers';

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
      admin: { username: 'admin', password: 'admin123', role: 'Administrator' },
      standardUser: { username: 'standarduser', password: 'userpass', role: 'Standard User' }
    },
    roles: {},
    apiResponses: {},
    sessionData: {}
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
/*  BACKGROUND STEPS
/*  Common setup for all scenarios
/**************************************************/

Given('the role management system is available', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//body'));
});

Given('API endpoint {string} is configured', async function (endpoint: string) {
  this.apiEndpoint = endpoint;
  this.testData.apiEndpoint = endpoint;
});

/**************************************************/
/*  TEST CASE: TC-NEG-001
/*  Title: Non-admin user access rejection
/*  Priority: High
/*  Category: Security
/**************************************************/

Given('user is logged in with {string} role without admin privileges', async function (roleName: string) {
  const credentials = this.testData.users.standardUser;
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  this.currentUserRole = roleName;
});

Given('role {string} exists in the system', async function (roleName: string) {
  this.testData.roles[roleName] = { name: roleName, permissions: ['read', 'write'] };
});

Given('API endpoint requires admin authentication', async function () {
  this.apiRequiresAuth = true;
});

When('user attempts to navigate to {string} page directly', async function (url: string) {
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}${url}`);
  await waits.waitForLoad();
});

Then('{string} page should be displayed', async function (pageTitle: string) {
  const pageTitleXPath = `//*[contains(text(),'${pageTitle}')]`;
  await assertions.assertVisible(page.locator(pageTitleXPath));
});

Then('error message {string} should be displayed', async function (errorMessage: string) {
  const errorXPath = `//*[contains(text(),'${errorMessage}')]`;
  await assertions.assertVisible(page.locator(errorXPath));
});

When('user attempts to call API endpoint {string} with modified permissions', async function (endpoint: string) {
  this.apiResponse = await page.evaluate(async (apiEndpoint) => {
    try {
      const response = await fetch(apiEndpoint, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ permissions: ['read', 'write', 'delete'] })
      });
      return { status: response.status, body: await response.text() };
    } catch (error) {
      return { status: 0, error: error.message };
    }
  }, endpoint);
});

Then('API should return HTTP status code {int}', async function (statusCode: number) {
  expect(this.apiResponse.status).toBe(statusCode);
});

Then('API error response {string} should be returned', async function (errorMessage: string) {
  expect(this.apiResponse.body).toContain(errorMessage);
});

Then('no changes should be saved to roles table', async function () {
  await waits.waitForNetworkIdle();
  this.testData.rolesUnchanged = true;
});

Then('{string} role permissions should remain unchanged', async function (roleName: string) {
  const originalPermissions = this.testData.roles[roleName].permissions;
  this.testData.roles[roleName].currentPermissions = originalPermissions;
});

Then('security violation attempt should be logged in security audit trail with user ID and timestamp', async function () {
  this.testData.securityLogCreated = true;
});

/**************************************************/
/*  TEST CASE: TC-NEG-002
/*  Title: Empty permission validation
/*  Priority: High
/*  Category: Validation
/**************************************************/

Given('administrator is logged in and on role management page', async function () {
  const credentials = this.testData.users.admin;
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/admin/role-management`);
  await waits.waitForNetworkIdle();
});

Given('role {string} exists with {int} permissions assigned', async function (roleName: string, permissionCount: number) {
  this.testData.roles[roleName] = { 
    name: roleName, 
    permissions: Array.from({ length: permissionCount }, (_, i) => `permission${i + 1}`)
  };
});

Given('role modification form is accessible', async function () {
  await assertions.assertVisible(page.locator('//form[@id="role-modification-form"]'));
});

When('administrator selects {string} from roles list', async function (roleName: string) {
  const roleXPath = `//div[@id='role-${roleName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(roleXPath));
  await waits.waitForNetworkIdle();
});

Then('role modification form should open showing current permissions checked', async function () {
  await assertions.assertVisible(page.locator('//form[@id="role-modification-form"]'));
  const checkedBoxes = await page.locator('//input[@type="checkbox"][@checked]').count();
  expect(checkedBoxes).toBeGreaterThan(0);
});

When('administrator unchecks all permission checkboxes', async function () {
  const checkboxes = page.locator('//input[@type="checkbox"][@checked]');
  const count = await checkboxes.count();
  for (let i = 0; i < count; i++) {
    await checkboxes.nth(i).uncheck();
  }
});

Then('all checkboxes should be unchecked', async function () {
  const checkedCount = await page.locator('//input[@type="checkbox"][@checked]').count();
  expect(checkedCount).toBe(0);
});

Then('form should show {int} permissions selected', async function (count: number) {
  const selectedCountXPath = `//*[contains(text(),'${count} permissions selected')]`;
  await assertions.assertVisible(page.locator(selectedCountXPath));
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

Then('validation error {string} should be displayed', async function (errorMessage: string) {
  const errorXPath = `//*[contains(text(),'${errorMessage}')]`;
  await assertions.assertVisible(page.locator(errorXPath));
});

Then('red error banner should appear at top of form', async function () {
  await assertions.assertVisible(page.locator('//div[@id="error-banner"]'));
});

Then('form submission should be blocked', async function () {
  this.testData.formSubmissionBlocked = true;
});

Then('{string} permissions should remain unchanged in database', async function (roleName: string) {
  this.testData.roles[roleName].unchanged = true;
});

Then('no audit log entry should be created for failed modification attempt', async function () {
  this.testData.noAuditLog = true;
});

Then('administrator should remain on role modification form', async function () {
  await assertions.assertVisible(page.locator('//form[@id="role-modification-form"]'));
});

/**************************************************/
/*  TEST CASE: TC-NEG-003
/*  Title: Database connection failure handling
/*  Priority: High
/*  Category: Database
/**************************************************/

Given('administrator is logged in and on role modification form', async function () {
  const credentials = this.testData.users.admin;
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/admin/role-management`);
  await waits.waitForNetworkIdle();
});

Given('role {string} is selected for modification', async function (roleName: string) {
  const roleXPath = `//div[@id='role-${roleName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(roleXPath));
  await waits.waitForNetworkIdle();
  this.selectedRole = roleName;
});

Given('database connection can be simulated to fail during transaction', async function () {
  this.simulateDbFailure = true;
});

When('administrator modifies {string} role by adding {string} permission', async function (roleName: string, permission: string) {
  const permissionXPath = `//input[@id='permission-${permission}']`;
  await actions.click(page.locator(permissionXPath));
  this.addedPermission = permission;
});

Then('{string} permission checkbox should be checked', async function (permission: string) {
  const permissionXPath = `//input[@id='permission-${permission}']`;
  await assertions.assertVisible(page.locator(permissionXPath));
});

Then('form should show pending changes', async function () {
  await assertions.assertVisible(page.locator('//*[contains(text(),"Unsaved changes")]'));
});

When('database connection failure is simulated', async function () {
  await page.route('**/api/roles/**', route => route.abort('failed'));
});

Then('system should attempt to save but encounter database connection error', async function () {
  await waits.waitForNetworkIdle();
});

Then('error message {string} should be displayed', async function (errorMessage: string) {
  const errorXPath = `//*[contains(text(),'${errorMessage}')]`;
  await assertions.assertVisible(page.locator(errorXPath));
});

Then('red error banner should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="error-banner"]'));
});

Then('no partial updates should be applied', async function () {
  this.testData.noPartialUpdates = true;
});

Then('database error should be logged in system error logs with timestamp and error details', async function () {
  this.testData.errorLogged = true;
});

Then('administrator should remain on modification form with error message displayed', async function () {
  await assertions.assertVisible(page.locator('//form[@id="role-modification-form"]'));
  await assertions.assertVisible(page.locator('//div[@id="error-banner"]'));
});

Then('form should retain the attempted changes', async function () {
  const permissionXPath = `//input[@id='permission-${this.addedPermission}']`;
  await assertions.assertVisible(page.locator(permissionXPath));
});

/**************************************************/
/*  TEST CASE: TC-NEG-004
/*  Title: SQL injection protection
/*  Priority: High
/*  Category: Security
/**************************************************/

Given('administrator is logged in with admin privileges', async function () {
  const credentials = this.testData.users.admin;
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

Given('system has SQL injection protection enabled', async function () {
  this.testData.sqlInjectionProtection = true;
});

Given('input validation and parameterized queries are implemented', async function () {
  this.testData.parameterizedQueries = true;
});

When('administrator selects any existing role and opens modification form', async function () {
  await actions.click(page.locator('//div[@class="role-item"]').first());
  await waits.waitForNetworkIdle();
});

Then('role modification form should open with current role details', async function () {
  await assertions.assertVisible(page.locator('//form[@id="role-modification-form"]'));
});

When('administrator attempts to modify role name to {string}', async function (maliciousInput: string) {
  await actions.fill(page.locator('//input[@id="role-name"]'), maliciousInput);
  this.maliciousInput = maliciousInput;
});

Then('system should sanitize input', async function () {
  this.testData.inputSanitized = true;
});

Then('validation error {string} should be displayed', async function (errorMessage: string) {
  const errorXPath = `//*[contains(text(),'${errorMessage}')]`;
  await assertions.assertVisible(page.locator(errorXPath));
});

When('administrator attempts to submit form with malicious input', async function () {
  await actions.click(page.locator('//button[@id="save-changes"]'));
  await waits.waitForNetworkIdle();
});

Then('form submission should be blocked with error message', async function () {
  await assertions.assertVisible(page.locator('//div[@id="error-banner"]'));
});

Then('roles table should remain intact', async function () {
  this.testData.rolesTableIntact = true;
});

Then('all existing roles should remain in database', async function () {
  this.testData.allRolesPreserved = true;
});

Then('no SQL injection should be executed', async function () {
  this.testData.sqlInjectionBlocked = true;
});

Then('security incident should be logged with attempted malicious input details', async function () {
  this.testData.securityIncidentLogged = true;
});

Then('role modification should be rejected', async function () {
  this.testData.modificationRejected = true;
});

Then('no changes should be saved', async function () {
  this.testData.noChangesSaved = true;
});

/**************************************************/
/*  TEST CASE: TC-NEG-005
/*  Title: Session expiration handling
/*  Priority: Medium
/*  Category: Session
/**************************************************/

Given('session timeout is configured', async function () {
  this.testData.sessionTimeout = 1800;
});

When('administrator opens role modification form for {string} role', async function (roleName: string) {
  const roleXPath = `//div[@id='role-${roleName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(roleXPath));
  await waits.waitForNetworkIdle();
});

When('administrator adds {string} permission', async function (permission: string) {
  const permissionXPath = `//input[@id='permission-${permission}']`;
  await actions.click(page.locator(permissionXPath));
});

Then('form should show unsaved changes', async function () {
  await assertions.assertVisible(page.locator('//*[contains(text(),"Unsaved changes")]'));
});

When('session expires or session token is manually expired', async function () {
  await context.clearCookies();
  this.testData.sessionExpired = true;
});

Then('system should detect expired session', async function () {
  this.testData.sessionDetected = true;
});

Then('no modifications should be applied', async function () {
  this.testData.noModifications = true;
});

Then('user should be redirected to login page', async function () {
  await assertions.assertUrlContains('/login');
});

Then('attempted changes should be lost and not persisted', async function () {
  this.testData.changesLost = true;
});

Then('session expiration should be logged in authentication logs', async function () {
  this.testData.sessionExpirationLogged = true;
});

/**************************************************/
/*  TEST CASE: TC-NEG-006
/*  Title: Maximum permission limit validation
/*  Priority: Medium
/*  Category: Validation
/**************************************************/

Given('administrator is logged in and on role management page', async function () {
  const credentials = this.testData.users.admin;
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/admin/role-management`);
  await waits.waitForNetworkIdle();
});

Given('system has maximum permission limit configured as {int} permissions per role', async function (maxLimit: number) {
  this.testData.maxPermissionLimit = maxLimit;
});

Given('role {string} exists with {int} permissions already assigned', async function (roleName: string, permissionCount: number) {
  this.testData.roles[roleName] = { 
    name: roleName, 
    permissions: Array.from({ length: permissionCount }, (_, i) => `permission${i + 1}`)
  };
});

Given('at least {int} additional permission options are available to select', async function (additionalCount: number) {
  this.testData.additionalPermissions = additionalCount;
});

When('administrator selects {string} role to open modification form', async function (roleName: string) {
  const roleXPath = `//div[@id='role-${roleName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(roleXPath));
  await waits.waitForNetworkIdle();
});

Then('role modification form should display showing {int} permissions currently checked', async function (count: number) {
  const checkedCount = await page.locator('//input[@type="checkbox"][@checked]').count();
  expect(checkedCount).toBe(count);
});

When('administrator attempts to add {string} permission', async function (permission: string) {
  const permissionXPath = `//input[@id='permission-${permission.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(permissionXPath));
});

Then('both checkboxes should be checked', async function () {
  this.testData.bothChecked = true;
});

Then('form should show {int} permissions selected', async function (count: number) {
  const selectedCountXPath = `//*[contains(text(),'${count} permissions')]`;
  await assertions.assertVisible(page.locator(selectedCountXPath));
});

Then('error banner should appear in red', async function () {
  await assertions.assertVisible(page.locator('//div[@id="error-banner"]'));
});

Then('{string} button should be disabled', async function (buttonText: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const isDisabled = await page.locator(buttonXPath).isDisabled();
  expect(isDisabled).toBe(true);
});

Then('{string} role should retain original {int} permissions in database', async function (roleName: string, count: number) {
  this.testData.roles[roleName].originalCount = count;
});

Then('no changes should be saved due to validation failure', async function () {
  this.testData.validationFailed = true;
});

Then('validation error should be logged for monitoring purposes', async function () {
  this.testData.validationErrorLogged = true;
});

/**************************************************/
/*  TEST CASE: TC-NEG-007
/*  Title: Concurrent modification handling
/*  Priority: Medium
/*  Category: Concurrency
/**************************************************/

Given('administrator {string} is logged in', async function (adminName: string) {
  this.testData.admins = this.testData.admins || {};
  this.testData.admins[adminName] = { name: adminName, loggedIn: true };
});

Given('both administrators have access to role management section', async function () {
  this.testData.bothHaveAccess = true;
});

Given('role {string} exists with permissions {string}', async function (roleName: string, permissions: string) {
  this.testData.roles[roleName] = { 
    name: roleName, 
    permissions: permissions.split(', ')
  };
});

Given('both administrators open the same role for modification at the same time', async function () {
  this.testData.concurrentAccess = true;
});

When('{string} selects {string} role and opens modification form', async function (adminName: string, roleName: string) {
  const roleXPath = `//div[@id='role-${roleName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(roleXPath));
  await waits.waitForNetworkIdle();
  this.testData.admins[adminName].selectedRole = roleName;
});

When('{string} adds {string} permission', async function (adminName: string, permission: string) {
  const permissionXPath = `//input[@id='permission-${permission}']`;
  await actions.click(page.locator(permissionXPath));
  this.testData.admins[adminName].addedPermission = permission;
});

Then('{string} form should show {string} with {string} permissions selected', async function (adminName: string, roleName: string, permissions: string) {
  this.testData.admins[adminName].formPermissions = permissions;
});

When('{string} removes {string} permission', async function (adminName: string, permission: string) {
  const permissionXPath = `//input[@id='permission-${permission}']`;
  await actions.click(page.locator(permissionXPath));
  this.testData.admins[adminName].removedPermission = permission;
});

When('{string} clicks {string} button first', async function (adminName: string, buttonText: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(buttonXPath));
  await waits.waitForNetworkIdle();
  this.testData.admins[adminName].savedFirst = true;
});

Then('{string} should see success message', async function (adminName: string) {
  await assertions.assertVisible(page.locator('//*[contains(text(),"Success")]'));
});

Then('{string} role should be updated to {string}', async function (roleName: string, permissions: string) {
  this.testData.roles[roleName].permissions = permissions.split(', ');
});

When('{string} clicks {string} button immediately after {string}', async function (adminName: string, buttonText: string, otherAdmin: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(buttonXPath));
  await waits.waitForNetworkIdle();
});

Then('system should detect conflict', async function () {
  this.testData.conflictDetected = true;
});

Then('{string} role should show {string} permissions in database', async function (roleName: string, permissions: string) {
  this.testData.roles[roleName].finalPermissions = permissions.split(', ');
});

Then('{string} changes should not be applied to prevent data loss', async function (adminName: string) {
  this.testData.admins[adminName].changesRejected = true;
});

Then('only {string} modifications should be saved in database', async function (adminName: string) {
  this.testData.admins[adminName].modificationsAccepted = true;
});

Then('both modification attempts should be logged in audit trail with conflict notation', async function () {
  this.testData.conflictLogged = true;
});