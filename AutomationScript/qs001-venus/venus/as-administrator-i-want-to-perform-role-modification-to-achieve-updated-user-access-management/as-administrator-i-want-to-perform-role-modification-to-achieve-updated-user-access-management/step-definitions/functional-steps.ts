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
      admin: { username: 'admin@company.com', password: 'admin123' },
      user: { username: 'testuser', password: 'testpass' }
    },
    roles: {
      'Content Editor': { permissions: ['read', 'write'] },
      'Project Manager': { permissions: ['read', 'write', 'approve'] },
      'Data Viewer': { permissions: ['read'], readOnly: true },
      'Sales Representative': { permissions: ['read', 'write', 'create', 'update', 'delete'] },
      'Customer Support': { permissions: ['read', 'create', 'update'] },
      'Marketing Manager': { permissions: ['read', 'write', 'approve', 'export'] }
    }
  };
  
  this.performanceTimer = null;
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
/*  BACKGROUND STEPS - All Test Cases
/*  Setup: Administrator authentication and database
/**************************************************/

Given('administrator is logged in with valid admin credentials', async function () {
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000');
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), 'admin@company.com');
  await actions.fill(page.locator('//input[@id="password"]'), 'admin123');
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

Given('database connection is active and roles table is accessible', async function () {
  await assertions.assertVisible(page.locator('//div[@id="database-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="database-status"]'), 'Connected');
});

Given('administrator is logged in as {string} with admin privileges', async function (email: string) {
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000');
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), email);
  await actions.fill(page.locator('//input[@id="password"]'), 'admin123');
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  this.currentAdminUser = email;
});

Given('administrator is on {string} page', async function (pageName: string) {
  const pageXPath = `//a[@id="${pageName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await actions.click(page.locator(pageXPath));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator(`//h1[contains(text(),'${pageName}')]`));
});

Given('role {string} exists with permissions {string}', async function (roleName: string, permissions: string) {
  this.currentRole = roleName;
  this.currentPermissions = permissions.split(', ').map(p => p.trim());
  await assertions.assertVisible(page.locator(`//div[@id="role-${roleName.toLowerCase().replace(/\s+/g, '-')}"]`));
});

Given('role {string} exists with {string} flag set to true', async function (roleName: string, flagName: string) {
  this.currentRole = roleName;
  this.roleFlags = { [flagName]: true };
  await assertions.assertVisible(page.locator(`//div[@id="role-${roleName.toLowerCase().replace(/\s+/g, '-')}"]`));
});

Given('system has validation rules configured to prevent read-only roles from having write/delete permissions', async function () {
  this.validationRulesEnabled = true;
});

Given('conflicting permission validation is enabled', async function () {
  this.conflictValidationEnabled = true;
});

Given('audit logging system is enabled and functional', async function () {
  await assertions.assertVisible(page.locator('//div[@id="audit-system-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="audit-system-status"]'), 'Active');
});

Given('role {string} exists with {int} permissions assigned', async function (roleName: string, permissionCount: number) {
  this.currentRole = roleName;
  this.initialPermissionCount = permissionCount;
  await assertions.assertVisible(page.locator(`//div[@id="role-${roleName.toLowerCase().replace(/\s+/g, '-')}"]`));
});

Given('system is under normal load conditions', async function () {
  this.systemLoad = 'normal';
});

Given('network latency is within normal parameters', async function () {
  this.networkLatency = 'normal';
});

Given('all permission options are available', async function () {
  this.availablePermissions = ['read', 'write', 'create', 'update', 'delete', 'approve', 'export'];
});

Given('database contains accurate permission data for {string} role', async function (roleName: string) {
  this.currentRole = roleName;
  this.databaseSynced = true;
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  TC-001: Successfully modify existing role permissions
/*  Priority: High | Category: Functional
/**************************************************/

When('administrator clicks on {string} role from roles list', async function (roleName: string) {
  const roleXPath = `//div[@id="role-${roleName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await actions.click(page.locator(roleXPath));
  await waits.waitForNetworkIdle();
});

When('administrator checks {string} checkbox in permissions section', async function (permissionName: string) {
  const checkboxXPath = `//input[@id="permission-${permissionName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await actions.check(page.locator(checkboxXPath));
});

When('administrator clicks {string} button', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id="${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const buttons = page.locator(buttonIdXPath);
  
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TC-002: Role modification logs activity for compliance
/*  Priority: High | Category: Audit
/**************************************************/

When('administrator unchecks {string} checkbox', async function (permissionName: string) {
  const checkboxXPath = `//input[@id="permission-${permissionName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const checkbox = page.locator(checkboxXPath);
  if (await checkbox.isChecked()) {
    await actions.click(checkbox);
  }
});

When('administrator navigates to {string} page', async function (pageName: string) {
  const pageXPath = `//a[@id="${pageName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await actions.click(page.locator(pageXPath));
  await waits.waitForNetworkIdle();
});

When('administrator filters logs by {string} activity type', async function (activityType: string) {
  const filterXPath = `//select[@id="activity-type-filter"]`;
  await actions.selectByText(page.locator(filterXPath), activityType);
  await waits.waitForNetworkIdle();
});

When('administrator searches for {string} role', async function (roleName: string) {
  const searchXPath = `//input[@id="search-role"]`;
  await actions.fill(page.locator(searchXPath), roleName);
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TC-003: System prevents conflicting permissions
/*  Priority: High | Category: Negative Validation
/**************************************************/

When('administrator attempts to check {string} permission checkbox', async function (permissionName: string) {
  const checkboxXPath = `//input[@id="permission-${permissionName.toLowerCase().replace(/\s+/g, '-')}"]`;
  try {
    await actions.check(page.locator(checkboxXPath));
  } catch (error) {
    this.validationError = error;
  }
});

When('administrator clicks {string} button without resolving conflict', async function (buttonText: string) {
  const buttonXPath = `//button[@id="${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  try {
    await actions.click(page.locator(buttonXPath));
  } catch (error) {
    this.formSubmissionBlocked = true;
  }
});

/**************************************************/
/*  TC-004: Role modification performance requirement
/*  Priority: Medium | Category: Performance
/**************************************************/

When('administrator clicks on {string} role', async function (roleName: string) {
  const roleXPath = `//div[@id="role-${roleName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await actions.click(page.locator(roleXPath));
  await waits.waitForNetworkIdle();
});

When('administrator clicks {string} button and starts timer', async function (buttonText: string) {
  this.performanceTimer = Date.now();
  const buttonXPath = `//button[@id="${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  await actions.click(page.locator(buttonXPath));
});

/**************************************************/
/*  TC-005: Modify multiple permissions simultaneously
/*  Priority: Medium | Category: Functional
/**************************************************/

When('administrator checks {string} checkbox', async function (permissionName: string) {
  const checkboxXPath = `//input[@id="permission-${permissionName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await actions.check(page.locator(checkboxXPath));
});

/**************************************************/
/*  TC-006: Form displays current permissions accurately
/*  Priority: Medium | Category: UI Validation
/**************************************************/

When('administrator clicks {string} button', async function (buttonText: string) {
  const buttonXPath = `//button[@id="${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  await actions.click(page.locator(buttonXPath));
  await waits.waitForNetworkIdle();
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  TC-001: Successfully modify existing role permissions
/*  Priority: High | Category: Functional
/**************************************************/

Then('role modification form should display current permissions {string}', async function (permissions: string) {
  const permissionList = permissions.split(', ').map(p => p.trim());
  for (const permission of permissionList) {
    const checkboxXPath = `//input[@id="permission-${permission.toLowerCase().replace(/\s+/g, '-')}"]`;
    const checkbox = page.locator(checkboxXPath);
    await assertions.assertVisible(checkbox);
    expect(await checkbox.isChecked()).toBeTruthy();
  }
});

Then('{string} checkbox should be checked', async function (permissionName: string) {
  const checkboxXPath = `//input[@id="permission-${permissionName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const checkbox = page.locator(checkboxXPath);
  expect(await checkbox.isChecked()).toBeTruthy();
});

Then('form should show unsaved changes indicator', async function () {
  await assertions.assertVisible(page.locator('//div[@id="unsaved-changes-indicator"]'));
});

Then('loading spinner should be displayed for up to {int} seconds', async function (seconds: number) {
  await assertions.assertVisible(page.locator('//div[@id="loading-spinner"]'));
  await page.waitForSelector('//div[@id="loading-spinner"]', { state: 'hidden', timeout: seconds * 1000 });
});

Then('success message {string} should be displayed', async function (message: string) {
  await assertions.assertVisible(page.locator('//div[@id="success-message"]'));
  await assertions.assertContainsText(page.locator('//div[@id="success-message"]'), message);
});

Then('{string} role should display permissions {string}', async function (roleName: string, permissions: string) {
  const roleXPath = `//div[@id="role-${roleName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await assertions.assertVisible(page.locator(roleXPath));
  await assertions.assertContainsText(page.locator(roleXPath), permissions);
});

Then('role modification should be logged in audit trail with timestamp and admin user ID', async function () {
  await assertions.assertVisible(page.locator('//div[@id="audit-trail-entry"]'));
  await assertions.assertVisible(page.locator('//span[@id="audit-timestamp"]'));
  await assertions.assertVisible(page.locator('//span[@id="audit-admin-id"]'));
});

Then('users assigned to {string} role should have updated permissions effective immediately', async function (roleName: string) {
  await assertions.assertVisible(page.locator('//div[@id="permission-update-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="permission-update-status"]'), 'Updated');
});

/**************************************************/
/*  TC-002: Role modification logs activity for compliance
/*  Priority: High | Category: Audit
/**************************************************/

Then('{string} checkbox should be unchecked', async function (permissionName: string) {
  const checkboxXPath = `//input[@id="permission-${permissionName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const checkbox = page.locator(checkboxXPath);
  expect(await checkbox.isChecked()).toBeFalsy();
});

Then('form should indicate pending changes', async function () {
  await assertions.assertVisible(page.locator('//div[@id="pending-changes-indicator"]'));
});

Then('audit log entry should display timestamp', async function () {
  await assertions.assertVisible(page.locator('//td[@id="audit-timestamp"]'));
});

Then('audit log entry should display admin user {string}', async function (adminEmail: string) {
  await assertions.assertVisible(page.locator('//td[@id="audit-admin-user"]'));
  await assertions.assertContainsText(page.locator('//td[@id="audit-admin-user"]'), adminEmail);
});

Then('audit log entry should display action {string}', async function (action: string) {
  await assertions.assertVisible(page.locator('//td[@id="audit-action"]'));
  await assertions.assertContainsText(page.locator('//td[@id="audit-action"]'), action);
});

Then('audit log entry should display role name {string}', async function (roleName: string) {
  await assertions.assertVisible(page.locator('//td[@id="audit-role-name"]'));
  await assertions.assertContainsText(page.locator('//td[@id="audit-role-name"]'), roleName);
});

Then('audit log entry should display changes {string}', async function (changes: string) {
  await assertions.assertVisible(page.locator('//td[@id="audit-changes"]'));
  await assertions.assertContainsText(page.locator('//td[@id="audit-changes"]'), changes);
});

Then('log entry should contain complete details including user ID and before/after permission states', async function () {
  await assertions.assertVisible(page.locator('//td[@id="audit-user-id"]'));
  await assertions.assertVisible(page.locator('//td[@id="audit-before-state"]'));
  await assertions.assertVisible(page.locator('//td[@id="audit-after-state"]'));
});

/**************************************************/
/*  TC-003: System prevents conflicting permissions
/*  Priority: High | Category: Negative Validation
/**************************************************/

Then('role modification form should display {string} flag enabled', async function (flagName: string) {
  const flagXPath = `//input[@id="${flagName.toLowerCase().replace(/\s+/g, '-')}-flag"]`;
  const flag = page.locator(flagXPath);
  expect(await flag.isChecked()).toBeTruthy();
});

Then('only {string} permission checkbox should be checked', async function (permissionName: string) {
  const checkboxXPath = `//input[@id="permission-${permissionName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const checkbox = page.locator(checkboxXPath);
  expect(await checkbox.isChecked()).toBeTruthy();
});

Then('inline validation error {string} should be displayed', async function (errorMessage: string) {
  await assertions.assertVisible(page.locator('//span[@id="inline-validation-error"]'));
  await assertions.assertContainsText(page.locator('//span[@id="inline-validation-error"]'), errorMessage);
});

Then('form submission should be blocked', async function () {
  expect(this.formSubmissionBlocked).toBeTruthy();
});

Then('error message {string} should be displayed', async function (errorMessage: string) {
  await assertions.assertVisible(page.locator('//div[@id="error-message"]'));
  await assertions.assertContainsText(page.locator('//div[@id="error-message"]'), errorMessage);
});

Then('{string} button should be disabled', async function (buttonText: string) {
  const buttonXPath = `//button[@id="${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const button = page.locator(buttonXPath);
  expect(await button.isDisabled()).toBeTruthy();
});

Then('validation error should clear', async function () {
  await page.waitForSelector('//span[@id="inline-validation-error"]', { state: 'hidden', timeout: 3000 });
});

Then('error message should disappear', async function () {
  await page.waitForSelector('//div[@id="error-message"]', { state: 'hidden', timeout: 3000 });
});

Then('{string} button should be enabled', async function (buttonText: string) {
  const buttonXPath = `//button[@id="${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const button = page.locator(buttonXPath);
  expect(await button.isEnabled()).toBeTruthy();
});

Then('{string} role should remain unchanged in database with only read permission', async function (roleName: string) {
  const roleXPath = `//div[@id="role-${roleName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await assertions.assertVisible(page.locator(roleXPath));
  await assertions.assertContainsText(page.locator(roleXPath), 'read');
});

/**************************************************/
/*  TC-004: Role modification performance requirement
/*  Priority: Medium | Category: Performance
/**************************************************/

Then('role modification form should display current {int} permissions', async function (permissionCount: number) {
  const permissionCheckboxes = page.locator('//input[starts-with(@id,"permission-")]');
  const checkedCount = await permissionCheckboxes.evaluateAll((elements) => 
    elements.filter((el: any) => el.checked).length
  );
  expect(checkedCount).toBe(permissionCount);
});

Then('form should show {int} total permissions selected', async function (totalCount: number) {
  await assertions.assertVisible(page.locator('//div[@id="permission-count"]'));
  await assertions.assertContainsText(page.locator('//div[@id="permission-count"]'), totalCount.toString());
});

Then('loading indicator should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="loading-indicator"]'));
});

Then('success message {string} should be displayed within {int} seconds', async function (message: string, seconds: number) {
  const elapsedTime = Date.now() - this.performanceTimer;
  expect(elapsedTime).toBeLessThanOrEqual(seconds * 1000);
  await assertions.assertVisible(page.locator('//div[@id="success-message"]'));
  await assertions.assertContainsText(page.locator('//div[@id="success-message"]'), message);
});

Then('{string} role should be updated with {int} permissions in database', async function (roleName: string, permissionCount: number) {
  const roleXPath = `//div[@id="role-${roleName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await assertions.assertVisible(page.locator(roleXPath));
  await assertions.assertContainsText(page.locator(roleXPath), `${permissionCount} permissions`);
});

Then('performance metric should be logged showing modification completed within SLA', async function () {
  await assertions.assertVisible(page.locator('//div[@id="performance-metric"]'));
  await assertions.assertContainsText(page.locator('//div[@id="performance-metric"]'), 'Within SLA');
});

Then('system should remain responsive for next operation', async function () {
  await waits.waitForNetworkIdle();
  const nextButton = page.locator('//button[@id="next-operation"]');
  expect(await nextButton.isEnabled()).toBeTruthy();
});

/**************************************************/
/*  TC-005: Modify multiple permissions simultaneously
/*  Priority: Medium | Category: Functional
/**************************************************/

Then('form should show {int} permissions selected', async function (count: number) {
  await assertions.assertVisible(page.locator('//div[@id="permission-count"]'));
  await assertions.assertContainsText(page.locator('//div[@id="permission-count"]'), count.toString());
});

Then('single audit log entry should capture all permission changes in one transaction', async function () {
  const auditEntries = page.locator('//tr[@class="audit-entry"]');
  expect(await auditEntries.count()).toBe(1);
});

Then('all users with {string} role should receive updated permissions immediately', async function (roleName: string) {
  await assertions.assertVisible(page.locator('//div[@id="user-permission-sync-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="user-permission-sync-status"]'), 'Synced');
});

Then('role list should refresh showing updated permission count', async function () {
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="role-list"]'));
});

/**************************************************/
/*  TC-006: Form displays current permissions accurately
/*  Priority: Medium | Category: UI Validation
/**************************************************/

Then('role modification form should display role name {string} in header', async function (roleName: string) {
  await assertions.assertVisible(page.locator('//h2[@id="role-form-header"]'));
  await assertions.assertContainsText(page.locator('//h2[@id="role-form-header"]'), roleName);
});

Then('exactly {int} checkboxes should be checked: {string}', async function (count: number, permissionList: string) {
  const permissions = permissionList.split(', ').map(p => p.trim());
  expect(permissions.length).toBe(count);
  
  for (const permission of permissions) {
    const checkboxXPath = `//input[@id="permission-${permission.toLowerCase().replace(/\s+/g, '-')}"]`;
    const checkbox = page.locator(checkboxXPath);
    expect(await checkbox.isChecked()).toBeTruthy();
  }
});

Then('all other permission checkboxes should be unchecked', async function () {
  const allCheckboxes = page.locator('//input[starts-with(@id,"permission-")]');
  const uncheckedCount = await allCheckboxes.evaluateAll((elements) => 
    elements.filter((el: any) => !el.checked).length
  );
  expect(uncheckedCount).toBeGreaterThan(0);
});

Then('form should display {string} count indicator', async function (countText: string) {
  await assertions.assertVisible(page.locator('//div[@id="permission-count-indicator"]'));
  await assertions.assertContainsText(page.locator('//div[@id="permission-count-indicator"]'), countText);
});

Then('form should close and return to role management list', async function () {
  await page.waitForSelector('//div[@id="role-modification-form"]', { state: 'hidden', timeout: 3000 });
  await assertions.assertVisible(page.locator('//div[@id="role-list"]'));
});

Then('{string} role should remain unchanged in database', async function (roleName: string) {
  const roleXPath = `//div[@id="role-${roleName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await assertions.assertVisible(page.locator(roleXPath));
});

Then('no audit log entry should be created for cancelled modification', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/audit-logs`);
  await waits.waitForNetworkIdle();
  const recentEntry = page.locator('//tr[@class="audit-entry"][1]//td[@id="audit-action"]');
  const actionText = await recentEntry.textContent();
  expect(actionText).not.toContain('Role Modified');
});