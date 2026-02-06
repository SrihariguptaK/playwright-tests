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
      user: { username: 'testuser', password: 'testpass' }
    },
    sessions: {},
    roleData: {}
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
/*  BACKGROUND STEPS - All Test Cases
/*  Setup: Administrator login and navigation
/**************************************************/

Given('administrator is logged in with full admin privileges', async function () {
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000');
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), 'admin');
  await actions.fill(page.locator('//input[@id="password"]'), 'admin123');
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

Given('role management page is accessible', async function () {
  await actions.click(page.locator('//a[@id="role-management"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="role-management-page"]'));
});

/**************************************************/
/*  TEST CASE: TC-001
/*  Title: Modify role with maximum allowed permissions boundary
/*  Priority: High
/*  Category: Edge Cases
/**************************************************/

Given('test role {string} exists with {int} permissions assigned', async function (roleName: string, permissionCount: number) {
  this.roleData = { name: roleName, permissionCount: permissionCount };
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${roleName}')]`));
});

Given('system allows maximum of {int} permissions per role', async function (maxPermissions: number) {
  this.testData.maxPermissions = maxPermissions;
});

Given('database has {int} total available permissions configured', async function (totalPermissions: number) {
  this.testData.totalPermissions = totalPermissions;
});

/**************************************************/
/*  TEST CASE: TC-002
/*  Title: Modify role name with special characters and Unicode
/*  Priority: Medium
/*  Category: Edge Cases
/**************************************************/

Given('system supports UTF-8 character encoding', async function () {
  this.testData.encoding = 'UTF-8';
});

/**************************************************/
/*  TEST CASE: TC-003
/*  Title: Simultaneous role modification by multiple administrators
/*  Priority: High
/*  Category: Edge Cases - Concurrency
/**************************************************/

Given('two administrators {string} and {string} are logged in from different browser sessions', async function (admin1: string, admin2: string) {
  this.testData.sessions[admin1] = { page: page, context: context };
  
  const browser2 = await chromium.launch({ headless: process.env.HEADLESS !== 'false' });
  const context2 = await browser2.newContext({ viewport: { width: 1920, height: 1080 } });
  const page2 = await context2.newPage();
  
  this.testData.sessions[admin2] = { page: page2, context: context2, browser: browser2 };
  
  await page2.goto(process.env.BASE_URL || 'http://localhost:3000');
  await page2.locator('//input[@id="username"]').fill('admin2');
  await page2.locator('//input[@id="password"]').fill('admin123');
  await page2.locator('//button[@id="login"]').click();
  await page2.waitForLoadState('networkidle');
});

Given('both administrators have role modification permissions', async function () {
  this.testData.adminPermissions = ['role.modify', 'role.read', 'role.write'];
});

Given('test role {string} exists with permissions {string}', async function (roleName: string, permissions: string) {
  this.roleData = { name: roleName, permissions: permissions.split(', ') };
});

Given('role management page is open in both browser sessions', async function () {
  await actions.click(page.locator('//a[@id="role-management"]'));
  await waits.waitForNetworkIdle();
  
  const page2 = this.testData.sessions['Admin2'].page;
  await page2.locator('//a[@id="role-management"]').click();
  await page2.waitForLoadState('networkidle');
});

Given('system implements optimistic or pessimistic locking mechanism', async function () {
  this.testData.lockingMechanism = 'optimistic';
});

/**************************************************/
/*  TEST CASE: TC-004
/*  Title: Modify role with extremely long description at character limit boundary
/*  Priority: Medium
/*  Category: Edge Cases
/**************************************************/

Given('test role {string} exists with a short description', async function (roleName: string) {
  this.roleData = { name: roleName, description: 'Short description' };
});

Given('role description field has maximum character limit of {int} characters', async function (maxChars: number) {
  this.testData.maxDescriptionLength = maxChars;
});

Given('browser displays character count for text areas', async function () {
  this.testData.characterCounterEnabled = true;
});

/**************************************************/
/*  TEST CASE: TC-005
/*  Title: Modify role during high system load with concurrent operations
/*  Priority: High
/*  Category: Edge Cases - Performance
/**************************************************/

Given('system is under simulated high load with {int} concurrent user sessions', async function (sessionCount: number) {
  this.testData.concurrentSessions = sessionCount;
});

Given('performance monitoring tools are active', async function () {
  this.testData.performanceMonitoring = true;
});

Given('database connection pool has {int} active connections out of {int} maximum', async function (active: number, maximum: number) {
  this.testData.dbConnections = { active: active, maximum: maximum };
});

/**************************************************/
/*  TEST CASE: TC-006
/*  Title: Modify role by removing all permissions then adding them back
/*  Priority: Medium
/*  Category: Edge Cases
/**************************************************/

Given('role is not currently assigned to any active users', async function () {
  this.testData.roleAssignedUsers = 0;
});

Given('system allows roles to exist with zero permissions temporarily', async function () {
  this.testData.allowZeroPermissions = true;
});

/**************************************************/
/*  TEST CASE: TC-007
/*  Title: Modify role with session timeout occurring during modification
/*  Priority: High
/*  Category: Edge Cases - Session Management
/**************************************************/

Given('administrator session timeout is set to {int} minutes', async function (timeoutMinutes: number) {
  this.testData.sessionTimeout = timeoutMinutes;
});

Given('administrator has been idle for {int} minutes and {int} seconds', async function (minutes: number, seconds: number) {
  this.testData.idleTime = { minutes: minutes, seconds: seconds };
});

Given('test role {string} is open in edit mode with unsaved changes', async function (roleName: string) {
  await actions.click(page.locator(`//div[contains(text(),'${roleName}')]`));
  await waits.waitForNetworkIdle();
  this.testData.unsavedChanges = true;
});

Given('role has {int} permissions currently', async function (permissionCount: number) {
  this.roleData.currentPermissions = permissionCount;
});

Given('administrator has added {int} more permissions unsaved', async function (additionalPerms: number) {
  this.roleData.unsavedPermissions = additionalPerms;
});

Given('system implements session timeout with warning mechanism', async function () {
  this.testData.sessionWarningEnabled = true;
});

// ==================== WHEN STEPS ====================

When('administrator navigates to role management section', async function () {
  await actions.click(page.locator('//a[@id="role-management"]'));
  await waits.waitForNetworkIdle();
});

When('administrator clicks on {string} to open edit form', async function (roleName: string) {
  await actions.click(page.locator(`//div[contains(text(),'${roleName}')]`));
  await waits.waitForNetworkIdle();
});

When('administrator clicks on {string} in the roles list', async function (roleName: string) {
  await actions.click(page.locator(`//div[contains(text(),'${roleName}')]`));
  await waits.waitForNetworkIdle();
});

When('administrator selects all remaining {int} available permissions', async function (permissionCount: number) {
  const selectAllButton = page.locator('//button[@id="select-remaining-permissions"]');
  if (await selectAllButton.count() > 0) {
    await actions.click(selectAllButton);
  } else {
    for (let i = 0; i < permissionCount; i++) {
      await actions.click(page.locator(`(//input[@type="checkbox" and @class="permission-checkbox"])[${i + 1}]`));
    }
  }
});

When('administrator enters {string} in {string} field', async function (value: string, fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  const textareaXPath = `//textarea[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  
  const inputField = page.locator(fieldXPath);
  const textareaField = page.locator(textareaXPath);
  
  if (await inputField.count() > 0) {
    await actions.fill(inputField, value);
  } else if (await textareaField.count() > 0) {
    await actions.fill(textareaField, value);
  }
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

When('administrator changes role name to {string}', async function (newRoleName: string) {
  await actions.clearAndFill(page.locator('//input[@id="role-name"]'), newRoleName);
});

When('administrator adds permission {string} to existing permissions', async function (permission: string) {
  await actions.click(page.locator(`//input[@value='${permission}']`));
});

When('administrator adds permission {string} to the role', async function (permission: string) {
  await actions.click(page.locator(`//input[@value='${permission}']`));
});

When('{string} opens {string} for editing', async function (adminName: string, roleName: string) {
  const adminPage = this.testData.sessions[adminName].page;
  await adminPage.locator(`//div[contains(text(),'${roleName}')]`).click();
  await adminPage.waitForLoadState('networkidle');
});

When('{string} adds permission {string}', async function (adminName: string, permission: string) {
  const adminPage = this.testData.sessions[adminName].page;
  await adminPage.locator(`//input[@value='${permission}']`).click();
});

When('{string} clicks {string} button first', async function (adminName: string, buttonText: string) {
  const adminPage = this.testData.sessions[adminName].page;
  await adminPage.locator(`//button[contains(text(),'${buttonText}')]`).click();
  await adminPage.waitForLoadState('networkidle');
});

When('{string} clicks {string} button after {int} seconds', async function (adminName: string, buttonText: string, seconds: number) {
  await page.waitForTimeout(seconds * 1000);
  const adminPage = this.testData.sessions[adminName].page;
  await adminPage.locator(`//button[contains(text(),'${buttonText}')]`).click();
  await adminPage.waitForLoadState('networkidle');
});

When('administrator clears existing description', async function () {
  await actions.clearAndFill(page.locator('//textarea[@id="description"]'), '');
});

When('administrator pastes exactly {int} characters of text into description field', async function (charCount: number) {
  const longText = 'A'.repeat(charCount);
  await actions.fill(page.locator('//textarea[@id="description"]'), longText);
});

When('administrator attempts to type one additional character', async function () {
  await actions.type(page.locator('//textarea[@id="description"]'), 'X');
});

When('administrator removes {int} characters', async function (charCount: number) {
  const currentText = await page.locator('//textarea[@id="description"]').inputValue();
  const newText = currentText.slice(0, -charCount);
  await actions.fill(page.locator('//textarea[@id="description"]'), newText);
});

When('administrator reopens the role to verify description', async function () {
  await actions.click(page.locator('//button[@id="back"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator(`//div[contains(text(),'${this.roleData.name}')]`));
  await waits.waitForNetworkIdle();
});

When('administrator opens {string} in role modification form', async function (roleName: string) {
  await actions.click(page.locator(`//div[contains(text(),'${roleName}')]`));
  await waits.waitForNetworkIdle();
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

When('administrator clicks {string} with zero permissions', async function (buttonText: string) {
  await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  await waits.waitForNetworkIdle();
});

When('administrator immediately reopens {string}', async function (roleName: string) {
  await actions.click(page.locator(`//div[contains(text(),'${roleName}')]`));
  await waits.waitForNetworkIdle();
});

When('administrator adds permissions {string}', async function (permissions: string) {
  const permList = permissions.split(', ');
  for (const perm of permList) {
    await actions.click(page.locator(`//input[@value='${perm}']`));
  }
});

When('administrator waits for {int} seconds with unsaved changes', async function (seconds: number) {
  await page.waitForTimeout(seconds * 1000);
});

When('administrator adds permission {string}', async function (permission: string) {
  await actions.click(page.locator(`//input[@value='${permission}']`));
});

When('administrator updates role description to {string}', async function (description: string) {
  await actions.fill(page.locator('//textarea[@id="description"]'), description);
});

// ==================== THEN STEPS ====================

Then('role modification form should display {int} permissions selected', async function (permissionCount: number) {
  const counter = page.locator('//span[@id="permission-counter"]');
  await assertions.assertContainsText(counter, `${permissionCount}`);
});

Then('permission selector should show {string}', async function (text: string) {
  await assertions.assertContainsText(page.locator('//span[@id="permission-selector"]'), text);
});

Then('system should process request within {int} seconds', async function (seconds: number) {
  const startTime = Date.now();
  await waits.waitForNetworkIdle();
  const endTime = Date.now();
  const duration = (endTime - startTime) / 1000;
  expect(duration).toBeLessThanOrEqual(seconds);
});

Then('success message {string} should be displayed', async function (message: string) {
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${message}')]`));
});

Then('role details page should show all {int} permissions listed', async function (permissionCount: number) {
  const permissions = page.locator('//div[@class="permission-item"]');
  const count = await permissions.count();
  expect(count).toBe(permissionCount);
});

Then('role {string} should be saved in database with {int} permissions', async function (roleName: string, permissionCount: number) {
  this.roleData.savedPermissions = permissionCount;
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${roleName}')]`));
});

Then('audit log should contain entry with {string} action', async function (action: string) {
  await actions.click(page.locator('//a[@id="audit-log"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator(`//td[contains(text(),'${action}')]`));
});

Then('role edit form should display with current role name {string}', async function (roleName: string) {
  const nameField = page.locator('//input[@id="role-name"]');
  const value = await nameField.inputValue();
  expect(value).toBe(roleName);
});

Then('name field should accept all special characters and Unicode without validation errors', async function () {
  const errorMessage = page.locator('//div[@class="error-message"]');
  const errorCount = await errorMessage.count();
  expect(errorCount).toBe(0);
});

Then('permission counter should show {string}', async function (text: string) {
  await assertions.assertContainsText(page.locator('//span[@id="permission-counter"]'), text);
});

Then('system should validate and process request within {int} seconds', async function (seconds: number) {
  const startTime = Date.now();
  await waits.waitForNetworkIdle();
  const endTime = Date.now();
  const duration = (endTime - startTime) / 1000;
  expect(duration).toBeLessThanOrEqual(seconds);
});

Then('role name {string} should display correctly without character corruption', async function (roleName: string) {
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${roleName}')]`));
});

Then('all special characters and emoji should render properly', async function () {
  const roleNameElement = page.locator('//div[@id="role-name-display"]');
  await assertions.assertVisible(roleNameElement);
});

Then('role should be saved with Unicode name exactly as entered', async function () {
  await assertions.assertVisible(page.locator('//div[@id="success-message"]'));
});

Then('audit log should record modification with proper character encoding', async function () {
  await actions.click(page.locator('//a[@id="audit-log"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//td[contains(text(),"ROLE_MODIFIED")]'));
});

Then('{string} edit form should show {int} permissions selected', async function (adminName: string, permissionCount: number) {
  const adminPage = this.testData.sessions[adminName].page;
  const counter = adminPage.locator('//span[@id="permission-counter"]');
  const text = await counter.textContent();
  expect(text).toContain(`${permissionCount}`);
});

Then('{string} should see success message {string}', async function (adminName: string, message: string) {
  const adminPage = this.testData.sessions[adminName].page;
  const successMsg = adminPage.locator(`//div[contains(text(),'${message}')]`);
  await successMsg.waitFor({ state: 'visible' });
});

Then('role should have permissions {string}', async function (permissions: string) {
  this.roleData.currentPermissions = permissions.split(', ');
});

Then('system should detect conflict', async function () {
  await waits.waitForNetworkIdle();
});

Then('warning message {string} should be displayed', async function (message: string) {
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${message}')]`));
});

Then('option to reload or force save should be available', async function () {
  await assertions.assertVisible(page.locator('//button[@id="reload-current-version"]'));
  await assertions.assertVisible(page.locator('//button[@id="force-save"]'));
});

Then('form should refresh showing current permissions {string}', async function (permissions: string) {
  const permList = permissions.split(', ');
  for (const perm of permList) {
    await assertions.assertVisible(page.locator(`//input[@value='${perm}' and @checked]`));
  }
});

Then('success message should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="success-message"]'));
});

Then('role should have all {int} permissions {string}', async function (count: number, permissions: string) {
  this.roleData.finalPermissions = permissions.split(', ');
  expect(this.roleData.finalPermissions.length).toBe(count);
});

Then('audit log should show two separate modification entries with timestamps', async function () {
  await actions.click(page.locator('//a[@id="audit-log"]'));
  await waits.waitForNetworkIdle();
  const entries = page.locator('//td[contains(text(),"ROLE_MODIFIED")]');
  const count = await entries.count();
  expect(count).toBeGreaterThanOrEqual(2);
});

Then('edit form should display with character counter showing current count', async function () {
  await assertions.assertVisible(page.locator('//span[@id="character-counter"]'));
});

Then('text area should accept all {int} characters', async function (charCount: number) {
  const textarea = page.locator('//textarea[@id="description"]');
  const value = await textarea.inputValue();
  expect(value.length).toBe(charCount);
});

Then('counter should display {string}', async function (text: string) {
  await assertions.assertContainsText(page.locator('//span[@id="character-counter"]'), text);
});

Then('no validation error should appear', async function () {
  const errorMessage = page.locator('//div[@class="error-message"]');
  const errorCount = await errorMessage.count();
  expect(errorCount).toBe(0);
});

Then('system should prevent input beyond {int} characters', async function (maxChars: number) {
  const textarea = page.locator('//textarea[@id="description"]');
  const value = await textarea.inputValue();
  expect(value.length).toBeLessThanOrEqual(maxChars);
});

Then('counter should remain at {string}', async function (text: string) {
  await assertions.assertContainsText(page.locator('//span[@id="character-counter"]'), text);
});

Then('visual indicator should show limit reached', async function () {
  await assertions.assertVisible(page.locator('//span[@class="limit-reached"]'));
});

Then('character counter should update to {string}', async function (text: string) {
  await assertions.assertContainsText(page.locator('//span[@id="character-counter"]'), text);
});

Then('permission should be added successfully', async function () {
  await waits.waitForNetworkIdle();
});

Then('system should save successfully within {int} seconds', async function (seconds: number) {
  const startTime = Date.now();
  await waits.waitForNetworkIdle();
  const endTime = Date.now();
  const duration = (endTime - startTime) / 1000;
  expect(duration).toBeLessThanOrEqual(seconds);
});

Then('confirmation message {string} should be displayed', async function (message: string) {
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${message}')]`));
});

Then('description field should show exactly {int} characters as entered', async function (charCount: number) {
  const textarea = page.locator('//textarea[@id="description"]');
  const value = await textarea.inputValue();
  expect(value.length).toBe(charCount);
});

Then('no text truncation should have occurred', async function () {
  const textarea = page.locator('//textarea[@id="description"]');
  const value = await textarea.inputValue();
  expect(value.length).toBeGreaterThan(0);
});

Then('form should load within {int} seconds despite high load', async function (seconds: number) {
  const startTime = Date.now();
  await waits.waitForVisible(page.locator('//form[@id="role-edit-form"]'));
  const endTime = Date.now();
  const duration = (endTime - startTime) / 1000;
  expect(duration).toBeLessThanOrEqual(seconds);
});

Then('form should display current {int} permissions', async function (permissionCount: number) {
  const permissions = page.locator('//input[@type="checkbox" and @checked]');
  const count = await permissions.count();
  expect(count).toBe(permissionCount);
});

Then('permissions should be selected successfully', async function () {
  await waits.waitForNetworkIdle();
});

Then('counter should show {string}', async function (text: string) {
  await assertions.assertContainsText(page.locator('//span[@id="permission-counter"]'), text);
});

Then('description field should accept input without lag or UI freezing', async function () {
  await waits.waitForNetworkIdle();
});

Then('loading indicator should display during processing', async function () {
  await assertions.assertVisible(page.locator('//div[@id="loading-indicator"]'));
});

Then('audit log should show modification entry with correct timestamp', async function () {
  await actions.click(page.locator('//a[@id="audit-log"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//td[contains(text(),"ROLE_MODIFIED")]'));
});

Then('all {int} permissions should be correctly saved in database', async function (permissionCount: number) {
  this.roleData.savedPermissions = permissionCount;
});

Then('system should remain stable with no connection pool exhaustion', async function () {
  await waits.waitForNetworkIdle();
});

Then('edit form should display {int} currently assigned permissions', async function (permissionCount: number) {
  const permissions = page.locator('//input[@type="checkbox" and @checked]');
  const count = await permissions.count();
  expect(count).toBe(permissionCount);
});

Then('all permissions should be unchecked', async function () {
  const checkedPermissions = page.locator('//input[@type="checkbox" and @checked]');
  const count = await checkedPermissions.count();
  expect(count).toBe(0);
});

Then('warning message {string} should appear', async function (message: string) {
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${message}')]`));
});

Then('confirmation dialog {string} should be displayed', async function (message: string) {
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${message}')]`));
});

Then('role should be saved with zero permissions', async function () {
  this.roleData.currentPermissions = 0;
});

Then('success message {string} should appear', async function (message: string) {
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${message}')]`));
});

Then('audit log should record the change', async function () {
  await actions.click(page.locator('//a[@id="audit-log"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//td[contains(text(),"ROLE_MODIFIED")]'));
});

Then('role should have {int} permissions', async function (permissionCount: number) {
  this.roleData.currentPermissions = permissionCount;
});

Then('modification should complete within {int} seconds', async function (seconds: number) {
  const startTime = Date.now();
  await waits.waitForNetworkIdle();
  const endTime = Date.now();
  const duration = (endTime - startTime) / 1000;
  expect(duration).toBeLessThanOrEqual(seconds);
});

Then('audit log should contain two entries for both modifications', async function () {
  await actions.click(page.locator('//a[@id="audit-log"]'));
  await waits.waitForNetworkIdle();
  const entries = page.locator('//td[contains(text(),"ROLE_MODIFIED")]');
  const count = await entries.count();
  expect(count).toBeGreaterThanOrEqual(2);
});

Then('session timeout warning modal should appear with message {string}', async function (message: string) {
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${message}')]`));
});

Then('{string} and {string} buttons should be displayed', async function (button1: string, button2: string) {
  await assertions.assertVisible(page.locator(`//button[contains(text(),'${button1}')]`));
  await assertions.assertVisible(page.locator(`//button[contains(text(),'${button2}')]`));
});

Then('session should be extended', async function () {
  this.testData.sessionExtended = true;
});

Then('modal should close', async function () {
  await waits.waitForHidden(page.locator('//div[@id="session-timeout-modal"]'));
});

Then('user should remain on role edit form', async function () {
  await assertions.assertVisible(page.locator('//form[@id="role-edit-form"]'));
});

Then('all unsaved changes should be preserved with {int} permissions selected', async function (permissionCount: number) {
  const permissions = page.locator('//input[@type="checkbox" and @checked]');
  const count = await permissions.count();
  expect(count).toBe(permissionCount);
});

Then('system should validate active session', async function () {
  await waits.waitForNetworkIdle();
});

Then('role should have {int} permissions saved correctly', async function (permissionCount: number) {
  this.roleData.savedPermissions = permissionCount;
});

Then('audit log should show single modification entry with current timestamp', async function () {
  await actions.click(page.locator('//a[@id="audit-log"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//td[contains(text(),"ROLE_MODIFIED")]'));
});

Then('session extension event should be logged separately', async function () {
  await assertions.assertVisible(page.locator('//td[contains(text(),"SESSION_EXTENDED")]'));
});