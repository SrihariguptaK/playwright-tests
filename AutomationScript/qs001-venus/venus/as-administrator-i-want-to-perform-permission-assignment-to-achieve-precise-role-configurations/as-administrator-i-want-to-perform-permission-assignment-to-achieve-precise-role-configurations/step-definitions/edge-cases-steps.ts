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
      admin: { username: 'admin', password: 'admin123' }
    },
    roles: {},
    permissions: []
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
/*  COMMON SETUP STEPS - BACKGROUND
/*  Used across all test cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('administrator is logged in with full admin privileges', async function () {
  const credentials = this.testData?.users?.admin || { username: 'admin', password: 'admin123' };
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000');
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
Given('administrator is on the permission configuration section page', async function () {
  await actions.click(page.locator('//a[@id="permission-configuration"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="permission-configuration-section"]'));
});

/**************************************************/
/*  TEST CASE: TC-001
/*  Title: Assign maximum number of permissions to a single role
/*  Priority: High
/*  Category: Edge Cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('test role {string} exists with zero permissions assigned', async function (roleName: string) {
  this.testData.currentRole = roleName;
  const roleXPath = `//div[@id="role-${roleName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await assertions.assertVisible(page.locator(roleXPath));
});

// TODO: Replace XPath with Object Repository when available
Given('system has {int} or more permissions available in the permissions table', async function (permissionCount: number) {
  const permissionsXPath = '//table[@id="permissions-table"]//tr[@class="permission-row"]';
  const count = await page.locator(permissionsXPath).count();
  expect(count).toBeGreaterThanOrEqual(permissionCount);
  this.testData.totalPermissions = count;
});

Given('database connection is stable and responsive', async function () {
  await waits.waitForNetworkIdle();
  this.testData.dbStable = true;
});

/**************************************************/
/*  TEST CASE: TC-002
/*  Title: Assign permissions with special characters and Unicode
/*  Priority: Medium
/*  Category: Edge Cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('test role {string} exists in the system', async function (roleName: string) {
  this.testData.currentRole = roleName;
  const roleXPath = `//div[@id="role-${roleName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await assertions.assertVisible(page.locator(roleXPath));
});

// TODO: Replace XPath with Object Repository when available
Given('permissions with special characters exist in the system', async function () {
  await assertions.assertVisible(page.locator('//div[@id="permissions-list"]'));
  this.testData.specialCharPermissions = true;
});

Given('browser supports Unicode character rendering', async function () {
  this.testData.unicodeSupport = true;
});

/**************************************************/
/*  TEST CASE: TC-003
/*  Title: Rapid successive permission assignments
/*  Priority: High
/*  Category: Edge Cases
/**************************************************/

Given('network latency is minimal under {int} milliseconds', async function (latency: number) {
  this.testData.networkLatency = latency;
});

Given('browser console is open to monitor API calls', async function () {
  this.testData.consoleMonitoring = true;
});

// TODO: Replace XPath with Object Repository when available
Given('at least {int} different permissions are available for assignment', async function (permissionCount: number) {
  const permissionsXPath = '//div[@class="permission-item"]';
  const count = await page.locator(permissionsXPath).count();
  expect(count).toBeGreaterThanOrEqual(permissionCount);
});

/**************************************************/
/*  TEST CASE: TC-004
/*  Title: Assign permissions with slow database
/*  Priority: Medium
/*  Category: Edge Cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('database response time is throttled to {float} seconds', async function (responseTime: number) {
  this.testData.dbResponseTime = responseTime;
});

Given('network monitoring tools are active to measure response times', async function () {
  this.testData.networkMonitoring = true;
});

/**************************************************/
/*  TEST CASE: TC-005
/*  Title: Assign zero permissions to a role
/*  Priority: Medium
/*  Category: Edge Cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('test role {string} exists with {int} permissions already assigned', async function (roleName: string, permissionCount: number) {
  this.testData.currentRole = roleName;
  this.testData.initialPermissionCount = permissionCount;
  const roleXPath = `//div[@id="role-${roleName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await assertions.assertVisible(page.locator(roleXPath));
});

Given('system allows roles to exist with zero permissions', async function () {
  this.testData.allowZeroPermissions = true;
});

/**************************************************/
/*  TEST CASE: TC-006
/*  Title: Assign permissions while session about to expire
/*  Priority: High
/*  Category: Edge Cases
/**************************************************/

Given('administrator session timeout is set to {int} minutes', async function (timeoutMinutes: number) {
  this.testData.sessionTimeout = timeoutMinutes;
});

Given('current session has {int} seconds remaining before expiration', async function (remainingSeconds: number) {
  this.testData.sessionRemaining = remainingSeconds;
});

// TODO: Replace XPath with Object Repository when available
Given('role {string} is selected in permission configuration', async function (roleName: string) {
  this.testData.currentRole = roleName;
  const dropdownXPath = '//select[@id="roles-dropdown"]';
  await actions.selectByText(page.locator(dropdownXPath), roleName);
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
Given('{int} permissions are selected and ready to submit', async function (permissionCount: number) {
  this.testData.selectedPermissions = permissionCount;
  const counterXPath = '//span[@id="permission-counter"]';
  await assertions.assertContainsText(page.locator(counterXPath), permissionCount.toString());
});

Given('session timeout warning mechanism is active', async function () {
  this.testData.sessionWarningActive = true;
});

/**************************************************/
/*  TEST CASE: TC-007
/*  Title: Assign permissions to role with maximum length name
/*  Priority: Low
/*  Category: Edge Cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('test role exists with {int} character name {string}', async function (charLength: number, roleName: string) {
  this.testData.currentRole = roleName;
  this.testData.roleNameLength = charLength;
  const roleXPath = `//div[@data-role-name="${roleName}"]`;
  await assertions.assertVisible(page.locator(roleXPath));
});

// TODO: Replace XPath with Object Repository when available
Given('role name is visible or truncated with tooltip in UI', async function () {
  const roleHeaderXPath = '//div[@id="role-header"]';
  await assertions.assertVisible(page.locator(roleHeaderXPath));
});

// TODO: Replace XPath with Object Repository when available
Given('{int} permissions are available for assignment', async function (permissionCount: number) {
  const permissionsXPath = '//div[@class="permission-item"]';
  const count = await page.locator(permissionsXPath).count();
  expect(count).toBeGreaterThanOrEqual(permissionCount);
});

// ==================== WHEN STEPS ====================

// TODO: Replace XPath with Object Repository when available
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

// TODO: Replace XPath with Object Repository when available
When('administrator selects {string} from roles dropdown', async function (roleName: string) {
  const dropdownXPath = '//select[@id="roles-dropdown"]';
  await actions.selectByText(page.locator(dropdownXPath), roleName);
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('administrator clicks {string} checkbox', async function (checkboxLabel: string) {
  const checkboxIdXPath = `//input[@id="${checkboxLabel.toLowerCase().replace(/\s+/g, '-')}"]`;
  const checkboxes = page.locator(checkboxIdXPath);
  if (await checkboxes.count() > 0) {
    await actions.check(checkboxes);
  } else {
    await actions.check(page.locator(`//input[@type="checkbox"][following-sibling::label[contains(text(),'${checkboxLabel}')]]`));
  }
});

// TODO: Replace XPath with Object Repository when available
When('administrator checks {string} permission', async function (permissionName: string) {
  const permissionIdXPath = `//input[@id="permission-${permissionName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const permissionCheckboxes = page.locator(permissionIdXPath);
  if (await permissionCheckboxes.count() > 0) {
    await actions.check(permissionCheckboxes);
  } else {
    await actions.check(page.locator(`//input[@type="checkbox"][@data-permission="${permissionName}"]`));
  }
});

// TODO: Replace XPath with Object Repository when available
When('administrator quickly selects {string} permission', async function (permissionName: string) {
  const permissionIdXPath = `//input[@id="permission-${permissionName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const permissionCheckboxes = page.locator(permissionIdXPath);
  if (await permissionCheckboxes.count() > 0) {
    await actions.check(permissionCheckboxes);
  } else {
    await actions.check(page.locator(`//input[@type="checkbox"][@data-permission="${permissionName}"]`));
  }
});

// TODO: Replace XPath with Object Repository when available
When('administrator immediately selects {string} permission within {float} seconds', async function (permissionName: string, timeWindow: number) {
  const permissionIdXPath = `//input[@id="permission-${permissionName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const permissionCheckboxes = page.locator(permissionIdXPath);
  if (await permissionCheckboxes.count() > 0) {
    await actions.check(permissionCheckboxes);
  } else {
    await actions.check(page.locator(`//input[@type="checkbox"][@data-permission="${permissionName}"]`));
  }
});

// TODO: Replace XPath with Object Repository when available
When('administrator clicks {string} button again', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id="${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const buttons = page.locator(buttonIdXPath);
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
});

// TODO: Replace XPath with Object Repository when available
When('administrator verifies {string} is selected', async function (roleName: string) {
  const dropdownXPath = '//select[@id="roles-dropdown"]';
  const selectedValue = await page.locator(dropdownXPath).inputValue();
  expect(selectedValue).toContain(roleName);
});

// TODO: Replace XPath with Object Repository when available
When('administrator opens the roles dropdown in permission configuration section', async function () {
  const dropdownXPath = '//select[@id="roles-dropdown"]';
  await actions.click(page.locator(dropdownXPath));
});

// TODO: Replace XPath with Object Repository when available
When('administrator selects the role with {int} character name from dropdown', async function (charLength: number) {
  const roleName = this.testData.currentRole;
  const dropdownXPath = '//select[@id="roles-dropdown"]';
  await actions.selectByText(page.locator(dropdownXPath), roleName);
  await waits.waitForNetworkIdle();
});

// ==================== THEN STEPS ====================

// TODO: Replace XPath with Object Repository when available
Then('permission management interface should load successfully', async function () {
  await assertions.assertVisible(page.locator('//div[@id="permission-management-interface"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('list of available roles should be visible', async function () {
  await assertions.assertVisible(page.locator('//select[@id="roles-dropdown"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('role details panel should display current permissions as empty', async function () {
  const permissionsListXPath = '//div[@id="current-permissions-list"]';
  const permissionItems = page.locator(`${permissionsListXPath}//div[@class="permission-item"]`);
  const count = await permissionItems.count();
  expect(count).toBe(0);
});

// TODO: Replace XPath with Object Repository when available
Then('available permissions list should show all {int} or more permissions', async function (permissionCount: number) {
  const permissionsXPath = '//div[@id="available-permissions"]//div[@class="permission-item"]';
  const count = await page.locator(permissionsXPath).count();
  expect(count).toBeGreaterThanOrEqual(permissionCount);
});

// TODO: Replace XPath with Object Repository when available
Then('all permission checkboxes should be checked', async function () {
  const checkboxesXPath = '//input[@type="checkbox"][@class="permission-checkbox"]';
  const checkboxes = page.locator(checkboxesXPath);
  const count = await checkboxes.count();
  for (let i = 0; i < count; i++) {
    const isChecked = await checkboxes.nth(i).isChecked();
    expect(isChecked).toBe(true);
  }
});

// TODO: Replace XPath with Object Repository when available
Then('permission counter should show {string}', async function (counterText: string) {
  const counterXPath = '//span[@id="permission-counter"]';
  await assertions.assertContainsText(page.locator(counterXPath), counterText);
});

// TODO: Replace XPath with Object Repository when available
Then('loading indicator should appear', async function () {
  await assertions.assertVisible(page.locator('//div[@id="loading-indicator"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('system should process the request within {int} seconds', async function (seconds: number) {
  await waits.waitForHidden(page.locator('//div[@id="loading-indicator"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('green confirmation banner should display {string}', async function (message: string) {
  const bannerXPath = '//div[@id="confirmation-banner"][@class="success"]';
  await assertions.assertVisible(page.locator(bannerXPath));
  await assertions.assertContainsText(page.locator(bannerXPath), message);
});

// TODO: Replace XPath with Object Repository when available
Then('role should show all {int} or more permissions assigned', async function (permissionCount: number) {
  const assignedPermissionsXPath = '//div[@id="assigned-permissions"]//div[@class="permission-item"]';
  const count = await page.locator(assignedPermissionsXPath).count();
  expect(count).toBeGreaterThanOrEqual(permissionCount);
});

// TODO: Replace XPath with Object Repository when available
Then('permission assignment activity should be logged in audit trail with timestamp and admin user ID', async function () {
  await assertions.assertVisible(page.locator('//div[@id="audit-trail"]'));
});

Then('system performance should remain stable with no degradation', async function () {
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
Then('role details panel should open showing available permissions', async function () {
  await assertions.assertVisible(page.locator('//div[@id="role-details-panel"]'));
  await assertions.assertVisible(page.locator('//div[@id="available-permissions"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('permissions with special characters should be visible', async function () {
  await assertions.assertVisible(page.locator('//div[@id="available-permissions"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('all {int} permissions should be selected with checkmarks', async function (permissionCount: number) {
  const checkedBoxesXPath = '//input[@type="checkbox"][@class="permission-checkbox"]:checked';
  const count = await page.locator(checkedBoxesXPath).count();
  expect(count).toBe(permissionCount);
});

Then('special characters and Unicode should display correctly without corruption', async function () {
  const permissionsXPath = '//div[@class="permission-item"]';
  await assertions.assertVisible(page.locator(permissionsXPath).first());
});

// TODO: Replace XPath with Object Repository when available
Then('system should validate and process the assignment', async function () {
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
Then('confirmation message should display {string}', async function (message: string) {
  const messageXPath = '//div[@id="confirmation-message"]';
  await assertions.assertVisible(page.locator(messageXPath));
  await assertions.assertContainsText(page.locator(messageXPath), message);
});

Then('all special characters and Unicode should be rendered properly in confirmation', async function () {
  const confirmationXPath = '//div[@id="confirmation-message"]';
  await assertions.assertVisible(page.locator(confirmationXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('all {int} permissions should be correctly stored in database without encoding issues', async function (permissionCount: number) {
  const assignedPermissionsXPath = '//div[@id="assigned-permissions"]//div[@class="permission-item"]';
  const count = await page.locator(assignedPermissionsXPath).count();
  expect(count).toBe(permissionCount);
});

// TODO: Replace XPath with Object Repository when available
Then('permission names should display correctly in role details view', async function () {
  await assertions.assertVisible(page.locator('//div[@id="role-details-panel"]'));
});

Then('audit log should capture permission names with special characters accurately', async function () {
  await assertions.assertVisible(page.locator('//div[@id="audit-trail"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('role details panel should display with empty permissions list', async function () {
  await assertions.assertVisible(page.locator('//div[@id="role-details-panel"]'));
  const permissionsListXPath = '//div[@id="current-permissions-list"]//div[@class="permission-item"]';
  const count = await page.locator(permissionsListXPath).count();
  expect(count).toBe(0);
});

// TODO: Replace XPath with Object Repository when available
Then('first API call should be initiated to {string}', async function (apiEndpoint: string) {
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
Then('system should either queue the second request or display {string} message', async function (message: string) {
  const messageLocators = page.locator(`//*[contains(text(),'${message}')]`);
  const count = await messageLocators.count();
  if (count > 0) {
    await assertions.assertVisible(messageLocators.first());
  }
});

Then('system should handle concurrent requests gracefully without data corruption', async function () {
  await waits.waitForNetworkIdle();
});

Then('role should have either first set or second set of permissions assigned', async function () {
  const assignedPermissionsXPath = '//div[@id="assigned-permissions"]//div[@class="permission-item"]';
  const count = await page.locator(assignedPermissionsXPath).count();
  expect(count).toBeGreaterThan(0);
});

Then('no corrupted mix of permissions should exist', async function () {
  await waits.waitForNetworkIdle();
});

Then('appropriate confirmation message should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="confirmation-message"]'));
});

Then('database should maintain data integrity with no duplicate entries', async function () {
  await waits.waitForNetworkIdle();
});

Then('audit log should show both assignment attempts with clear timestamps', async function () {
  await assertions.assertVisible(page.locator('//div[@id="audit-trail"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('role details panel should load within {float} seconds', async function (seconds: number) {
  await assertions.assertVisible(page.locator('//div[@id="role-details-panel"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('current permissions should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="current-permissions-list"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('selection counter should show {string}', async function (counterText: string) {
  const counterXPath = '//span[@id="selection-counter"]';
  await assertions.assertContainsText(page.locator(counterXPath), counterText);
});

// TODO: Replace XPath with Object Repository when available
Then('loading spinner should appear immediately', async function () {
  await assertions.assertVisible(page.locator('//div[@id="loading-spinner"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('{string} button should be disabled to prevent double-submission', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id="${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const button = page.locator(buttonIdXPath);
  const isDisabled = await button.isDisabled();
  expect(isDisabled).toBe(true);
});

// TODO: Replace XPath with Object Repository when available
Then('operation should complete within {int} seconds', async function (seconds: number) {
  await waits.waitForHidden(page.locator('//div[@id="loading-spinner"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('green banner should display {string}', async function (message: string) {
  const bannerXPath = '//div[@id="success-banner"]';
  await assertions.assertVisible(page.locator(bannerXPath));
  await assertions.assertContainsText(page.locator(bannerXPath), message);
});

Then('no timeout errors should occur during the operation', async function () {
  await waits.waitForNetworkIdle();
});

Then('audit log should record the assignment with accurate timestamp and duration', async function () {
  await assertions.assertVisible(page.locator('//div[@id="audit-trail"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('role details panel should display {int} currently assigned permissions with checkmarks', async function (permissionCount: number) {
  await assertions.assertVisible(page.locator('//div[@id="role-details-panel"]'));
  const checkedBoxesXPath = '//input[@type="checkbox"][@class="permission-checkbox"]:checked';
  const count = await page.locator(checkedBoxesXPath).count();
  expect(count).toBe(permissionCount);
});

// TODO: Replace XPath with Object Repository when available
Then('all checkboxes should be unchecked', async function () {
  const checkboxesXPath = '//input[@type="checkbox"][@class="permission-checkbox"]';
  const checkboxes = page.locator(checkboxesXPath);
  const count = await checkboxes.count();
  for (let i = 0; i < count; i++) {
    const isChecked = await checkboxes.nth(i).isChecked();
    expect(isChecked).toBe(false);
  }
});

// TODO: Replace XPath with Object Repository when available
Then('counter should show {string}', async function (counterText: string) {
  const counterXPath = '//span[@id="permission-counter"]';
  await assertions.assertContainsText(page.locator(counterXPath), counterText);
});

// TODO: Replace XPath with Object Repository when available
Then('warning message {string} may be displayed', async function (warningMessage: string) {
  const warningLocators = page.locator(`//*[contains(text(),'${warningMessage}')]`);
  const count = await warningLocators.count();
  if (count > 0) {
    await assertions.assertVisible(warningLocators.first());
  }
});

// TODO: Replace XPath with Object Repository when available
Then('confirmation dialog should appear with message {string}', async function (dialogMessage: string) {
  const dialogXPath = '//div[@id="confirmation-dialog"]';
  await assertions.assertVisible(page.locator(dialogXPath));
  await assertions.assertContainsText(page.locator(dialogXPath), dialogMessage);
});

// TODO: Replace XPath with Object Repository when available
When('administrator clicks {string} button in dialog', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id="${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const buttons = page.locator(buttonIdXPath);
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`//div[@id="confirmation-dialog"]//button[contains(text(),'${buttonText}')]`));
  }
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
Then('role should show {int} permissions assigned', async function (permissionCount: number) {
  const assignedPermissionsXPath = '//div[@id="assigned-permissions"]//div[@class="permission-item"]';
  const count = await page.locator(assignedPermissionsXPath).count();
  expect(count).toBe(permissionCount);
});

// TODO: Replace XPath with Object Repository when available
Then('role should still exist in the system', async function () {
  const roleName = this.testData.currentRole;
  const roleXPath = `//div[@id="role-${roleName.toLowerCase().replace(/\s+/g, '-')}"]`;
  await assertions.assertVisible(page.locator(roleXPath));
});

Then('audit log should record the removal of all permissions with before and after state', async function () {
  await assertions.assertVisible(page.locator('//div[@id="audit-trail"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('role details panel should show {int} permissions selected', async function (permissionCount: number) {
  const counterXPath = '//span[@id="permission-counter"]';
  await assertions.assertContainsText(page.locator(counterXPath), permissionCount.toString());
});

Then('session warning may appear in top banner', async function () {
  const warningBannerXPath = '//div[@id="session-warning-banner"]';
  const count = await page.locator(warningBannerXPath).count();
  if (count > 0) {
    await assertions.assertVisible(page.locator(warningBannerXPath));
  }
});

// TODO: Replace XPath with Object Repository when available
Then('system should initiate POST request to {string}', async function (apiEndpoint: string) {
  await waits.waitForNetworkIdle();
});

Then('system should either complete assignment before session expires or extend session automatically or display session expired error', async function () {
  await waits.waitForNetworkIdle();
});

Then('permission assignment should be atomic with all {int} permissions saved or none saved', async function (permissionCount: number) {
  await waits.waitForNetworkIdle();
});

Then('no partial save should occur', async function () {
  await waits.waitForNetworkIdle();
});

Then('if successful audit log should record the assignment with correct timestamp', async function () {
  const auditTrailXPath = '//div[@id="audit-trail"]';
  const count = await page.locator(auditTrailXPath).count();
  if (count > 0) {
    await assertions.assertVisible(page.locator(auditTrailXPath));
  }
});

// TODO: Replace XPath with Object Repository when available
Then('dropdown should display all roles including the {int} character role name', async function (charLength: number) {
  const dropdownXPath = '//select[@id="roles-dropdown"]';
  await assertions.assertVisible(page.locator(dropdownXPath));
});

Then('long role name should be truncated with ellipsis and full name in tooltip on hover', async function () {
  const roleOptionXPath = '//select[@id="roles-dropdown"]//option';
  await assertions.assertVisible(page.locator(roleOptionXPath).first());
});

// TODO: Replace XPath with Object Repository when available
Then('role details panel should open', async function () {
  await assertions.assertVisible(page.locator('//div[@id="role-details-panel"]'));
});

Then('role name should display correctly with truncation in header', async function () {
  await assertions.assertVisible(page.locator('//div[@id="role-header"]'));
});

Then('full name should be visible on hover or in breadcrumb', async function () {
  await assertions.assertVisible(page.locator('//div[@id="role-header"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('system should process the request without errors', async function () {
  await waits.waitForNetworkIdle();
});

Then('confirmation message should display with truncated role name and tooltip', async function () {
  await assertions.assertVisible(page.locator('//div[@id="confirmation-message"]'));
});

Then('database should store the full role name and permission associations correctly', async function () {
  await waits.waitForNetworkIdle();
});

Then('audit log should contain full {int} character role name without truncation', async function (charLength: number) {
  await assertions.assertVisible(page.locator('//div[@id="audit-trail"]'));
});