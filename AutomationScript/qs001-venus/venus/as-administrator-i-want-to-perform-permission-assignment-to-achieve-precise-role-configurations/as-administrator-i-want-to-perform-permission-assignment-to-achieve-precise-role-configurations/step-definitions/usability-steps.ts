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
      admin: { username: 'admin', password: 'admin123' }
    },
    permissions: {
      read_only: 'read_only',
      delete_all: 'delete_all',
      bypass_audit: 'bypass_audit'
    },
    conflictingPermissions: {
      read_only: ['write_all', 'delete_all'],
      delete_all: ['bypass_audit']
    }
  };
  
  this.selectedPermissions = [];
  this.systemState = {};
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

Given('administrator is authenticated with admin privileges', async function () {
  const credentials = this.testData?.users?.admin || { username: 'admin', password: 'admin123' };
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000/login');
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

Given('at least one role exists in the system', async function () {
  await waits.waitForVisible(page.locator('//div[@id="roles-list"]'));
  const roleCount = await page.locator('//div[@id="roles-list"]//div[contains(@class,"role-item")]').count();
  expect(roleCount).toBeGreaterThan(0);
});

Given('permission configuration section is accessible', async function () {
  await actions.click(page.locator('//a[@id="permission-config"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="permission-configuration"]'));
});

Given('multiple permissions are available for assignment', async function () {
  await waits.waitForVisible(page.locator('//div[@id="permissions-list"]'));
  const permissionCount = await page.locator('//div[@id="permissions-list"]//div[contains(@class,"permission-item")]').count();
  expect(permissionCount).toBeGreaterThan(1);
});

Given('system has defined conflicting permission rules', async function () {
  this.conflictingRules = this.testData?.conflictingPermissions || {};
});

Given('a role is selected for permission modification', async function () {
  await actions.click(page.locator('//div[@id="roles-list"]//div[contains(@class,"role-item")][1]'));
  await waits.waitForNetworkIdle();
  this.selectedRole = await page.locator('//div[@id="selected-role-name"]').textContent();
});

Given('permission assignment interface is displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="permission-assignment-interface"]'));
});

Given('multiple roles exist with varying permission sets', async function () {
  const roleCount = await page.locator('//div[@id="roles-list"]//div[contains(@class,"role-item")]').count();
  expect(roleCount).toBeGreaterThanOrEqual(2);
});

Given('permission assignment history exists in the system', async function () {
  await waits.waitForVisible(page.locator('//div[@id="permission-history"]'));
});

Given('at least {int} permissions are available in the system', async function (count: number) {
  const permissionCount = await page.locator('//div[@id="permissions-list"]//div[contains(@class,"permission-item")]').count();
  expect(permissionCount).toBeGreaterThanOrEqual(count);
});

Given('administrator has selected permissions for a role', async function () {
  await actions.click(page.locator('//div[@id="permissions-list"]//input[@type="checkbox"][1]'));
  await actions.click(page.locator('//div[@id="permissions-list"]//input[@type="checkbox"][2]'));
  this.selectedPermissions = ['permission1', 'permission2'];
});

Given('role has maximum capacity of {int} permissions', async function (maxCapacity: number) {
  this.maxPermissionCapacity = maxCapacity;
});

// ==================== WHEN STEPS ====================

When('administrator navigates to permission configuration section', async function () {
  await actions.click(page.locator('//a[@id="permission-config"]'));
  await waits.waitForNetworkIdle();
});

When('administrator selects a role to modify permissions', async function () {
  await actions.click(page.locator('//div[@id="roles-list"]//div[contains(@class,"role-item")][1]'));
  await waits.waitForNetworkIdle();
  this.selectedRole = await page.locator('//div[@id="selected-role-name"]').textContent();
});

When('administrator begins assigning multiple permissions to the role', async function () {
  await actions.click(page.locator('//div[@id="permissions-list"]//input[@type="checkbox"][1]'));
  await actions.click(page.locator('//div[@id="permissions-list"]//input[@type="checkbox"][2]'));
  await actions.click(page.locator('//div[@id="permissions-list"]//input[@type="checkbox"][3]'));
});

When('administrator submits the permission assignment form', async function () {
  await actions.click(page.locator('//button[@id="submit-permissions"]'));
});

When('administrator observes the validation and submission process', async function () {
  await waits.waitForVisible(page.locator('//div[@id="validation-status"]'));
});

When('administrator waits for process completion', async function () {
  await waits.waitForVisible(page.locator('//div[@id="confirmation-message"]'));
});

When('administrator selects {string} permission', async function (permissionName: string) {
  const permissionXPath = `//div[@id="permissions-list"]//input[@data-permission="${permissionName}"]`;
  await actions.click(page.locator(permissionXPath));
  this.selectedPermissions.push(permissionName);
});

When('administrator attempts to select a conflicting permission', async function () {
  await actions.click(page.locator('//div[@id="permissions-list"]//input[@data-permission="write_all"]'));
});

When('administrator hovers over disabled conflicting permissions', async function () {
  await actions.hover(page.locator('//div[@id="permissions-list"]//input[@disabled][@data-permission="write_all"]'));
});

When('administrator tries to assign {string} and {string} permissions together', async function (perm1: string, perm2: string) {
  await actions.click(page.locator(`//div[@id="permissions-list"]//input[@data-permission="${perm1}"]`));
  await actions.click(page.locator(`//div[@id="permissions-list"]//input[@data-permission="${perm2}"]`));
});

When('administrator observes the submit button state with conflicts', async function () {
  await waits.waitForVisible(page.locator('//button[@id="submit-permissions"][@disabled]'));
});

When('administrator selects a role', async function () {
  await actions.click(page.locator('//div[@id="roles-list"]//div[contains(@class,"role-item")][1]'));
  await waits.waitForNetworkIdle();
});

When('administrator reviews the permission list without clicking', async function () {
  await waits.waitForVisible(page.locator('//div[@id="permissions-list"]'));
});

When('administrator hovers over info icon next to a permission', async function () {
  await actions.hover(page.locator('//div[@id="permissions-list"]//div[contains(@class,"permission-item")][1]//i[contains(@class,"info-icon")]'));
});

When('administrator looks for visual indicators of permission relationships', async function () {
  await waits.waitForVisible(page.locator('//div[@id="permission-relationships"]'));
});

When('administrator checks for visibility of recent changes', async function () {
  await waits.waitForVisible(page.locator('//div[@id="recent-changes"]'));
});

When('administrator searches for permissions', async function () {
  await actions.fill(page.locator('//input[@id="permission-search"]'), 'read');
  await waits.waitForNetworkIdle();
});

When('administrator encounters {string}', async function (errorScenario: string) {
  this.errorScenario = errorScenario;
  
  if (errorScenario === 'conflicting permissions submitted') {
    await actions.click(page.locator('//div[@id="permissions-list"]//input[@data-permission="read_only"]'));
    await actions.click(page.locator('//div[@id="permissions-list"]//input[@data-permission="write_all"]'));
    await actions.click(page.locator('//button[@id="submit-permissions"]'));
  } else if (errorScenario === 'network failure during submission') {
    await context.setOffline(true);
    await actions.click(page.locator('//button[@id="submit-permissions"]'));
  } else if (errorScenario === 'permissions exceed role capacity limits') {
    for (let i = 1; i <= 12; i++) {
      await actions.click(page.locator(`//div[@id="permissions-list"]//input[@type="checkbox"][${i}]`));
    }
    await actions.click(page.locator('//button[@id="submit-permissions"]'));
  } else if (errorScenario === 'insufficient privileges for assignment') {
    await actions.click(page.locator('//div[@id="permissions-list"]//input[@data-permission="admin_permission"]'));
    await actions.click(page.locator('//button[@id="submit-permissions"]'));
  }
});

When('network failure occurs during submission', async function () {
  await context.setOffline(true);
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

When('administrator selects {int} permissions for the role', async function (count: number) {
  for (let i = 1; i <= count; i++) {
    await actions.click(page.locator(`//div[@id="permissions-list"]//input[@type="checkbox"][${i}]`));
  }
  this.selectedPermissions = Array.from({ length: count }, (_, i) => `permission${i + 1}`);
});

// ==================== THEN STEPS ====================

Then('page should load with clear indication of current section', async function () {
  await assertions.assertVisible(page.locator('//div[@id="permission-configuration"]'));
  await assertions.assertVisible(page.locator('//h1[contains(text(),"Permission Configuration")]'));
});

Then('available roles should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="roles-list"]'));
  const roleCount = await page.locator('//div[@id="roles-list"]//div[contains(@class,"role-item")]').count();
  expect(roleCount).toBeGreaterThan(0);
});

Then('system should display visual feedback showing which role is selected', async function () {
  await assertions.assertVisible(page.locator('//div[@id="roles-list"]//div[contains(@class,"role-item selected")]'));
});

Then('current permissions for selected role should be loaded', async function () {
  await assertions.assertVisible(page.locator('//div[@id="current-permissions"]'));
});

Then('each permission selection should show immediate visual feedback', async function () {
  const checkedCount = await page.locator('//div[@id="permissions-list"]//input[@type="checkbox"]:checked').count();
  expect(checkedCount).toBeGreaterThan(0);
});

Then('checkmark or color change should be displayed for selected permissions', async function () {
  await assertions.assertVisible(page.locator('//div[@id="permissions-list"]//div[contains(@class,"permission-selected")]'));
});

Then('permission counter should update in real-time', async function () {
  await assertions.assertVisible(page.locator('//div[@id="permission-counter"]'));
  const counterText = await page.locator('//div[@id="permission-counter"]').textContent();
  expect(counterText).toMatch(/\d+/);
});

Then('system should display loading indicator', async function () {
  await assertions.assertVisible(page.locator('//div[@id="loading-indicator"]'));
});

Then('{string} status message should be displayed', async function (message: string) {
  await assertions.assertContainsText(page.locator('//div[@id="status-message"]'), message);
});

Then('progress indicator should show validation completion', async function () {
  await waits.waitForVisible(page.locator('//div[@id="progress-indicator"][contains(@class,"complete")]'));
});

Then('{string} message should be displayed during API call', async function (message: string) {
  await assertions.assertContainsText(page.locator('//div[@id="api-status-message"]'), message);
});

Then('confirmation message {string} should be displayed', async function (message: string) {
  await assertions.assertContainsText(page.locator('//div[@id="confirmation-message"]'), message);
});

Then('role name should be shown in confirmation message', async function () {
  const confirmationText = await page.locator('//div[@id="confirmation-message"]').textContent();
  expect(confirmationText).toContain(this.selectedRole || 'Role');
});

Then('timestamp should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="timestamp"]'));
});

Then('summary of changes should be visible', async function () {
  await assertions.assertVisible(page.locator('//div[@id="changes-summary"]'));
});

Then('permission should be selected', async function () {
  const checkedCount = await page.locator('//div[@id="permissions-list"]//input[@type="checkbox"]:checked').count();
  expect(checkedCount).toBeGreaterThan(0);
});

Then('conflicting permissions should be automatically disabled', async function () {
  const disabledCount = await page.locator('//div[@id="permissions-list"]//input[@type="checkbox"][@disabled]').count();
  expect(disabledCount).toBeGreaterThan(0);
});

Then('conflicting permissions should be visually marked as unavailable', async function () {
  await assertions.assertVisible(page.locator('//div[@id="permissions-list"]//div[contains(@class,"permission-disabled")]'));
});

Then('system should prevent selection', async function () {
  const isDisabled = await page.locator('//div[@id="permissions-list"]//input[@data-permission="write_all"]').isDisabled();
  expect(isDisabled).toBe(true);
});

Then('inline warning message {string} should be displayed', async function (warningMessage: string) {
  await assertions.assertContainsText(page.locator('//div[@id="inline-warning"]'), warningMessage);
});

Then('tooltip should appear explaining why permission is unavailable', async function () {
  await assertions.assertVisible(page.locator('//div[@id="tooltip"]'));
});

Then('tooltip should show which permission is causing the conflict', async function () {
  const tooltipText = await page.locator('//div[@id="tooltip"]').textContent();
  expect(tooltipText).toMatch(/read_only|write_all|delete_all/);
});

Then('warning dialog should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="warning-dialog"]'));
});

Then('dialog should show {string}', async function (dialogMessage: string) {
  await assertions.assertContainsText(page.locator('//div[@id="warning-dialog"]'), dialogMessage);
});

Then('explanation of the security risk should be provided', async function () {
  await assertions.assertVisible(page.locator('//div[@id="security-risk-explanation"]'));
});

Then('submit button should be disabled', async function () {
  const isDisabled = await page.locator('//button[@id="submit-permissions"]').isDisabled();
  expect(isDisabled).toBe(true);
});

Then('tooltip {string} should be displayed', async function (tooltipText: string) {
  await actions.hover(page.locator('//button[@id="submit-permissions"]'));
  await assertions.assertContainsText(page.locator('//div[@id="button-tooltip"]'), tooltipText);
});

Then('submit button should remain disabled until conflicts are resolved', async function () {
  const isDisabled = await page.locator('//button[@id="submit-permissions"]').isDisabled();
  expect(isDisabled).toBe(true);
});

Then('role name should be displayed prominently', async function () {
  await assertions.assertVisible(page.locator('//div[@id="selected-role-name"]'));
});

Then('currently assigned permissions should be clearly marked', async function () {
  await assertions.assertVisible(page.locator('//div[@id="current-permissions"]//div[contains(@class,"assigned")]'));
});

Then('available permissions should be visible', async function () {
  await assertions.assertVisible(page.locator('//div[@id="permissions-list"]'));
});

Then('permission categories should be displayed for easy scanning', async function () {
  await assertions.assertVisible(page.locator('//div[@id="permission-categories"]'));
});

Then('each permission should show name and brief description', async function () {
  const firstPermission = page.locator('//div[@id="permissions-list"]//div[contains(@class,"permission-item")][1]');
  await assertions.assertVisible(firstPermission.locator('//div[contains(@class,"permission-name")]'));
  await assertions.assertVisible(firstPermission.locator('//div[contains(@class,"permission-description")]'));
});

Then('icon or visual indicator should be displayed for each permission', async function () {
  await assertions.assertVisible(page.locator('//div[@id="permissions-list"]//div[contains(@class,"permission-item")][1]//i[contains(@class,"icon")]'));
});

Then('current assignment status should be visible without navigation', async function () {
  await assertions.assertVisible(page.locator('//div[@id="assignment-status"]'));
});

Then('detailed tooltip should appear', async function () {
  await assertions.assertVisible(page.locator('//div[@id="detailed-tooltip"]'));
});

Then('full permission description should be shown', async function () {
  await assertions.assertVisible(page.locator('//div[@id="detailed-tooltip"]//div[contains(@class,"full-description")]'));
});

Then('actions enabled by permission should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="detailed-tooltip"]//div[contains(@class,"enabled-actions")]'));
});

Then('potential security implications should be visible', async function () {
  await assertions.assertVisible(page.locator('//div[@id="detailed-tooltip"]//div[contains(@class,"security-implications")]'));
});

Then('list of other roles with this permission should be shown', async function () {
  await assertions.assertVisible(page.locator('//div[@id="detailed-tooltip"]//div[contains(@class,"other-roles")]'));
});

Then('system should display visual grouping with color coding', async function () {
  await assertions.assertVisible(page.locator('//div[@id="permission-groups"][contains(@class,"color-coded")]'));
});

Then('related permissions should be shown with indentation', async function () {
  await assertions.assertVisible(page.locator('//div[@id="permissions-list"]//div[contains(@class,"indented")]'));
});

Then('permission dependencies should be visible', async function () {
  await assertions.assertVisible(page.locator('//div[@id="permission-dependencies"]'));
});

Then('{string} indicator should be displayed', async function (indicatorText: string) {
  const indicatorXPath = `//div[@id='${indicatorText.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(indicatorXPath));
});

Then('last {int} permission changes should be shown with timestamps', async function (count: number) {
  const changeCount = await page.locator('//div[@id="recent-changes"]//div[contains(@class,"change-item")]').count();
  expect(changeCount).toBeGreaterThanOrEqual(count);
});

Then('administrator who made each change should be visible', async function () {
  await assertions.assertVisible(page.locator('//div[@id="recent-changes"]//div[contains(@class,"change-item")][1]//span[contains(@class,"admin-name")]'));
});

Then('search box should be prominently visible', async function () {
  await assertions.assertVisible(page.locator('//input[@id="permission-search"]'));
});

Then('placeholder text should show example searches', async function () {
  const placeholder = await page.locator('//input[@id="permission-search"]').getAttribute('placeholder');
  expect(placeholder).toBeTruthy();
});

Then('filters should be available for permission categories', async function () {
  await assertions.assertVisible(page.locator('//div[@id="category-filters"]'));
});

Then('exact permission names should not be required for search', async function () {
  await actions.fill(page.locator('//input[@id="permission-search"]'), 'rea');
  await waits.waitForNetworkIdle();
  const resultCount = await page.locator('//div[@id="search-results"]//div[contains(@class,"permission-item")]').count();
  expect(resultCount).toBeGreaterThan(0);
});

Then('error message {string} should be displayed', async function (errorMessage: string) {
  await assertions.assertContainsText(page.locator('//div[@id="error-message"]'), errorMessage);
});

Then('error should appear near the relevant field or section', async function () {
  await assertions.assertVisible(page.locator('//div[@id="error-message"][contains(@class,"inline-error")]'));
});

Then('error icon should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="error-message"]//i[contains(@class,"error-icon")]'));
});

Then('error should use warning color styling', async function () {
  const errorElement = page.locator('//div[@id="error-message"]');
  const className = await errorElement.getAttribute('class');
  expect(className).toMatch(/warning|error|danger/);
});

Then('error message should be in plain language without technical jargon', async function () {
  const errorText = await page.locator('//div[@id="error-message"]').textContent();
  expect(errorText).toBeTruthy();
  expect(errorText).not.toMatch(/500|404|ERR_|Exception/);
});

Then('actionable next steps should be provided', async function () {
  await assertions.assertVisible(page.locator('//div[@id="error-message"]//div[contains(@class,"next-steps")]'));
});

Then('all selected permissions should remain selected after error', async function () {
  const checkedCount = await page.locator('//div[@id="permissions-list"]//input[@type="checkbox"]:checked').count();
  expect(checkedCount).toBeGreaterThan(0);
});

Then('administrator should be able to fix issue without re-entering data', async function () {
  const checkedCount = await page.locator('//div[@id="permissions-list"]//input[@type="checkbox"]:checked').count();
  expect(checkedCount).toEqual(this.selectedPermissions.length);
});

Then('{string} button should be prominently displayed', async function (buttonText: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(buttonXPath));
});

Then('system should attempt to save permissions again', async function () {
  await context.setOffline(false);
  await waits.waitForNetworkIdle();
});

Then('loading indicator should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="loading-indicator"]'));
});

Then('counter showing current versus maximum should be visible', async function () {
  await assertions.assertVisible(page.locator('//div[@id="permission-counter"]'));
  const counterText = await page.locator('//div[@id="permission-counter"]').textContent();
  expect(counterText).toMatch(/\d+\s*\/\s*\d+/);
});

Then('list of selected permissions should be displayed for easy review', async function () {
  await assertions.assertVisible(page.locator('//div[@id="selected-permissions-list"]'));
  const selectedCount = await page.locator('//div[@id="selected-permissions-list"]//div[contains(@class,"permission-item")]').count();
  expect(selectedCount).toBeGreaterThan(0);
});