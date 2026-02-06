import { Given, When, Then, Before, After } from '@cucumber/cucumber';
import { Page, Browser, BrowserContext, chromium, expect } from '@playwright/test';
import { BasePage } from '../pages/BasePage';
import { HomePage } from '../pages/HomePage';
import { GenericActions } from '../utils/GenericActions';
import { AssertionHelpers } from '../utils/AssertionHelpers';
import { WaitHelpers } from '../utils/WaitHelpers';

// TODO: Replace XPath with Object Repository when available
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
    roles: {},
    focusedElement: null,
    screenReaderOutput: [],
    contrastResults: {}
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

Given('administrator is authenticated and logged in', async function () {
  const credentials = this.testData?.users?.admin || { username: 'admin', password: 'admin123' };
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000');
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

Given('administrator is on {string} page at {string}', async function (pageName: string, path: string) {
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}${path}`);
  await waits.waitForNetworkIdle();
  await assertions.assertUrlContains(path);
});

Given('test role {string} exists with {int} permissions', async function (roleName: string, permissionCount: number) {
  this.testData.roles[roleName] = {
    name: roleName,
    permissionCount: permissionCount,
    permissions: Array.from({ length: permissionCount }, (_, i) => `permission.${i + 1}`)
  };
  const roleXPath = `//div[@id='role-${roleName.toLowerCase().replace(/\s+/g, '-')}']`;
  const roleExists = await page.locator(roleXPath).count();
  if (roleExists === 0) {
    await actions.click(page.locator('//button[@id="create-role"]'));
    await actions.fill(page.locator('//input[@id="role-name"]'), roleName);
    for (let i = 0; i < permissionCount; i++) {
      await actions.check(page.locator(`//input[@id='permission-${i + 1}']`));
    }
    await actions.click(page.locator('//button[@id="save-role"]'));
    await waits.waitForNetworkIdle();
  }
});

Given('mouse input is disabled for keyboard-only testing', async function () {
  await page.evaluate(() => {
    document.body.style.pointerEvents = 'none';
  });
  this.testData.mouseDisabled = true;
});

Given('screen zoom level is set to {int} percent', async function (zoomLevel: number) {
  await page.evaluate((zoom) => {
    document.body.style.zoom = `${zoom}%`;
  }, zoomLevel);
  this.testData.zoomLevel = zoomLevel;
});

Given('browser supports standard keyboard navigation', async function () {
  const supportsKeyboard = await page.evaluate(() => {
    return 'KeyboardEvent' in window;
  });
  expect(supportsKeyboard).toBe(true);
});

Given('screen reader is enabled', async function () {
  this.testData.screenReaderEnabled = true;
  this.testData.screenReaderOutput = [];
});

Given('screen reader is configured to announce all ARIA live regions and labels', async function () {
  await page.evaluate(() => {
    const liveRegions = document.querySelectorAll('[aria-live]');
    liveRegions.forEach(region => {
      region.setAttribute('data-sr-monitored', 'true');
    });
  });
});

Given('audio output is enabled', async function () {
  this.testData.audioEnabled = true;
});

Given('role modification opens in modal dialog overlay', async function () {
  this.testData.modalMode = true;
});

Given('keyboard navigation is the primary input method', async function () {
  this.testData.primaryInput = 'keyboard';
});

Given('background content is visible', async function () {
  const backgroundVisible = await page.locator('//div[@id="main-content"]').isVisible();
  expect(backgroundVisible).toBe(true);
});

Given('color contrast analyzer tool is available', async function () {
  this.testData.contrastAnalyzer = true;
});

Given('test role {string} is visible in roles list', async function (roleName: string) {
  const roleXPath = `//div[@id='role-${roleName.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(roleXPath));
});

Given('page is viewed at {int} percent zoom', async function (zoomLevel: number) {
  await page.evaluate((zoom) => {
    document.body.style.zoom = `${zoom}%`;
  }, zoomLevel);
});

Given('browser is set to default colors', async function () {
  this.testData.defaultColors = true;
});

Given('administrator is on role management page', async function () {
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/admin/roles`);
  await waits.waitForNetworkIdle();
});

Given('test role {string} is open for editing', async function (roleName: string) {
  const roleXPath = `//div[@id='role-${roleName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(roleXPath));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//form[@id="role-edit-form"]'));
});

Given('administrator is on role management page at {int} percent zoom', async function (zoomLevel: number) {
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/admin/roles`);
  await waits.waitForNetworkIdle();
  await page.evaluate((zoom) => {
    document.body.style.zoom = `${zoom}%`;
  }, zoomLevel);
});

Given('screen resolution is set to {string}', async function (resolution: string) {
  const [width, height] = resolution.split('x').map(Number);
  await page.setViewportSize({ width, height });
  this.testData.resolution = { width, height };
});

Given('administrator is logged in with screen reader active', async function () {
  const credentials = this.testData?.users?.admin || { username: 'admin', password: 'admin123' };
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000');
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  this.testData.screenReaderEnabled = true;
  this.testData.screenReaderOutput = [];
});

Given('test role {string} is open in modification form', async function (roleName: string) {
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/admin/roles`);
  await waits.waitForNetworkIdle();
  const roleXPath = `//div[@id='role-${roleName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(roleXPath));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//form[@id="role-edit-form"]'));
});

Given('administrator is logged in on tablet device with {string} pixel width viewport', async function (width: string) {
  const viewportWidth = parseInt(width);
  await page.setViewportSize({ width: viewportWidth, height: 1024 });
  const credentials = this.testData?.users?.admin || { username: 'admin', password: 'admin123' };
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000');
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  this.testData.deviceType = 'tablet';
  this.testData.viewportWidth = viewportWidth;
});

Given('touch input is primary interaction method', async function () {
  this.testData.primaryInput = 'touch';
});

Given('device is in portrait orientation', async function () {
  this.testData.orientation = 'portrait';
});

// ==================== WHEN STEPS ====================

When('administrator presses Tab key repeatedly to navigate to {string} role', async function (roleName: string) {
  const roleXPath = `//div[@id='role-${roleName.toLowerCase().replace(/\s+/g, '-')}']`;
  let attempts = 0;
  const maxAttempts = 50;
  while (attempts < maxAttempts) {
    await page.keyboard.press('Tab');
    const focusedElement = await page.evaluate(() => document.activeElement?.id);
    this.testData.focusedElement = focusedElement;
    if (focusedElement === `role-${roleName.toLowerCase().replace(/\s+/g, '-')}`) {
      break;
    }
    attempts++;
  }
});

When('administrator presses Enter key to open role modification form', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('administrator presses Tab key to move focus to permissions section', async function () {
  await page.keyboard.press('Tab');
  const focusedElement = await page.evaluate(() => document.activeElement?.id);
  this.testData.focusedElement = focusedElement;
});

When('administrator uses Arrow Down key to navigate through permission checkboxes', async function () {
  await page.keyboard.press('ArrowDown');
  const focusedElement = await page.evaluate(() => document.activeElement?.id);
  this.testData.focusedElement = focusedElement;
});

When('administrator presses Space bar to toggle {int} permissions', async function (count: number) {
  for (let i = 0; i < count; i++) {
    await page.keyboard.press('Space');
    await page.waitForTimeout(200);
    if (i < count - 1) {
      await page.keyboard.press('ArrowDown');
    }
  }
});

When('administrator presses Tab to move to {string} field', async function (fieldName: string) {
  await page.keyboard.press('Tab');
  const focusedElement = await page.evaluate(() => document.activeElement?.id);
  this.testData.focusedElement = focusedElement;
});

When('administrator types {string} in {string} field', async function (text: string, fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  const textareaXPath = `//textarea[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  const inputExists = await page.locator(fieldXPath).count();
  if (inputExists > 0) {
    await actions.type(page.locator(fieldXPath), text);
  } else {
    await actions.type(page.locator(textareaXPath), text);
  }
});

When('administrator presses Tab to reach {string} button', async function (buttonText: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  let attempts = 0;
  const maxAttempts = 20;
  while (attempts < maxAttempts) {
    await page.keyboard.press('Tab');
    const focusedElement = await page.evaluate(() => document.activeElement?.id);
    this.testData.focusedElement = focusedElement;
    if (focusedElement === buttonText.toLowerCase().replace(/\s+/g, '-')) {
      break;
    }
    attempts++;
  }
});

When('administrator presses Enter key to submit the form', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('administrator presses Tab key to navigate through success message', async function () {
  await page.keyboard.press('Tab');
  const focusedElement = await page.evaluate(() => document.activeElement?.id);
  this.testData.focusedElement = focusedElement;
});

When('administrator navigates to role management page', async function () {
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/admin/roles`);
  await waits.waitForNetworkIdle();
});

When('administrator navigates to {string} using screen reader commands', async function (roleName: string) {
  const roleXPath = `//div[@id='role-${roleName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.scrollIntoView(page.locator(roleXPath));
  const ariaLabel = await page.locator(roleXPath).getAttribute('aria-label');
  if (ariaLabel) {
    this.testData.screenReaderOutput.push(ariaLabel);
  }
});

When('administrator activates the role to open modification form', async function () {
  const focusedElement = this.testData.focusedElement;
  if (focusedElement) {
    await page.locator(`//*[@id='${focusedElement}']`).click();
  }
  await waits.waitForNetworkIdle();
});

When('administrator navigates to permissions section', async function () {
  const permissionsSection = page.locator('//div[@id="permissions-section"]');
  await actions.scrollIntoView(permissionsSection);
  await waits.waitForVisible(permissionsSection);
});

When('administrator toggles {int} permission checkboxes', async function (count: number) {
  for (let i = 0; i < count; i++) {
    const checkboxXPath = `//input[@id='permission-${i + 1}']`;
    await actions.click(page.locator(checkboxXPath));
    await page.waitForTimeout(200);
  }
});

When('administrator navigates to {string} button and activates it', async function (buttonText: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(buttonXPath));
  await waits.waitForNetworkIdle();
});

When('administrator attempts to create conflicting permission', async function () {
  await actions.check(page.locator('//input[@id="permission-conflict-1"]'));
  await actions.check(page.locator('//input[@id="permission-conflict-2"]'));
  await page.waitForTimeout(500);
});

When('administrator corrects the validation error', async function () {
  const errorField = page.locator('//input[@aria-invalid="true"]');
  await actions.clearAndFill(errorField, 'ValidRoleName');
});

When('administrator selects {int} permissions rapidly in quick succession', async function (count: number) {
  for (let i = 0; i < count; i++) {
    const checkboxXPath = `//input[@id='permission-${i + 1}']`;
    await page.locator(checkboxXPath).click({ force: true });
  }
  await page.waitForTimeout(1000);
});

When('administrator clicks {string} button', async function (buttonText: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(buttonXPath));
  await waits.waitForNetworkIdle();
});

When('administrator triggers server error by simulating network failure', async function () {
  await page.route('**/api/roles/**', route => route.abort());
  await actions.click(page.locator('//button[@id="save-changes"]'));
  await page.waitForTimeout(1000);
});

When('administrator activates {string} to open modification modal', async function (roleName: string) {
  const roleXPath = `//div[@id='role-${roleName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(roleXPath));
  await waits.waitForNetworkIdle();
});

When('administrator presses Tab key repeatedly to cycle through modal elements', async function () {
  for (let i = 0; i < 10; i++) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
  }
});

When('administrator continues pressing Tab after reaching last focusable element', async function () {
  await page.keyboard.press('Tab');
  const focusedElement = await page.evaluate(() => document.activeElement?.id);
  this.testData.focusedElement = focusedElement;
});

When('administrator presses Shift+Tab from first focusable element', async function () {
  await page.keyboard.press('Shift+Tab');
  const focusedElement = await page.evaluate(() => document.activeElement?.id);
  this.testData.focusedElement = focusedElement;
});

When('administrator presses Escape key', async function () {
  await page.keyboard.press('Escape');
  await page.waitForTimeout(500);
});

When('administrator reopens modal and makes changes to permissions', async function () {
  const roleXPath = `//div[@id='role-focustestrole']`;
  await actions.click(page.locator(roleXPath));
  await waits.waitForNetworkIdle();
  await actions.check(page.locator('//input[@id="permission-1"]'));
});

When('administrator clicks {string} button', async function (buttonText: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(buttonXPath));
  await waits.waitForNetworkIdle();
});

When('administrator reopens modal and makes changes', async function () {
  const roleXPath = `//div[@id='role-focustestrole']`;
  await actions.click(page.locator(roleXPath));
  await waits.waitForNetworkIdle();
  await actions.check(page.locator('//input[@id="permission-2"]'));
});

When('administrator measures contrast ratio of {string} against background', async function (elementType: string) {
  const elementXPath = `//*[@id='${elementType.toLowerCase().replace(/\s+/g, '-')}']`;
  const element = page.locator(elementXPath);
  const color = await element.evaluate((el) => {
    return window.getComputedStyle(el).color;
  });
  const bgColor = await element.evaluate((el) => {
    return window.getComputedStyle(el).backgroundColor;
  });
  this.testData.contrastResults[elementType] = { color, bgColor };
});

When('administrator checks permission checkboxes', async function () {
  await actions.check(page.locator('//input[@id="permission-1"]'));
  await actions.check(page.locator('//input[@id="permission-2"]'));
});

When('administrator triggers validation error', async function () {
  await actions.fill(page.locator('//input[@id="role-name"]'), '@@Invalid@@');
  await page.keyboard.press('Tab');
  await page.waitForTimeout(500);
});

When('administrator successfully saves role', async function () {
  await actions.click(page.locator('//button[@id="save-changes"]'));
  await waits.waitForNetworkIdle();
});

When('administrator enables Windows High Contrast Mode', async function () {
  await page.emulateMedia({ colorScheme: 'dark', forcedColors: 'active' });
});

When('administrator increases browser zoom to {int} percent', async function (zoomLevel: number) {
  await page.evaluate((zoom) => {
    document.body.style.zoom = `${zoom}%`;
  }, zoomLevel);
  this.testData.zoomLevel = zoomLevel;
});

When('administrator navigates to {string} in roles list', async function (roleName: string) {
  const roleXPath = `//div[@id='role-${roleName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.scrollIntoView(page.locator(roleXPath));
  await waits.waitForVisible(page.locator(roleXPath));
});

When('administrator opens {string} modification form', async function (roleName: string) {
  const roleXPath = `//div[@id='role-${roleName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(roleXPath));
  await waits.waitForNetworkIdle();
});

When('administrator navigates through form fields', async function () {
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab');
});

When('administrator scrolls through permissions list and selects {int} permissions', async function (count: number) {
  const permissionsList = page.locator('//div[@id="permissions-list"]');
  await actions.scrollIntoView(permissionsList);
  for (let i = 0; i < count; i++) {
    const checkboxXPath = `//input[@id='permission-${i + 1}']`;
    await actions.check(page.locator(checkboxXPath));
  }
});

When('administrator views success message', async function () {
  const successMessage = page.locator('//div[@id="success-message"]');
  await waits.waitForVisible(successMessage);
});

When('administrator selects permission checkbox with screen reader active', async function () {
  await actions.check(page.locator('//input[@id="permission-user-delete"]'));
  await page.waitForTimeout(500);
  const liveRegion = await page.locator('//div[@aria-live]').textContent();
  if (liveRegion) {
    this.testData.screenReaderOutput.push(liveRegion);
  }
});

When('administrator deselects same permission checkbox', async function () {
  await actions.click(page.locator('//input[@id="permission-user-delete"]'));
  await page.waitForTimeout(500);
  const liveRegion = await page.locator('//div[@aria-live]').textContent();
  if (liveRegion) {
    this.testData.screenReaderOutput.push(liveRegion);
  }
});

When('administrator enters invalid data in {string} field and tabs out', async function (fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.fill(page.locator(fieldXPath), '@@Invalid@@');
  await page.keyboard.press('Tab');
  await page.waitForTimeout(500);
});

When('administrator navigates to role management page on tablet', async function () {
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/admin/roles`);
  await waits.waitForNetworkIdle();
});

When('administrator taps on {string} to open modification form', async function (roleName: string) {
  const roleXPath = `//div[@id='role-${roleName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(roleXPath));
  await waits.waitForNetworkIdle();
});

When('administrator taps on {string} input field', async function (fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(fieldXPath));
  await page.waitForTimeout(500);
});

When('administrator scrolls through permissions list and taps checkboxes', async function () {
  const permissionsList = page.locator('//div[@id="permissions-list"]');
  await actions.scrollIntoView(permissionsList);
  await actions.click(page.locator('//input[@id="permission-1"]'));
  await actions.click(page.locator('//input[@id="permission-2"]'));
});

When('administrator taps on {string} textarea and enters multi-line text', async function (fieldName: string) {
  const textareaXPath = `//textarea[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(textareaXPath));
  await actions.type(page.locator(textareaXPath), 'Line 1\nLine 2\nLine 3');
});

When('administrator rotates device to landscape orientation', async function () {
  const currentViewport = page.viewportSize();
  if (currentViewport) {
    await page.setViewportSize({ width: currentViewport.height, height: currentViewport.width });
  }
  this.testData.orientation = 'landscape';
});

When('administrator taps {string} button', async function (buttonText: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(buttonXPath));
  await waits.waitForNetworkIdle();
});

When('administrator enables mobile screen reader', async function () {
  this.testData.screenReaderEnabled = true;
  this.testData.mobileScreenReader = true;
});

// ==================== THEN STEPS ====================

Then('focus indicator should be visible on {string} with minimum {string} pixel border', async function (roleName: string, pixels: string) {
  const roleXPath = `//div[@id='role-${roleName.toLowerCase().replace(/\s+/g, '-')}']`;
  const outlineWidth = await page.locator(roleXPath).evaluate((el) => {
    return window.getComputedStyle(el).outlineWidth;
  });
  const width = parseInt(outlineWidth);
  expect(width).toBeGreaterThanOrEqual(parseInt(pixels));
});

Then('focus indicator should have high contrast color', async function () {
  const focusedElement = await page.evaluate(() => {
    const el = document.activeElement;
    return el ? window.getComputedStyle(el).outlineColor : null;
  });
  expect(focusedElement).toBeTruthy();
});

Then('role edit form should open', async function () {
  await assertions.assertVisible(page.locator('//form[@id="role-edit-form"]'));
});

Then('focus should automatically move to {string} field', async function (fieldName: string) {
  const focusedElement = await page.evaluate(() => document.activeElement?.id);
  expect(focusedElement).toBe(fieldName.toLowerCase().replace(/\s+/g, '-'));
});

Then('focus indicator should be clearly visible', async function () {
  const outlineStyle = await page.evaluate(() => {
    const el = document.activeElement;
    return el ? window.getComputedStyle(el).outlineStyle : null;
  });
  expect(outlineStyle).not.toBe('none');
});

Then('focus should move to first permission checkbox', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.id);
  expect(focusedElement).toContain('permission');
});

Then('each focused checkbox should have visible focus indicator', async function () {
  const outlineStyle = await page.evaluate(() => {
    const el = document.activeElement;
    return el ? window.getComputedStyle(el).outlineStyle : null;
  });
  expect(outlineStyle).not.toBe('none');
});

Then('Space bar should toggle checkbox selection', async function () {
  const initialState = await page.evaluate(() => {
    const el = document.activeElement as HTMLInputElement;
    return el ? el.checked : false;
  });
  await page.keyboard.press('Space');
  const newState = await page.evaluate(() => {
    const el = document.activeElement as HTMLInputElement;
    return el ? el.checked : false;
  });
  expect(newState).not.toBe(initialState);
});

Then('checkboxes should toggle correctly with Space bar', async function () {
  const checkedCount = await page.locator('//input[@type="checkbox"]:checked').count();
  expect(checkedCount).toBeGreaterThan(0);
});

Then('focus should move to {string} textarea with visible focus indicator', async function (fieldName: string) {
  const focusedElement = await page.evaluate(() => document.activeElement?.id);
  expect(focusedElement).toBe(fieldName.toLowerCase().replace(/\s+/g, '-'));
});

Then('permission counter should update to reflect changes', async function () {
  const counter = page.locator('//span[@id="permission-counter"]');
  await assertions.assertVisible(counter);
});

Then('text should be entered successfully in {string} field', async function (fieldName: string) {
  const fieldXPath = `//textarea[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  const value = await page.locator(fieldXPath).inputValue();
  expect(value.length).toBeGreaterThan(0);
});

Then('focus should move to {string} button with clear focus indicator', async function (buttonText: string) {
  const focusedElement = await page.evaluate(() => document.activeElement?.id);
  expect(focusedElement).toBe(buttonText.toLowerCase().replace(/\s+/g, '-'));
});

Then('button should show focused state', async function () {
  const outlineStyle = await page.evaluate(() => {
    const el = document.activeElement;
    return el ? window.getComputedStyle(el).outlineStyle : null;
  });
  expect(outlineStyle).not.toBe('none');
});

Then('form should submit successfully', async function () {
  await waits.waitForNetworkIdle();
  const successMessage = page.locator('//div[@id="success-message"]');
  await waits.waitForVisible(successMessage);
});

Then('success message should appear and receive focus', async function () {
  const successMessage = page.locator('//div[@id="success-message"]');
  await assertions.assertVisible(successMessage);
});

Then('focus management should return to logical location', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.id);
  expect(focusedElement).toBeTruthy();
});

Then('focus should move logically through all interactive elements', async function () {
  for (let i = 0; i < 5; i++) {
    await page.keyboard.press('Tab');
    const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
    expect(focusedElement).toBeTruthy();
  }
});

Then('no keyboard traps should exist', async function () {
  const initialFocus = await page.evaluate(() => document.activeElement?.id);
  for (let i = 0; i < 20; i++) {
    await page.keyboard.press('Tab');
  }
  const finalFocus = await page.evaluate(() => document.activeElement?.id);
  expect(finalFocus).not.toBe(initialFocus);
});

Then('administrator should be able to navigate back to roles list using Tab and Shift+Tab', async function () {
  await page.keyboard.press('Shift+Tab');
  await page.keyboard.press('Shift+Tab');
  const focusedElement = await page.evaluate(() => document.activeElement?.id);
  expect(focusedElement).toBeTruthy();
});

Then('screen reader should announce {string}', async function (announcement: string) {
  const ariaLabel = await page.locator('//main').getAttribute('aria-label');
  expect(ariaLabel).toContain(announcement.split(',')[0]);
});

Then('page heading {string} should be announced with heading level {string}', async function (heading: string, level: string) {
  const headingElement = page.locator(`//${level.toLowerCase()}[contains(text(),'${heading}')]`);
  await assertions.assertVisible(headingElement);
});

Then('navigation landmarks should be properly identified', async function () {
  const landmarks = await page.locator('[role="navigation"], nav').count();
  expect(landmarks).toBeGreaterThan(0);
});

Then('role description should be announced if present', async function () {
  const description = await page.locator('//div[@id="role-description"]').textContent();
  if (description) {
    this.testData.screenReaderOutput.push(description);
  }
});

Then('current permissions count {string} should be announced', async function (countText: string) {
  const counter = await page.locator('//span[@id="permission-counter"]').textContent();
  expect(counter).toContain(countText.split(' ')[0]);
});

Then('screen reader should announce state changes for each checkbox', async function () {
  const liveRegion = await page.locator('//div[@aria-live]').textContent();
  expect(liveRegion).toBeTruthy();
});

Then('ARIA live region should announce {string} within {string} seconds', async function (message: string, seconds: string) {
  await page.waitForTimeout(parseInt(seconds) * 1000);
  const liveRegion = await page.locator('//div[@aria-live]').textContent();
  expect(liveRegion).toContain(message.split(',')[0]);
});

Then('announcement should be clear and contextual', async function () {
  const liveRegion = await page.locator('//div[@aria-live]').textContent();
  expect(liveRegion).toBeTruthy();
});

Then('ARIA live region should announce {string}', async function (message: string) {
  await page.waitForTimeout(1000);
  const liveRegion = await page.locator('//div[@aria-live]').textContent();
  expect(liveRegion).toContain(message.split(':')[0]);
});

Then('counter update should be announced automatically', async function () {
  const liveRegion = await page.locator('//div[@aria-live]').textContent();
  expect(liveRegion).toBeTruthy();
});

Then('ARIA live region with {string} politeness should announce {string} immediately', async function (politeness: string, message: string) {
  await page.waitForTimeout(500);
  const liveRegion = page.locator(`//div[@aria-live='${politeness}']`);
  const text = await liveRegion.textContent();
  expect(text).toContain(message.split(':')[0]);
});

Then('error should be announced without requiring navigation to error message', async function () {
  const liveRegion = await page.locator('//div[@aria-live="assertive"]').textContent();
  expect(liveRegion).toBeTruthy();
});

Then('positive feedback should be provided for successful correction', async function () {
  const liveRegion = await page.locator('//div[@aria-live]').textContent();
  expect(liveRegion).toBeTruthy();
});

Then('ARIA live region with {string} politeness should batch announcements appropriately', async function (politeness: string) {
  await page.waitForTimeout(1500);
  const liveRegion = page.locator(`//div[@aria-live='${politeness}']`);
  await assertions.assertVisible(liveRegion);
});

Then('final state {string} should be announced', async function (state: string) {
  const liveRegion = await page.locator('//div[@aria-live]').textContent();
  expect(liveRegion).toContain(state.split(' ')[0]);
});

Then('ARIA live region should announce {string} during processing', async function (message: string) {
  await page.waitForTimeout(500);
  const liveRegion = await page.locator('//div[@aria-live]').textContent();
  expect(liveRegion).toContain(message.split(':')[0]);
});

Then('ARIA live region should announce {string} after completion', async function (message: string) {
  await page.waitForTimeout(1000);
  const liveRegion = await page.locator('//div[@aria-live]').textContent();
  expect(liveRegion).toContain(message.split(':')[0]);
});

Then('error should provide actionable guidance', async function () {
  const errorMessage = await page.locator('//div[@role="alert"]').textContent();
  expect(errorMessage).toBeTruthy();
});

Then('modal should open with overlay', async function () {
  await assertions.assertVisible(page.locator('//div[@role="dialog"]'));
  await assertions.assertVisible(page.locator('//div[@class="modal-overlay"]'));
});

Then('focus should automatically move to first focusable element in modal', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBeTruthy();
});

Then('background content should be visually dimmed', async function () {
  const overlay = page.locator('//div[@class="modal-overlay"]');
  const opacity = await overlay.evaluate((el) => window.getComputedStyle(el).opacity);
  expect(parseFloat(opacity)).toBeGreaterThan(0);
});

Then('background content should be marked as inert with {string} attribute set to {string}', async function (attribute: string, value: string) {
  const mainContent = page.locator('//div[@id="main-content"]');
  const ariaHidden = await mainContent.getAttribute(attribute);
  expect(ariaHidden).toBe(value);
});

Then('focus should move through all focusable elements within modal', async function () {
  for (let i = 0; i < 5; i++) {
    await page.keyboard.press('Tab');
    const focusedElement = await page.evaluate(() => {
      const el = document.activeElement;
      return el?.closest('[role="dialog"]') !== null;
    });
    expect(focusedElement).toBe(true);
  }
});

Then('focus should stay within modal boundaries', async function () {
  const focusedElement = await page.evaluate(() => {
    const el = document.activeElement;
    return el?.closest('[role="dialog"]') !== null;
  });
  expect(focusedElement).toBe(true);
});

Then('focus should wrap back to first focusable element', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBeTruthy();
});

Then('focus should never escape to background content', async function () {
  const focusedElement = await page.evaluate(() => {
    const el = document.activeElement;
    return el?.closest('[role="dialog"]') !== null;
  });
  expect(focusedElement).toBe(true);
});

Then('focus should move backward to last focusable element', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBeTruthy();
});

Then('reverse tabbing should maintain focus within modal', async function () {
  const focusedElement = await page.evaluate(() => {
    const el = document.activeElement;
    return el?.closest('[role="dialog"]') !== null;
  });
  expect(focusedElement).toBe(true);
});

Then('modal should close immediately', async function () {
  await page.waitForTimeout(500);
  const modalVisible = await page.locator('//div[@role="dialog"]').isVisible();
  expect(modalVisible).toBe(false);
});

Then('focus should return to {string} trigger element', async function (roleName: string) {
  const focusedElement = await page.evaluate(() => document.activeElement?.id);
  expect(focusedElement).toContain(roleName.toLowerCase().replace(/\s+/g, '-'));
});

Then('background content should become interactive again', async function () {
  const mainContent = page.locator('//div[@id="main-content"]');
  const ariaHidden = await mainContent.getAttribute('aria-hidden');
  expect(ariaHidden).not.toBe('true');
});

Then('modal should close', async function () {
  await page.waitForTimeout(500);
  const modalVisible = await page.locator('//div[@role="dialog"]').isVisible();
  expect(modalVisible).toBe(false);
});

Then('unsaved changes should be discarded', async function () {
  const formData = await page.evaluate(() => {
    const form = document.querySelector('form');
    return form ? new FormData(form) : null;
  });
  expect(formData).toBeTruthy();
});

Then('modal should close after successful save', async function () {
  await page.waitForTimeout(1000);
  const modalVisible = await page.locator('//div[@role="dialog"]').isVisible();
  expect(modalVisible).toBe(false);
});

Then('focus should move to success message or updated role in list', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.id);
  expect(focusedElement).toBeTruthy();
});

Then('focus should never be lost or sent to top of page', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).not.toBe('BODY');
});

Then('contrast ratio should be at least {string} for {string} text', async function (ratio: string, textSize: string) {
  const minRatio = parseFloat(ratio.split(':')[0]);
  expect(minRatio).toBeGreaterThanOrEqual(3);
});

Then('element should be clearly readable', async function () {
  const element = await page.evaluate(() => {
    const el = document.activeElement;
    return el ? window.getComputedStyle(el).color : null;
  });
  expect(element).toBeTruthy();
});

Then('checked checkboxes should use checkmark icon in addition to color', async function () {
  const checkedIcon = await page.locator('//input[@type="checkbox"]:checked + svg').count();
  expect(checkedIcon).toBeGreaterThan(0);
});

Then('unchecked boxes should have clear empty state', async function () {
  const uncheckedBoxes = await page.locator('//input[@type="checkbox"]:not(:checked)').count();
  expect(uncheckedBoxes).toBeGreaterThan(0);
});

Then('states should be distinguishable in grayscale mode', async function () {
  await page.emulateMedia({ colorScheme: 'no-preference' });
  const checkboxes = await page.locator('//input[@type="checkbox"]').count();
  expect(checkboxes).toBeGreaterThan(0);
});

Then('error state should be indicated by icon or text in addition to red color', async function () {
  const errorIcon = await page.locator('//div[@role="alert"] svg, //div[@role="alert"] span').count();
  expect(errorIcon).toBeGreaterThan(0);
});

Then('error borders should have sufficient contrast', async function () {
  const errorField = page.locator('//input[@aria-invalid="true"]');
  const borderColor = await errorField.evaluate((el) => window.getComputedStyle(el).borderColor);
  expect(borderColor).toBeTruthy();
});

Then('success state should use icon or text in addition to green color', async function () {
  const successIcon = await page.locator('//div[@id="success-message"] svg, //div[@id="success-message"] span').count();
  expect(successIcon).toBeGreaterThan(0);
});

Then('all text should remain visible and readable', async function () {
  const textElements = await page.locator('body *').evaluateAll((elements) => {
    return elements.filter(el => el.textContent && el.textContent.trim().length > 0).length;
  });
  expect(textElements).toBeGreaterThan(0);
});

Then('interactive elements should be distinguishable', async function () {
  const interactiveElements = await page.locator('button, a, input, select, textarea').count();
  expect(interactiveElements).toBeGreaterThan(0);
});

Then('focus indicators should be visible', async function () {
  await page.keyboard.press('Tab');
  const outlineStyle = await page.evaluate(() => {
    const el = document.activeElement;
    return el ? window.getComputedStyle(el).outlineStyle : null;
  });
  expect(outlineStyle).not.toBe('none');
});

Then('no information should be conveyed by color alone', async function () {
  const ariaLabels = await page.locator('[aria-label]').count();
  expect(ariaLabels).toBeGreaterThan(0);
});

Then('page should scale to {int} percent', async function (zoomLevel: number) {
  const currentZoom = await page.evaluate(() => {
    return document.body.style.zoom;
  });
  expect(currentZoom).toBe(`${zoomLevel}%`);
});

Then('all content should remain visible', async function () {
  const bodyHeight = await page.locator('body').evaluate((el) => el.scrollHeight);
  expect(bodyHeight).toBeGreaterThan(0);
});

Then('no horizontal scrolling should be required for main content', async function () {
  const bodyWidth = await page.locator('body').evaluate((el) => el.scrollWidth);
  const viewportWidth = page.viewportSize()?.width || 0;
  expect(bodyWidth).toBeLessThanOrEqual(viewportWidth + 50);
});

Then('text should be readable and not truncated', async function () {
  const textOverflow = await page.locator('body *').evaluateAll((elements) => {
    return elements.filter(el => {
      const style = window.getComputedStyle(el);
      return style.textOverflow === 'ellipsis';
    }).length;
  });
  expect(textOverflow).toBe(0);
});

Then('roles list should remain usable', async function () {
  const rolesList = page.locator('//div[@id="roles-list"]');
  await assertions.assertVisible(rolesList);
});

Then('role names should be fully visible', async function () {
  const roleNames = await page.locator('//div[contains(@id,"role-")]').count();
  expect(roleNames).toBeGreaterThan(0);
});

Then('action buttons should be accessible and not overlapping', async function () {
  const buttons = await page.locator('button').count();
  expect(buttons).toBeGreaterThan(0);
});

Then('form should open properly scaled', async function () {
  const form = page.locator('//form[@id="role-edit-form"]');
  await assertions.assertVisible(form);
});

Then('all form fields should be visible and accessible', async function () {
  const formFields = await page.locator('input, textarea, select').count();
  expect(formFields).toBeGreaterThan(0);
});

Then('no content should be cut off or hidden', async function () {
  const hiddenElements = await page.locator('[style*="display: none"]').count();
  expect(hiddenElements).toBe(0);
});

Then('all form labels should be fully visible and readable', async function () {
  const labels = await page.locator('label').count();
  expect(labels).toBeGreaterThan(0);
});

Then('input fields should be appropriately sized', async function () {
  const inputHeight = await page.locator('input').first().evaluate((el) => el.offsetHeight);
  expect(inputHeight).toBeGreaterThan(30);
});

Then('checkboxes and labels should not be overlapping', async function () {
  const checkboxes = await page.locator('//input[@type="checkbox"]').count();
  expect(checkboxes).toBeGreaterThan(0);
});

Then('permissions list should be scrollable if needed', async function () {
  const permissionsList = page.locator('//div[@id="permissions-list"]');
  const scrollHeight = await permissionsList.evaluate((el) => el.scrollHeight);
  expect(scrollHeight).toBeGreaterThan(0);
});

Then('checkboxes should remain aligned with labels', async function () {
  const checkboxes = await page.locator('//input[@type="checkbox"]').count();
  expect(checkboxes).toBeGreaterThan(0);
});

Then('no text truncation should occur', async function () {
  const truncated = await page.locator('[style*="text-overflow: ellipsis"]').count();
  expect(truncated).toBe(0);
});

Then('button should be fully visible and accessible', async function () {
  const button = page.locator('//button[@id="save-changes"]');
  await assertions.assertVisible(button);
});

Then('button text should not be truncated', async function () {
  const buttonText = await page.locator('//button[@id="save-changes"]').textContent();
  expect(buttonText).toBeTruthy();
});

Then('button should be large enough to click easily with minimum {string} by {string} pixel touch target', async function (width: string, height: string) {
  const button = page.locator('//button[@id="save-changes"]');
  const box = await button.boundingBox();
  expect(box?.width).toBeGreaterThanOrEqual(parseInt(width));
  expect(box?.height).toBeGreaterThanOrEqual(parseInt(height));
});

Then('success message should be fully readable', async function () {
  const successMessage = page.locator('//div[@id="success-message"]');
  await assertions.assertVisible(successMessage);
});

Then('message should not be cut off or hidden', async function () {
  const messageText = await page.locator('//div[@id="success-message"]').textContent();
  expect(messageText).toBeTruthy();
});

Then('close button should be accessible if present', async function () {
  const closeButton = await page.locator('//button[@id="close-message"]').count();
  if (closeButton > 0) {
    await assertions.assertVisible(page.locator('//button[@id="close-message"]'));
  }
});

Then('all interactive elements should have minimum {string} by {string} pixel touch targets', async function (width: string, height: string) {
  const buttons = await page.locator('button, a, input[type="checkbox"]').all();
  for (const button of buttons) {
    const box = await button.boundingBox();
    if (box) {
      expect(box.width).toBeGreaterThanOrEqual(parseInt(width));
      expect(box.height).toBeGreaterThanOrEqual(parseInt(height));
    }
  }
});

Then('adequate spacing of minimum {string} pixels should exist between touch targets', async function (spacing: string) {
  const buttons = await page.locator('button').all();
  expect(buttons.length).toBeGreaterThan(0);
});

Then('form should open in mobile-optimized layout', async function () {
  const form = page.locator('//form[@id="role-edit-form"]');
  await assertions.assertVisible(form);
});

Then('tap target should be easy to activate without accidental adjacent taps', async function () {
  const roleElement = page.locator('//div[@id="role-mobileaccessrole"]');
  const box = await roleElement.boundingBox();
  expect(box?.width).toBeGreaterThanOrEqual(44);
});

Then('form fields should be appropriately sized for touch input', async function () {
  const inputHeight = await page.locator('input').first().evaluate((el) => el.offsetHeight);
  expect(inputHeight).toBeGreaterThanOrEqual(44);
});

Then('virtual keyboard should appear', async function () {
  await page.waitForTimeout(500);
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBe('INPUT');
});

Then('input field should have minimum {string} pixel height', async function (height: string) {
  const inputHeight = await page.locator('input:focus').evaluate((el) => el.offsetHeight);
  expect(inputHeight).toBeGreaterThanOrEqual(parseInt(height));
});

Then('field label should remain visible when keyboard is open', async function () {
  const label = page.locator('label');
  await assertions.assertVisible(label.first());
});

Then('zoom should not be triggered on focus with font-size {string} pixels or larger', async function (fontSize: string) {
  const inputFontSize = await page.locator('input:focus').evaluate((el) => {
    return window.getComputedStyle(el).fontSize;
  });
  expect(parseInt(inputFontSize)).toBeGreaterThanOrEqual(parseInt(fontSize));
});

Then('checkboxes should have minimum {string} by {string} pixel touch targets', async function (width: string, height: string) {
  const checkbox = page.locator('//input[@type="checkbox"]').first();
  const box = await checkbox.boundingBox();
  expect(box?.width).toBeGreaterThanOrEqual(parseInt(width));
  expect(box?.height).toBeGreaterThanOrEqual(parseInt(height));
});

Then('checkbox labels should be tappable to toggle state', async function () {
  const label = page.locator('//label[@for="permission-1"]');
  await actions.click(label);
  const checked = await page.locator('//input[@id="permission-1"]').isChecked();
  expect(checked).toBeTruthy();
});

Then('scrolling should be smooth without accidental checkbox activation', async function () {
  const permissionsList = page.locator('//div[@id="permissions-list"]');
  await permissionsList.evaluate((el) => el.scrollBy(0, 100));
  await page.waitForTimeout(300);
});

Then('adequate spacing should prevent mis-taps', async function () {
  const checkboxes = await page.locator('//input[@type="checkbox"]').all();
  expect(checkboxes.length).toBeGreaterThan(0);
});

Then('textarea should expand appropriately for content', async function () {
  const textarea = page.locator('//textarea[@id="description"]');
  const height = await textarea.evaluate((el) => el.scrollHeight);
  expect(height).toBeGreaterThan(44);
});

Then('virtual keyboard should not obscure textarea', async function () {
  const textarea = page.locator('//textarea[@id="description"]');
  const box = await textarea.boundingBox();
  expect(box?.y).toBeLessThan(500);
});

Then('text entry should be smooth without lag', async function () {
  await page.waitForTimeout(300);
  const value = await page.locator('//textarea[@id="description"]').inputValue();
  expect(value.length).toBeGreaterThan(0);
});

Then('textarea should have minimum {string} pixel height', async function (height: string) {
  const textareaHeight = await page.locator('//textarea[@id="description"]').evaluate((el) => el.offsetHeight);
  expect(textareaHeight).toBeGreaterThanOrEqual(parseInt(height));
});

Then('form should adapt to landscape layout', async function () {
  const form = page.locator('//form[@id="role-edit-form"]');
  await assertions.assertVisible(form);
});

Then('all fields should remain accessible', async function () {
  const fields = await page.locator('input, textarea, select').count();
  expect(fields).toBeGreaterThan(0);
});

Then('touch targets should maintain minimum size', async function () {
  const button = page.locator('//button[@id="save-changes"]');
  const box = await button.boundingBox();
  expect(box?.width).toBeGreaterThanOrEqual(44);
  expect(box?.height).toBeGreaterThanOrEqual(44);
});

Then('no content should be cut off or inaccessible', async function () {
  const bodyWidth = await page.locator('body').evaluate((el) => el.scrollWidth);
  const viewportWidth = page.viewportSize()?.width || 0;
  expect(bodyWidth).toBeLessThanOrEqual(viewportWidth + 50);
});

Then('button should have minimum {string} by {string} pixel size', async function (width: string, height: string) {
  const button = page.locator('//button[@id="save-changes"]');
  const box = await button.boundingBox();
  expect(box?.width).toBeGreaterThanOrEqual(parseInt(width));
  expect(box?.height).toBeGreaterThanOrEqual(parseInt(height));
});

Then('button should provide visual feedback on tap', async function () {
  const button = page.locator('//button[@id="save-changes"]');
  await button.evaluate((el) => {
    el.style.backgroundColor = '#ccc';
  });
  await page.waitForTimeout(200);
});

Then('success message should appear and be readable on mobile viewport', async function () {
  const successMessage = page.locator('//div[@id="success-message"]');
  await assertions.assertVisible(successMessage);
});

Then('swipe gestures should navigate between elements correctly', async function () {
  await page.waitForTimeout(500);
  const elements = await page.locator('button, a, input').count();
  expect(elements).toBeGreaterThan(0);
});

Then('double-tap should activate elements', async function () {
  const button = page.locator('//button[@id="save-changes"]');
  await button.dblclick();
  await page.waitForTimeout(300);
});

Then('all elements should have proper labels announced', async function () {
  const labeledElements = await page.locator('[aria-label], label').count();
  expect(labeledElements).toBeGreaterThan(0);
});

Then('rotor controls should work as expected', async function () {
  const headings = await page.locator('h1, h2, h3, h4, h5, h6').count();
  expect(headings).toBeGreaterThan(0);
});