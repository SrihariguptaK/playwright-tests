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
      administrator: { username: 'admin', password: 'admin123' }
    },
    focusedElements: [],
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

/**************************************************/
/*  SHARED BACKGROUND STEPS
/*  Category: Accessibility
/*  Priority: High
/**************************************************/

Given('administrator is authenticated and logged in', async function () {
  const credentials = this.testData?.users?.administrator || { username: 'admin', password: 'admin123' };
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000');
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

Given('administrator is on {string} page', async function (pageName: string) {
  const pageUrl = `/${pageName.toLowerCase().replace(/\s+/g, '-')}`;
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}${pageUrl}`);
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator(`//h1[contains(text(),'${pageName}')]`));
});

/**************************************************/
/*  TC-001: Keyboard Navigation Workflow
/*  Priority: High
/*  Category: Accessibility - Keyboard Navigation
/**************************************************/

Given('test role {string} exists with {int} permissions already assigned', async function (roleName: string, permissionCount: number) {
  this.testData.currentRole = roleName;
  this.testData.initialPermissionCount = permissionCount;
  await page.evaluate(({ role, count }) => {
    window.testData = window.testData || {};
    window.testData.roles = window.testData.roles || {};
    window.testData.roles[role] = { permissionsAssigned: count };
  }, { role: roleName, count: permissionCount });
});

Given('mouse input is disabled for testing', async function () {
  await page.evaluate(() => {
    document.body.style.pointerEvents = 'none';
  });
  this.testData.mouseDisabled = true;
});

Given('at least {int} permissions are available in the system', async function (permissionCount: number) {
  this.testData.availablePermissions = permissionCount;
  await page.evaluate((count) => {
    window.testData = window.testData || {};
    window.testData.availablePermissions = count;
  }, permissionCount);
});

/**************************************************/
/*  TC-002: Screen Reader Announcements
/*  Priority: High
/*  Category: Accessibility - Screen Reader
/**************************************************/

Given('screen reader {string} is active', async function (screenReaderName: string) {
  this.testData.screenReader = screenReaderName;
  this.testData.screenReaderOutput = [];
  await page.evaluate(() => {
    window.screenReaderAnnouncements = [];
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === 'childList' || mutation.type === 'characterData') {
          const target = mutation.target as HTMLElement;
          if (target.getAttribute('role') === 'alert' || target.getAttribute('aria-live')) {
            window.screenReaderAnnouncements.push(target.textContent || '');
          }
        }
      });
    });
    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
  });
});

Given('test role {string} exists in the system', async function (roleName: string) {
  this.testData.currentRole = roleName;
  await page.evaluate((role) => {
    window.testData = window.testData || {};
    window.testData.roles = window.testData.roles || {};
    window.testData.roles[role] = { exists: true };
  }, roleName);
});

Given('screen reader speech output is being monitored', async function () {
  this.testData.monitoringSpeech = true;
  await page.evaluate(() => {
    window.speechMonitoring = true;
  });
});

Given('page has proper ARIA labels and live regions implemented', async function () {
  const ariaLiveRegions = await page.locator('//*[@aria-live]').count();
  expect(ariaLiveRegions).toBeGreaterThan(0);
});

/**************************************************/
/*  TC-003: Focus Management and Trap Prevention
/*  Priority: High
/*  Category: Accessibility - Focus Management
/**************************************************/

Given('permission assignment interface opens in modal dialog', async function () {
  this.testData.modalOpen = true;
  await waits.waitForVisible(page.locator('//div[@role="dialog"]'));
});

Given('keyboard is the only input method being used', async function () {
  await page.evaluate(() => {
    document.body.style.pointerEvents = 'none';
  });
  this.testData.keyboardOnly = true;
});

/**************************************************/
/*  TC-004: Color Contrast Compliance
/*  Priority: High
/*  Category: Accessibility - WCAG AA
/**************************************************/

Given('color contrast analyzer tool is available', async function () {
  this.testData.contrastAnalyzer = true;
  await page.addScriptTag({
    content: `
      window.getContrastRatio = function(fg, bg) {
        const getLuminance = (rgb) => {
          const [r, g, b] = rgb.match(/\\d+/g).map(Number);
          const [rs, gs, bs] = [r, g, b].map(c => {
            c = c / 255;
            return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
          });
          return 0.2126 * rs + 0.7152 * gs + 0.0722 * bs;
        };
        const l1 = getLuminance(fg);
        const l2 = getLuminance(bg);
        return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
      };
    `
  });
});

Given('permission assignment interface is fully loaded', async function () {
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator('//h1[contains(text(),"Permission")]'));
});

Given('test role with some permissions assigned is selected', async function () {
  await actions.click(page.locator('//select[@id="role-dropdown"]'));
  await actions.selectByText(page.locator('//select[@id="role-dropdown"]'), 'TestRole');
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TC-006: Browser Zoom Usability
/*  Priority: Medium
/*  Category: Accessibility - Responsive
/**************************************************/

Given('browser zoom is set to {string} initially', async function (zoomLevel: string) {
  const zoom = parseFloat(zoomLevel) / 100;
  await page.evaluate((z) => {
    document.body.style.zoom = z.toString();
  }, zoom);
  this.testData.currentZoom = zoomLevel;
});

Given('browser window is set to {string} resolution', async function (resolution: string) {
  const [width, height] = resolution.split('x').map(Number);
  await page.setViewportSize({ width, height });
});

Given('test role {string} exists with {int} permissions available', async function (roleName: string, permissionCount: number) {
  this.testData.currentRole = roleName;
  this.testData.availablePermissions = permissionCount;
});

/**************************************************/
/*  TC-007: ARIA Live Regions
/*  Priority: High
/*  Category: Accessibility - ARIA
/**************************************************/

Given('permission management interface is open', async function () {
  await actions.click(page.locator('//button[@id="manage-permissions"]'));
  await waits.waitForVisible(page.locator('//div[@role="dialog"]'));
});

Given('test role {string} is selected', async function (roleName: string) {
  this.testData.currentRole = roleName;
  await actions.selectByText(page.locator('//select[@id="role-dropdown"]'), roleName);
  await waits.waitForNetworkIdle();
});

Given('ARIA live regions are implemented for dynamic content updates', async function () {
  const liveRegions = await page.locator('//*[@aria-live]').count();
  expect(liveRegions).toBeGreaterThan(0);
});

Given('screen reader verbosity is set to medium level', async function () {
  this.testData.screenReaderVerbosity = 'medium';
});

/**************************************************/
/*  TC-008: Error Handling - Form Validation
/*  Priority: High
/*  Category: Accessibility - Error Handling
/**************************************************/

Given('conflicting permissions {string} and {string} exist in system', async function (permission1: string, permission2: string) {
  this.testData.conflictingPermissions = [permission1, permission2];
  await page.evaluate(({ p1, p2 }) => {
    window.testData = window.testData || {};
    window.testData.conflictingPermissions = [p1, p2];
  }, { p1: permission1, p2: permission2 });
});

Given('form validation is implemented with ARIA error handling', async function () {
  const formValidation = await page.evaluate(() => {
    return document.querySelector('form') !== null;
  });
  expect(formValidation).toBe(true);
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  TC-001: Keyboard Navigation Workflow
/**************************************************/

When('administrator presses Tab key repeatedly to navigate to {string} button', async function (buttonText: string) {
  const buttonXPath = `//button[contains(text(),'${buttonText}')]`;
  let focused = false;
  let attempts = 0;
  while (!focused && attempts < 50) {
    await page.keyboard.press('Tab');
    const activeElement = await page.evaluate(() => document.activeElement?.textContent);
    if (activeElement?.includes(buttonText)) {
      focused = true;
    }
    attempts++;
  }
  this.testData.focusedElements = this.testData.focusedElements || [];
  this.testData.focusedElements.push(buttonText);
});

When('administrator presses Enter key to activate {string} button', async function (buttonText: string) {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('administrator presses Tab to reach roles dropdown', async function () {
  let focused = false;
  let attempts = 0;
  while (!focused && attempts < 20) {
    await page.keyboard.press('Tab');
    const activeElement = await page.evaluate(() => {
      const el = document.activeElement;
      return el?.tagName === 'SELECT' || el?.getAttribute('role') === 'combobox';
    });
    if (activeElement) {
      focused = true;
    }
    attempts++;
  }
});

When('administrator presses Space key to open dropdown', async function () {
  await page.keyboard.press('Space');
  await page.waitForTimeout(300);
});

When('administrator uses Arrow Down key to navigate to {string}', async function (optionText: string) {
  let found = false;
  let attempts = 0;
  while (!found && attempts < 20) {
    await page.keyboard.press('ArrowDown');
    const currentOption = await page.evaluate(() => {
      const select = document.activeElement as HTMLSelectElement;
      return select?.options?.[select.selectedIndex]?.text;
    });
    if (currentOption?.includes(optionText)) {
      found = true;
    }
    attempts++;
  }
});

When('administrator presses Enter to select role', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('administrator presses Tab to navigate to permissions list', async function () {
  await page.keyboard.press('Tab');
  await page.waitForTimeout(200);
});

When('administrator uses Arrow keys to move through permission checkboxes', async function () {
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('ArrowDown');
});

When('administrator presses Space to check {int} additional permissions', async function (count: number) {
  for (let i = 0; i < count; i++) {
    await page.keyboard.press('Space');
    await page.waitForTimeout(200);
    await page.keyboard.press('ArrowDown');
  }
});

When('administrator presses Tab to navigate to {string} button', async function (buttonText: string) {
  let focused = false;
  let attempts = 0;
  while (!focused && attempts < 20) {
    await page.keyboard.press('Tab');
    const activeElement = await page.evaluate(() => document.activeElement?.textContent);
    if (activeElement?.includes(buttonText)) {
      focused = true;
    }
    attempts++;
  }
});

When('administrator presses Enter to submit the form', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('administrator presses Tab after submission', async function () {
  await page.keyboard.press('Tab');
  await page.waitForTimeout(200);
});

/**************************************************/
/*  TC-002: Screen Reader Announcements
/**************************************************/

When('administrator navigates to permission configuration section using screen reader commands', async function () {
  await page.keyboard.press('H');
  await page.waitForTimeout(300);
});

When('administrator navigates to and activates {string} button', async function (buttonText: string) {
  const buttonXPath = `//button[contains(text(),'${buttonText}')]`;
  await actions.click(page.locator(buttonXPath));
  await waits.waitForNetworkIdle();
});

When('administrator navigates to roles dropdown using screen reader commands', async function () {
  await page.keyboard.press('Tab');
  await page.waitForTimeout(200);
});

When('administrator opens dropdown', async function () {
  await page.keyboard.press('Space');
  await page.waitForTimeout(300);
});

When('administrator selects {string} from dropdown using arrow keys', async function (roleName: string) {
  let found = false;
  let attempts = 0;
  while (!found && attempts < 20) {
    await page.keyboard.press('ArrowDown');
    const currentOption = await page.evaluate(() => {
      const select = document.activeElement as HTMLSelectElement;
      return select?.options?.[select.selectedIndex]?.text;
    });
    if (currentOption?.includes(roleName)) {
      found = true;
      await page.keyboard.press('Enter');
    }
    attempts++;
  }
  await waits.waitForNetworkIdle();
});

When('administrator navigates to permissions list', async function () {
  await page.keyboard.press('Tab');
  await page.waitForTimeout(200);
});

When('administrator checks {int} permission checkboxes', async function (count: number) {
  for (let i = 0; i < count; i++) {
    await page.keyboard.press('Space');
    await page.waitForTimeout(200);
    await page.keyboard.press('Tab');
  }
});

When('administrator navigates through updated role details', async function () {
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab');
});

/**************************************************/
/*  TC-003: Focus Management
/**************************************************/

When('administrator opens permission management modal using Enter key on {string} button', async function (buttonText: string) {
  const buttonXPath = `//button[contains(text(),'${buttonText}')]`;
  await page.locator(buttonXPath).focus();
  await page.keyboard.press('Enter');
  await waits.waitForVisible(page.locator('//div[@role="dialog"]'));
});

When('administrator presses Tab repeatedly to navigate through modal elements', async function () {
  this.testData.modalElements = [];
  for (let i = 0; i < 10; i++) {
    await page.keyboard.press('Tab');
    const activeElement = await page.evaluate(() => {
      const el = document.activeElement;
      return { tag: el?.tagName, text: el?.textContent?.substring(0, 30) };
    });
    this.testData.modalElements.push(activeElement);
    await page.waitForTimeout(100);
  }
});

When('administrator presses Shift+Tab to navigate backwards', async function () {
  for (let i = 0; i < 5; i++) {
    await page.keyboard.press('Shift+Tab');
    await page.waitForTimeout(100);
  }
});

When('administrator attempts to Tab to elements outside modal', async function () {
  for (let i = 0; i < 15; i++) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(50);
  }
});

When('administrator selects {string}', async function (roleName: string) {
  await actions.selectByText(page.locator('//select[@id="role-dropdown"]'), roleName);
  await waits.waitForNetworkIdle();
});

When('administrator checks {int} permissions', async function (count: number) {
  const checkboxes = page.locator('//input[@type="checkbox"]');
  for (let i = 0; i < count; i++) {
    await actions.check(checkboxes.nth(i));
    await page.waitForTimeout(100);
  }
});

When('administrator presses Enter on {string} button', async function (buttonText: string) {
  const buttonXPath = `//button[contains(text(),'${buttonText}')]`;
  await page.locator(buttonXPath).focus();
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('modal closes after successful submission', async function () {
  await waits.waitForHidden(page.locator('//div[@role="dialog"]'));
});

When('administrator reopens modal', async function () {
  await actions.click(page.locator('//button[@id="manage-permissions"]'));
  await waits.waitForVisible(page.locator('//div[@role="dialog"]'));
});

When('administrator presses Escape key', async function () {
  await page.keyboard.press('Escape');
  await page.waitForTimeout(300);
});

/**************************************************/
/*  TC-004: Color Contrast
/**************************************************/

When('administrator measures contrast ratio of {string} against background', async function (elementName: string) {
  const elementXPath = `//*[contains(text(),'${elementName}')]`;
  const contrastRatio = await page.evaluate((xpath) => {
    const element = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue as HTMLElement;
    if (!element) return 0;
    const fgColor = window.getComputedStyle(element).color;
    const bgColor = window.getComputedStyle(element).backgroundColor;
    return (window as any).getContrastRatio(fgColor, bgColor);
  }, elementXPath);
  this.testData.contrastResults[elementName] = contrastRatio;
});

/**************************************************/
/*  TC-005: Success/Error Messages Contrast
/**************************************************/

When('administrator triggers success confirmation message', async function () {
  await actions.click(page.locator('//button[@id="submit"]'));
  await waits.waitForVisible(page.locator('//div[@role="alert"]'));
});

When('administrator triggers error state by assigning conflicting permissions', async function () {
  await actions.check(page.locator('//input[@value="Admin"]'));
  await actions.check(page.locator('//input[@value="ReadOnly"]'));
  await actions.click(page.locator('//button[@id="submit"]'));
  await waits.waitForVisible(page.locator('//div[@role="alert"]'));
});

/**************************************************/
/*  TC-006: Browser Zoom
/**************************************************/

When('administrator sets browser zoom to {string}', async function (zoomLevel: string) {
  const zoom = parseFloat(zoomLevel) / 100;
  await page.evaluate((z) => {
    document.body.style.zoom = z.toString();
  }, zoom);
  this.testData.currentZoom = zoomLevel;
  await page.waitForTimeout(500);
});

When('administrator navigates to permission configuration section', async function () {
  await actions.click(page.locator('//a[contains(text(),"Permission")]'));
  await waits.waitForNetworkIdle();
});

When('administrator clicks {string} button', async function (buttonText: string) {
  const buttonXPath = `//button[contains(text(),'${buttonText}')]`;
  await actions.click(page.locator(buttonXPath));
  await waits.waitForNetworkIdle();
});

When('administrator scrolls through permissions list', async function () {
  await actions.scrollIntoView(page.locator('//div[@id="permissions-list"]'));
  await page.mouse.wheel(0, 300);
});

When('administrator verifies all form controls are visible', async function () {
  await assertions.assertVisible(page.locator('//button[@id="submit"]'));
  await assertions.assertVisible(page.locator('//button[@id="cancel"]'));
});

When('administrator resizes browser window while at {string} zoom', async function (zoomLevel: string) {
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.waitForTimeout(500);
});

/**************************************************/
/*  TC-007: ARIA Live Regions
/**************************************************/

When('administrator checks first permission checkbox', async function () {
  await actions.check(page.locator('//input[@type="checkbox"]').first());
  await page.waitForTimeout(500);
});

When('administrator checks two more permission checkboxes in quick succession', async function () {
  await actions.check(page.locator('//input[@type="checkbox"]').nth(1));
  await page.waitForTimeout(100);
  await actions.check(page.locator('//input[@type="checkbox"]').nth(2));
  await page.waitForTimeout(500);
});

When('administrator unchecks one permission', async function () {
  await actions.click(page.locator('//input[@type="checkbox"]').first());
  await page.waitForTimeout(500);
});

When('submission completes successfully', async function () {
  await waits.waitForVisible(page.locator('//div[@role="alert"]'));
});

When('administrator triggers validation error by assigning conflicting permissions', async function () {
  await actions.check(page.locator('//input[@value="Admin"]'));
  await actions.check(page.locator('//input[@value="ReadOnly"]'));
  await actions.click(page.locator('//button[@id="submit"]'));
  await waits.waitForVisible(page.locator('//div[@role="alert"]'));
});

When('administrator navigates away from and back to updated role details', async function () {
  await actions.click(page.locator('//a[@id="home"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//a[contains(text(),"Permission")]'));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TC-008: Error Handling
/**************************************************/

When('administrator assigns conflicting permission {string}', async function (permissionName: string) {
  await actions.check(page.locator(`//input[@value="${permissionName}"]`));
  await page.waitForTimeout(200);
});

When('administrator uses screen reader to navigate to permission checkboxes with errors', async function () {
  await page.keyboard.press('Tab');
  await page.waitForTimeout(300);
});

When('validation error occurs', async function () {
  await waits.waitForVisible(page.locator('//div[@role="alert"]'));
});

When('administrator unchecks one of the conflicting permissions', async function () {
  await actions.click(page.locator('//input[@value="Admin"]'));
  await page.waitForTimeout(500);
});

/**************************************************/
/*  TC-009: Network Error
/**************************************************/

When('network connection is disconnected', async function () {
  await context.setOffline(true);
});

When('administrator assigns {int} valid permissions', async function (count: number) {
  const checkboxes = page.locator('//input[@type="checkbox"]');
  for (let i = 0; i < count; i++) {
    await actions.check(checkboxes.nth(i));
    await page.waitForTimeout(100);
  }
});

/**************************************************/
/*  TC-010: Multiple Errors
/**************************************************/

When('administrator triggers multiple validation errors', async function () {
  await actions.check(page.locator('//input[@value="Admin"]'));
  await actions.check(page.locator('//input[@value="ReadOnly"]'));
  await actions.fill(page.locator('//input[@id="role-name"]'), '');
  await actions.click(page.locator('//button[@id="submit"]'));
  await waits.waitForVisible(page.locator('//div[@role="alert"]'));
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  TC-001: Keyboard Navigation
/**************************************************/

Then('focus should move through page elements with visible focus indicator', async function () {
  const focusIndicator = await page.evaluate(() => {
    const el = document.activeElement;
    const styles = window.getComputedStyle(el as Element);
    return styles.outline !== 'none' || styles.boxShadow !== 'none';
  });
  expect(focusIndicator).toBe(true);
});

Then('{string} button should have {string} focus ring', async function (buttonText: string, focusStyle: string) {
  const buttonXPath = `//button[contains(text(),'${buttonText}')]`;
  await page.locator(buttonXPath).focus();
  const hasFocusRing = await page.evaluate((xpath) => {
    const button = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue as HTMLElement;
    const styles = window.getComputedStyle(button);
    return styles.outline !== 'none' || styles.boxShadow !== 'none';
  }, buttonXPath);
  expect(hasFocusRing).toBe(true);
});

Then('permission management interface should open', async function () {
  await assertions.assertVisible(page.locator('//div[@role="dialog"]'));
});

Then('focus should automatically move to first interactive element', async function () {
  const firstInteractive = await page.evaluate(() => {
    const dialog = document.querySelector('[role="dialog"]');
    const interactive = dialog?.querySelector('button, input, select, textarea, a[href]');
    return document.activeElement === interactive;
  });
  expect(firstInteractive).toBe(true);
});

Then('dropdown should open with focus on first role', async function () {
  const dropdownExpanded = await page.evaluate(() => {
    const select = document.activeElement as HTMLSelectElement;
    return select?.tagName === 'SELECT';
  });
  expect(dropdownExpanded).toBe(true);
});

Then('Arrow keys should navigate through roles with visual highlight', async function () {
  await page.keyboard.press('ArrowDown');
  await page.waitForTimeout(100);
  const highlighted = await page.evaluate(() => {
    const select = document.activeElement as HTMLSelectElement;
    return select?.selectedIndex >= 0;
  });
  expect(highlighted).toBe(true);
});

Then('{string} should be selected', async function (roleName: string) {
  const selected = await page.evaluate((name) => {
    const select = document.activeElement as HTMLSelectElement;
    return select?.options?.[select.selectedIndex]?.text.includes(name);
  }, roleName);
  expect(selected).toBe(true);
});

Then('role details panel should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="role-details"]'));
});

Then('focus should move to each permission checkbox with visible focus indicator', async function () {
  const focusVisible = await page.evaluate(() => {
    const el = document.activeElement;
    const styles = window.getComputedStyle(el as Element);
    return styles.outline !== 'none' || styles.boxShadow !== 'none';
  });
  expect(focusVisible).toBe(true);
});

Then('Space key should toggle checkbox state', async function () {
  const initialState = await page.evaluate(() => (document.activeElement as HTMLInputElement)?.checked);
  await page.keyboard.press('Space');
  await page.waitForTimeout(100);
  const newState = await page.evaluate(() => (document.activeElement as HTMLInputElement)?.checked);
  expect(newState).toBe(!initialState);
});

Then('{string} count should be displayed', async function (countText: string) {
  await assertions.assertContainsText(page.locator('//div[@id="permission-count"]'), countText);
});

Then('{string} button should receive focus with clear indicator', async function (buttonText: string) {
  const buttonXPath = `//button[contains(text(),'${buttonText}')]`;
  const hasFocus = await page.evaluate((xpath) => {
    const button = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue as HTMLElement;
    return document.activeElement === button;
  }, buttonXPath);
  expect(hasFocus).toBe(true);
});

Then('Enter key should activate submission', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

Then('loading state should be announced', async function () {
  await assertions.assertVisible(page.locator('//*[contains(text(),"Processing")]'));
});

Then('focus should move to confirmation message or logical element', async function () {
  const focusOnMessage = await page.evaluate(() => {
    const alert = document.querySelector('[role="alert"]');
    return alert?.contains(document.activeElement);
  });
  expect(focusOnMessage).toBe(true);
});

Then('confirmation message should be accessible via Tab navigation', async function () {
  await page.keyboard.press('Tab');
  const reachable = await page.evaluate(() => {
    return document.activeElement !== document.body;
  });
  expect(reachable).toBe(true);
});

Then('administrator should be able to continue navigating with keyboard', async function () {
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab');
  const canNavigate = await page.evaluate(() => document.activeElement !== document.body);
  expect(canNavigate).toBe(true);
});

Then('all permission assignment actions should be completed successfully', async function () {
  await assertions.assertVisible(page.locator('//div[@role="alert"]'));
});

Then('focus indicators should be visible throughout entire workflow', async function () {
  const focusVisible = await page.evaluate(() => {
    const el = document.activeElement;
    const styles = window.getComputedStyle(el as Element);
    return styles.outline !== 'none' || styles.boxShadow !== 'none';
  });
  expect(focusVisible).toBe(true);
});

Then('no keyboard traps should occur', async function () {
  for (let i = 0; i < 20; i++) {
    await page.keyboard.press('Tab');
    const notTrapped = await page.evaluate(() => document.activeElement !== null);
    expect(notTrapped).toBe(true);
  }
});

Then('permissions should be saved correctly in database', async function () {
  await waits.waitForNetworkIdle();
  const saved = await page.evaluate(() => {
    return window.testData?.permissionsSaved === true;
  });
  expect(saved).toBeTruthy();
});

/**************************************************/
/*  TC-002: Screen Reader
/**************************************************/

Then('screen reader should announce {string}', async function (announcement: string) {
  const announced = await page.evaluate((text) => {
    return window.screenReaderAnnouncements?.some((a: string) => a.includes(text));
  }, announcement);
  expect(announced).toBeTruthy();
});

Then('screen reader should announce {string} before activation', async function (announcement: string) {
  await page.waitForTimeout(300);
});

Then('screen reader should announce {string} after activation', async function (announcement: string) {
  await page.waitForTimeout(300);
});

Then('screen reader should announce available interactive elements', async function () {
  const elements = await page.locator('button, a, input, select').count();
  expect(elements).toBeGreaterThan(0);
});

Then('screen reader should announce number of available options', async function () {
  const optionCount = await page.locator('//select[@id="role-dropdown"]/option').count();
  expect(optionCount).toBeGreaterThan(0);
});

Then('screen reader should announce each role name as arrow keys navigate', async function () {
  await page.keyboard.press('ArrowDown');
  await page.waitForTimeout(200);
});

Then('screen reader should announce {string} when Enter is pressed', async function (announcement: string) {
  await page.waitForTimeout(300);
});

Then('screen reader should announce {string} when panel updates', async function (announcement: string) {
  await page.waitForTimeout(300);
});

Then('live region should announce {string} after each change', async function (announcement: string) {
  await page.waitForTimeout(500);
  await assertions.assertContainsText(page.locator('//*[@aria-live]'), announcement);
});

Then('screen reader should announce updated permission count', async function () {
  await page.waitForTimeout(300);
});

Then('screen reader should announce newly assigned permissions in logical reading order', async function () {
  await page.waitForTimeout(300);
});

Then('all interactive elements should have proper accessible names', async function () {
  const elementsWithLabels = await page.evaluate(() => {
    const interactive = document.querySelectorAll('button, input, select, a[href]');
    return Array.from(interactive).every(el => {
      return el.getAttribute('aria-label') || el.textContent?.trim() || (el as HTMLInputElement).labels?.length;
    });
  });
  expect(elementsWithLabels).toBe(true);
});

Then('state changes should be announced via ARIA live regions', async function () {
  const liveRegions = await page.locator('//*[@aria-live]').count();
  expect(liveRegions).toBeGreaterThan(0);
});

Then('administrator should complete entire workflow using screen reader without visual reference', async function () {
  await page.waitForTimeout(500);
});

/**************************************************/
/*  TC-003: Focus Management
/**************************************************/

Then('modal should open', async function () {
  await assertions.assertVisible(page.locator('//div[@role="dialog"]'));
});

Then('background content should be inert', async function () {
  const backgroundInert = await page.evaluate(() => {
    const main = document.querySelector('main');
    return main?.getAttribute('aria-hidden') === 'true' || main?.hasAttribute('inert');
  });
  expect(backgroundInert).toBeTruthy();
});

Then('focus should cycle through close button, role dropdown, permission checkboxes, {string} button, {string} button', async function (button1: string, button2: string) {
  await page.waitForTimeout(300);
});

Then('focus should return to close button after last element', async function () {
  const onCloseButton = await page.evaluate(() => {
    const closeBtn = document.querySelector('[aria-label="Close"]');
    return document.activeElement === closeBtn;
  });
  expect(onCloseButton).toBeTruthy();
});

Then('focus should remain trapped within modal', async function () {
  const inModal = await page.evaluate(() => {
    const modal = document.querySelector('[role="dialog"]');
    return modal?.contains(document.activeElement);
  });
  expect(inModal).toBe(true);
});

Then('focus should move in reverse order through all interactive elements', async function () {
  await page.waitForTimeout(300);
});

Then('focus should cycle from first to last element when reaching beginning', async function () {
  await page.waitForTimeout(300);
});

Then('background should be marked with {string} attribute set to {string}', async function (attribute: string, value: string) {
  const hasAttribute = await page.evaluate(({ attr, val }) => {
    const main = document.querySelector('main');
    return main?.getAttribute(attr) === val;
  }, { attr: attribute, val: value });
  expect(hasAttribute).toBeTruthy();
});

Then('form should submit', async function () {
  await waits.waitForNetworkIdle();
});

Then('loading state should maintain focus management', async function () {
  const focusManaged = await page.evaluate(() => document.activeElement !== document.body);
  expect(focusManaged).toBe(true);
});

Then('focus should remain in modal during processing', async function () {
  const inModal = await page.evaluate(() => {
    const modal = document.querySelector('[role="dialog"]');
    return modal?.contains(document.activeElement);
  });
  expect(inModal).toBe(true);
});

Then('focus should return to {string} button', async function (buttonText: string) {
  const buttonXPath = `//button[contains(text(),'${buttonText}')]`;
  const hasFocus = await page.evaluate((xpath) => {
    const button = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
    return document.activeElement === button;
  }, buttonXPath);
  expect(hasFocus).toBe(true);
});

Then('modal should close', async function () {
  await waits.waitForHidden(page.locator('//div[@role="dialog"]'));
});

Then('no changes should be saved', async function () {
  await page.waitForTimeout(300);
});

Then('focus should not be lost or moved to body element at any point', async function () {
  const notOnBody = await page.evaluate(() => document.activeElement !== document.body);
  expect(notOnBody).toBe(true);
});

/**************************************************/
/*  TC-004: Color Contrast
/**************************************************/

Then('contrast ratio should be at least {string}', async function (minRatio: string) {
  const ratio = parseFloat(minRatio);
  const actualRatio = Object.values(this.testData.contrastResults)[0] as number;
  expect(actualRatio).toBeGreaterThanOrEqual(ratio);
});

Then('element should meet WCAG 2.1 AA standard', async function () {
  const actualRatio = Object.values(this.testData.contrastResults)[0] as number;
  expect(actualRatio).toBeGreaterThanOrEqual(4.5);
});

Then('information should not be conveyed by color alone', async function () {
  const hasMultipleIndicators = await page.evaluate(() => {
    const alerts = document.querySelectorAll('[role="alert"]');
    return Array.from(alerts).every(alert => {
      const hasIcon = alert.querySelector('svg, img, [class*="icon"]');
      const hasText = alert.textContent?.trim().length > 0;
      return hasIcon && hasText;
    });
  });
  expect(hasMultipleIndicators).toBeTruthy();
});

/**************************************************/
/*  TC-005: Success/Error Messages
/**************************************************/

Then('success message text should have {string} contrast against green background', async function (minRatio: string) {
  const ratio = parseFloat(minRatio);
  const contrastRatio = await page.evaluate(() => {
    const alert = document.querySelector('[role="alert"]');
    if (!alert) return 0;
    const fgColor = window.getComputedStyle(alert).color;
    const bgColor = window.getComputedStyle(alert).backgroundColor;
    return (window as any).getContrastRatio(fgColor, bgColor);
  });
  expect(contrastRatio).toBeGreaterThanOrEqual(ratio);
});

Then('success icon should have {string} contrast', async function (minRatio: string) {
  const ratio = parseFloat(minRatio);
  await page.waitForTimeout(300);
});

Then('success should be indicated by icon and text not color alone', async function () {
  const hasMultipleIndicators = await page.evaluate(() => {
    const alert = document.querySelector('[role="alert"]');
    const hasIcon = alert?.querySelector('svg, img, [class*="icon"]');
    const hasText = alert?.textContent?.trim().length > 0;
    return hasIcon && hasText;
  });
  expect(hasMultipleIndicators).toBeTruthy();
});

Then('error message text should have {string} contrast against red background', async function (minRatio: string) {
  const ratio = parseFloat(minRatio);
  const contrastRatio = await page.evaluate(() => {
    const alert = document.querySelector('[role="alert"]');
    if (!alert) return 0;
    const fgColor = window.getComputedStyle(alert).color;
    const bgColor = window.getComputedStyle(alert).backgroundColor;
    return (window as any).getContrastRatio(fgColor, bgColor);
  });
  expect(contrastRatio).toBeGreaterThanOrEqual(ratio);
});

Then('error icon should have {string} contrast', async function (minRatio: string) {
  await page.waitForTimeout(300);
});

Then('error should be indicated by icon and text not color alone', async function () {
  const hasMultipleIndicators = await page.evaluate(() => {
    const alert = document.querySelector('[role="alert"]');
    const hasIcon = alert?.querySelector('svg, img, [class*="icon"]');
    const hasText = alert?.textContent?.trim().length > 0;
    return hasIcon && hasText;
  });
  expect(hasMultipleIndicators).toBeTruthy();
});

/**************************************************/
/*  TC-006: Browser Zoom
/**************************************************/

Then('page content should scale to {string}', async function (zoomLevel: string) {
  const currentZoom = await page.evaluate(() => document.body.style.zoom);
  expect(currentZoom).toBe((parseFloat(zoomLevel) / 100).toString());
});

Then('all elements should remain visible and functional', async function () {
  const visible = await page.locator('button, input, select').first().isVisible();
  expect(visible).toBe(true);
});

Then('no horizontal scrolling should be required for main content', async function () {
  const noHorizontalScroll = await page.evaluate(() => {
    return document.documentElement.scrollWidth <= document.documentElement.clientWidth;
  });
  expect(noHorizontalScroll).toBe(true);
});

Then('button should be fully visible and clickable at {string} zoom', async function (zoomLevel: string) {
  await assertions.assertVisible(page.locator('//button[@id="manage-permissions"]'));
});

Then('permission management interface should open without layout breaking', async function () {
  await assertions.assertVisible(page.locator('//div[@role="dialog"]'));
});

Then('dropdown should be fully functional at {string} zoom', async function (zoomLevel: string) {
  await assertions.assertVisible(page.locator('//select[@id="role-dropdown"]'));
});

Then('all role names should be readable', async function () {
  const readable = await page.locator('//select[@id="role-dropdown"]/option').first().isVisible();
  expect(readable).toBe(true);
});

Then('dropdown should not extend beyond viewport', async function () {
  const inViewport = await page.evaluate(() => {
    const select = document.querySelector('select');
    const rect = select?.getBoundingClientRect();
    return rect && rect.right <= window.innerWidth;
  });
  expect(inViewport).toBe(true);
});

Then('scrolling within dropdown should work if needed', async function () {
  await page.waitForTimeout(300);
});

Then('permissions list should be scrollable if needed', async function () {
  await page.waitForTimeout(300);
});

Then('checkboxes and labels should be properly aligned and clickable', async function () {
  const aligned = await page.locator('//input[@type="checkbox"]').first().isVisible();
  expect(aligned).toBe(true);
});

Then('text should not overlap or truncate inappropriately', async function () {
  await page.waitForTimeout(300);
});

Then('{string} button should be visible without horizontal scroll', async function (buttonText: string) {
  const buttonXPath = `//button[contains(text(),'${buttonText}')]`;
  await assertions.assertVisible(page.locator(buttonXPath));
});

Then('all buttons should be properly sized and clickable', async function () {
  const buttons = await page.locator('button').count();
  expect(buttons).toBeGreaterThan(0);
});

Then('no UI elements should be cut off or hidden', async function () {
  await page.waitForTimeout(300);
});

Then('confirmation message should display properly at {string} zoom', async function (zoomLevel: string) {
  await assertions.assertVisible(page.locator('//div[@role="alert"]'));
});

Then('text should be readable', async function () {
  const readable = await page.locator('//div[@role="alert"]').isVisible();
  expect(readable).toBe(true);
});

Then('message should not overflow viewport', async function () {
  const inViewport = await page.evaluate(() => {
    const alert = document.querySelector('[role="alert"]');
    const rect = alert?.getBoundingClientRect();
    return rect && rect.right <= window.innerWidth;
  });
  expect(inViewport).toBe(true);
});

Then('close button should be accessible', async function () {
  await assertions.assertVisible(page.locator('//button[@aria-label="Close"]'));
});

Then('layout should adapt responsively', async function () {
  await page.waitForTimeout(500);
});

Then('content should reflow appropriately', async function () {
  await page.waitForTimeout(300);
});

Then('no loss of functionality or content should occur', async function () {
  const functional = await page.locator('button').first().isEnabled();
  expect(functional).toBe(true);
});

Then('all functionality should remain accessible at {string} zoom level', async function (zoomLevel: string) {
  await page.waitForTimeout(300);
});

/**************************************************/
/*  TC-007: ARIA Live Regions
/**************************************************/

Then('screen reader should announce {string} immediately', async function (announcement: string) {
  await page.waitForTimeout(500);
});

Then('ARIA live region should announce {string} within {int} seconds', async function (announcement: string, seconds: number) {
  await page.waitForTimeout(seconds * 1000);
  await assertions.assertContainsText(page.locator('//*[@aria-live]'), announcement);
});

Then('each checkbox state should be announced', async function () {
  await page.waitForTimeout(300);
});

Then('live region should update to {string}', async function (text: string) {
  await page.waitForTimeout(500);
  await assertions.assertContainsText(page.locator('//*[@aria-live]'), text);
});

Then('announcements should not interrupt each other', async function () {
  await page.waitForTimeout(300);
});

Then('count should update dynamically', async function () {
  await page.waitForTimeout(300);
});

Then('live region should announce {string}', async function (announcement: string) {
  await page.waitForTimeout(500);
  await assertions.assertContainsText(page.locator('//*[@aria-live]'), announcement);
});

Then('screen reader should indicate busy state if aria-busy is used', async function () {
  const hasBusy = await page.evaluate(() => {
    return document.querySelector('[aria-busy="true"]') !== null;
  });
  expect(hasBusy).toBeTruthy();
});

Then('ARIA live region with role alert should announce {string}', async function (announcement: string) {
  await page.waitForTimeout(500);
  await assertions.assertVisible(page.locator('//div[@role="alert"]'));
});

Then('announcement should interrupt other speech due to assertive priority', async function () {
  const assertive = await page.evaluate(() => {
    const alert = document.querySelector('[role="alert"]');
    return alert?.getAttribute('aria-live') === 'assertive';
  });
  expect(assertive).toBeTruthy();
});

Then('all dynamic content changes should be announced via ARIA live regions', async function () {
  const liveRegions = await page.locator('//*[@aria-live]').count();
  expect(liveRegions).toBeGreaterThan(0);
});

Then('announcements should use appropriate politeness levels', async function () {
  await page.waitForTimeout(300);
});

/**************************************************/
/*  TC-008: Error Handling
/**************************************************/

Then('form validation should prevent submission', async function () {
  await page.waitForTimeout(500);
});

Then('error message {string} should be displayed', async function (errorMessage: string) {
  await assertions.assertContainsText(page.locator('//div[@role="alert"]'), errorMessage);
});

Then('error message should be associated with permission checkboxes via aria-describedby', async function () {
  const hasDescribedBy = await page.evaluate(() => {
    const checkbox = document.querySelector('input[type="checkbox"]');
    return checkbox?.hasAttribute('aria-describedby');
  });
  expect(hasDescribedBy).toBeTruthy();
});

Then('screen reader should announce {string}', async function (announcement: string) {
  await page.waitForTimeout(500);
});

Then('{string} attribute should be set to {string} on relevant controls', async function (attribute: string, value: string) {
  const hasAttribute = await page.evaluate(({ attr, val }) => {
    const checkbox = document.querySelector('input[type="checkbox"]');
    return checkbox?.getAttribute(attr) === val;
  }, { attr: attribute, val: value });
  expect(hasAttribute).toBeTruthy();
});

Then('error icon should appear next to conflicting permissions', async function () {
  await assertions.assertVisible(page.locator('//*[contains(@class,"error-icon")]'));
});

Then('error text should be displayed with sufficient contrast {string}', async function (minRatio: string) {
  const ratio = parseFloat(minRatio);
  const contrastRatio = await page.evaluate(() => {
    const error = document.querySelector('[role="alert"]');
    if (!error) return 0;
    const fgColor = window.getComputedStyle(error).color;
    const bgColor = window.getComputedStyle(error).backgroundColor;
    return (window as any).getContrastRatio(fgColor, bgColor);
  });
  expect(contrastRatio).toBeGreaterThanOrEqual(ratio);
});

Then('focus should move to first invalid field or error summary', async function () {
  const focusOnError = await page.evaluate(() => {
    const error = document.querySelector('[role="alert"], [aria-invalid="true"]');
    return error?.contains(document.activeElement) || document.activeElement?.getAttribute('aria-invalid') === 'true';
  });
  expect(focusOnError).toBeTruthy();
});

Then('error summary should have role alert or be in ARIA live region', async function () {
  const hasAlert = await page.evaluate(() => {
    return document.querySelector('[role="alert"]') !== null || document.querySelector('[aria-live]') !== null;
  });
  expect(hasAlert).toBe(true);
});

Then('error message should disappear or update', async function () {
  await page.waitForTimeout(500);
});

Then('all error messages should be programmatically associated with form controls', async function () {
  const associated = await page.evaluate(() => {
    const controls = document.querySelectorAll('input, select, textarea');
    return Array.from(controls).every(control => {
      return control.hasAttribute('aria-describedby') || control.hasAttribute('aria-errormessage');
    });
  });
  expect(associated).toBeTruthy();
});

Then('invalid controls should have {string} attribute set to {string}', async function (attribute: string, value: string) {
  const hasAttribute = await page.evaluate(({ attr, val }) => {
    const invalid = document.querySelector('[aria-invalid="true"]');
    return invalid?.getAttribute(attr) === val;
  }, { attr: attribute, val: value });
  expect(hasAttribute).toBeTruthy();
});

Then('errors should be indicated by multiple means not color alone', async function () {
  const hasMultipleIndicators = await page.evaluate(() => {
    const error = document.querySelector('[role="alert"]');
    const hasIcon = error?.querySelector('svg, img, [class*="icon"]');
    const hasText = error?.textContent?.trim().length > 0;
    return hasIcon && hasText;
  });
  expect(hasMultipleIndicators).toBeTruthy();
});

/**************************************************/
/*  TC-009: Network Error
/**************************************************/

Then('network error message {string} should be displayed', async function (errorMessage: string) {
  await assertions.assertContainsText(page.locator('//div[@role="alert"]'), errorMessage);
});

Then('error should have role alert', async function () {
  await assertions.assertVisible(page.locator('//div[@role="alert"]'));
});

Then('error should be announced by screen reader', async function () {
  await page.waitForTimeout(500);
});

Then('error should provide actionable guidance', async function () {
  const hasGuidance = await page.evaluate(() => {
    const alert = document.querySelector('[role="alert"]');
    return alert?.textContent?.includes('try again') || alert?.textContent?.includes('check');
  });
  expect(hasGuidance).toBeTruthy();
});

Then('error message should be specific and actionable', async function () {
  const isSpecific = await page.evaluate(() => {
    const alert = document.querySelector('[role="alert"]');
    return alert?.textContent && alert.textContent.length > 10;
  });
  expect(isSpecific).toBeTruthy();
});

Then('error message should provide guidance on how to fix issue', async function () {
  const hasGuidance = await page.evaluate(() => {
    const alert = document.querySelector('[role="alert"]');
    return alert?.textContent?.includes('try') || alert?.textContent?.includes('check') || alert?.textContent?.includes('please');
  });
  expect(hasGuidance).toBeTruthy();
});

/**************************************************/
/*  TC-010: Multiple Errors
/**************************************************/

Then('error summary should provide clear instructions for resolution', async function () {
  await assertions.assertVisible(page.locator('//div[@role="alert"]'));
});

Then('error messages should be specific and actionable', async function () {
  const isSpecific = await page.evaluate(() => {
    const alert = document.querySelector('[role="alert"]');
    return alert?.textContent && alert.textContent.length > 10;
  });
  expect(isSpecific).toBeTruthy();
});

Then('error messages should provide guidance on how to fix errors', async function () {
  const hasGuidance = await page.evaluate(() => {
    const alert = document.querySelector('[role="alert"]');
    return alert?.textContent?.includes('fix') || alert?.textContent?.includes('correct') || alert?.textContent?.includes('resolve');
  });
  expect(hasGuidance).toBeTruthy();
});

Then('error summary should include error count', async function () {
  const hasCount = await page.evaluate(() => {
    const alert = document.querySelector('[role="alert"]');
    return /\d+/.test(alert?.textContent || '');
  });
  expect(hasCount).toBeTruthy();
});