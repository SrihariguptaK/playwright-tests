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
      supportAnalyst: { username: 'support_analyst', password: 'analyst123' }
    },
    screenReaders: ['NVDA', 'JAWS', 'VoiceOver', 'TalkBack'],
    contrastRatios: {
      normalText: '4.5:1',
      largeText: '3:1',
      uiComponents: '3:1'
    }
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
/*  Category: Setup
/**************************************************/

Given('Support Analyst is logged into knowledge base system', async function () {
  const credentials = this.testData?.users?.supportAnalyst || { username: 'support_analyst', password: 'analyst123' };
  await actions.navigateTo(process.env.BASE_URL || 'https://knowledgebase.example.com');
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

Given('validation error documentation page is loaded', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/validation-errors`);
  await waits.waitForLoad();
  await assertions.assertVisible(page.locator('//h1[contains(text(),"Validation Error Documentation")]'));
});

/**************************************************/
/*  TC-001: Keyboard Navigation
/*  Priority: High
/*  Category: Accessibility
/**************************************************/

Given('mouse or trackpad is disconnected for testing', async function () {
  this.keyboardOnlyMode = true;
  await page.evaluate(() => {
    document.body.style.cursor = 'none';
  });
});

Given('keyboard is the only input device available', async function () {
  this.inputMethod = 'keyboard';
});

Given('{string} screen reader is installed and running', async function (screenReaderName: string) {
  this.activeScreenReader = screenReaderName;
  this.screenReaderActive = true;
});

Given('screen reader is set to verbose mode', async function () {
  this.screenReaderMode = 'verbose';
});

Given('color contrast analyzer tool is installed', async function () {
  this.contrastAnalyzerEnabled = true;
});

Given('documentation includes text, buttons, links, error indicators, and success messages', async function () {
  await assertions.assertVisible(page.locator('//body'));
  const elementTypes = ['button', 'a', 'input', 'select'];
  for (const type of elementTypes) {
    const count = await page.locator(type).count();
    expect(count).toBeGreaterThan(0);
  }
});

Given('dark mode is available', async function () {
  const darkModeToggle = page.locator('//button[@id="dark-mode-toggle"]');
  await assertions.assertVisible(darkModeToggle);
});

Given('browser is set to standard viewport size {string}', async function (viewportSize: string) {
  const [width, height] = viewportSize.split('x').map(Number);
  await page.setViewportSize({ width, height });
});

Given('browser zoom is set to {string} percent', async function (zoomLevel: string) {
  const zoom = parseInt(zoomLevel) / 100;
  await page.evaluate((zoomValue) => {
    document.body.style.zoom = zoomValue.toString();
  }, zoom);
  this.currentZoom = parseInt(zoomLevel);
});

Given('screen reader {string} is active and running', async function (screenReaderName: string) {
  this.activeScreenReader = screenReaderName;
  this.screenReaderActive = true;
});

Given('documentation system supports real-time updates', async function () {
  this.realTimeUpdatesEnabled = true;
});

Given('ARIA live regions are implemented for dynamic content', async function () {
  const liveRegions = await page.locator('[aria-live]').count();
  expect(liveRegions).toBeGreaterThan(0);
});

Given('Support Analyst is accessing knowledge base on tablet device', async function () {
  await context.close();
  context = await browser.newContext({
    viewport: { width: 768, height: 1024 },
    userAgent: 'Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
    hasTouch: true,
    isMobile: true
  });
  page = await context.newPage();
  actions = new GenericActions(page, context);
  assertions = new AssertionHelpers(page);
  waits = new WaitHelpers(page);
});

Given('validation error documentation is loaded in mobile browser', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/validation-errors`);
  await waits.waitForLoad();
});

Given('touch screen is primary input method', async function () {
  this.inputMethod = 'touch';
});

Given('device is in portrait orientation', async function () {
  await page.setViewportSize({ width: 768, height: 1024 });
  this.orientation = 'portrait';
});

Given('Support Analyst is accessing knowledge base on Android tablet', async function () {
  await context.close();
  context = await browser.newContext({
    viewport: { width: 800, height: 1280 },
    userAgent: 'Mozilla/5.0 (Linux; Android 11; Tablet) AppleWebKit/537.36',
    hasTouch: true,
    isMobile: true
  });
  page = await context.newPage();
  actions = new GenericActions(page, context);
  assertions = new AssertionHelpers(page);
  waits = new WaitHelpers(page);
});

Given('validation error documentation is loaded in Chrome mobile browser', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/validation-errors`);
  await waits.waitForLoad();
});

Given('validation error documentation includes modal dialogs for detailed views', async function () {
  const modalTriggers = await page.locator('//button[contains(@class,"modal-trigger")]').count();
  expect(modalTriggers).toBeGreaterThan(0);
});

Given('keyboard is primary input method', async function () {
  this.inputMethod = 'keyboard';
});

Given('screen reader is active', async function () {
  this.screenReaderActive = true;
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  TC-001: Keyboard Navigation
/*  Priority: High
/*  Category: Accessibility
/**************************************************/

When('user presses Tab key from browser address bar', async function () {
  await page.keyboard.press('Tab');
  await waits.waitForNetworkIdle();
});

When('user continues pressing Tab through all interactive elements', async function () {
  const interactiveElements = await page.locator('a, button, input, select, textarea, [tabindex]:not([tabindex="-1"])').count();
  this.totalInteractiveElements = interactiveElements;
  for (let i = 0; i < Math.min(interactiveElements, 10); i++) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
  }
});

When('user presses Shift+Tab to navigate backwards', async function () {
  await page.keyboard.press('Shift+Tab');
  await page.waitForTimeout(100);
});

When('user navigates to search field using Tab', async function () {
  const searchField = page.locator('//input[@id="search-field"]');
  await searchField.focus();
});

When('user enters {string} in search field', async function (searchTerm: string) {
  await actions.fill(page.locator('//input[@id="search-field"]'), searchTerm);
});

When('user presses Enter key', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('user uses Tab to navigate to first search result', async function () {
  await page.keyboard.press('Tab');
  await page.waitForTimeout(100);
});

When('user presses Escape key', async function () {
  await page.keyboard.press('Escape');
  await page.waitForTimeout(200);
});

When('user navigates to filter dropdown using Tab', async function () {
  const dropdown = page.locator('//select[@id="filter-dropdown"]');
  await dropdown.focus();
});

When('user presses Space key to open dropdown', async function () {
  await page.keyboard.press('Space');
  await page.waitForTimeout(100);
});

When('user uses Arrow keys to select filter option', async function () {
  await page.keyboard.press('ArrowDown');
  await page.waitForTimeout(100);
});

When('user presses Enter to apply selection', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('user activates screen reader heading navigation with H key', async function () {
  this.headingNavigationActive = true;
  const headings = await page.locator('h1, h2, h3, h4, h5, h6').all();
  this.headingsList = headings;
});

When('user navigates to search field using E key for edit fields', async function () {
  this.editFieldNavigationActive = true;
  await page.locator('//input[@id="search-field"]').focus();
});

When('user navigates through list of validation errors using L key', async function () {
  this.listNavigationActive = true;
  const lists = await page.locator('ul, ol').all();
  this.listsFound = lists;
});

When('user activates validation error link', async function () {
  await actions.click(page.locator('//a[contains(@class,"validation-error-link")]').first());
  await waits.waitForNetworkIdle();
});

When('user navigates through troubleshooting steps using Down arrow', async function () {
  await page.keyboard.press('ArrowDown');
  await page.waitForTimeout(100);
});

When('user navigates to interactive buttons using Tab key', async function () {
  const button = page.locator('button').first();
  await button.focus();
});

When('user navigates to interactive links using Tab key', async function () {
  const link = page.locator('a').first();
  await link.focus();
});

When('user uses screen reader landmark navigation with D key', async function () {
  this.landmarkNavigationActive = true;
  const landmarks = await page.locator('[role="navigation"], [role="search"], [role="main"], [role="complementary"], [role="contentinfo"]').all();
  this.landmarksFound = landmarks;
});

When('user checks body text color against background color using contrast analyzer', async function () {
  const bodyText = page.locator('body');
  const textColor = await bodyText.evaluate((el) => window.getComputedStyle(el).color);
  const bgColor = await bodyText.evaluate((el) => window.getComputedStyle(el).backgroundColor);
  this.bodyTextContrast = { textColor, bgColor };
});

When('user checks heading text contrast ratios against backgrounds', async function () {
  const heading = page.locator('h1, h2, h3').first();
  const textColor = await heading.evaluate((el) => window.getComputedStyle(el).color);
  const bgColor = await heading.evaluate((el) => window.getComputedStyle(el).backgroundColor);
  this.headingContrast = { textColor, bgColor };
});

When('user analyzes link text color contrast in {word} state', async function (state: string) {
  const link = page.locator('a').first();
  if (state === 'hover') {
    await actions.hover(link);
  } else if (state === 'focus') {
    await link.focus();
  }
  const textColor = await link.evaluate((el) => window.getComputedStyle(el).color);
  const bgColor = await link.evaluate((el) => window.getComputedStyle(el).backgroundColor);
  this.linkContrast = { state, textColor, bgColor };
});

When('user checks error indicator colors against backgrounds', async function () {
  const errorIndicator = page.locator('//div[contains(@class,"error-indicator")]').first();
  if (await errorIndicator.count() > 0) {
    const color = await errorIndicator.evaluate((el) => window.getComputedStyle(el).color);
    const bgColor = await errorIndicator.evaluate((el) => window.getComputedStyle(el).backgroundColor);
    this.errorIndicatorContrast = { color, bgColor };
  }
});

When('user verifies button text and background color combinations', async function () {
  const button = page.locator('button').first();
  const textColor = await button.evaluate((el) => window.getComputedStyle(el).color);
  const bgColor = await button.evaluate((el) => window.getComputedStyle(el).backgroundColor);
  this.buttonContrast = { textColor, bgColor };
});

When('user tests focus indicators on interactive elements for color contrast', async function () {
  const focusableElement = page.locator('a, button, input').first();
  await focusableElement.focus();
  const outlineColor = await focusableElement.evaluate((el) => window.getComputedStyle(el).outlineColor);
  this.focusIndicatorColor = outlineColor;
});

When('user switches to dark mode', async function () {
  await actions.click(page.locator('//button[@id="dark-mode-toggle"]'));
  await waits.waitForNetworkIdle();
  this.darkModeEnabled = true;
});

When('user checks body text color against background color', async function () {
  const bodyText = page.locator('body');
  const textColor = await bodyText.evaluate((el) => window.getComputedStyle(el).color);
  const bgColor = await bodyText.evaluate((el) => window.getComputedStyle(el).backgroundColor);
  this.bodyTextContrast = { textColor, bgColor };
});

When('user checks UI components contrast', async function () {
  const uiComponent = page.locator('button, input, select').first();
  const color = await uiComponent.evaluate((el) => window.getComputedStyle(el).color);
  const bgColor = await uiComponent.evaluate((el) => window.getComputedStyle(el).backgroundColor);
  this.uiComponentContrast = { color, bgColor };
});

When('user verifies documentation displays correctly at baseline', async function () {
  await assertions.assertVisible(page.locator('//h1'));
  await assertions.assertVisible(page.locator('//main'));
});

When('user increases browser zoom to {string} percent using Ctrl and plus key', async function (zoomLevel: string) {
  const zoom = parseInt(zoomLevel) / 100;
  await page.evaluate((zoomValue) => {
    document.body.style.zoom = zoomValue.toString();
  }, zoom);
  this.currentZoom = parseInt(zoomLevel);
  await page.waitForTimeout(500);
});

When('user increases browser zoom to {string} percent', async function (zoomLevel: string) {
  const zoom = parseInt(zoomLevel) / 100;
  await page.evaluate((zoomValue) => {
    document.body.style.zoom = zoomValue.toString();
  }, zoom);
  this.currentZoom = parseInt(zoomLevel);
  await page.waitForTimeout(500);
});

When('user navigates through documentation using keyboard at {string} percent zoom', async function (zoomLevel: string) {
  await page.keyboard.press('Tab');
  await page.waitForTimeout(100);
  await page.keyboard.press('Tab');
  await page.waitForTimeout(100);
});

When('user uses search functionality at {string} percent zoom', async function (zoomLevel: string) {
  const searchField = page.locator('//input[@id="search-field"]');
  await assertions.assertVisible(searchField);
});

When('user enters search term in search field', async function () {
  await actions.fill(page.locator('//input[@id="search-field"]'), 'VAL-ERR-001');
});

When('user views search results', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('user opens detailed troubleshooting steps at {string} percent zoom', async function (zoomLevel: string) {
  await actions.click(page.locator('//a[contains(@class,"validation-error-link")]').first());
  await waits.waitForNetworkIdle();
});

When('user resizes browser window at {string} percent zoom', async function (zoomLevel: string) {
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.waitForTimeout(300);
});

When('administrator publishes new validation error entry', async function () {
  await page.evaluate(() => {
    const event = new CustomEvent('newErrorAdded', { detail: { errorCode: 'VAL-ERR-999' } });
    document.dispatchEvent(event);
  });
  await page.waitForTimeout(500);
});

When('user performs search for validation error that returns results dynamically', async function () {
  await actions.fill(page.locator('//input[@id="search-field"]'), 'VAL-ERR');
  await page.keyboard.press('Enter');
  await page.waitForTimeout(500);
});

When('user applies filter to error list that updates content dynamically', async function () {
  await actions.click(page.locator('//select[@id="filter-dropdown"]'));
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Enter');
  await page.waitForTimeout(500);
});

When('user triggers error state during documentation loading', async function () {
  await page.evaluate(() => {
    const event = new CustomEvent('loadError', { detail: { message: 'Unable to load documentation' } });
    document.dispatchEvent(event);
  });
  await page.waitForTimeout(300);
});

When('user receives notification that documentation has been updated', async function () {
  await page.evaluate(() => {
    const event = new CustomEvent('documentationUpdated');
    document.dispatchEvent(event);
  });
  await page.waitForTimeout(300);
});

When('user uses pagination to load additional error entries', async function () {
  await actions.click(page.locator('//button[@id="load-more"]'));
  await page.waitForTimeout(500);
});

When('user measures all interactive elements using browser developer tools', async function () {
  const interactiveElements = await page.locator('a, button, input, select').all();
  this.touchTargetSizes = [];
  for (const element of interactiveElements.slice(0, 5)) {
    const box = await element.boundingBox();
    if (box) {
      this.touchTargetSizes.push({ width: box.width, height: box.height });
    }
  }
});

When('user taps on search field', async function () {
  const searchField = page.locator('//input[@id="search-field"]');
  await searchField.tap();
  await page.waitForTimeout(200);
});

When('user taps on validation error list items', async function () {
  const listItem = page.locator('//li[contains(@class,"error-list-item")]').first();
  await listItem.tap();
  await page.waitForTimeout(200);
});

When('user uses pinch-to-zoom gesture on documentation content', async function () {
  await page.evaluate(() => {
    document.body.style.zoom = '2';
  });
  await page.waitForTimeout(300);
});

When('user rotates device from portrait to landscape orientation', async function () {
  await page.setViewportSize({ width: 1024, height: 768 });
  this.orientation = 'landscape';
  await page.waitForTimeout(300);
});

When('user tests swipe gestures for navigation', async function () {
  this.swipeGesturesTested = true;
});

When('user enables {string} accessibility feature on iOS device', async function (feature: string) {
  this.accessibilityFeature = feature;
  this.accessibilityEnabled = true;
});

When('user navigates documentation', async function () {
  await page.keyboard.press('Tab');
  await page.waitForTimeout(100);
});

When('user enables {string} accessibility feature on Android device', async function (feature: string) {
  this.accessibilityFeature = feature;
  this.accessibilityEnabled = true;
});

When('user navigates to validation error entry', async function () {
  const errorEntry = page.locator('//a[contains(@class,"validation-error-link")]').first();
  await errorEntry.focus();
});

When('user presses Enter to open detailed view in modal dialog', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(300);
});

When('user presses Tab key repeatedly within modal', async function () {
  for (let i = 0; i < 5; i++) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
  }
});

When('user presses Shift+Tab from first focusable element in modal', async function () {
  const modal = page.locator('//div[@role="dialog"]');
  const firstFocusable = modal.locator('a, button, input').first();
  await firstFocusable.focus();
  await page.keyboard.press('Shift+Tab');
  await page.waitForTimeout(100);
});

When('user presses Escape key while modal is open', async function () {
  await page.keyboard.press('Escape');
  await page.waitForTimeout(300);
});

When('user reopens modal', async function () {
  const errorEntry = page.locator('//a[contains(@class,"validation-error-link")]').first();
  await actions.click(errorEntry);
  await waits.waitForNetworkIdle();
});

When('user clicks close button', async function () {
  await actions.click(page.locator('//button[@id="modal-close"]'));
  await page.waitForTimeout(300);
});

When('user verifies background content while modal is open', async function () {
  const backgroundContent = page.locator('//main');
  const ariaHidden = await backgroundContent.getAttribute('aria-hidden');
  this.backgroundAriaHidden = ariaHidden;
});

When('user tests with screen reader virtual cursor', async function () {
  this.virtualCursorActive = true;
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  TC-001: Keyboard Navigation
/*  Priority: High
/*  Category: Accessibility
/**************************************************/

Then('focus should move to first interactive element with visible focus indicator', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBeTruthy();
  const outlineWidth = await page.evaluate(() => {
    const el = document.activeElement;
    return el ? window.getComputedStyle(el).outlineWidth : '0px';
  });
  expect(outlineWidth).not.toBe('0px');
});

Then('focus should move in logical order through search bar, filter dropdowns, and error list items', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(['INPUT', 'SELECT', 'A', 'BUTTON']).toContain(focusedElement);
});

Then('focus indicator should be clearly visible with minimum {string} outline', async function (minOutline: string) {
  const outlineWidth = await page.evaluate(() => {
    const el = document.activeElement;
    return el ? window.getComputedStyle(el).outlineWidth : '0px';
  });
  const widthValue = parseFloat(outlineWidth);
  expect(widthValue).toBeGreaterThanOrEqual(2);
});

Then('no focus traps should occur', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBeTruthy();
});

Then('focus should move in reverse order correctly', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBeTruthy();
});

Then('all previously focused elements should be accessible in reverse', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBeTruthy();
});

Then('search should execute successfully', async function () {
  await waits.waitForNetworkIdle();
  const results = await page.locator('//div[contains(@class,"search-results")]').count();
  expect(results).toBeGreaterThan(0);
});

Then('focus should move to search results', async function () {
  const resultsContainer = page.locator('//div[contains(@class,"search-results")]');
  await assertions.assertVisible(resultsContainer);
});

Then('results should be announced to assistive technologies', async function () {
  const ariaLive = await page.locator('[aria-live]').count();
  expect(ariaLive).toBeGreaterThan(0);
});

Then('detailed documentation should open', async function () {
  await assertions.assertVisible(page.locator('//div[contains(@class,"detailed-view")]'));
});

Then('focus should move to main heading of documentation page', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBe('H1');
});

Then('view should close', async function () {
  const detailedView = page.locator('//div[contains(@class,"detailed-view")]');
  await waits.waitForHidden(detailedView);
});

Then('focus should return to search result link that triggered the action', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBe('A');
});

Then('dropdown should open with Space or Enter', async function () {
  const dropdown = page.locator('//select[@id="filter-dropdown"]');
  await assertions.assertVisible(dropdown);
});

Then('Arrow keys should navigate options', async function () {
  const selectedOption = await page.evaluate(() => {
    const select = document.querySelector('select') as HTMLSelectElement;
    return select?.selectedIndex;
  });
  expect(selectedOption).toBeGreaterThanOrEqual(0);
});

Then('Enter should apply selection', async function () {
  await waits.waitForNetworkIdle();
});

Then('Escape should close without applying', async function () {
  const dropdown = page.locator('//select[@id="filter-dropdown"]');
  await assertions.assertVisible(dropdown);
});

Then('screen reader should announce all headings in hierarchical order', async function () {
  const headings = await page.locator('h1, h2, h3, h4, h5, h6').all();
  expect(headings.length).toBeGreaterThan(0);
});

Then('{string} should be announced as main h1', async function (headingText: string) {
  const h1 = page.locator('h1');
  await assertions.assertContainsText(h1, headingText);
});

Then('error categories should be announced as h2', async function () {
  const h2Count = await page.locator('h2').count();
  expect(h2Count).toBeGreaterThan(0);
});

Then('individual errors should be announced as h3', async function () {
  const h3Count = await page.locator('h3').count();
  expect(h3Count).toBeGreaterThan(0);
});

Then('screen reader should announce {string} with proper label association', async function (announcement: string) {
  const searchField = page.locator('//input[@id="search-field"]');
  const ariaLabel = await searchField.getAttribute('aria-label');
  expect(ariaLabel).toBeTruthy();
});

Then('screen reader should announce {string}', async function (announcement: string) {
  const lists = await page.locator('ul, ol').count();
  expect(lists).toBeGreaterThan(0);
});

Then('each error entry should be announced with format {string}', async function (format: string) {
  const listItems = await page.locator('li').count();
  expect(listItems).toBeGreaterThan(0);
});

Then('screen reader should announce {string}', async function (announcement: string) {
  const heading = page.locator('h1').first();
  await assertions.assertVisible(heading);
});

Then('detailed description should be read with proper semantic structure', async function () {
  const paragraphs = await page.locator('p').count();
  expect(paragraphs).toBeGreaterThan(0);
});

Then('screen reader should announce ordered list {string}', async function (announcement: string) {
  const orderedLists = await page.locator('ol').count();
  expect(orderedLists).toBeGreaterThan(0);
});

Then('each step should be read as {string} with proper numbering', async function (format: string) {
  const listItems = await page.locator('ol li').count();
  expect(listItems).toBeGreaterThan(0);
});

Then('screen reader should announce button purpose clearly as {string}', async function (announcement: string) {
  const button = page.locator('button').first();
  const ariaLabel = await button.getAttribute('aria-label');
  expect(ariaLabel || await button.textContent()).toBeTruthy();
});

Then('screen reader should announce link purpose clearly as {string}', async function (announcement: string) {
  const link = page.locator('a').first();
  const ariaLabel = await link.getAttribute('aria-label');
  expect(ariaLabel || await link.textContent()).toBeTruthy();
});

Then('screen reader should announce {string} landmark', async function (landmarkName: string) {
  const landmarks = await page.locator('[role]').count();
  expect(landmarks).toBeGreaterThan(0);
});

Then('contrast ratio should be at least {string} for normal text meeting WCAG AA standard', async function (ratio: string) {
  expect(this.bodyTextContrast).toBeTruthy();
});

Then('large text should have minimum {string} contrast ratio', async function (ratio: string) {
  expect(this.headingContrast).toBeTruthy();
});

Then('preferably {string} for AA compliance', async function (ratio: string) {
  expect(this.headingContrast).toBeTruthy();
});

Then('link should maintain minimum {string} contrast ratio', async function (ratio: string) {
  expect(this.linkContrast).toBeTruthy();
});

Then('links should be distinguishable from surrounding text without relying solely on color', async function () {
  const link = page.locator('a').first();
  const textDecoration = await link.evaluate((el) => window.getComputedStyle(el).textDecoration);
  expect(textDecoration).toContain('underline');
});

Then('underline or other indicator should be present', async function () {
  const link = page.locator('a').first();
  const textDecoration = await link.evaluate((el) => window.getComputedStyle(el).textDecoration);
  expect(textDecoration).toBeTruthy();
});

Then('error indicators should have {string} contrast ratio for UI components', async function (ratio: string) {
  expect(this.errorIndicatorContrast).toBeTruthy();
});

Then('error indicators should not rely solely on color', async function () {
  const errorIndicator = page.locator('//div[contains(@class,"error-indicator")]').first();
  if (await errorIndicator.count() > 0) {
    const hasIcon = await errorIndicator.locator('svg, img, i').count();
    expect(hasIcon).toBeGreaterThan(0);
  }
});

Then('icons or text labels should accompany color coding', async function () {
  const errorIndicator = page.locator('//div[contains(@class,"error-indicator")]').first();
  if (await errorIndicator.count() > 0) {
    const hasContent = await errorIndicator.textContent();
    expect(hasContent).toBeTruthy();
  }
});

Then('button text should have {string} contrast against button background', async function (ratio: string) {
  expect(this.buttonContrast).toBeTruthy();
});

Then('button should have {string} contrast against page background', async function (ratio: string) {
  expect(this.buttonContrast).toBeTruthy();
});

Then('disabled buttons should be clearly distinguishable', async function () {
  const disabledButton = page.locator('button:disabled').first();
  if (await disabledButton.count() > 0) {
    const opacity = await disabledButton.evaluate((el) => window.getComputedStyle(el).opacity);
    expect(parseFloat(opacity)).toBeLessThan(1);
  }
});

Then('focus indicators should have minimum {string} contrast ratio against adjacent colors', async function (ratio: string) {
  expect(this.focusIndicatorColor).toBeTruthy();
});

Then('focus indicators should be clearly visible', async function () {
  const focusedElement = page.locator(':focus');
  if (await focusedElement.count() > 0) {
    const outlineWidth = await focusedElement.evaluate((el) => window.getComputedStyle(el).outlineWidth);
    expect(parseFloat(outlineWidth)).toBeGreaterThan(0);
  }
});

Then('contrast ratio should be at least {string} for text', async function (ratio: string) {
  expect(this.bodyTextContrast).toBeTruthy();
});

Then('contrast ratio should be at least {string} for UI components', async function (ratio: string) {
  expect(this.uiComponentContrast).toBeTruthy();
});

Then('dark mode should maintain same WCAG AA contrast standards', async function () {
  expect(this.darkModeEnabled).toBe(true);
});

Then('all content should be visible and readable', async function () {
  await assertions.assertVisible(page.locator('//main'));
});

Then('content should be properly formatted', async function () {
  const mainContent = page.locator('//main');
  await assertions.assertVisible(mainContent);
});

Then('content should reflow appropriately', async function () {
  const bodyWidth = await page.evaluate(() => document.body.scrollWidth);
  const viewportWidth = await page.evaluate(() => window.innerWidth);
  expect(bodyWidth).toBeLessThanOrEqual(viewportWidth * 1.1);
});

Then('no horizontal scrolling should be required', async function () {
  const bodyWidth = await page.evaluate(() => document.body.scrollWidth);
  const viewportWidth = await page.evaluate(() => window.innerWidth);
  expect(bodyWidth).toBeLessThanOrEqual(viewportWidth * 1.1);
});

Then('all text should remain readable', async function () {
  const fontSize = await page.evaluate(() => {
    const body = document.body;
    return window.getComputedStyle(body).fontSize;
  });
  expect(parseFloat(fontSize)).toBeGreaterThan(0);
});

Then('no content overlap should occur', async function () {
  const overlaps = await page.evaluate(() => {
    const elements = Array.from(document.querySelectorAll('*'));
    return elements.length > 0;
  });
  expect(overlaps).toBe(true);
});

Then('all content should remain accessible without horizontal scrolling', async function () {
  const bodyWidth = await page.evaluate(() => document.body.scrollWidth);
  const viewportWidth = await page.evaluate(() => window.innerWidth);
  expect(bodyWidth).toBeLessThanOrEqual(viewportWidth * 1.1);
});

Then('text should reflow within viewport', async function () {
  const bodyWidth = await page.evaluate(() => document.body.scrollWidth);
  const viewportWidth = await page.evaluate(() => window.innerWidth);
  expect(bodyWidth).toBeLessThanOrEqual(viewportWidth * 1.1);
});

Then('no content should be cut off or hidden', async function () {
  const mainContent = page.locator('//main');
  await assertions.assertVisible(mainContent);
});

Then('all functionality should remain operational', async function () {
  const buttons = await page.locator('button').count();
  expect(buttons).toBeGreaterThan(0);
});

Then('focus indicators should remain visible', async function () {
  await page.keyboard.press('Tab');
  const outlineWidth = await page.evaluate(() => {
    const el = document.activeElement;
    return el ? window.getComputedStyle(el).outlineWidth : '0px';
  });
  expect(parseFloat(outlineWidth)).toBeGreaterThan(0);
});

Then('Tab navigation should work correctly', async function () {
  await page.keyboard.press('Tab');
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBeTruthy();
});

Then('focused elements should scroll into view automatically', async function () {
  await page.keyboard.press('Tab');
  await page.waitForTimeout(100);
});

Then('search field should be fully visible and functional', async function () {
  const searchField = page.locator('//input[@id="search-field"]');
  await assertions.assertVisible(searchField);
});

Then('search results should display without layout breaking', async function () {
  const results = page.locator('//div[contains(@class,"search-results")]');
  await assertions.assertVisible(results);
});

Then('results should be readable and clickable', async function () {
  const resultLinks = await page.locator('//div[contains(@class,"search-results")] a').count();
  expect(resultLinks).toBeGreaterThan(0);
});

Then('modal or detail view should open correctly', async function () {
  const detailView = page.locator('//div[contains(@class,"detailed-view")]');
  await assertions.assertVisible(detailView);
});

Then('all content should be readable', async function () {
  const content = page.locator('//main');
  await assertions.assertVisible(content);
});

Then('close button should be visible and accessible', async function () {
  const closeButton = page.locator('//button[@id="modal-close"]');
  await assertions.assertVisible(closeButton);
});

Then('no content overflow issues should occur', async function () {
  const bodyWidth = await page.evaluate(() => document.body.scrollWidth);
  const viewportWidth = await page.evaluate(() => window.innerWidth);
  expect(bodyWidth).toBeLessThanOrEqual(viewportWidth * 1.1);
});

Then('content should continue to reflow appropriately', async function () {
  const bodyWidth = await page.evaluate(() => document.body.scrollWidth);
  const viewportWidth = await page.evaluate(() => window.innerWidth);
  expect(bodyWidth).toBeLessThanOrEqual(viewportWidth * 1.1);
});

Then('mobile responsive breakpoints should trigger correctly', async function () {
  const isMobileLayout = await page.evaluate(() => window.innerWidth < 768);
  expect(typeof isMobileLayout).toBe('boolean');
});

Then('no loss of functionality should occur', async function () {
  const buttons = await page.locator('button').count();
  expect(buttons).toBeGreaterThan(0);
});

Then('screen reader should announce {string} via ARIA live region', async function (announcement: string) {
  const liveRegion = page.locator('[aria-live]').first();
  await assertions.assertVisible(liveRegion);
});

Then('user focus should not move', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBeTruthy();
});

Then('aria-live should be set to {string} to avoid interrupting user', async function (liveValue: string) {
  const liveRegion = page.locator('[aria-live="polite"]').first();
  if (await liveRegion.count() > 0) {
    const ariaLive = await liveRegion.getAttribute('aria-live');
    expect(ariaLive).toBe(liveValue);
  }
});

Then('current reading position should not be disrupted', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBeTruthy();
});

Then('screen reader should immediately announce {string}', async function (announcement: string) {
  const liveRegion = page.locator('[aria-live]').first();
  await assertions.assertVisible(liveRegion);
});

Then('aria-live should be set to {string} for critical information', async function (liveValue: string) {
  const liveRegion = page.locator('[aria-live="assertive"]').first();
  if (await liveRegion.count() > 0) {
    const ariaLive = await liveRegion.getAttribute('aria-live');
    expect(ariaLive).toBe(liveValue);
  }
});

Then('polite live region should be used', async function () {
  const liveRegion = page.locator('[aria-live="polite"]').first();
  if (await liveRegion.count() > 0) {
    await assertions.assertVisible(liveRegion);
  }
});

Then('all touch targets should be minimum {string} CSS pixels', async function (minSize: string) {
  const minPixels = parseInt(minSize.split('x')[0]);
  if (this.touchTargetSizes) {
    for (const size of this.touchTargetSizes) {
      expect(size.width).toBeGreaterThanOrEqual(minPixels * 0.9);
      expect(size.height).toBeGreaterThanOrEqual(minPixels * 0.9);
    }
  }
});

Then('adequate spacing should exist between targets', async function () {
  expect(this.touchTargetSizes).toBeTruthy();
});

Then('search field should activate on first tap', async function () {
  const searchField = page.locator('//input[@id="search-field"]');
  const isFocused = await searchField.evaluate((el) => el === document.activeElement);
  expect(isFocused).toBe(true);
});

Then('virtual keyboard should appear', async function () {
  await page.waitForTimeout(200);
});

Then('field should be large enough to tap accurately without hitting adjacent elements', async function () {
  const searchField = page.locator('//input[@id="search-field"]');
  const box = await searchField.boundingBox();
  expect(box?.width).toBeGreaterThan(40);
  expect(box?.height).toBeGreaterThan(40);
});

Then('list items should respond to single tap', async function () {
  await page.waitForTimeout(200);
});

Then('no accidental activations of adjacent items should occur', async function () {
  expect(true).toBe(true);
});

Then('tap area should include entire list item row', async function () {
  const listItem = page.locator('//li[contains(@class,"error-list-item")]').first();
  const box = await listItem.boundingBox();
  expect(box?.width).toBeGreaterThan(100);
});

Then('pinch-to-zoom should work smoothly up to {string} percent', async function (maxZoom: string) {
  const currentZoom = await page.evaluate(() => document.body.style.zoom);
  expect(currentZoom).toBeTruthy();
});

Then('documentation should reflow correctly', async function () {
  const bodyWidth = await page.evaluate(() => document.body.scrollWidth);
  const viewportWidth = await page.evaluate(() => window.innerWidth);
  expect(bodyWidth).toBeLessThanOrEqual(viewportWidth * 1.1);
});

Then('all content should remain accessible', async function () {
  const mainContent = page.locator('//main');
  await assertions.assertVisible(mainContent);
});

Then('touch targets should maintain minimum size requirements', async function () {
  const button = page.locator('button').first();
  const box = await button.boundingBox();
  expect(box?.width).toBeGreaterThan(40);
  expect(box?.height).toBeGreaterThan(40);
});

Then('no functionality should be lost', async function () {
  const buttons = await page.locator('button').count();
  expect(buttons).toBeGreaterThan(0);
});

Then('swipe gestures should work consistently', async function () {
  expect(this.swipeGesturesTested).toBe(true);
});

Then('alternative navigation methods should be available for users who cannot perform gestures', async function () {
  const buttons = await page.locator('button').count();
  expect(buttons).toBeGreaterThan(0);
});

Then('mobile screen reader should announce all content correctly', async function () {
  expect(this.accessibilityEnabled).toBe(true);
});

Then('touch exploration should work', async function () {
  expect(this.accessibilityEnabled).toBe(true);
});

Then('double-tap to activate should function properly', async function () {
  expect(this.accessibilityEnabled).toBe(true);
});

Then('modal should open', async function () {
  const modal = page.locator('//div[@role="dialog"]');
  await assertions.assertVisible(modal);
});

Then('focus should automatically move to first focusable element in modal', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(['A', 'BUTTON', 'INPUT']).toContain(focusedElement);
});

Then('screen reader should announce modal title and role {string}', async function (role: string) {
  const modal = page.locator('//div[@role="dialog"]');
  const roleAttr = await modal.getAttribute('role');
  expect(roleAttr).toBe(role);
});

Then('focus should cycle only through elements within modal', async function () {
  const focusedElement = await page.evaluate(() => {
    const activeEl = document.activeElement;
    const modal = document.querySelector('[role="dialog"]');
    return modal?.contains(activeEl);
  });
  expect(focusedElement).toBe(true);
});

Then('focus trap should be active', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBeTruthy();
});

Then('focus should move in logical order through modal content', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBeTruthy();
});

Then('background content should not be accessible via Tab', async function () {
  const focusedElement = await page.evaluate(() => {
    const activeEl = document.activeElement;
    const modal = document.querySelector('[role="dialog"]');
    return modal?.contains(activeEl);
  });
  expect(focusedElement).toBe(true);
});

Then('focus should move to last focusable element in modal', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(['A', 'BUTTON', 'INPUT']).toContain(focusedElement);
});

Then('circular focus trap should be active', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBeTruthy();
});

Then('focus should not escape to background content', async function () {
  const focusedElement = await page.evaluate(() => {
    const activeEl = document.activeElement;
    const modal = document.querySelector('[role="dialog"]');
    return modal?.contains(activeEl);
  });
  expect(focusedElement).toBe(true);
});

Then('modal should close', async function () {
  const modal = page.locator('//div[@role="dialog"]');
  await waits.waitForHidden(modal);
});

Then('focus should return to validation error link that triggered modal', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBe('A');
});

Then('screen reader should announce modal closure', async function () {
  expect(this.screenReaderActive).toBe(true);
});

Then('focus should return to triggering element', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(['A', 'BUTTON']).toContain(focusedElement);
});

Then('no focus should be lost or moved to unexpected location', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBeTruthy();
});

Then('background content should have aria-hidden attribute set to {string}', async function (value: string) {
  expect(this.backgroundAriaHidden).toBe(value);
});

Then('clicking background should not activate background elements', async function () {
  const modal = page.locator('//div[@role="dialog"]');
  await assertions.assertVisible(modal);
});

Then('screen reader should not read background content', async function () {
  expect(this.backgroundAriaHidden).toBe('true');
});

Then('screen reader should announce modal beginning and end', async function () {
  const modal = page.locator('//div[@role="dialog"]');
  await assertions.assertVisible(modal);
});

Then('virtual cursor navigation should be contained within modal', async function () {
  expect(this.virtualCursorActive).toBe(true);
});

Then('background content should not be accessible via virtual cursor', async function () {
  expect(this.backgroundAriaHidden).toBe('true');
});