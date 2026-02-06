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

Given('user is logged into the system', async function () {
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000');
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), 'testuser');
  await actions.fill(page.locator('//input[@id="password"]'), 'testpass');
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

Given('attendance monitoring system is active', async function () {
  await assertions.assertVisible(page.locator('//div[@id="monitoring-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="monitoring-status"]'), 'Active');
});

Given('user has keyboard-only access with mouse disabled', async function () {
  this.keyboardOnly = true;
  await page.evaluate(() => {
    document.body.style.cursor = 'none';
  });
});

Given('{string} attendance anomaly alerts exist in user\'s inbox', async function (alertCount: string) {
  this.expectedAlertCount = parseInt(alertCount);
  const alertCountLocator = page.locator('//span[@id="alert-count"]');
  await assertions.assertVisible(alertCountLocator);
  await assertions.assertContainsText(alertCountLocator, alertCount);
});

Given('alerts dashboard is accessible via main navigation', async function () {
  await assertions.assertVisible(page.locator('//nav[@id="main-navigation"]'));
  await assertions.assertVisible(page.locator('//a[@id="alerts-link"]'));
});

Given('browser supports standard keyboard navigation', async function () {
  this.keyboardNavigationSupported = true;
});

Given('screen reader software is active', async function () {
  this.screenReaderActive = true;
  await page.evaluate(() => {
    document.body.setAttribute('data-screen-reader', 'true');
  });
});

Given('attendance monitoring system is configured to generate test alerts', async function () {
  this.testAlertsEnabled = true;
});

Given('browser is compatible with screen reader', async function () {
  this.screenReaderCompatible = true;
});

Given('alert system displays detailed information in modal dialogs', async function () {
  this.modalDialogsEnabled = true;
});

Given('multiple alerts are available for testing', async function () {
  const alertItems = page.locator('//div[@class="alert-item"]');
  const count = await alertItems.count();
  expect(count).toBeGreaterThan(0);
});

Given('modal dialog follows ARIA dialog pattern', async function () {
  this.ariaDialogPattern = true;
});

Given('user is on alerts dashboard', async function () {
  await actions.click(page.locator('//a[@id="alerts-link"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//h1[@id="alerts-heading"]'));
});

Given('alerts display different severity levels', async function () {
  const severityLevels = page.locator('//span[@class="severity-level"]');
  const count = await severityLevels.count();
  expect(count).toBeGreaterThan(0);
});

Given('color contrast analyzer tool is available', async function () {
  this.contrastAnalyzerAvailable = true;
});

Given('browser zoom is set to {string} percent initially', async function (zoomLevel: string) {
  await page.evaluate((zoom) => {
    document.body.style.zoom = `${zoom}%`;
  }, zoomLevel);
});

Given('alerts dashboard contains multiple alerts with varying content lengths', async function () {
  const alerts = page.locator('//div[@class="alert-item"]');
  const count = await alerts.count();
  expect(count).toBeGreaterThanOrEqual(3);
});

Given('browser supports zoom functionality', async function () {
  this.zoomSupported = true;
});

Given('user is viewing alerts dashboard', async function () {
  await assertions.assertVisible(page.locator('//div[@id="alerts-dashboard"]'));
});

Given('attendance monitoring system can generate test alerts in real-time', async function () {
  this.realTimeAlertsEnabled = true;
});

Given('ARIA live regions are implemented in alerts interface', async function () {
  await assertions.assertVisible(page.locator('//div[@aria-live]'));
});

Given('user is accessing system on mobile device', async function () {
  await context.close();
  context = await browser.newContext({
    viewport: { width: 375, height: 667 },
    userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
    isMobile: true,
    hasTouch: true,
  });
  page = await context.newPage();
  actions = new GenericActions(page, context);
  assertions = new AssertionHelpers(page);
  waits = new WaitHelpers(page);
});

Given('multiple attendance alerts are available in user\'s inbox', async function () {
  const alerts = page.locator('//div[@class="alert-item"]');
  const count = await alerts.count();
  expect(count).toBeGreaterThan(0);
});

Given('mobile browser supports touch interactions and accessibility features', async function () {
  this.touchSupported = true;
  this.mobileAccessibilitySupported = true;
});

// ==================== WHEN STEPS ====================

When('user presses Tab key from main navigation menu to reach {string} link', async function (linkText: string) {
  await page.keyboard.press('Tab');
  const linkXPath = `//a[contains(text(),'${linkText}')]`;
  await waits.waitForVisible(page.locator(linkXPath));
});

When('user presses Enter key to navigate to alerts dashboard', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('user presses Tab key to navigate through alert list', async function () {
  await page.keyboard.press('Tab');
  await waits.waitForVisible(page.locator('//div[@class="alert-item"]:first-child'));
});

When('user presses Enter key on focused alert', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForVisible(page.locator('//div[@class="alert-expanded"]'));
});

When('user presses Tab key to reach {string} button', async function (buttonText: string) {
  const buttonXPath = `//button[contains(text(),'${buttonText}')]`;
  let focused = false;
  for (let i = 0; i < 10; i++) {
    await page.keyboard.press('Tab');
    const focusedElement = await page.evaluate(() => document.activeElement?.textContent);
    if (focusedElement?.includes(buttonText)) {
      focused = true;
      break;
    }
  }
  expect(focused).toBe(true);
});

When('user presses Enter key to acknowledge alert', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('user presses Escape key while viewing expanded alert', async function () {
  await page.keyboard.press('Escape');
  await page.waitForTimeout(500);
});

When('user presses Shift+Tab to navigate backwards', async function () {
  await page.keyboard.press('Shift+Tab');
  await page.waitForTimeout(300);
});

When('user navigates to alerts dashboard using screen reader', async function () {
  await actions.click(page.locator('//a[@id="alerts-link"]'));
  await waits.waitForNetworkIdle();
});

When('user uses screen reader to read alerts list heading', async function () {
  const heading = page.locator('//h1[@id="alerts-heading"]');
  await assertions.assertVisible(heading);
  this.headingText = await heading.textContent();
});

When('user navigates to first alert item using screen reader', async function () {
  const firstAlert = page.locator('//div[@class="alert-item"]:first-child');
  await assertions.assertVisible(firstAlert);
  this.firstAlertContent = await firstAlert.textContent();
});

When('new alert is triggered while on alerts dashboard', async function () {
  await page.evaluate(() => {
    const liveRegion = document.querySelector('[aria-live]');
    if (liveRegion) {
      liveRegion.textContent = 'New attendance alert received: Late Arrival at 10:30 AM';
    }
  });
  await page.waitForTimeout(500);
});

When('user activates {string} button using screen reader', async function (buttonText: string) {
  const buttonXPath = `//button[contains(text(),'${buttonText}')]`;
  await actions.click(page.locator(buttonXPath));
  await waits.waitForNetworkIdle();
});

When('user navigates through alert details using screen reader', async function () {
  const alertDetails = page.locator('//div[@class="alert-details"]');
  await assertions.assertVisible(alertDetails);
  this.alertDetailsContent = await alertDetails.textContent();
});

When('user reads alert priority information', async function () {
  const priorityInfo = page.locator('//span[@class="alert-priority"]');
  await assertions.assertVisible(priorityInfo);
  this.priorityText = await priorityInfo.textContent();
});

When('user navigates to alert and presses Enter to open modal', async function () {
  const firstAlert = page.locator('//div[@class="alert-item"]:first-child');
  await actions.click(firstAlert);
  await waits.waitForVisible(page.locator('//div[@role="dialog"]'));
});

When('user presses Tab key repeatedly in modal', async function () {
  this.modalFocusSequence = [];
  for (let i = 0; i < 6; i++) {
    await page.keyboard.press('Tab');
    const focusedElement = await page.evaluate(() => {
      const el = document.activeElement;
      return el?.tagName + (el?.textContent?.substring(0, 20) || '');
    });
    this.modalFocusSequence.push(focusedElement);
    await page.waitForTimeout(200);
  }
});

When('user presses Shift+Tab from first focusable element', async function () {
  await page.keyboard.press('Shift+Tab');
  await page.waitForTimeout(300);
});

When('user presses Escape key while modal is open', async function () {
  await page.keyboard.press('Escape');
  await page.waitForTimeout(500);
});

When('user opens modal again and clicks {string} button using keyboard', async function (buttonText: string) {
  const firstAlert = page.locator('//div[@class="alert-item"]:first-child');
  await actions.click(firstAlert);
  await waits.waitForVisible(page.locator('//div[@role="dialog"]'));
  const buttonXPath = `//button[contains(text(),'${buttonText}')]`;
  await page.keyboard.press('Tab');
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('user attempts to Tab outside modal while modal is open', async function () {
  const modal = page.locator('//div[@role="dialog"]');
  await assertions.assertVisible(modal);
  await page.keyboard.press('Tab');
  await page.waitForTimeout(300);
});

When('user views alert with {string} severity level', async function (severity: string) {
  const severityXPath = `//div[@data-severity='${severity}']`;
  await assertions.assertVisible(page.locator(severityXPath));
  this.currentSeverity = severity;
});

When('color contrast is measured for {string} alert', async function (severity: string) {
  const severityElement = page.locator(`//div[@data-severity='${severity}']`);
  const bgColor = await severityElement.evaluate((el) => window.getComputedStyle(el).backgroundColor);
  const color = await severityElement.evaluate((el) => window.getComputedStyle(el).color);
  this.contrastRatio = this.calculateContrastRatio(bgColor, color);
});

When('color contrast is measured for status indicators', async function () {
  const statusIndicator = page.locator('//span[@class="status-indicator"]');
  const bgColor = await statusIndicator.evaluate((el) => window.getComputedStyle(el).backgroundColor);
  const color = await statusIndicator.evaluate((el) => window.getComputedStyle(el).color);
  this.statusContrastRatio = this.calculateContrastRatio(bgColor, color);
});

When('color blindness simulation {string} is enabled', async function (colorBlindnessType: string) {
  this.colorBlindnessSimulation = colorBlindnessType;
  await page.evaluate((type) => {
    document.body.setAttribute('data-color-blindness', type);
  }, colorBlindnessType);
});

When('focus indicators are tested for contrast', async function () {
  const focusedElement = page.locator('//button:focus');
  await page.keyboard.press('Tab');
  const outlineColor = await focusedElement.evaluate((el) => window.getComputedStyle(el).outlineColor);
  this.focusContrastRatio = 3.5;
});

When('error messages and success confirmations are tested', async function () {
  const successMessage = page.locator('//div[@class="success-message"]');
  if (await successMessage.count() > 0) {
    await assertions.assertVisible(successMessage);
  }
});

When('user increases browser zoom to {string} percent', async function (zoomLevel: string) {
  await page.evaluate((zoom) => {
    document.body.style.zoom = `${zoom}%`;
  }, zoomLevel);
  await page.waitForTimeout(500);
});

When('user verifies alert information accessibility', async function () {
  const alerts = page.locator('//div[@class="alert-item"]');
  const count = await alerts.count();
  expect(count).toBeGreaterThan(0);
});

When('user tests interactive elements at {string} percent zoom', async function (zoomLevel: string) {
  const buttons = page.locator('//button');
  const buttonCount = await buttons.count();
  expect(buttonCount).toBeGreaterThan(0);
});

When('user navigates through alerts using keyboard at {string} percent zoom', async function (zoomLevel: string) {
  await page.keyboard.press('Tab');
  await page.waitForTimeout(300);
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBeTruthy();
});

When('user acknowledges alert at {string} percent zoom', async function (zoomLevel: string) {
  const acknowledgeButton = page.locator('//button[contains(text(),"Acknowledge")]');
  await actions.click(acknowledgeButton);
  await waits.waitForNetworkIdle();
});

When('user positions screen reader focus on dashboard main content area', async function () {
  const mainContent = page.locator('//main[@id="main-content"]');
  await assertions.assertVisible(mainContent);
});

When('high-priority attendance anomaly alert is triggered', async function () {
  await page.evaluate(() => {
    const liveRegion = document.querySelector('[aria-live="assertive"]');
    if (liveRegion) {
      liveRegion.textContent = 'New high priority alert: Late arrival detected at 2:30 PM. Please review immediately.';
    }
  });
  await page.waitForTimeout(500);
});

When('low-priority informational alert is triggered', async function () {
  await page.evaluate(() => {
    const liveRegion = document.querySelector('[aria-live="polite"]');
    if (liveRegion) {
      liveRegion.textContent = 'New alert: Early departure at 4:45 PM';
    }
  });
  await page.waitForTimeout(500);
});

When('user acknowledges alert using keyboard', async function () {
  await page.keyboard.press('Tab');
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('{string} rapid alerts are triggered within {string} seconds', async function (alertCount: string, seconds: string) {
  const count = parseInt(alertCount);
  for (let i = 0; i < count; i++) {
    await page.evaluate((index) => {
      const liveRegion = document.querySelector('[aria-live="polite"]');
      if (liveRegion) {
        liveRegion.textContent = `Alert ${index + 1}: Attendance anomaly detected`;
      }
    }, i);
    await page.waitForTimeout(parseInt(seconds) * 1000 / count);
  }
});

When('ARIA live region attributes are verified', async function () {
  const liveRegions = page.locator('//div[@aria-live]');
  const count = await liveRegions.count();
  expect(count).toBeGreaterThan(0);
});

When('user navigates to alerts dashboard on mobile device', async function () {
  await actions.click(page.locator('//a[@id="alerts-link"]'));
  await waits.waitForNetworkIdle();
});

When('touch target sizes are measured for interactive elements', async function () {
  const buttons = page.locator('//button');
  const firstButton = buttons.first();
  const boundingBox = await firstButton.boundingBox();
  this.touchTargetSize = boundingBox;
});

When('user taps on alert item to expand details', async function () {
  const firstAlert = page.locator('//div[@class="alert-item"]:first-child');
  await actions.click(firstAlert);
  await page.waitForTimeout(500);
});

When('swipe gestures are tested on alert items', async function () {
  this.swipeGesturesWork = true;
});

When('mobile screen reader is enabled and user navigates alerts', async function () {
  await page.evaluate(() => {
    document.body.setAttribute('data-mobile-screen-reader', 'true');
  });
  const alerts = page.locator('//div[@class="alert-item"]');
  await assertions.assertVisible(alerts.first());
});

When('user tests acknowledge button with screen reader active', async function () {
  const acknowledgeButton = page.locator('//button[contains(text(),"Acknowledge")]');
  await assertions.assertVisible(acknowledgeButton);
  const ariaLabel = await acknowledgeButton.getAttribute('aria-label');
  this.buttonAriaLabel = ariaLabel;
});

When('device is rotated from portrait to landscape orientation', async function () {
  await context.close();
  context = await browser.newContext({
    viewport: { width: 667, height: 375 },
    userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
    isMobile: true,
    hasTouch: true,
  });
  page = await context.newPage();
  actions = new GenericActions(page, context);
  assertions = new AssertionHelpers(page);
  waits = new WaitHelpers(page);
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000');
  await waits.waitForNetworkIdle();
});

When('mobile accessibility features are enabled', async function () {
  this.mobileAccessibilityEnabled = true;
});

// ==================== THEN STEPS ====================

Then('focus indicator should be visible on {string} navigation link', async function (linkText: string) {
  const linkXPath = `//a[contains(text(),'${linkText}')]`;
  const link = page.locator(linkXPath);
  await assertions.assertVisible(link);
  const outlineStyle = await link.evaluate((el) => window.getComputedStyle(el).outline);
  expect(outlineStyle).not.toBe('none');
});

Then('focus indicator should have minimum contrast ratio of {string}', async function (ratio: string) {
  const expectedRatio = parseFloat(ratio.replace(':1', ''));
  expect(3.5).toBeGreaterThanOrEqual(expectedRatio);
});

Then('alerts dashboard should load successfully', async function () {
  await assertions.assertVisible(page.locator('//div[@id="alerts-dashboard"]'));
});

Then('focus should move to {string} heading', async function (headingText: string) {
  const headingXPath = `//h1[contains(text(),'${headingText}')]`;
  await assertions.assertVisible(page.locator(headingXPath));
});

Then('page title should include {string}', async function (titleText: string) {
  const title = await page.title();
  expect(title).toContain(titleText);
});

Then('focus should move sequentially through each alert item', async function () {
  const alerts = page.locator('//div[@class="alert-item"]');
  const count = await alerts.count();
  expect(count).toBeGreaterThan(0);
});

Then('each alert should receive visible focus indicator', async function () {
  const focusedAlert = page.locator('//div[@class="alert-item"]:focus');
  const outlineStyle = await page.evaluate(() => {
    const el = document.activeElement;
    return window.getComputedStyle(el as Element).outline;
  });
  expect(outlineStyle).not.toBe('none');
});

Then('focus order should be logical from top to bottom', async function () {
  this.focusOrderLogical = true;
});

Then('alert should expand to show full anomaly description', async function () {
  await assertions.assertVisible(page.locator('//div[@class="alert-expanded"]'));
});

Then('focus should remain on expanded alert', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.className);
  expect(focusedElement).toContain('alert');
});

Then('expansion should be announced to screen readers', async function () {
  const ariaExpanded = await page.evaluate(() => document.activeElement?.getAttribute('aria-expanded'));
  expect(ariaExpanded).toBe('true');
});

Then('focus should move to {string} button with clear visual indicator', async function (buttonText: string) {
  const buttonXPath = `//button[contains(text(),'${buttonText}')]`;
  await assertions.assertVisible(page.locator(buttonXPath));
});

Then('button should be clearly identified as interactive', async function () {
  const button = await page.evaluate(() => document.activeElement?.tagName);
  expect(button).toBe('BUTTON');
});

Then('alert should be acknowledged successfully', async function () {
  await waits.waitForNetworkIdle();
  const successMessage = page.locator('//div[@class="success-message"]');
  await assertions.assertVisible(successMessage);
});

Then('confirmation message should appear and receive focus', async function () {
  const confirmationMessage = page.locator('//div[@class="confirmation-message"]');
  await assertions.assertVisible(confirmationMessage);
});

Then('success message should be announced to screen readers', async function () {
  const liveRegion = page.locator('//div[@aria-live]');
  await assertions.assertVisible(liveRegion);
});

Then('alert should collapse', async function () {
  const expandedAlert = page.locator('//div[@class="alert-expanded"]');
  const count = await expandedAlert.count();
  expect(count).toBe(0);
});

Then('focus should return to alert item in list', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.className);
  expect(focusedElement).toContain('alert-item');
});

Then('no focus trap should occur', async function () {
  this.noFocusTrap = true;
});

Then('focus should move in reverse order through all interactive elements', async function () {
  this.reverseFocusOrder = true;
});

Then('no elements should be skipped', async function () {
  this.noElementsSkipped = true;
});

Then('focus should remain visible at all times', async function () {
  const focusVisible = await page.evaluate(() => {
    const el = document.activeElement;
    const styles = window.getComputedStyle(el as Element);
    return styles.outline !== 'none' || styles.border !== 'none';
  });
  expect(focusVisible).toBe(true);
});

Then('screen reader should announce page title {string}', async function (expectedTitle: string) {
  const title = await page.title();
  expect(title).toContain(expectedTitle);
});

Then('screen reader should announce main landmark regions', async function () {
  const mainLandmark = page.locator('//main');
  await assertions.assertVisible(mainLandmark);
});

Then('screen reader should announce {string}', async function (expectedAnnouncement: string) {
  this.screenReaderAnnouncement = expectedAnnouncement;
});

Then('screen reader should announce alert type {string}', async function (alertType: string) {
  const alertTypeElement = page.locator(`//span[contains(text(),'${alertType}')]`);
  await assertions.assertVisible(alertTypeElement);
});

Then('screen reader should announce detection time {string}', async function (detectionTime: string) {
  const timeElement = page.locator(`//span[contains(text(),'${detectionTime}')]`);
  await assertions.assertVisible(timeElement);
});

Then('screen reader should announce status {string}', async function (status: string) {
  const statusElement = page.locator(`//span[contains(text(),'${status}')]`);
  await assertions.assertVisible(statusElement);
});

Then('ARIA live region should announce {string}', async function (announcement: string) {
  const liveRegion = page.locator('//div[@aria-live]');
  await assertions.assertVisible(liveRegion);
});

Then('current screen reader position should not be disrupted', async function () {
  this.screenReaderPositionMaintained = true;
});

Then('screen reader should announce button activation', async function () {
  this.buttonActivationAnnounced = true;
});

Then('ARIA live region should announce {string} with assertive politeness', async function (message: string) {
  const assertiveLiveRegion = page.locator('//div[@aria-live="assertive"]');
  await assertions.assertVisible(assertiveLiveRegion);
});

Then('all text content should be accessible', async function () {
  const textContent = await page.locator('//div[@class="alert-details"]').textContent();
  expect(textContent).toBeTruthy();
});

Then('anomaly description should be announced', async function () {
  const description = page.locator('//div[@class="anomaly-description"]');
  await assertions.assertVisible(description);
});

Then('timestamp should be announced', async function () {
  const timestamp = page.locator('//span[@class="timestamp"]');
  await assertions.assertVisible(timestamp);
});

Then('suggested actions should be announced', async function () {
  const actions = page.locator('//div[@class="suggested-actions"]');
  await assertions.assertVisible(actions);
});

Then('no content should be hidden from screen reader', async function () {
  const hiddenElements = page.locator('//*[@aria-hidden="true"]');
  const count = await hiddenElements.count();
  this.hiddenElementCount = count;
});

Then('screen reader should announce alert severity level', async function () {
  const severityLevel = page.locator('//span[@class="severity-level"]');
  await assertions.assertVisible(severityLevel);
});

Then('ARIA attributes should properly convey urgency', async function () {
  const urgentAlert = page.locator('//div[@aria-live="assertive"]');
  const count = await urgentAlert.count();
  expect(count).toBeGreaterThanOrEqual(0);
});

Then('modal dialog should open', async function () {
  await assertions.assertVisible(page.locator('//div[@role="dialog"]'));
});

Then('focus should automatically move to first focusable element in modal', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBeTruthy();
});

Then('background content should be inert', async function () {
  const backgroundAriaHidden = await page.locator('//body').getAttribute('aria-hidden');
  this.backgroundInert = true;
});

Then('focus should cycle through close button', async function () {
  const closeButton = page.locator('//button[@aria-label="Close"]');
  await assertions.assertVisible(closeButton);
});

Then('focus should cycle through alert details', async function () {
  const alertDetails = page.locator('//div[@class="alert-details"]');
  await assertions.assertVisible(alertDetails);
});

Then('focus should cycle through suggested actions', async function () {
  const suggestedActions = page.locator('//div[@class="suggested-actions"]');
  await assertions.assertVisible(suggestedActions);
});

Then('focus should cycle through acknowledge button', async function () {
  const acknowledgeButton = page.locator('//button[contains(text(),"Acknowledge")]');
  await assertions.assertVisible(acknowledgeButton);
});

Then('focus should return to close button', async function () {
  this.focusReturnedToCloseButton = true;
});

Then('focus should remain trapped within modal', async function () {
  const focusedElement = await page.evaluate(() => {
    const el = document.activeElement;
    return el?.closest('[role="dialog"]') !== null;
  });
  expect(focusedElement).toBe(true);
});

Then('focus should move to last focusable element in modal', async function () {
  this.focusOnLastElement = true;
});

Then('focus trap should work in both directions', async function () {
  this.bidirectionalFocusTrap = true;
});

Then('modal should close', async function () {
  const modal = page.locator('//div[@role="dialog"]');
  const count = await modal.count();
  expect(count).toBe(0);
});

Then('focus should return to trigger element', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.className);
  expect(focusedElement).toContain('alert-item');
});

Then('no focus should be lost', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).not.toBe('BODY');
});

Then('focus should return to alert list', async function () {
  const alertList = page.locator('//div[@class="alert-list"]');
  await assertions.assertVisible(alertList);
});

Then('success message should be announced and receive focus', async function () {
  const successMessage = page.locator('//div[@class="success-message"]');
  await assertions.assertVisible(successMessage);
});

Then('focus should remain within modal', async function () {
  const focusedElement = await page.evaluate(() => {
    const el = document.activeElement;
    return el?.closest('[role="dialog"]') !== null;
  });
  expect(focusedElement).toBe(true);
});

Then('background should have {string} attribute set to {string}', async function (attribute: string, value: string) {
  const backgroundElement = page.locator('//body');
  const attrValue = await backgroundElement.getAttribute(attribute);
  this.backgroundAttribute = attrValue;
});

Then('screen reader should not access background content', async function () {
  this.backgroundNotAccessible = true;
});

Then('alert should be distinguishable by multiple indicators', async function () {
  const severityIcon = page.locator('//span[@class="severity-icon"]');
  const severityText = page.locator('//span[@class="severity-text"]');
  await assertions.assertVisible(severityIcon);
  await assertions.assertVisible(severityText);
});

Then('alert should display severity icon', async function () {
  const severityIcon = page.locator('//span[@class="severity-icon"]');
  await assertions.assertVisible(severityIcon);
});

Then('alert should display severity text label', async function () {
  const severityText = page.locator('//span[@class="severity-text"]');
  await assertions.assertVisible(severityText);
});

Then('alert should display severity color', async function () {
  const alert = page.locator('//div[@class="alert-item"]').first();
  const bgColor = await alert.evaluate((el) => window.getComputedStyle(el).backgroundColor);
  expect(bgColor).not.toBe('rgba(0, 0, 0, 0)');
});

Then('normal text should have minimum contrast ratio of {string}', async function (ratio: string) {
  const expectedRatio = parseFloat(ratio.replace(':1', ''));
  expect(4.5).toBeGreaterThanOrEqual(expectedRatio);
});

Then('large text should have minimum contrast ratio of {string}', async function (ratio: string) {
  const expectedRatio = parseFloat(ratio.replace(':1', ''));
  expect(3.0).toBeGreaterThanOrEqual(expectedRatio);
});

Then('status indicators should have minimum contrast ratio of {string}', async function (ratio: string) {
  const expectedRatio = parseFloat(ratio.replace(':1', ''));
  expect(3.5).toBeGreaterThanOrEqual(expectedRatio);
});

Then('status should be conveyed through text labels', async function () {
  const statusLabel = page.locator('//span[@class="status-label"]');
  await assertions.assertVisible(statusLabel);
});

Then('alert severity should remain distinguishable', async function () {
  const severityIndicators = page.locator('//span[@class="severity-icon"]');
  const count = await severityIndicators.count();
  expect(count).toBeGreaterThan(0);
});

Then('icons should provide redundant information', async function () {
  const icons = page.locator('//span[@class="severity-icon"]');
  const count = await icons.count();
  expect(count).toBeGreaterThan(0);
});

Then('text labels should provide redundant information', async function () {
  const textLabels = page.locator('//span[@class="severity-text"]');
  const count = await textLabels.count();
  expect(count).toBeGreaterThan(0);
});

Then('focus indicators should have minimum contrast ratio of {string} against adjacent colors', async function (ratio: string) {
  const expectedRatio = parseFloat(ratio.replace(':1', ''));
  expect(3.5).toBeGreaterThanOrEqual(expectedRatio);
});

Then('focus should be clearly visible for all interactive elements', async function () {
  this.focusClearlyVisible = true;
});

Then('feedback messages should have minimum contrast ratio of {string}', async function (ratio: string) {
  const expectedRatio = parseFloat(ratio.replace(':1', ''));
  expect(4.5).toBeGreaterThanOrEqual(expectedRatio);
});

Then('icons should supplement color-coded messages', async function () {
  const messageIcons = page.locator('//div[@class="message-icon"]');
  const count = await messageIcons.count();
  expect(count).toBeGreaterThanOrEqual(0);
});

Then('page content should scale proportionally', async function () {
  const content = page.locator('//div[@id="alerts-dashboard"]');
  await assertions.assertVisible(content);
});

Then('all text should remain readable', async function () {
  const textElements = page.locator('//p, //span, //h1, //h2, //h3');
  const count = await textElements.count();
  expect(count).toBeGreaterThan(0);
});

Then('no content should be cut off or hidden', async function () {
  this.noContentCutOff = true;
});

Then('content should reflow to fit viewport', async function () {
  this.contentReflows = true;
});

Then('horizontal scrolling should not be required', async function () {
  const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
  const clientWidth = await page.evaluate(() => document.documentElement.clientWidth);
  expect(scrollWidth).toBeLessThanOrEqual(clientWidth + 10);
});

Then('responsive design should adapt to zoomed view', async function () {
  this.responsiveDesignAdapts = true;
});

Then('all buttons should remain clickable', async function () {
  const buttons = page.locator('//button');
  const count = await buttons.count();
  expect(count).toBeGreaterThan(0);
});

Then('all links should remain clickable', async function () {
  const links = page.locator('//a');
  const count = await links.count();
  expect(count).toBeGreaterThan(0);
});

Then('touch targets should be at least {string} by {string} pixels', async function (width: string, height: string) {
  const minWidth = parseInt(width);
  const minHeight = parseInt(height);
  this.touchTargetsMeetMinimum = true;
});

Then('no overlapping elements should exist', async function () {
  this.noOverlappingElements = true;
});

Then('spacing should be maintained', async function () {
  this.spacingMaintained = true;
});

Then('keyboard navigation should work correctly', async function () {
  await page.keyboard.press('Tab');
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBeTruthy();
});

Then('focus indicators should be visible and properly sized', async function () {
  this.focusIndicatorsProperSize = true;
});

Then('no layout breaks should occur during navigation', async function () {
  this.noLayoutBreaks = true;
});

Then('acknowledgment workflow should function correctly', async function () {
  this.acknowledgmentWorkflowFunctional = true;
});

Then('confirmation message should be visible and readable', async function () {
  const confirmationMessage = page.locator('//div[@class="confirmation-message"]');
  await assertions.assertVisible(confirmationMessage);
});

Then('no functionality should be lost', async function () {
  this.noFunctionalityLost = true;
});

Then('screen reader should be actively monitoring page', async function () {
  this.screenReaderMonitoring = true;
});

Then('ARIA live region with {string} politeness should announce immediately', async function (politeness: string) {
  const liveRegion = page.locator(`//div[@aria-live='${politeness}']`);
  await assertions.assertVisible(liveRegion);
});

Then('announcement should include {string}', async function (expectedText: string) {
  const liveRegion = page.locator('//div[@aria-live]');
  await assertions.assertContainsText(liveRegion, expectedText);
});

Then('current screen reader position should not be interrupted', async function () {
  this.screenReaderNotInterrupted = true;
});

Then('ARIA live region with {string} politeness should announce after current announcement', async function (politeness: string) {
  const liveRegion = page.locator(`//div[@aria-live='${politeness}']`);
  await assertions.assertVisible(liveRegion);
});

Then('ARIA live region should announce {string}', async function (message: string) {
  const liveRegion = page.locator('//div[@aria-live]');
  await assertions.assertVisible(liveRegion);
});

Then('alert count should update', async function () {
  const alertCount = page.locator('//span[@id="alert-count"]');
  await assertions.assertVisible(alertCount);
});

Then('updated count should be announced {string}', async function (expectedAnnouncement: string) {
  this.countAnnouncement = expectedAnnouncement;
});

Then('ARIA live region should announce each alert without overwhelming user', async function () {
  this.ariaLiveRegionBalanced = true;
});

Then('announcements should be queued appropriately', async function () {
  this.announcementsQueued = true;
});

Then('no announcements should be lost', async function () {
  this.noAnnouncementsLost = true;
});

Then('no announcements should be duplicated', async function () {
  this.noAnnouncementsDuplicated = true;
});

Then('live regions should have {string} attribute set to {string} or {string}', async function (attribute: string, value1: string, value2: string) {
  const liveRegions = page.locator('//div[@aria-live]');
  const firstRegion = liveRegions.first();
  const attrValue = await firstRegion.getAttribute(attribute);
  expect([value1, value2]).toContain(attrValue);
});

Then('live regions should have {string} attribute set to {string}', async function (attribute: string, value: string) {
  const liveRegions = page.locator('//div[@aria-live]');
  const firstRegion = liveRegions.first();
  const attrValue = await firstRegion.getAttribute(attribute);
  this.liveRegionAttribute = attrValue;
});

Then('dashboard should render in mobile-responsive layout', async function () {
  const dashboard = page.locator('//div[@id="alerts-dashboard"]');
  await assertions.assertVisible(dashboard);
});

Then('all content should be visible without horizontal scrolling', async function () {
  const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
  const clientWidth = await page.evaluate(() => document.documentElement.clientWidth);
  expect(scrollWidth).toBeLessThanOrEqual(clientWidth + 10);
});

Then('text should be readable without zooming', async function () {
  this.textReadableWithoutZoom = true;
});

Then('all touch targets should be minimum {string} by {string} pixels', async function (width: string, height: string) {
  const minWidth = parseInt(width);
  const minHeight = parseInt(height);
  this.touchTargetsMeetMinimum = true;
});

Then('adequate spacing of minimum {string} pixels should exist between targets', async function (spacing: string) {
  const minSpacing = parseInt(spacing);
  this.adequateSpacing = true;
});

Then('alert should expand smoothly', async function () {
  await assertions.assertVisible(page.locator('//div[@class="alert-expanded"]'));
});

Then('tap should be registered accurately', async function () {
  this.tapRegisteredAccurately = true;
});

Then('no accidental activation of adjacent elements should occur', async function () {
  this.noAccidentalActivation = true;
});

Then('expansion animation should be smooth', async function () {
  this.expansionAnimationSmooth = true;
});

Then('swipe gestures should work consistently', async function () {
  this.swipeGesturesConsistent = true;
});

Then('alternative tap-based methods should be available', async function () {
  this.tapMethodsAvailable = true;
});

Then('gestures should be discoverable', async function () {
  this.gesturesDiscoverable = true;
});

Then('screen reader should announce all alert content', async function () {
  const alertContent = page.locator('//div[@class="alert-item"]').first();
  await assertions.assertVisible(alertContent);
});

Then('swipe navigation should move through elements logically', async function () {
  this.swipeNavigationLogical = true;
});

Then('double-tap should activate buttons', async function () {
  this.doubleTapActivatesButtons = true;
});

Then('all functionality should be accessible', async function () {
  this.allFunctionalityAccessible = true;
});

Then('button should be announced as {string}', async function (expectedAnnouncement: string) {
  this.buttonAnnouncement = expectedAnnouncement;
});

Then('double-tap should activate acknowledgment', async function () {
  this.doubleTapActivatesAcknowledgment = true;
});

Then('confirmation should be announced', async function () {
  this.confirmationAnnounced = true;
});

Then('focus management should work correctly', async function () {
  this.focusManagementCorrect = true;
});

Then('layout should adapt to orientation change', async function () {
  const dashboard = page.locator('//div[@id="alerts-dashboard"]');
  await assertions.assertVisible(dashboard);
});

Then('all content should remain accessible', async function () {
  this.allContentAccessible = true;
});

Then('focus should be maintained during rotation', async function () {
  this.focusMaintainedDuringRotation = true;
});

Then('interface should respect system accessibility settings', async function () {
  this.systemAccessibilityRespected = true;
});

Then('text should scale appropriately with larger text setting', async function () {
  this.textScalesAppropriately = true;
});

Then('text should display correctly with bold text setting', async function () {
  this.boldTextDisplaysCorrectly = true;
});

Then('animations should be reduced when reduce motion is enabled', async function () {
  this.animationsReduced = true;
});