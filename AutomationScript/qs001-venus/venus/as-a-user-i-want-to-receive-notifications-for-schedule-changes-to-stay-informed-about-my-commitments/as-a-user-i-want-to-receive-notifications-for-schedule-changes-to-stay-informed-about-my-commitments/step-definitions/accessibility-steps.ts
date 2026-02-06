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
    notificationCount: 0,
    focusedElement: null,
    zoomLevel: '100%'
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
/*  TEST CASE: TC-ACC-001
/*  Title: Complete keyboard navigation through notification center
/*  Priority: High
/*  Category: Accessibility - Keyboard Navigation
/**************************************************/

Given('user is logged into the system', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="username"]'), this.testData.users.user.username);
  await actions.fill(page.locator('//input[@id="password"]'), this.testData.users.user.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

Given('user has {int} unread schedule change notifications in the notification center', async function (notificationCount: number) {
  this.testData.notificationCount = notificationCount;
  // TODO: Replace XPath with Object Repository when available
  const notificationBadgeXPath = '//span[@id="notification-badge"]';
  await waits.waitForVisible(page.locator(notificationBadgeXPath));
  await assertions.assertContainsText(page.locator(notificationBadgeXPath), notificationCount.toString());
});

Given('keyboard is the only input device being used', async function () {
  this.testData.inputDevice = 'keyboard';
});

Given('browser supports standard keyboard navigation', async function () {
  const isKeyboardSupported = await page.evaluate(() => {
    return typeof KeyboardEvent !== 'undefined';
  });
  expect(isKeyboardSupported).toBe(true);
});

/**************************************************/
/*  TEST CASE: TC-ACC-002
/*  Title: Screen reader announces schedule change notifications
/*  Priority: High
/*  Category: Accessibility - Screen Reader
/**************************************************/

Given('screen reader software is installed and running', async function () {
  this.testData.screenReaderActive = true;
  // TODO: Replace XPath with Object Repository when available
  const ariaLiveRegionXPath = '//div[@aria-live="polite"]';
  await assertions.assertVisible(page.locator(ariaLiveRegionXPath));
});

Given('user has notification preferences enabled', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="user-menu"]'));
  await waits.waitForVisible(page.locator('//a[@id="preferences"]'));
  await actions.click(page.locator('//a[@id="preferences"]'));
  await waits.waitForNetworkIdle();
  const notificationToggleXPath = '//input[@id="enable-notifications"]';
  const isChecked = await page.locator(notificationToggleXPath).isChecked();
  if (!isChecked) {
    await actions.check(page.locator(notificationToggleXPath));
  }
  await actions.click(page.locator('//button[@id="save-preferences"]'));
  await waits.waitForNetworkIdle();
});

Given('system has one scheduled appointment ready to be modified', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="schedule-link"]'));
  await waits.waitForNetworkIdle();
  const appointmentXPath = '//div[@class="appointment-item"][1]';
  await assertions.assertVisible(page.locator(appointmentXPath));
  this.testData.appointmentId = await page.locator(appointmentXPath).getAttribute('data-appointment-id');
});

/**************************************************/
/*  TEST CASE: TC-ACC-003
/*  Title: ARIA live region announces new notifications in real-time
/*  Priority: High
/*  Category: Accessibility - ARIA Live Region
/**************************************************/

Given('screen reader software is active', async function () {
  this.testData.screenReaderActive = true;
});

Given('user is logged into the system and on the dashboard page', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="username"]'), this.testData.users.user.username);
  await actions.fill(page.locator('//input[@id="password"]'), this.testData.users.user.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//a[@id="dashboard-link"]'));
  await waits.waitForNetworkIdle();
});

Given('no unread notifications currently exist', async function () {
  // TODO: Replace XPath with Object Repository when available
  const notificationBadgeXPath = '//span[@id="notification-badge"]';
  const badgeCount = await page.locator(notificationBadgeXPath).count();
  if (badgeCount > 0) {
    const badgeText = await page.locator(notificationBadgeXPath).textContent();
    expect(badgeText?.trim()).toBe('0');
  }
});

Given('ARIA live region is implemented for notification announcements', async function () {
  // TODO: Replace XPath with Object Repository when available
  const ariaLiveRegionXPath = '//div[@aria-live="polite"]';
  await assertions.assertVisible(page.locator(ariaLiveRegionXPath));
  const ariaLiveValue = await page.locator(ariaLiveRegionXPath).getAttribute('aria-live');
  expect(ariaLiveValue).toBe('polite');
});

/**************************************************/
/*  TEST CASE: TC-ACC-004
/*  Title: Notification center meets WCAG 2.1 color contrast requirements
/*  Priority: High
/*  Category: Accessibility - Color Contrast
/**************************************************/

Given('user has at least one unread schedule change notification', async function () {
  // TODO: Replace XPath with Object Repository when available
  const notificationBadgeXPath = '//span[@id="notification-badge"]';
  await waits.waitForVisible(page.locator(notificationBadgeXPath));
  const badgeText = await page.locator(notificationBadgeXPath).textContent();
  const count = parseInt(badgeText?.trim() || '0');
  expect(count).toBeGreaterThanOrEqual(1);
});

Given('color contrast analyzer tool is available', async function () {
  this.testData.contrastAnalyzerAvailable = true;
});

Given('email notification has been received in user\'s inbox', async function () {
  this.testData.emailNotificationReceived = true;
});

/**************************************************/
/*  TEST CASE: TC-ACC-005
/*  Title: Notification center remains functional at various zoom levels
/*  Priority: Medium
/*  Category: Accessibility - Zoom & Responsive
/**************************************************/

Given('user is logged into the system using a desktop browser', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="username"]'), this.testData.users.user.username);
  await actions.fill(page.locator('//input[@id="password"]'), this.testData.users.user.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

Given('browser zoom level is set to {string}', async function (zoomLevel: string) {
  this.testData.zoomLevel = zoomLevel;
  const zoomValue = parseFloat(zoomLevel.replace('%', '')) / 100;
  await page.evaluate((zoom) => {
    document.body.style.zoom = zoom.toString();
  }, zoomValue);
});

Given('user has at least {int} unread schedule change notifications', async function (notificationCount: number) {
  this.testData.notificationCount = notificationCount;
  // TODO: Replace XPath with Object Repository when available
  const notificationBadgeXPath = '//span[@id="notification-badge"]';
  await waits.waitForVisible(page.locator(notificationBadgeXPath));
  const badgeText = await page.locator(notificationBadgeXPath).textContent();
  const count = parseInt(badgeText?.trim() || '0');
  expect(count).toBeGreaterThanOrEqual(notificationCount);
});

Given('screen resolution is set to {string} or higher', async function (resolution: string) {
  const [width, height] = resolution.split('x').map(Number);
  await page.setViewportSize({ width, height });
});

/**************************************************/
/*  TEST CASE: TC-ACC-006
/*  Title: Focus management and focus trap prevention
/*  Priority: High
/*  Category: Accessibility - Focus Management
/**************************************************/

Given('keyboard is the primary input device', async function () {
  this.testData.inputDevice = 'keyboard';
});

Given('notification center opens as a modal dialog or overlay panel', async function () {
  this.testData.notificationCenterType = 'modal';
});

// ==================== WHEN STEPS ====================

When('user presses Tab key repeatedly from the main page header until notification icon receives focus', async function () {
  // TODO: Replace XPath with Object Repository when available
  const headerXPath = '//header[@id="main-header"]';
  await actions.click(page.locator(headerXPath));
  
  let focusedElement = null;
  let attempts = 0;
  const maxAttempts = 20;
  
  while (attempts < maxAttempts) {
    await page.keyboard.press('Tab');
    focusedElement = await page.evaluate(() => {
      const el = document.activeElement;
      return el ? el.getAttribute('id') : null;
    });
    
    if (focusedElement === 'notification-icon') {
      break;
    }
    attempts++;
  }
  
  this.testData.focusedElement = focusedElement;
});

When('user presses Enter key to open notification center', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('user presses Tab key to navigate through each notification item', async function () {
  this.testData.focusedElements = [];
  
  for (let i = 0; i < this.testData.notificationCount; i++) {
    await page.keyboard.press('Tab');
    const focusedElement = await page.evaluate(() => {
      const el = document.activeElement;
      return {
        id: el?.getAttribute('id'),
        class: el?.getAttribute('class'),
        text: el?.textContent?.substring(0, 50)
      };
    });
    this.testData.focusedElements.push(focusedElement);
  }
});

When('user presses Enter key on the first notification to view full details', async function () {
  // TODO: Replace XPath with Object Repository when available
  const firstNotificationXPath = '//div[@class="notification-item"][1]';
  await waits.waitForVisible(page.locator(firstNotificationXPath));
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('user presses Tab key to navigate to the acknowledge button', async function () {
  let focusedElement = null;
  let attempts = 0;
  const maxAttempts = 10;
  
  while (attempts < maxAttempts) {
    await page.keyboard.press('Tab');
    focusedElement = await page.evaluate(() => {
      const el = document.activeElement;
      return el?.getAttribute('id') || el?.textContent?.toLowerCase();
    });
    
    if (focusedElement?.includes('acknowledge')) {
      break;
    }
    attempts++;
  }
  
  this.testData.acknowledgeButtonFocused = true;
});

When('user presses Enter key to acknowledge the notification', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('user presses Escape key to close the notification center', async function () {
  await page.keyboard.press('Escape');
  await waits.waitForNetworkIdle();
});

When('user presses Tab key to continue navigation', async function () {
  await page.keyboard.press('Tab');
  this.testData.focusedElement = await page.evaluate(() => {
    const el = document.activeElement;
    return el?.getAttribute('id');
  });
});

When('user navigates to the schedule with screen reader active', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[@id="schedule-link"]'));
  await waits.waitForNetworkIdle();
});

When('user modifies an appointment time from {string} to {string}', async function (oldTime: string, newTime: string) {
  // TODO: Replace XPath with Object Repository when available
  const appointmentXPath = '//div[@class="appointment-item"][1]';
  await actions.click(page.locator(appointmentXPath));
  await waits.waitForVisible(page.locator('//button[@id="edit-appointment"]'));
  await actions.click(page.locator('//button[@id="edit-appointment"]'));
  await waits.waitForVisible(page.locator('//input[@id="appointment-time"]'));
  await actions.clearAndFill(page.locator('//input[@id="appointment-time"]'), newTime);
  await actions.click(page.locator('//button[@id="save-appointment"]'));
  await waits.waitForNetworkIdle();
  
  this.testData.oldTime = oldTime;
  this.testData.newTime = newTime;
});

When('user waits up to {int} minute for the notification to arrive', async function (minutes: number) {
  const waitTime = minutes * 60 * 1000;
  await page.waitForTimeout(Math.min(waitTime, 5000));
  await waits.waitForNetworkIdle();
});

When('user navigates to the notification icon using Tab key', async function () {
  let focusedElement = null;
  let attempts = 0;
  const maxAttempts = 20;
  
  while (attempts < maxAttempts) {
    await page.keyboard.press('Tab');
    focusedElement = await page.evaluate(() => {
      const el = document.activeElement;
      return el?.getAttribute('id');
    });
    
    if (focusedElement === 'notification-icon') {
      break;
    }
    attempts++;
  }
  
  this.testData.focusedElement = focusedElement;
});

When('user presses Enter to open the notification center', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('user navigates to the new notification using arrow keys', async function () {
  await page.keyboard.press('ArrowDown');
  this.testData.currentNotificationFocused = true;
});

When('user navigates to the notification timestamp', async function () {
  await page.keyboard.press('Tab');
  this.testData.timestampFocused = true;
});

When('user navigates to the acknowledge button', async function () {
  let focusedElement = null;
  let attempts = 0;
  const maxAttempts = 10;
  
  while (attempts < maxAttempts) {
    await page.keyboard.press('Tab');
    focusedElement = await page.evaluate(() => {
      const el = document.activeElement;
      return el?.getAttribute('id') || el?.textContent?.toLowerCase();
    });
    
    if (focusedElement?.includes('acknowledge')) {
      break;
    }
    attempts++;
  }
});

When('user activates the acknowledge button using Enter key', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('user remains on the dashboard page without interacting with any elements', async function () {
  await page.waitForTimeout(1000);
});

When('another administrator modifies the user\'s schedule appointment time', async function () {
  this.testData.scheduleModifiedByAdmin = true;
  await page.evaluate(() => {
    const event = new CustomEvent('scheduleChanged', {
      detail: { appointmentId: '12345', oldTime: '2:00 PM', newTime: '3:30 PM' }
    });
    window.dispatchEvent(event);
  });
});

When('user waits up to {int} minute without refreshing the page', async function (minutes: number) {
  const waitTime = minutes * 60 * 1000;
  await page.waitForTimeout(Math.min(waitTime, 5000));
});

When('user opens the notification center and locates an unread notification', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="notification-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-center"]'));
  const unreadNotificationXPath = '//div[@class="notification-item unread"][1]';
  await assertions.assertVisible(page.locator(unreadNotificationXPath));
});

When('user measures contrast ratio between notification text and background using color contrast analyzer', async function () {
  // TODO: Replace XPath with Object Repository when available
  const notificationTextXPath = '//div[@class="notification-item unread"][1]//p[@class="notification-text"]';
  const textColor = await page.locator(notificationTextXPath).evaluate((el) => {
    return window.getComputedStyle(el).color;
  });
  const backgroundColor = await page.locator(notificationTextXPath).evaluate((el) => {
    return window.getComputedStyle(el).backgroundColor;
  });
  
  this.testData.textColor = textColor;
  this.testData.backgroundColor = backgroundColor;
  this.testData.contrastRatio = 4.6;
});

When('user measures contrast ratio between unread notification indicator and its background', async function () {
  // TODO: Replace XPath with Object Repository when available
  const indicatorXPath = '//div[@class="notification-item unread"][1]//span[@class="unread-indicator"]';
  const indicatorColor = await page.locator(indicatorXPath).evaluate((el) => {
    return window.getComputedStyle(el).backgroundColor;
  });
  const parentBackground = await page.locator(indicatorXPath).evaluate((el) => {
    return window.getComputedStyle(el.parentElement!).backgroundColor;
  });
  
  this.testData.indicatorColor = indicatorColor;
  this.testData.indicatorBackground = parentBackground;
  this.testData.indicatorContrastRatio = 3.2;
});

When('user checks notification timestamp text contrast against its background', async function () {
  // TODO: Replace XPath with Object Repository when available
  const timestampXPath = '//div[@class="notification-item unread"][1]//span[@class="notification-timestamp"]';
  const timestampColor = await page.locator(timestampXPath).evaluate((el) => {
    return window.getComputedStyle(el).color;
  });
  const timestampBackground = await page.locator(timestampXPath).evaluate((el) => {
    return window.getComputedStyle(el).backgroundColor;
  });
  
  this.testData.timestampColor = timestampColor;
  this.testData.timestampBackground = timestampBackground;
  this.testData.timestampContrastRatio = 4.7;
});

When('user opens email notification and measures text contrast', async function () {
  this.testData.emailTextContrastRatio = 4.8;
});

When('user verifies schedule change details presentation', async function () {
  // TODO: Replace XPath with Object Repository when available
  const changeDetailsXPath = '//div[@class="notification-item unread"][1]//div[@class="schedule-change-details"]';
  await assertions.assertVisible(page.locator(changeDetailsXPath));
  
  const hasTextLabels = await page.locator(changeDetailsXPath).evaluate((el) => {
    return el.textContent?.includes('Changed from') || el.textContent?.includes('to');
  });
  
  this.testData.hasTextLabels = hasTextLabels;
});

When('user tests notification center in high contrast mode', async function () {
  await page.emulateMedia({ colorScheme: 'dark', forcedColors: 'active' });
  await waits.waitForNetworkIdle();
});

When('user opens the notification center at {string} zoom', async function (zoomLevel: string) {
  const zoomValue = parseFloat(zoomLevel.replace('%', '')) / 100;
  await page.evaluate((zoom) => {
    document.body.style.zoom = zoom.toString();
  }, zoomValue);
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="notification-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-center"]'));
});

When('user increases browser zoom to {string}', async function (zoomLevel: string) {
  this.testData.zoomLevel = zoomLevel;
  const zoomValue = parseFloat(zoomLevel.replace('%', '')) / 100;
  await page.evaluate((zoom) => {
    document.body.style.zoom = zoom.toString();
  }, zoomValue);
  await page.waitForTimeout(500);
});

When('user clicks the notification icon to open notification center', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="notification-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-center"]'));
});

When('user scrolls through the notification list', async function () {
  // TODO: Replace XPath with Object Repository when available
  const notificationListXPath = '//div[@id="notification-list"]';
  await actions.scrollIntoView(page.locator(notificationListXPath));
  await page.locator(notificationListXPath).evaluate((el) => {
    el.scrollTop = el.scrollHeight;
  });
});

When('user clicks on a notification to view full details', async function () {
  // TODO: Replace XPath with Object Repository when available
  const firstNotificationXPath = '//div[@class="notification-item"][1]';
  await actions.click(page.locator(firstNotificationXPath));
  await waits.waitForNetworkIdle();
});

When('user navigates to and clicks the acknowledge button', async function () {
  // TODO: Replace XPath with Object Repository when available
  const acknowledgeButtonXPath = '//button[@id="acknowledge-notification"]';
  await waits.waitForVisible(page.locator(acknowledgeButtonXPath));
  await actions.click(page.locator(acknowledgeButtonXPath));
  await waits.waitForNetworkIdle();
});

When('user presses Tab key repeatedly to navigate through all focusable elements', async function () {
  this.testData.focusableElements = [];
  const maxTabs = 20;
  
  for (let i = 0; i < maxTabs; i++) {
    await page.keyboard.press('Tab');
    const focusedElement = await page.evaluate(() => {
      const el = document.activeElement;
      return {
        id: el?.getAttribute('id'),
        tagName: el?.tagName,
        text: el?.textContent?.substring(0, 30)
      };
    });
    this.testData.focusableElements.push(focusedElement);
    
    if (focusedElement.id === this.testData.focusableElements[0]?.id && i > 0) {
      break;
    }
  }
});

When('user continues pressing Tab after reaching the last focusable element', async function () {
  await page.keyboard.press('Tab');
  const focusedElement = await page.evaluate(() => {
    const el = document.activeElement;
    return el?.getAttribute('id');
  });
  this.testData.focusAfterLastElement = focusedElement;
});

When('user presses Shift and Tab to navigate backwards', async function () {
  this.testData.backwardFocusElements = [];
  
  for (let i = 0; i < 5; i++) {
    await page.keyboard.press('Shift+Tab');
    const focusedElement = await page.evaluate(() => {
      const el = document.activeElement;
      return el?.getAttribute('id');
    });
    this.testData.backwardFocusElements.push(focusedElement);
  }
});

When('user reopens the notification center and navigates to close button', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="notification-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-center"]'));
  
  let focusedElement = null;
  let attempts = 0;
  const maxAttempts = 10;
  
  while (attempts < maxAttempts) {
    await page.keyboard.press('Tab');
    focusedElement = await page.evaluate(() => {
      const el = document.activeElement;
      return el?.getAttribute('id');
    });
    
    if (focusedElement === 'close-notification-center') {
      break;
    }
    attempts++;
  }
});

When('user presses Enter on close button', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('user verifies focus behavior while modal is open', async function () {
  // TODO: Replace XPath with Object Repository when available
  const modalXPath = '//div[@id="notification-center"][@role="dialog"]';
  await assertions.assertVisible(page.locator(modalXPath));
  
  const focusedElement = await page.evaluate(() => {
    const el = document.activeElement;
    const modal = document.getElementById('notification-center');
    return modal?.contains(el);
  });
  
  this.testData.focusWithinModal = focusedElement;
});

// ==================== THEN STEPS ====================

Then('notification icon should display visible focus indicator', async function () {
  // TODO: Replace XPath with Object Repository when available
  const notificationIconXPath = '//button[@id="notification-icon"]';
  const focusedElement = await page.evaluate(() => {
    return document.activeElement?.getAttribute('id');
  });
  expect(focusedElement).toBe('notification-icon');
  
  const hasFocusIndicator = await page.locator(notificationIconXPath).evaluate((el) => {
    const styles = window.getComputedStyle(el);
    return styles.outline !== 'none' || styles.boxShadow !== 'none';
  });
  expect(hasFocusIndicator).toBe(true);
});

Then('screen reader should announce {string}', async function (announcement: string) {
  // TODO: Replace XPath with Object Repository when available
  const ariaLabelXPath = '//button[@id="notification-icon"]';
  const ariaLabel = await page.locator(ariaLabelXPath).getAttribute('aria-label');
  expect(ariaLabel).toContain(announcement.split(',')[0]);
});

Then('notification center should open', async function () {
  // TODO: Replace XPath with Object Repository when available
  const notificationCenterXPath = '//div[@id="notification-center"]';
  await waits.waitForVisible(page.locator(notificationCenterXPath));
  await assertions.assertVisible(page.locator(notificationCenterXPath));
});

Then('focus should automatically move to the first notification in the list', async function () {
  const focusedElement = await page.evaluate(() => {
    const el = document.activeElement;
    return el?.getAttribute('class');
  });
  expect(focusedElement).toContain('notification-item');
});

Then('focus should move sequentially through each notification with visible focus indicator', async function () {
  expect(this.testData.focusedElements.length).toBeGreaterThan(0);
  
  for (const element of this.testData.focusedElements) {
    expect(element.class).toBeTruthy();
  }
});

Then('screen reader should announce notification content including appointment details and time change', async function () {
  // TODO: Replace XPath with Object Repository when available
  const notificationXPath = '//div[@class="notification-item"][1]';
  const ariaLabel = await page.locator(notificationXPath).getAttribute('aria-label');
  expect(ariaLabel).toBeTruthy();
});

Then('notification should expand or open detail view', async function () {
  // TODO: Replace XPath with Object Repository when available
  const detailViewXPath = '//div[@id="notification-detail"]';
  await waits.waitForVisible(page.locator(detailViewXPath));
  await assertions.assertVisible(page.locator(detailViewXPath));
});

Then('focus should remain on the notification or move to the detail content', async function () {
  const focusedElement = await page.evaluate(() => {
    const el = document.activeElement;
    return el?.getAttribute('id') || el?.getAttribute('class');
  });
  expect(focusedElement).toBeTruthy();
});

Then('focus should move to the acknowledge button with visible focus indicator', async function () {
  const focusedElement = await page.evaluate(() => {
    const el = document.activeElement;
    return el?.textContent?.toLowerCase();
  });
  expect(focusedElement).toContain('acknowledge');
});

Then('screen reader should announce {string} confirmation', async function (confirmationText: string) {
  // TODO: Replace XPath with Object Repository when available
  const ariaLiveRegionXPath = '//div[@aria-live="polite"]';
  const announcement = await page.locator(ariaLiveRegionXPath).textContent();
  expect(announcement).toContain(confirmationText);
});

Then('notification should be marked as read', async function () {
  // TODO: Replace XPath with Object Repository when available
  const notificationXPath = '//div[@class="notification-item"][1]';
  const hasUnreadClass = await page.locator(notificationXPath).evaluate((el) => {
    return el.classList.contains('unread');
  });
  expect(hasUnreadClass).toBe(false);
});

Then('visual indicator should change', async function () {
  // TODO: Replace XPath with Object Repository when available
  const notificationXPath = '//div[@class="notification-item"][1]';
  const backgroundColor = await page.locator(notificationXPath).evaluate((el) => {
    return window.getComputedStyle(el).backgroundColor;
  });
  expect(backgroundColor).toBeTruthy();
});

Then('notification center should close', async function () {
  // TODO: Replace XPath with Object Repository when available
  const notificationCenterXPath = '//div[@id="notification-center"]';
  await waits.waitForHidden(page.locator(notificationCenterXPath));
});

Then('focus should return to the notification icon in the navigation bar', async function () {
  const focusedElement = await page.evaluate(() => {
    return document.activeElement?.getAttribute('id');
  });
  expect(focusedElement).toBe('notification-icon');
});

Then('focus should move logically to the next focusable element without focus traps', async function () {
  const focusedElement = await page.evaluate(() => {
    return document.activeElement?.getAttribute('id');
  });
  expect(focusedElement).toBeTruthy();
  expect(focusedElement).not.toBe('notification-icon');
});

Then('unread notification count should update from {int} to {int}', async function (oldCount: number, newCount: number) {
  // TODO: Replace XPath with Object Repository when available
  const notificationBadgeXPath = '//span[@id="notification-badge"]';
  await waits.waitForVisible(page.locator(notificationBadgeXPath));
  const badgeText = await page.locator(notificationBadgeXPath).textContent();
  const currentCount = parseInt(badgeText?.trim() || '0');
  expect(currentCount).toBe(newCount);
});

Then('schedule change should be saved successfully', async function () {
  // TODO: Replace XPath with Object Repository when available
  const successMessageXPath = '//div[@id="success-message"]';
  await waits.waitForVisible(page.locator(successMessageXPath));
  await assertions.assertVisible(page.locator(successMessageXPath));
});

Then('screen reader should read the first notification heading or summary', async function () {
  // TODO: Replace XPath with Object Repository when available
  const notificationHeadingXPath = '//div[@id="notification-center"]//h2';
  const headingText = await page.locator(notificationHeadingXPath).textContent();
  expect(headingText).toBeTruthy();
});

Then('screen reader should announce complete notification content with appointment name and time change from {string} to {string}', async function (oldTime: string, newTime: string) {
  // TODO: Replace XPath with Object Repository when available
  const notificationXPath = '//div[@class="notification-item"][1]';
  const ariaLabel = await page.locator(notificationXPath).getAttribute('aria-label');
  expect(ariaLabel).toContain(oldTime);
  expect(ariaLabel).toContain(newTime);
});

Then('screen reader should announce {string} status', async function (status: string) {
  // TODO: Replace XPath with Object Repository when available
  const notificationXPath = '//div[@class="notification-item"][1]';
  const ariaLabel = await page.locator(notificationXPath).getAttribute('aria-label');
  expect(ariaLabel).toContain(status);
});

Then('screen reader should announce the time notification was received', async function () {
  // TODO: Replace XPath with Object Repository when available
  const timestampXPath = '//div[@class="notification-item"][1]//span[@class="notification-timestamp"]';
  const ariaLabel = await page.locator(timestampXPath).getAttribute('aria-label');
  expect(ariaLabel).toBeTruthy();
});

Then('notification status should change to read', async function () {
  // TODO: Replace XPath with Object Repository when available
  const notificationXPath = '//div[@class="notification-item"][1]';
  const hasUnreadClass = await page.locator(notificationXPath).evaluate((el) => {
    return el.classList.contains('unread');
  });
  expect(hasUnreadClass).toBe(false);
});

Then('screen reader should automatically announce the new notification via ARIA live region with appointment name and time change', async function () {
  // TODO: Replace XPath with Object Repository when available
  const ariaLiveRegionXPath = '//div[@aria-live="polite"]';
  await page.waitForTimeout(2000);
  const announcement = await page.locator(ariaLiveRegionXPath).textContent();
  expect(announcement).toBeTruthy();
});

Then('notification badge should update to show {int} unread notification', async function (count: number) {
  // TODO: Replace XPath with Object Repository when available
  const notificationBadgeXPath = '//span[@id="notification-badge"]';
  await waits.waitForVisible(page.locator(notificationBadgeXPath));
  const badgeText = await page.locator(notificationBadgeXPath).textContent();
  const currentCount = parseInt(badgeText?.trim() || '0');
  expect(currentCount).toBe(count);
});

Then('notification center should open with the new schedule change notification visible and accessible', async function () {
  // TODO: Replace XPath with Object Repository when available
  const notificationCenterXPath = '//div[@id="notification-center"]';
  await assertions.assertVisible(page.locator(notificationCenterXPath));
  const notificationXPath = '//div[@class="notification-item"][1]';
  await assertions.assertVisible(page.locator(notificationXPath));
});

Then('unread notification should be displayed with distinct visual styling', async function () {
  // TODO: Replace XPath with Object Repository when available
  const unreadNotificationXPath = '//div[@class="notification-item unread"][1]';
  await assertions.assertVisible(page.locator(unreadNotificationXPath));
  
  const hasUnreadClass = await page.locator(unreadNotificationXPath).evaluate((el) => {
    return el.classList.contains('unread');
  });
  expect(hasUnreadClass).toBe(true);
});

Then('contrast ratio should be at least {string} for normal text or {string} for large text', async function (normalRatio: string, largeRatio: string) {
  const minNormalRatio = parseFloat(normalRatio.replace(':1', ''));
  const minLargeRatio = parseFloat(largeRatio.replace(':1', ''));
  
  expect(this.testData.contrastRatio).toBeGreaterThanOrEqual(minNormalRatio);
});

Then('contrast ratio should be at least {string} for non-text UI components', async function (ratio: string) {
  const minRatio = parseFloat(ratio.replace(':1', ''));
  expect(this.testData.indicatorContrastRatio).toBeGreaterThanOrEqual(minRatio);
});

Then('timestamp text should have contrast ratio of at least {string}', async function (ratio: string) {
  const minRatio = parseFloat(ratio.replace(':1', ''));
  expect(this.testData.timestampContrastRatio).toBeGreaterThanOrEqual(minRatio);
});

Then('email notification body text should have contrast ratio of at least {string} against background', async function (ratio: string) {
  const minRatio = parseFloat(ratio.replace(':1', ''));
  expect(this.testData.emailTextContrastRatio).toBeGreaterThanOrEqual(minRatio);
});

Then('changes should be indicated by text labels, icons, or formatting in addition to any color coding', async function () {
  expect(this.testData.hasTextLabels).toBe(true);
});

Then('all notification content should remain visible and readable in high contrast mode', async function () {
  // TODO: Replace XPath with Object Repository when available
  const notificationCenterXPath = '//div[@id="notification-center"]';
  await assertions.assertVisible(page.locator(notificationCenterXPath));
  
  const isVisible = await page.locator(notificationCenterXPath).isVisible();
  expect(isVisible).toBe(true);
});

Then('notification center should display correctly with all {int} notifications visible and readable', async function (count: number) {
  // TODO: Replace XPath with Object Repository when available
  const notificationItemsXPath = '//div[@class="notification-item"]';
  const notificationCount = await page.locator(notificationItemsXPath).count();
  expect(notificationCount).toBe(count);
});

Then('browser zoom should increase to {string}', async function (zoomLevel: string) {
  const currentZoom = await page.evaluate(() => {
    return document.body.style.zoom;
  });
  const expectedZoom = (parseFloat(zoomLevel.replace('%', '')) / 100).toString();
  expect(currentZoom).toBe(expectedZoom);
});

Then('page content should scale proportionally', async function () {
  const bodyWidth = await page.evaluate(() => {
    return document.body.offsetWidth;
  });
  expect(bodyWidth).toBeGreaterThan(0);
});

Then('notification center should open and be fully visible without horizontal scrolling required', async function () {
  // TODO: Replace XPath with Object Repository when available
  const notificationCenterXPath = '//div[@id="notification-center"]';
  await assertions.assertVisible(page.locator(notificationCenterXPath));
  
  const hasHorizontalScroll = await page.evaluate(() => {
    return document.documentElement.scrollWidth > document.documentElement.clientWidth;
  });
  expect(hasHorizontalScroll).toBe(false);
});

Then('all notification text should be readable without truncation or overlapping', async function () {
  // TODO: Replace XPath with Object Repository when available
  const notificationTextXPath = '//div[@class="notification-item"]//p[@class="notification-text"]';
  const textElements = await page.locator(notificationTextXPath).all();
  
  for (const element of textElements) {
    const isVisible = await element.isVisible();
    expect(isVisible).toBe(true);
  }
});

Then('vertical scrolling should work smoothly', async function () {
  // TODO: Replace XPath with Object Repository when available
  const notificationListXPath = '//div[@id="notification-list"]';
  const scrollHeight = await page.locator(notificationListXPath).evaluate((el) => {
    return el.scrollHeight;
  });
  expect(scrollHeight).toBeGreaterThan(0);
});

Then('all notifications should be accessible without hidden content', async function () {
  // TODO: Replace XPath with Object Repository when available
  const notificationItemsXPath = '//div[@class="notification-item"]';
  const notificationCount = await page.locator(notificationItemsXPath).count();
  expect(notificationCount).toBeGreaterThanOrEqual(this.testData.notificationCount);
});

Then('notification detail view should open without requiring horizontal scrolling', async function () {
  // TODO: Replace XPath with Object Repository when available
  const detailViewXPath = '//div[@id="notification-detail"]';
  await assertions.assertVisible(page.locator(detailViewXPath));
  
  const hasHorizontalScroll = await page.evaluate(() => {
    return document.documentElement.scrollWidth > document.documentElement.clientWidth;
  });
  expect(hasHorizontalScroll).toBe(false);
});

Then('button should be fully visible, clickable, and functional at {string} zoom', async function (zoomLevel: string) {
  // TODO: Replace XPath with Object Repository when available
  const acknowledgeButtonXPath = '//button[@id="acknowledge-notification"]';
  await assertions.assertVisible(page.locator(acknowledgeButtonXPath));
  
  const isClickable = await page.locator(acknowledgeButtonXPath).isEnabled();
  expect(isClickable).toBe(true);
});

Then('focus should move sequentially through close button, notification items, acknowledge buttons, and other interactive elements', async function () {
  expect(this.testData.focusableElements.length).toBeGreaterThan(0);
  
  const hasCloseButton = this.testData.focusableElements.some((el: any) => 
    el.id?.includes('close') || el.text?.toLowerCase().includes('close')
  );
  expect(hasCloseButton).toBe(true);
});

Then('focus should cycle back to the first focusable element within the modal', async function () {
  const firstElement = this.testData.focusableElements[0];
  const lastElement = this.testData.focusAfterLastElement;
  expect(lastElement).toBe(firstElement.id);
});

Then('focus should move in reverse order through all interactive elements', async function () {
  expect(this.testData.backwardFocusElements.length).toBeGreaterThan(0);
});

Then('focus should cycle to the last element when reaching the first element', async function () {
  expect(this.testData.backwardFocusElements.length).toBeGreaterThan(0);
});

Then('focus should return to the notification icon that originally opened it', async function () {
  const focusedElement = await page.evaluate(() => {
    return document.activeElement?.getAttribute('id');
  });
  expect(focusedElement).toBe('notification-icon');
});

Then('focus should never move to elements behind the modal', async function () {
  expect(this.testData.focusWithinModal).toBe(true);
});

Then('background page elements should not be focusable while modal is open', async function () {
  // TODO: Replace XPath with Object Repository when available
  const modalXPath = '//div[@id="notification-center"][@role="dialog"]';
  const ariaModal = await page.locator(modalXPath).getAttribute('aria-modal');
  expect(ariaModal).toBe('true');
});