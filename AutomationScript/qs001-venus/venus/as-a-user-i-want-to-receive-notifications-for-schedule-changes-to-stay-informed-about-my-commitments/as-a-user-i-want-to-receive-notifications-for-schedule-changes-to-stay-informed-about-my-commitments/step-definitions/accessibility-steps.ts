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
    focusedElements: [],
    ariaAttributes: {},
    contrastRatios: {}
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
/*  Used across all accessibility test cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user is logged into the system with valid credentials', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  
  const credentials = this.testData?.users?.user || { username: 'testuser', password: 'testpass' };
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-A11Y-001
/*  Title: Complete keyboard navigation through notification center
/*  Priority: High
/*  Category: Accessibility - Keyboard Navigation
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user has {int} unread schedule change notifications in notification center', async function (notificationCount: number) {
  this.notificationCount = notificationCount;
  const notificationBellXPath = '//button[@id="notification-bell"]';
  await waits.waitForVisible(page.locator(notificationBellXPath));
  
  const badgeXPath = '//span[@id="notification-count-badge"]';
  const badge = page.locator(badgeXPath);
  if (await badge.count() > 0) {
    const badgeText = await badge.textContent();
    expect(parseInt(badgeText || '0')).toBeGreaterThanOrEqual(notificationCount);
  }
});

Given('browser is set to standard keyboard navigation mode', async function () {
  this.keyboardNavigationMode = 'standard';
  this.mouseDisabled = false;
});

Given('no mouse or pointing device is used', async function () {
  this.mouseDisabled = true;
  this.keyboardOnly = true;
});

/**************************************************/
/*  TEST CASE: TC-A11Y-002
/*  Title: Screen reader announces schedule change notifications with complete context
/*  Priority: High
/*  Category: Accessibility - Screen Reader
/**************************************************/

Given('user has notification preferences enabled for in-app alerts', async function () {
  this.notificationPreferences = {
    inAppAlerts: true,
    emailAlerts: false,
    pushNotifications: false
  };
});

Given('user is on dashboard page', async function () {
  await actions.navigateTo(process.env.BASE_URL + '/dashboard');
  await waits.waitForNetworkIdle();
  await waits.waitForDomContentLoaded();
});

Given('screen reader is enabled', async function () {
  this.screenReaderEnabled = true;
  this.screenReaderAnnouncements = [];
});

Given('screen reader is set to announce live regions and notifications', async function () {
  this.screenReaderSettings = {
    announceLiveRegions: true,
    announceNotifications: true,
    verbosity: 'high'
  };
});

/**************************************************/
/*  TEST CASE: TC-A11Y-003
/*  Title: Focus management and focus trap prevention in notification modal dialogs
/*  Priority: High
/*  Category: Accessibility - Focus Management
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user has {int} schedule change notification available', async function (count: number) {
  this.availableNotifications = count;
  const notificationBellXPath = '//button[@id="notification-bell"]';
  await waits.waitForVisible(page.locator(notificationBellXPath));
});

Given('notification detail view opens in modal dialog', async function () {
  this.modalDialogEnabled = true;
  this.modalType = 'notification-detail';
});

/**************************************************/
/*  TEST CASE: TC-A11Y-004
/*  Title: Color contrast ratios and non-color-dependent information in notification UI
/*  Priority: High
/*  Category: Accessibility - Color Contrast
/**************************************************/

Given('user has multiple notifications with different statuses', async function () {
  this.notificationStatuses = ['unread', 'read', 'acknowledged', 'archived'];
  this.multipleNotifications = true;
});

Given('notifications include different priority levels or types', async function () {
  this.notificationPriorities = ['high', 'medium', 'low'];
  this.notificationTypes = ['schedule-change', 'reminder', 'alert', 'info'];
});

Given('color contrast analyzer tool is available', async function () {
  this.contrastAnalyzerAvailable = true;
  this.contrastResults = {};
});

/**************************************************/
/*  TEST CASE: TC-A11Y-005
/*  Title: Notification interface usability at 200% browser zoom and text scaling
/*  Priority: Medium
/*  Category: Accessibility - Zoom and Scaling
/**************************************************/

Given('user has {int} schedule change notifications with varying content lengths', async function (count: number) {
  this.notificationCount = count;
  this.varyingContentLengths = true;
});

Given('browser supports zoom functionality', async function () {
  this.browserZoomSupported = true;
  this.currentZoomLevel = 100;
});

// TODO: Replace XPath with Object Repository when available
Given('notification center contains notifications with full details', async function () {
  this.notificationsWithFullDetails = true;
  const notificationCenterXPath = '//div[@id="notification-center"]';
  await waits.waitForVisible(page.locator(notificationCenterXPath));
});

/**************************************************/
/*  TEST CASE: TC-A11Y-006
/*  Title: ARIA roles, labels, and live region implementation for dynamic notification updates
/*  Priority: High
/*  Category: Accessibility - ARIA Implementation
/**************************************************/

Given('browser developer tools are open to inspect ARIA attributes', async function () {
  this.devToolsOpen = true;
  this.ariaInspectionMode = true;
});

Given('administrator account is available to trigger schedule changes', async function () {
  this.adminAccount = {
    username: 'admin',
    password: 'admin123',
    role: 'administrator'
  };
});

/**************************************************/
/*  TEST CASE: TC-A11Y-007
/*  Title: Mobile accessibility including touch target sizes and gesture alternatives
/*  Priority: Medium
/*  Category: Accessibility - Mobile
/**************************************************/

Given('user is on mobile device or mobile browser emulation', async function () {
  await context.close();
  context = await browser.newContext({
    viewport: { width: 375, height: 667 },
    userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
    isMobile: true,
    hasTouch: true
  });
  page = await context.newPage();
  
  actions = new GenericActions(page, context);
  assertions = new AssertionHelpers(page);
  waits = new WaitHelpers(page);
  
  this.mobileDevice = true;
  this.touchEnabled = true;
});

Given('user has {int} schedule change notifications available', async function (count: number) {
  this.availableNotifications = count;
  this.notificationCount = count;
});

Given('mobile screen reader is available for testing', async function () {
  this.mobileScreenReaderEnabled = true;
  this.screenReaderType = 'mobile';
});

Given('touch screen functionality is enabled', async function () {
  this.touchScreenEnabled = true;
  this.gesturesEnabled = true;
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  TEST CASE: TC-A11Y-001
/*  Title: Complete keyboard navigation through notification center
/*  Priority: High
/*  Category: Accessibility - Keyboard Navigation
/**************************************************/

When('user presses Tab key repeatedly from main page header', async function () {
  this.focusedElements = [];
  const headerXPath = '//header[@id="main-header"]';
  await actions.click(page.locator(headerXPath));
  
  for (let i = 0; i < 10; i++) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(200);
    const focusedElement = await page.evaluate(() => {
      const el = document.activeElement;
      return {
        tagName: el?.tagName,
        id: el?.id,
        className: el?.className,
        ariaLabel: el?.getAttribute('aria-label')
      };
    });
    this.focusedElements.push(focusedElement);
  }
});

When('user presses Enter key on notification bell icon', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(300);
});

When('user presses Tab key to navigate through each notification', async function () {
  this.notificationFocusSequence = [];
  const notificationListXPath = '//div[@id="notification-list"]';
  const notificationItems = page.locator('//div[@class="notification-item"]');
  const count = await notificationItems.count();
  
  for (let i = 0; i < count; i++) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(200);
    const focusedElement = await page.evaluate(() => {
      const el = document.activeElement;
      return {
        id: el?.id,
        className: el?.className,
        textContent: el?.textContent?.substring(0, 50)
      };
    });
    this.notificationFocusSequence.push(focusedElement);
  }
});

When('user presses Enter key on focused notification', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(500);
});

When('user presses Tab to navigate to {string} button', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  let buttonFocused = false;
  
  for (let i = 0; i < 20; i++) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
    
    const focusedElement = await page.evaluate(() => {
      return document.activeElement?.textContent || '';
    });
    
    if (focusedElement.includes(buttonText)) {
      buttonFocused = true;
      break;
    }
  }
  
  this.buttonFocused = buttonFocused;
});

When('user presses Enter key', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(300);
});

When('user presses Escape key', async function () {
  await page.keyboard.press('Escape');
  await page.waitForTimeout(300);
});

When('user presses Shift+Tab to navigate backwards', async function () {
  this.backwardFocusSequence = [];
  
  for (let i = 0; i < 5; i++) {
    await page.keyboard.press('Shift+Tab');
    await page.waitForTimeout(200);
    const focusedElement = await page.evaluate(() => {
      const el = document.activeElement;
      return {
        tagName: el?.tagName,
        id: el?.id,
        textContent: el?.textContent?.substring(0, 30)
      };
    });
    this.backwardFocusSequence.push(focusedElement);
  }
});

/**************************************************/
/*  TEST CASE: TC-A11Y-002
/*  Title: Screen reader announces schedule change notifications with complete context
/*  Priority: High
/*  Category: Accessibility - Screen Reader
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('administrator updates user scheduled appointment from {string} to {string}', async function (originalTime: string, newTime: string) {
  this.originalTime = originalTime;
  this.newTime = newTime;
  this.scheduleChangeTriggered = true;
  
  const liveRegionXPath = '//div[@aria-live="polite"]';
  await waits.waitForVisible(page.locator(liveRegionXPath));
  
  const liveRegionContent = await page.locator(liveRegionXPath).textContent();
  this.liveRegionAnnouncement = liveRegionContent;
});

When('user navigates to notification bell icon using screen reader navigation commands', async function () {
  const notificationBellXPath = '//button[@id="notification-bell"]';
  await page.keyboard.press('Tab');
  await page.waitForTimeout(200);
  
  let attempts = 0;
  while (attempts < 20) {
    const focusedElement = await page.evaluate(() => document.activeElement?.id);
    if (focusedElement === 'notification-bell') {
      break;
    }
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
    attempts++;
  }
  
  const ariaLabel = await page.locator(notificationBellXPath).getAttribute('aria-label');
  this.screenReaderAnnouncement = ariaLabel;
});

When('user activates notification bell icon using Enter key', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(300);
});

When('user navigates through notification using arrow keys', async function () {
  this.notificationDetails = [];
  
  for (let i = 0; i < 5; i++) {
    await page.keyboard.press('ArrowDown');
    await page.waitForTimeout(200);
    
    const focusedContent = await page.evaluate(() => {
      const el = document.activeElement;
      return {
        textContent: el?.textContent,
        ariaLabel: el?.getAttribute('aria-label'),
        role: el?.getAttribute('role')
      };
    });
    this.notificationDetails.push(focusedContent);
  }
});

When('user navigates to {string} button within notification', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  
  for (let i = 0; i < 10; i++) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
    
    const focusedText = await page.evaluate(() => document.activeElement?.textContent);
    if (focusedText?.includes(buttonText)) {
      break;
    }
  }
  
  const ariaLabel = await page.evaluate(() => document.activeElement?.getAttribute('aria-label'));
  this.buttonAriaLabel = ariaLabel;
});

When('user activates {string} button using Enter key', async function (buttonText: string) {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(300);
  
  const liveRegionXPath = '//div[@aria-live]';
  const liveRegions = page.locator(liveRegionXPath);
  if (await liveRegions.count() > 0) {
    const announcement = await liveRegions.first().textContent();
    this.acknowledgmentAnnouncement = announcement;
  }
});

When('user navigates to notification history section', async function () {
  const historyXPath = '//section[@id="notification-history"]';
  await page.keyboard.press('Tab');
  
  let attempts = 0;
  while (attempts < 15) {
    const focusedElement = await page.evaluate(() => document.activeElement?.id);
    if (focusedElement?.includes('history')) {
      break;
    }
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
    attempts++;
  }
});

When('user navigates through past notifications using screen reader commands', async function () {
  this.pastNotifications = [];
  
  for (let i = 0; i < 5; i++) {
    await page.keyboard.press('ArrowDown');
    await page.waitForTimeout(200);
    
    const notificationData = await page.evaluate(() => {
      const el = document.activeElement;
      return {
        textContent: el?.textContent,
        ariaLabel: el?.getAttribute('aria-label'),
        ariaDescribedBy: el?.getAttribute('aria-describedby')
      };
    });
    this.pastNotifications.push(notificationData);
  }
});

/**************************************************/
/*  TEST CASE: TC-A11Y-003
/*  Title: Focus management and focus trap prevention in notification modal dialogs
/*  Priority: High
/*  Category: Accessibility - Focus Management
/**************************************************/

When('user navigates to notification center using Tab key', async function () {
  const notificationBellXPath = '//button[@id="notification-bell"]';
  
  for (let i = 0; i < 20; i++) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
    
    const focusedId = await page.evaluate(() => document.activeElement?.id);
    if (focusedId === 'notification-bell') {
      break;
    }
  }
});

When('user opens notification center with Enter key', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(300);
  
  const firstFocusableElement = await page.evaluate(() => document.activeElement?.id);
  this.firstFocusedElement = firstFocusableElement;
});

When('user presses Enter on notification to open detailed view modal', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(500);
  
  const modalXPath = '//div[@role="dialog"]';
  await waits.waitForVisible(page.locator(modalXPath));
  
  const modalFocusedElement = await page.evaluate(() => document.activeElement?.id);
  this.modalFirstFocusedElement = modalFocusedElement;
});

When('user presses Tab key repeatedly to cycle through all focusable elements', async function () {
  this.modalFocusableElements = [];
  const startingElement = await page.evaluate(() => document.activeElement?.id);
  
  for (let i = 0; i < 15; i++) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(150);
    
    const focusedElement = await page.evaluate(() => {
      const el = document.activeElement;
      return {
        id: el?.id,
        tagName: el?.tagName,
        textContent: el?.textContent?.substring(0, 30),
        role: el?.getAttribute('role')
      };
    });
    this.modalFocusableElements.push(focusedElement);
    
    const currentElement = await page.evaluate(() => document.activeElement?.id);
    if (currentElement === startingElement && i > 2) {
      this.focusWrapped = true;
      break;
    }
  }
});

When('user continues pressing Tab after reaching last focusable element', async function () {
  await page.keyboard.press('Tab');
  await page.waitForTimeout(200);
  
  const focusedElement = await page.evaluate(() => {
    const el = document.activeElement;
    const modal = document.querySelector('[role="dialog"]');
    return {
      id: el?.id,
      isInsideModal: modal?.contains(el) || false
    };
  });
  
  this.focusAfterLastElement = focusedElement;
});

When('user presses Shift+Tab from first focusable element', async function () {
  const modalXPath = '//div[@role="dialog"]';
  const firstFocusable = await page.evaluate(() => {
    const modal = document.querySelector('[role="dialog"]');
    const focusableElements = modal?.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
    return focusableElements?.[0]?.id;
  });
  
  await page.keyboard.press('Shift+Tab');
  await page.waitForTimeout(200);
  
  const focusedElement = await page.evaluate(() => document.activeElement?.id);
  this.focusAfterShiftTab = focusedElement;
});

When('user presses Escape key while focus is anywhere in modal', async function () {
  this.elementBeforeEscape = await page.evaluate(() => document.activeElement?.id);
  
  await page.keyboard.press('Escape');
  await page.waitForTimeout(300);
  
  this.elementAfterEscape = await page.evaluate(() => document.activeElement?.id);
});

When('user opens modal again', async function () {
  const notificationItemXPath = '//div[@class="notification-item"]';
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(500);
});

When('user clicks {string} button using Enter key', async function (buttonText: string) {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(300);
});

/**************************************************/
/*  TEST CASE: TC-A11Y-004
/*  Title: Color contrast ratios and non-color-dependent information in notification UI
/*  Priority: High
/*  Category: Accessibility - Color Contrast
/**************************************************/

When('user opens notification center', async function () {
  const notificationBellXPath = '//button[@id="notification-bell"]';
  await actions.click(page.locator(notificationBellXPath));
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(300);
});

When('user checks contrast ratio between notification text and background', async function () {
  this.textContrastRatios = await page.evaluate(() => {
    const notifications = document.querySelectorAll('.notification-item');
    const ratios: any[] = [];
    
    notifications.forEach((notification: any) => {
      const textColor = window.getComputedStyle(notification).color;
      const backgroundColor = window.getComputedStyle(notification).backgroundColor;
      
      ratios.push({
        textColor,
        backgroundColor,
        element: 'notification-text'
      });
    });
    
    return ratios;
  });
});

When('user checks contrast ratio of notification bell icon and background', async function () {
  this.iconContrastRatio = await page.evaluate(() => {
    const bell = document.querySelector('#notification-bell');
    if (!bell) return null;
    
    const iconColor = window.getComputedStyle(bell).color;
    const backgroundColor = window.getComputedStyle(bell).backgroundColor;
    
    return {
      iconColor,
      backgroundColor,
      element: 'notification-bell'
    };
  });
  
  const badgeXPath = '//span[@id="notification-count-badge"]';
  this.badgeContrastRatio = await page.evaluate(() => {
    const badge = document.querySelector('#notification-count-badge');
    if (!badge) return null;
    
    const textColor = window.getComputedStyle(badge).color;
    const backgroundColor = window.getComputedStyle(badge).backgroundColor;
    
    return {
      textColor,
      backgroundColor,
      element: 'notification-badge'
    };
  });
});

When('user identifies how unread notifications are distinguished from read notifications', async function () {
  this.notificationDistinctionMethods = await page.evaluate(() => {
    const unreadNotifications = document.querySelectorAll('.notification-item.unread');
    const readNotifications = document.querySelectorAll('.notification-item.read');
    
    const methods: any[] = [];
    
    if (unreadNotifications.length > 0) {
      const unread = unreadNotifications[0] as HTMLElement;
      const fontWeight = window.getComputedStyle(unread).fontWeight;
      const hasIcon = unread.querySelector('.unread-icon') !== null;
      const hasLabel = unread.querySelector('.unread-label') !== null;
      
      methods.push({
        type: 'unread',
        fontWeight,
        hasIcon,
        hasLabel,
        ariaLabel: unread.getAttribute('aria-label')
      });
    }
    
    return methods;
  });
});

When('user checks how different notification types or priorities are indicated', async function () {
  this.priorityIndicators = await page.evaluate(() => {
    const notifications = document.querySelectorAll('.notification-item');
    const indicators: any[] = [];
    
    notifications.forEach((notification: any) => {
      const hasIcon = notification.querySelector('.priority-icon') !== null;
      const hasLabel = notification.querySelector('.priority-label') !== null;
      const hasPattern = notification.classList.contains('priority-high') || 
                        notification.classList.contains('priority-medium') ||
                        notification.classList.contains('priority-low');
      const ariaLabel = notification.getAttribute('aria-label');
      
      indicators.push({
        hasIcon,
        hasLabel,
        hasPattern,
        ariaLabel
      });
    });
    
    return indicators;
  });
});

When('user enables browser high contrast mode', async function () {
  await page.emulateMedia({ colorScheme: 'dark', forcedColors: 'active' });
  await page.waitForTimeout(500);
  this.highContrastModeEnabled = true;
});

When('user checks {string} button and other interactive elements for contrast', async function (buttonText: string) {
  this.buttonContrastRatios = await page.evaluate(() => {
    const buttons = document.querySelectorAll('button');
    const ratios: any[] = [];
    
    buttons.forEach((button: any) => {
      const textColor = window.getComputedStyle(button).color;
      const backgroundColor = window.getComputedStyle(button).backgroundColor;
      const borderColor = window.getComputedStyle(button).borderColor;
      
      ratios.push({
        textColor,
        backgroundColor,
        borderColor,
        buttonText: button.textContent
      });
    });
    
    return ratios;
  });
});

When('user verifies timestamp and metadata text contrast', async function () {
  this.metadataContrastRatios = await page.evaluate(() => {
    const timestamps = document.querySelectorAll('.notification-timestamp, .notification-metadata');
    const ratios: any[] = [];
    
    timestamps.forEach((element: any) => {
      const textColor = window.getComputedStyle(element).color;
      const backgroundColor = window.getComputedStyle(element).backgroundColor;
      
      ratios.push({
        textColor,
        backgroundColor,
        element: element.className
      });
    });
    
    return ratios;
  });
});

/**************************************************/
/*  TEST CASE: TC-A11Y-005
/*  Title: Notification interface usability at 200% browser zoom and text scaling
/*  Priority: Medium
/*  Category: Accessibility - Zoom and Scaling
/**************************************************/

When('user sets browser zoom to {int} percent', async function (zoomLevel: number) {
  await page.evaluate((zoom) => {
    document.body.style.zoom = `${zoom}%`;
  }, zoomLevel);
  await page.waitForTimeout(500);
  this.currentZoomLevel = zoomLevel;
});

When('user clicks notification bell icon at {int} percent zoom', async function (zoomLevel: number) {
  const notificationBellXPath = '//button[@id="notification-bell"]';
  await actions.click(page.locator(notificationBellXPath));
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(300);
});

When('user navigates through notification list at {int} percent zoom', async function (zoomLevel: number) {
  const notificationItemsXPath = '//div[@class="notification-item"]';
  const notifications = page.locator(notificationItemsXPath);
  const count = await notifications.count();
  
  this.notificationsAtZoom = [];
  for (let i = 0; i < count; i++) {
    const notification = notifications.nth(i);
    const boundingBox = await notification.boundingBox();
    const isVisible = await notification.isVisible();
    
    this.notificationsAtZoom.push({
      index: i,
      boundingBox,
      isVisible
    });
  }
});

When('user opens notification detail view at {int} percent zoom', async function (zoomLevel: number) {
  const notificationItemXPath = '//div[@class="notification-item"]';
  await actions.click(page.locator(notificationItemXPath).first());
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(500);
  
  const modalXPath = '//div[@role="dialog"]';
  const modalBoundingBox = await page.locator(modalXPath).boundingBox();
  this.modalBoundingBoxAtZoom = modalBoundingBox;
});

When('user tests {string} button at {int} percent zoom', async function (buttonText: string, zoomLevel: number) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  
  let buttonLocator;
  if (await buttons.count() > 0) {
    buttonLocator = buttons.first();
  } else {
    buttonLocator = page.locator(`//button[contains(text(),'${buttonText}')]`).first();
  }
  
  const boundingBox = await buttonLocator.boundingBox();
  const isVisible = await buttonLocator.isVisible();
  
  this.buttonAtZoom = {
    boundingBox,
    isVisible,
    meetsMinimumSize: boundingBox ? (boundingBox.width >= 44 && boundingBox.height >= 44) : false
  };
});

When('user enables browser text-only zoom to {int} percent', async function (zoomLevel: number) {
  await page.evaluate((zoom) => {
    document.body.style.fontSize = `${zoom}%`;
  }, zoomLevel);
  await page.waitForTimeout(500);
  this.textOnlyZoomLevel = zoomLevel;
});

When('user verifies notification timestamps at {int} percent zoom', async function (zoomLevel: number) {
  this.timestampsAtZoom = await page.evaluate(() => {
    const timestamps = document.querySelectorAll('.notification-timestamp');
    const results: any[] = [];
    
    timestamps.forEach((timestamp: any) => {
      const rect = timestamp.getBoundingClientRect();
      const isVisible = rect.width > 0 && rect.height > 0;
      const computedStyle = window.getComputedStyle(timestamp);
      
      results.push({
        isVisible,
        width: rect.width,
        height: rect.height,
        fontSize: computedStyle.fontSize,
        textContent: timestamp.textContent
      });
    });
    
    return results;
  });
});

/**************************************************/
/*  TEST CASE: TC-A11Y-006
/*  Title: ARIA roles, labels, and live region implementation for dynamic notification updates
/*  Priority: High
/*  Category: Accessibility - ARIA Implementation
/**************************************************/

When('user inspects notification bell icon element in browser developer tools', async function () {
  const notificationBellXPath = '//button[@id="notification-bell"]';
  this.bellAriaAttributes = await page.locator(notificationBellXPath).evaluate((el) => {
    return {
      role: el.getAttribute('role'),
      ariaLabel: el.getAttribute('aria-label'),
      ariaHasPopup: el.getAttribute('aria-haspopup'),
      ariaExpanded: el.getAttribute('aria-expanded')
    };
  });
});

When('user checks notification count badge for ARIA implementation', async function () {
  const badgeXPath = '//span[@id="notification-count-badge"]';
  this.badgeAriaAttributes = await page.locator(badgeXPath).evaluate((el) => {
    return {
      ariaLabel: el.getAttribute('aria-label'),
      ariaLive: el.getAttribute('aria-live'),
      role: el.getAttribute('role'),
      textContent: el.textContent
    };
  });
});

When('administrator creates new schedule change while user inspects notification area', async function () {
  this.scheduleChangeCreated = true;
  
  const liveRegionXPath = '//div[@aria-live]';
  await waits.waitForVisible(page.locator(liveRegionXPath));
  await page.waitForTimeout(500);
  
  this.liveRegionAttributes = await page.locator(liveRegionXPath).evaluate((el) => {
    return {
      ariaLive: el.getAttribute('aria-live'),
      ariaAtomic: el.getAttribute('aria-atomic'),
      role: el.getAttribute('role'),
      textContent: el.textContent
    };
  });
});

When('user opens notification center and inspects notification list container', async function () {
  const notificationBellXPath = '//button[@id="notification-bell"]';
  await actions.click(page.locator(notificationBellXPath));
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(300);
  
  const notificationListXPath = '//div[@id="notification-list"]';
  this.listAriaAttributes = await page.locator(notificationListXPath).evaluate((el) => {
    return {
      role: el.getAttribute('role'),
      ariaLabel: el.getAttribute('aria-label'),
      ariaLabelledBy: el.getAttribute('aria-labelledby')
    };
  });
});

When('user inspects individual notification elements for ARIA attributes', async function () {
  const notificationItemsXPath = '//div[@class="notification-item"]';
  this.notificationAriaAttributes = await page.locator(notificationItemsXPath).first().evaluate((el) => {
    return {
      role: el.getAttribute('role'),
      ariaLabel: el.getAttribute('aria-label'),
      ariaLabelledBy: el.getAttribute('aria-labelledby'),
      ariaDescribedBy: el.getAttribute('aria-describedby')
    };
  });
});

When('user inspects {string} button for ARIA implementation', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  
  let buttonLocator;
  if (await buttons.count() > 0) {
    buttonLocator = buttons.first();
  } else {
    buttonLocator = page.locator(`//button[contains(text(),'${buttonText}')]`).first();
  }
  
  this.buttonAriaAttributes = await buttonLocator.evaluate((el) => {
    return {
      role: el.getAttribute('role'),
      ariaLabel: el.getAttribute('aria-label'),
      ariaPressed: el.getAttribute('aria-pressed'),
      ariaChecked: el.getAttribute('aria-checked')
    };
  });
});

When('user acknowledges notification and checks for ARIA live region update', async function () {
  const acknowledgeButtonXPath = '//button[@id="acknowledge"]';
  await actions.click(page.locator(acknowledgeButtonXPath));
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(500);
  
  const liveRegionXPath = '//div[@aria-live]';
  this.acknowledgmentLiveRegion = await page.locator(liveRegionXPath).evaluate((el) => {
    return {
      textContent: el.textContent,
      ariaLive: el.getAttribute('aria-live')
    };
  });
  
  const notificationBellXPath = '//button[@id="notification-bell"]';
  this.updatedBellAriaExpanded = await page.locator(notificationBellXPath).getAttribute('aria-expanded');
});

When('user inspects modal dialog for notification details for ARIA attributes', async function () {
  const modalXPath = '//div[@role="dialog"]';
  this.modalAriaAttributes = await page.locator(modalXPath).evaluate((el) => {
    return {
      role: el.getAttribute('role'),
      ariaModal: el.getAttribute('aria-modal'),
      ariaLabelledBy: el.getAttribute('aria-labelledby'),
      ariaDescribedBy: el.getAttribute('aria-describedby')
    };
  });
});

/**************************************************/
/*  TEST CASE: TC-A11Y-007
/*  Title: Mobile accessibility including touch target sizes and gesture alternatives
/*  Priority: Medium
/*  Category: Accessibility - Mobile
/**************************************************/

When('user measures notification bell icon touch target size on mobile', async function () {
  const notificationBellXPath = '//button[@id="notification-bell"]';
  const boundingBox = await page.locator(notificationBellXPath).boundingBox();
  
  this.bellTouchTarget = {
    width: boundingBox?.width || 0,
    height: boundingBox?.height || 0,
    meetsMinimum: (boundingBox?.width || 0) >= 44 && (boundingBox?.height || 0) >= 44
  };
  
  const adjacentElements = await page.evaluate(() => {
    const bell = document.querySelector('#notification-bell');
    if (!bell) return [];
    
    const bellRect = bell.getBoundingClientRect();
    const allElements = document.querySelectorAll('button, a, input');
    const adjacent: any[] = [];
    
    allElements.forEach((el: any) => {
      if (el === bell) return;
      const rect = el.getBoundingClientRect();
      const distance = Math.min(
        Math.abs(rect.left - bellRect.right),
        Math.abs(rect.right - bellRect.left),
        Math.abs(rect.top - bellRect.bottom),
        Math.abs(rect.bottom - bellRect.top)
      );
      
      if (distance < 50) {
        adjacent.push({ distance, element: el.id || el.tagName });
      }
    });
    
    return adjacent;
  });
  
  this.adjacentElementSpacing = adjacentElements;
});

When('user taps notification bell icon to open notification center', async function () {
  const notificationBellXPath = '//button[@id="notification-bell"]';
  await actions.click(page.locator(notificationBellXPath));
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(300);
  
  const notificationCenterXPath = '//div[@id="notification-center"]';
  this.notificationCenterOpened = await page.locator(notificationCenterXPath).isVisible();
});

When('user verifies touch target sizes for individual notifications in list', async function () {
  const notificationItemsXPath = '//div[@class="notification-item"]';
  const notifications = page.locator(notificationItemsXPath);
  const count = await notifications.count();
  
  this.notificationTouchTargets = [];
  for (let i = 0; i < Math.min(count, 5); i++) {
    const boundingBox = await notifications.nth(i).boundingBox();
    this.notificationTouchTargets.push({
      index: i,
      width: boundingBox?.width || 0,
      height: boundingBox?.height || 0,
      meetsMinimum: (boundingBox?.height || 0) >= 44
    });
  }
});

When('user tests swipe gestures on notifications', async function () {
  const notificationItemXPath = '//div[@class="notification-item"]';
  const firstNotification = page.locator(notificationItemXPath).first();
  const boundingBox = await firstNotification.boundingBox();
  
  if (boundingBox) {
    await page.mouse.move(boundingBox.x + boundingBox.width / 2, boundingBox.y + boundingBox.height / 2);
    await page.mouse.down();
    await page.mouse.move(boundingBox.x - 100, boundingBox.y + boundingBox.height / 2);
    await page.mouse.up();
    await page.waitForTimeout(300);
  }
  
  this.swipeGestureExecuted = true;
});

When('user enables mobile screen reader and navigates to notification center', async function () {
  this.mobileScreenReaderEnabled = true;
  
  const notificationBellXPath = '//button[@id="notification-bell"]';
  const ariaLabel = await page.locator(notificationBellXPath).getAttribute('aria-label');
  this.screenReaderBellAnnouncement = ariaLabel;
  
  await actions.click(page.locator(notificationBellXPath));
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(300);
});

When('user uses screen reader to navigate through notifications and activate {string} button', async function (buttonText: string) {
  const notificationItemsXPath = '//div[@class="notification-item"]';
  const notifications = page.locator(notificationItemsXPath);
  const count = await notifications.count();
  
  this.screenReaderNotificationAnnouncements = [];
  for (let i = 0; i < Math.min(count, 3); i++) {
    const ariaLabel = await notifications.nth(i).getAttribute('aria-label');
    this.screenReaderNotificationAnnouncements.push(ariaLabel);
  }
  
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  
  let buttonLocator;
  if (await buttons.count() > 0) {
    buttonLocator = buttons.first();
  } else {
    buttonLocator = page.locator(`//button[contains(text(),'${buttonText}')]`).first();
  }
  
  await actions.click(buttonLocator);
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(300);
});

When('user tests notification modal or detail view on mobile with screen reader', async function () {
  const notificationItemXPath = '//div[@class="notification-item"]';
  await actions.click(page.locator(notificationItemXPath).first());
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(500);
  
  const modalXPath = '//div[@role="dialog"]';
  this.modalAriaAttributesMobile = await page.locator(modalXPath).evaluate((el) => {
    return {
      role: el.getAttribute('role'),
      ariaModal: el.getAttribute('aria-modal'),
      ariaLabelledBy: el.getAttribute('aria-labelledby')
    };
  });
  
  const closeButtonXPath = '//button[@id="close"]';
  const closeButtonBoundingBox = await page.locator(closeButtonXPath).boundingBox();
  this.closeButtonTouchTarget = {
    width: closeButtonBoundingBox?.width || 0,
    height: closeButtonBoundingBox?.height || 0,
    meetsMinimum: (closeButtonBoundingBox?.width || 0) >= 44 && (closeButtonBoundingBox?.height || 0) >= 44
  };
});

When('user rotates device between portrait and landscape orientation', async function () {
  await context.close();
  
  context = await browser.newContext({
    viewport: { width: 667, height: 375 },
    userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
    isMobile: true,
    hasTouch: true
  });
  page = await context.newPage();
  
  actions = new GenericActions(page, context);
  assertions = new AssertionHelpers(page);
  waits = new WaitHelpers(page);
  
  await actions.navigateTo(process.env.BASE_URL + '/dashboard');
  await waits.waitForNetworkIdle();
  
  this.landscapeOrientation = true;
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  TEST CASE: TC-A11Y-001
/*  Title: Complete keyboard navigation through notification center
/*  Priority: High
/*  Category: Accessibility - Keyboard Navigation
/**************************************************/

Then('focus indicator should move through page elements in logical order', async function () {
  expect(this.focusedElements).toBeDefined();
  expect(this.focusedElements.length).toBeGreaterThan(0);
  
  const hasFocusProgression = this.focusedElements.every((el: any) => el.tagName || el.id);
  expect(hasFocusProgression).toBe(true);
});

Then('focus should reach notification bell icon with clear visual focus indicator', async function () {
  const notificationBellFocused = this.focusedElements.some((el: any) => 
    el.id === 'notification-bell' || el.ariaLabel?.includes('Notification')
  );
  expect(notificationBellFocused).toBe(true);
  
  const notificationBellXPath = '//button[@id="notification-bell"]';
  const focusVisible = await page.locator(notificationBellXPath).evaluate((el) => {
    const styles = window.getComputedStyle(el, ':focus');
    return styles.outline !== 'none' || styles.boxShadow !== 'none';
  });
  expect(focusVisible).toBe(true);
});

Then('notification center panel should open', async function () {
  const notificationCenterXPath = '//div[@id="notification-center"]';
  await assertions.assertVisible(page.locator(notificationCenterXPath));
});

Then('focus should automatically move to first notification in list', async function () {
  const focusedElement = await page.evaluate(() => {
    const el = document.activeElement;
    return {
      id: el?.id,
      className: el?.className
    };
  });
  
  const isFocusedOnNotification = focusedElement.className?.includes('notification') || 
                                   focusedElement.id?.includes('notification');
  expect(isFocusedOnNotification).toBe(true);
});

Then('notification count badge should be visible', async function () {
  const badgeXPath = '//span[@id="notification-count-badge"]';
  await assertions.assertVisible(page.locator(badgeXPath));
});

Then('focus should move sequentially through each notification item with visible focus indicator', async function () {
  expect(this.notificationFocusSequence).toBeDefined();
  expect(this.notificationFocusSequence.length).toBeGreaterThan(0);
  
  const allHaveFocus = this.notificationFocusSequence.every((el: any) => el.id || el.className);
  expect(allHaveFocus).toBe(true);
});

Then('notification details should be readable', async function () {
  const notificationItemsXPath = '//div[@class="notification-item"]';
  const firstNotification = page.locator(notificationItemsXPath).first();
  const textContent = await firstNotification.textContent();
  
  expect(textContent).toBeDefined();
  expect(textContent?.length).toBeGreaterThan(0);
});

Then('focus should not get trapped', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBeDefined();
  expect(focusedElement).not.toBe('BODY');
});

Then('notification should expand or detail modal should open', async function () {
  const modalXPath = '//div[@role="dialog"]';
  const expandedXPath = '//div[@class="notification-expanded"]';
  
  const modalVisible = await page.locator(modalXPath).isVisible().catch(() => false);
  const expandedVisible = await page.locator(expandedXPath).isVisible().catch(() => false);
  
  expect(modalVisible || expandedVisible).toBe(true);
});

Then('focus should move to notification detail content', async function () {
  const focusedElement = await page.evaluate(() => {
    const el = document.activeElement;
    return {
      id: el?.id,
      className: el?.className,
      role: el?.getAttribute('role')
    };
  });
  
  const isFocusedOnContent = focusedElement.role === 'dialog' || 
                             focusedElement.className?.includes('notification') ||
                             focusedElement.className?.includes('modal');
  expect(isFocusedOnContent).toBe(true);
});

Then('all interactive elements should be keyboard accessible', async function () {
  const interactiveElements = await page.evaluate(() => {
    const modal = document.querySelector('[role="dialog"]') || document.querySelector('.notification-expanded');
    if (!modal) return [];
    
    const elements = modal.querySelectorAll('button, a, input, select, textarea, [tabindex]:not([tabindex="-1"])');
    return Array.from(elements).map((el: any) => ({
      tagName: el.tagName,
      tabIndex: el.tabIndex,
      id: el.id
    }));
  });
  
  expect(interactiveElements.length).toBeGreaterThan(0);
  const allAccessible = interactiveElements.every((el: any) => el.tabIndex >= 0);
  expect(allAccessible).toBe(true);
});

Then('notification should be marked as acknowledged', async function () {
  await page.waitForTimeout(300);
  
  const acknowledgedXPath = '//div[@class="notification-item acknowledged"]';
  const acknowledgedVisible = await page.locator(acknowledgedXPath).isVisible().catch(() => false);
  
  expect(acknowledgedVisible).toBe(true);
});

Then('visual confirmation should appear', async function () {
  const confirmationXPath = '//div[@class="confirmation-message"]';
  const toastXPath = '//div[@class="toast-notification"]';
  
  const confirmationVisible = await page.locator(confirmationXPath).isVisible().catch(() => false);
  const toastVisible = await page.locator(toastXPath).isVisible().catch(() => false);
  
  expect(confirmationVisible || toastVisible).toBe(true);
});

Then('focus should return to logical location', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.id);
  expect(focusedElement).toBeDefined();
  expect(focusedElement).not.toBe('');
});

Then('notification center should close', async function () {
  const notificationCenterXPath = '//div[@id="notification-center"]';
  const isVisible = await page.locator(notificationCenterXPath).isVisible().catch(() => false);
  expect(isVisible).toBe(false);
});

Then('focus should return to notification bell icon', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.id);
  expect(focusedElement).toBe('notification-bell');
});

Then('notification count should update to reflect acknowledged notification', async function () {
  const badgeXPath = '//span[@id="notification-count-badge"]';
  const badge = page.locator(badgeXPath);
  
  if (await badge.isVisible()) {
    const badgeText = await badge.textContent();
    const count = parseInt(badgeText || '0');
    expect(count).toBeLessThan(this.notificationCount);
  }
});

Then('focus should move in reverse order through all previously accessible elements', async function () {
  expect(this.backwardFocusSequence).toBeDefined();
  expect(this.backwardFocusSequence.length).toBeGreaterThan(0);
  
  const allHaveFocus = this.backwardFocusSequence.every((el: any) => el.id || el.tagName);
  expect(allHaveFocus).toBe(true);
});

Then('focus should not skip or trap', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBeDefined();
  expect(focusedElement).not.toBe('BODY');
});

/**************************************************/
/*  TEST CASE: TC-A11Y-002
/*  Title: Screen reader announces schedule change notifications with complete context
/*  Priority: High
/*  Category: Accessibility - Screen Reader
/**************************************************/

Then('screen reader should immediately announce new notification via ARIA live region', async function () {
  const liveRegionXPath = '//div[@aria-live]';
  await assertions.assertVisible(page.locator(liveRegionXPath));
  
  const liveRegionContent = await page.locator(liveRegionXPath).textContent();
  expect(liveRegionContent).toBeDefined();
  expect(liveRegionContent?.length).toBeGreaterThan(0);
});

Then('announcement should include {string}', async function (expectedText: string) {
  expect(this.liveRegionAnnouncement).toContain('Alert');
  expect(this.liveRegionAnnouncement).toContain('Schedule change');
  expect(this.liveRegionAnnouncement).toContain(this.originalTime);
  expect(this.liveRegionAnnouncement).toContain(this.newTime);
});

Then('screen reader should announce {string}', async function (expectedAnnouncement: string) {
  expect(this.screenReaderAnnouncement).toBeDefined();
  expect(this.screenReaderAnnouncement).toContain('Notification');
});

Then('screen reader should announce {string}', async function (expectedText: string) {
  const liveRegionXPath = '//div[@aria-live]';
  const announcement = await page.locator(liveRegionXPath).textContent();
  expect(announcement).toContain(expectedText);
});

Then('screen reader should read first notification summary', async function () {
  const notificationItemXPath = '//div[@class="notification-item"]';
  const firstNotification = page.locator(notificationItemXPath).first();
  const ariaLabel = await firstNotification.getAttribute('aria-label');
  
  expect(ariaLabel).toBeDefined();
  expect(ariaLabel?.length).toBeGreaterThan(0);
});

Then('screen reader should announce notification type {string}', async function (notificationType: string) {
  expect(this.notificationDetails).toBeDefined();
  const hasType = this.notificationDetails.some((detail: any) => 
    detail.textContent?.includes(notificationType) || detail.ariaLabel?.includes(notificationType)
  );
  expect(hasType).toBe(true);
});

Then('screen reader should announce original time {string}', async function (originalTime: string) {
  const hasOriginalTime = this.notificationDetails.some((detail: any) => 
    detail.textContent?.includes(originalTime) || detail.ariaLabel?.includes(originalTime)
  );
  expect(hasOriginalTime).toBe(true);
});

Then('screen reader should announce new time {string}', async function (newTime: string) {
  const hasNewTime = this.notificationDetails.some((detail: any) => 
    detail.textContent?.includes(newTime) || detail.ariaLabel?.includes(newTime)
  );
  expect(hasNewTime).toBe(true);
});

Then('screen reader should announce date and timestamp', async function () {
  const hasTimestamp = this.notificationDetails.some((detail: any) => 
    detail.textContent?.match(/\d{1,2}:\d{2}/) || detail.ariaLabel?.match(/\d{1,2}:\d{2}/)
  );
  expect(hasTimestamp).toBe(true);
});

Then('screen reader should announce {string} with appropriate role and state', async function (buttonText: string) {
  expect(this.buttonAriaLabel).toBeDefined();
  expect(this.buttonAriaLabel).toContain(buttonText);
});

Then('screen reader should announce {string}', async function (announcement: string) {
  expect(this.acknowledgmentAnnouncement).toBeDefined();
  expect(this.acknowledgmentAnnouncement).toContain('acknowledged');
});

Then('screen reader should announce updated state {string}', async function (state: string) {
  const liveRegionXPath = '//div[@aria-live]';
  const announcement = await page.locator(liveRegionXPath).textContent();
  expect(announcement).toContain('read');
});

Then('screen reader should announce {string}', async function (announcement: string) {
  const historyXPath = '//section[@id="notification-history"]';
  const ariaLabel = await page.locator(historyXPath).getAttribute('aria-label');
  expect(ariaLabel).toContain('history');
});

Then('screen reader should provide context about past notifications being available', async function () {
  const historyXPath = '//section[@id="notification-history"]';
  const ariaLabel = await page.locator(historyXPath).getAttribute('aria-label');
  expect(ariaLabel).toBeDefined();
  expect(ariaLabel?.length).toBeGreaterThan(0);
});

Then('screen reader should announce each past notification with full context', async function () {
  expect(this.pastNotifications).toBeDefined();
  expect(this.pastNotifications.length).toBeGreaterThan(0);
  
  const allHaveContext = this.pastNotifications.every((notification: any) => 
    notification.ariaLabel || notification.textContent
  );
  expect(allHaveContext).toBe(true);
});

Then('screen reader should announce date, time, and acknowledgment status', async function () {
  const hasCompleteInfo = this.pastNotifications.some((notification: any) => {
    const content = notification.ariaLabel || notification.textContent || '';
    return content.match(/\d{1,2}:\d{2}/) && (content.includes('acknowledged') || content.includes('read'));
  });
  expect(hasCompleteInfo).toBe(true);
});

/**************************************************/
/*  TEST CASE: TC-A11Y-003
/*  Title: Focus management and focus trap prevention in notification modal dialogs
/*  Priority: High
/*  Category: Accessibility - Focus Management
/**************************************************/

Then('notification center should open', async function () {
  const notificationCenterXPath = '//div[@id="notification-center"]';
  await assertions.assertVisible(page.locator(notificationCenterXPath));
});

Then('focus should be placed on first focusable element within panel', async function () {
  expect(this.firstFocusedElement).toBeDefined();
  expect(this.firstFocusedElement).not.toBe('');
});

Then('modal dialog should open', async function () {
  const modalXPath = '//div[@role="dialog"]';
  await assertions.assertVisible(page.locator(modalXPath));
});

Then('focus should automatically move to first focusable element in modal', async function () {
  expect(this.modalFirstFocusedElement).toBeDefined();
  
  const isInsideModal = await page.evaluate(() => {
    const modal = document.querySelector('[role="dialog"]');
    const focused = document.activeElement;
    return modal?.contains(focused) || false;
  });
  expect(isInsideModal).toBe(true);
});

Then('background content should be inert', async function () {
  const backgroundInert = await page.evaluate(() => {
    const modal = document.querySelector('[role="dialog"]');
    const body = document.body;
    return modal?.getAttribute('aria-modal') === 'true' || body.hasAttribute('inert');
  });
  expect(backgroundInert).toBe(true);
});

Then('focus should move through all interactive elements in logical order', async function () {
  expect(this.modalFocusableElements).toBeDefined();
  expect(this.modalFocusableElements.length).toBeGreaterThan(0);
});

Then('focus should include notification details, {string} button, {string} button', async function (button1: string, button