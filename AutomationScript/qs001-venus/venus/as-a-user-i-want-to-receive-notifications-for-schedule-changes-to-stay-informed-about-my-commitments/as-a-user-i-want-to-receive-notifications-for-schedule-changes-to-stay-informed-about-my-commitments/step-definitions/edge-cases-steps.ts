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
    appointments: [],
    notifications: [],
    systemState: {}
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
/*  Category: Setup
/*  Description: Common preconditions for all edge case scenarios
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user is logged into the system with valid credentials', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  
  const usernameXPath = '//input[@id="username"]';
  const passwordXPath = '//input[@id="password"]';
  const loginButtonXPath = '//button[@id="login"]';
  
  await actions.fill(page.locator(usernameXPath), 'testuser');
  await actions.fill(page.locator(passwordXPath), 'testpass');
  await actions.click(page.locator(loginButtonXPath));
  await waits.waitForNetworkIdle();
  
  const dashboardXPath = '//div[@id="dashboard"]';
  await waits.waitForVisible(page.locator(dashboardXPath));
});

// TODO: Replace XPath with Object Repository when available
Given('user has notification preferences enabled for schedule changes', async function () {
  const settingsButtonXPath = '//button[@id="settings"]';
  await actions.click(page.locator(settingsButtonXPath));
  await waits.waitForNetworkIdle();
  
  const notificationPreferencesXPath = '//div[@id="notification-preferences"]';
  await waits.waitForVisible(page.locator(notificationPreferencesXPath));
  
  const scheduleChangeNotificationXPath = '//input[@id="notification-schedule-changes"]';
  const checkbox = page.locator(scheduleChangeNotificationXPath);
  
  if (await checkbox.isChecked() === false) {
    await actions.check(checkbox);
  }
  
  const emailNotificationXPath = '//input[@id="notification-email-enabled"]';
  const emailCheckbox = page.locator(emailNotificationXPath);
  
  if (await emailCheckbox.isChecked() === false) {
    await actions.check(emailCheckbox);
  }
  
  const inAppNotificationXPath = '//input[@id="notification-inapp-enabled"]';
  const inAppCheckbox = page.locator(inAppNotificationXPath);
  
  if (await inAppCheckbox.isChecked() === false) {
    await actions.check(inAppCheckbox);
  }
  
  const saveButtonXPath = '//button[@id="save-preferences"]';
  await actions.click(page.locator(saveButtonXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
Given('email service and in-app notification service are operational', async function () {
  const systemStatusXPath = '//div[@id="system-status"]';
  await assertions.assertVisible(page.locator(systemStatusXPath));
  
  const emailServiceStatusXPath = '//span[@id="email-service-status"]';
  await assertions.assertContainsText(page.locator(emailServiceStatusXPath), 'operational');
  
  const inAppServiceStatusXPath = '//span[@id="inapp-service-status"]';
  await assertions.assertContainsText(page.locator(inAppServiceStatusXPath), 'operational');
});

/**************************************************/
/*  TEST CASE: TC-EDGE-001
/*  Title: Multiple rapid schedule changes within seconds deliver all notifications accurately
/*  Priority: High
/*  Category: Edge Cases
/*  Description: Validates notification delivery for rapid consecutive schedule modifications
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user has at least one scheduled appointment in the system', async function () {
  const appointmentsMenuXPath = '//a[@id="appointments-menu"]';
  await actions.click(page.locator(appointmentsMenuXPath));
  await waits.waitForNetworkIdle();
  
  const appointmentListXPath = '//div[@id="appointment-list"]';
  await waits.waitForVisible(page.locator(appointmentListXPath));
  
  const appointmentItemsXPath = '//div[@class="appointment-item"]';
  const appointmentCount = await page.locator(appointmentItemsXPath).count();
  
  if (appointmentCount === 0) {
    const createAppointmentButtonXPath = '//button[@id="create-appointment"]';
    await actions.click(page.locator(createAppointmentButtonXPath));
    await waits.waitForNetworkIdle();
    
    const appointmentTitleXPath = '//input[@id="appointment-title"]';
    await actions.fill(page.locator(appointmentTitleXPath), 'Test Appointment');
    
    const appointmentTimeXPath = '//input[@id="appointment-time"]';
    await actions.fill(page.locator(appointmentTimeXPath), '2:00 PM');
    
    const saveAppointmentButtonXPath = '//button[@id="save-appointment"]';
    await actions.click(page.locator(saveAppointmentButtonXPath));
    await waits.waitForNetworkIdle();
  }
  
  this.testData.currentAppointmentId = await page.locator('//div[@class="appointment-item"][1]').getAttribute('data-appointment-id');
});

// TODO: Replace XPath with Object Repository when available
When('user modifies appointment time from {string} to {string}', async function (fromTime: string, toTime: string) {
  const editAppointmentButtonXPath = `//button[@id="edit-appointment-${this.testData.currentAppointmentId}"]`;
  await actions.click(page.locator(editAppointmentButtonXPath));
  await waits.waitForNetworkIdle();
  
  const appointmentTimeFieldXPath = '//input[@id="appointment-time"]';
  await actions.clearAndFill(page.locator(appointmentTimeFieldXPath), toTime);
  
  const saveChangesButtonXPath = '//button[@id="save-appointment-changes"]';
  await actions.click(page.locator(saveChangesButtonXPath));
  await waits.waitForNetworkIdle();
  
  this.testData.lastModificationTime = new Date();
});

// TODO: Replace XPath with Object Repository when available
When('within {int} seconds user modifies the same appointment from {string} to {string}', async function (seconds: number, fromTime: string, toTime: string) {
  await page.waitForTimeout(2000);
  
  const editAppointmentButtonXPath = `//button[@id="edit-appointment-${this.testData.currentAppointmentId}"]`;
  await actions.click(page.locator(editAppointmentButtonXPath));
  await waits.waitForNetworkIdle();
  
  const appointmentTimeFieldXPath = '//input[@id="appointment-time"]';
  await actions.clearAndFill(page.locator(appointmentTimeFieldXPath), toTime);
  
  const saveChangesButtonXPath = '//button[@id="save-appointment-changes"]';
  await actions.click(page.locator(saveChangesButtonXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('within another {int} seconds user modifies the same appointment from {string} to {string}', async function (seconds: number, fromTime: string, toTime: string) {
  await page.waitForTimeout(2000);
  
  const editAppointmentButtonXPath = `//button[@id="edit-appointment-${this.testData.currentAppointmentId}"]`;
  await actions.click(page.locator(editAppointmentButtonXPath));
  await waits.waitForNetworkIdle();
  
  const appointmentTimeFieldXPath = '//input[@id="appointment-time"]';
  await actions.clearAndFill(page.locator(appointmentTimeFieldXPath), toTime);
  
  const saveChangesButtonXPath = '//button[@id="save-appointment-changes"]';
  await actions.click(page.locator(saveChangesButtonXPath));
  await waits.waitForNetworkIdle();
});

When('user waits for {int} minute', async function (minutes: number) {
  await page.waitForTimeout(minutes * 60000);
});

// TODO: Replace XPath with Object Repository when available
Then('user should receive {int} notifications in email inbox', async function (expectedCount: number) {
  const emailInboxXPath = '//div[@id="email-inbox"]';
  await actions.click(page.locator(emailInboxXPath));
  await waits.waitForNetworkIdle();
  
  const emailNotificationsXPath = '//div[@class="email-notification"]';
  await assertions.assertElementCount(page.locator(emailNotificationsXPath), expectedCount);
});

// TODO: Replace XPath with Object Repository when available
Then('user should receive {int} notifications in in-app notification center', async function (expectedCount: number) {
  const notificationCenterIconXPath = '//button[@id="notification-center-icon"]';
  await actions.click(page.locator(notificationCenterIconXPath));
  await waits.waitForNetworkIdle();
  
  const inAppNotificationsXPath = '//div[@class="inapp-notification"]';
  await assertions.assertElementCount(page.locator(inAppNotificationsXPath), expectedCount);
});

// TODO: Replace XPath with Object Repository when available
Then('each notification should contain accurate schedule change details', async function () {
  const notificationsXPath = '//div[@class="inapp-notification"]';
  const notifications = page.locator(notificationsXPath);
  const count = await notifications.count();
  
  for (let i = 0; i < count; i++) {
    const notification = notifications.nth(i);
    const notificationTextXPath = '//div[@class="notification-content"]';
    await assertions.assertVisible(notification.locator(notificationTextXPath));
  }
});

// TODO: Replace XPath with Object Repository when available
Then('notification for first change should show time change from {string} to {string}', async function (fromTime: string, toTime: string) {
  const firstNotificationXPath = '//div[@class="inapp-notification"][1]';
  const notificationContent = page.locator(firstNotificationXPath);
  
  await assertions.assertContainsText(notificationContent, fromTime);
  await assertions.assertContainsText(notificationContent, toTime);
});

// TODO: Replace XPath with Object Repository when available
Then('notification for second change should show time change from {string} to {string}', async function (fromTime: string, toTime: string) {
  const secondNotificationXPath = '//div[@class="inapp-notification"][2]';
  const notificationContent = page.locator(secondNotificationXPath);
  
  await assertions.assertContainsText(notificationContent, fromTime);
  await assertions.assertContainsText(notificationContent, toTime);
});

// TODO: Replace XPath with Object Repository when available
Then('notification for third change should show time change from {string} to {string}', async function (fromTime: string, toTime: string) {
  const thirdNotificationXPath = '//div[@class="inapp-notification"][3]';
  const notificationContent = page.locator(thirdNotificationXPath);
  
  await assertions.assertContainsText(notificationContent, fromTime);
  await assertions.assertContainsText(notificationContent, toTime);
});

// TODO: Replace XPath with Object Repository when available
Then('each notification should have correct timestamp', async function () {
  const notificationsXPath = '//div[@class="inapp-notification"]';
  const notifications = page.locator(notificationsXPath);
  const count = await notifications.count();
  
  for (let i = 0; i < count; i++) {
    const notification = notifications.nth(i);
    const timestampXPath = '//span[@class="notification-timestamp"]';
    await assertions.assertVisible(notification.locator(timestampXPath));
    
    const timestampText = await notification.locator(timestampXPath).textContent();
    expect(timestampText).toBeTruthy();
  }
});

// TODO: Replace XPath with Object Repository when available
Then('no duplicate notifications should be present', async function () {
  const notificationsXPath = '//div[@class="inapp-notification"]';
  const notifications = page.locator(notificationsXPath);
  const count = await notifications.count();
  
  const notificationIds = [];
  for (let i = 0; i < count; i++) {
    const notificationId = await notifications.nth(i).getAttribute('data-notification-id');
    expect(notificationIds).not.toContain(notificationId);
    notificationIds.push(notificationId);
  }
});

// TODO: Replace XPath with Object Repository when available
Then('notification history should show all {int} changes in chronological order', async function (expectedCount: number) {
  const notificationHistoryXPath = '//div[@id="notification-history"]';
  await actions.click(page.locator(notificationHistoryXPath));
  await waits.waitForNetworkIdle();
  
  const historyItemsXPath = '//div[@class="history-item"]';
  await assertions.assertElementCount(page.locator(historyItemsXPath), expectedCount);
  
  const timestamps = [];
  const historyItems = page.locator(historyItemsXPath);
  const count = await historyItems.count();
  
  for (let i = 0; i < count; i++) {
    const timestampXPath = '//span[@class="history-timestamp"]';
    const timestampText = await historyItems.nth(i).locator(timestampXPath).getAttribute('data-timestamp');
    timestamps.push(new Date(timestampText).getTime());
  }
  
  for (let i = 1; i < timestamps.length; i++) {
    expect(timestamps[i]).toBeGreaterThanOrEqual(timestamps[i - 1]);
  }
});

// TODO: Replace XPath with Object Repository when available
Then('user\'s schedule should reflect final appointment time of {string}', async function (expectedTime: string) {
  const appointmentsMenuXPath = '//a[@id="appointments-menu"]';
  await actions.click(page.locator(appointmentsMenuXPath));
  await waits.waitForNetworkIdle();
  
  const appointmentTimeXPath = `//div[@data-appointment-id="${this.testData.currentAppointmentId}"]//span[@class="appointment-time"]`;
  await assertions.assertContainsText(page.locator(appointmentTimeXPath), expectedTime);
});

/**************************************************/
/*  TEST CASE: TC-EDGE-002
/*  Title: Schedule change at midnight boundary delivers notification with correct date and time
/*  Priority: Medium
/*  Category: Edge Cases
/*  Description: Validates notification delivery during midnight date transition
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user has a scheduled appointment for the next day', async function () {
  const appointmentsMenuXPath = '//a[@id="appointments-menu"]';
  await actions.click(page.locator(appointmentsMenuXPath));
  await waits.waitForNetworkIdle();
  
  const createAppointmentButtonXPath = '//button[@id="create-appointment"]';
  await actions.click(page.locator(createAppointmentButtonXPath));
  await waits.waitForNetworkIdle();
  
  const appointmentTitleXPath = '//input[@id="appointment-title"]';
  await actions.fill(page.locator(appointmentTitleXPath), 'Tomorrow Appointment');
  
  const tomorrow = new Date();
  tomorrow.setDate(tomorrow.getDate() + 1);
  const tomorrowDateString = tomorrow.toISOString().split('T')[0];
  
  const appointmentDateXPath = '//input[@id="appointment-date"]';
  await actions.fill(page.locator(appointmentDateXPath), tomorrowDateString);
  
  const appointmentTimeXPath = '//input[@id="appointment-time"]';
  await actions.fill(page.locator(appointmentTimeXPath), '10:00 AM');
  
  const saveAppointmentButtonXPath = '//button[@id="save-appointment"]';
  await actions.click(page.locator(saveAppointmentButtonXPath));
  await waits.waitForNetworkIdle();
  
  this.testData.tomorrowAppointmentId = await page.locator('//div[@class="appointment-item"][1]').getAttribute('data-appointment-id');
});

// TODO: Replace XPath with Object Repository when available
Given('system time is set to {string}', async function (timeString: string) {
  const systemTimeSettingsXPath = '//div[@id="system-time-settings"]';
  await actions.click(page.locator(systemTimeSettingsXPath));
  await waits.waitForNetworkIdle();
  
  const setTimeXPath = '//input[@id="set-system-time"]';
  await actions.fill(page.locator(setTimeXPath), timeString);
  
  const applyTimeButtonXPath = '//button[@id="apply-system-time"]';
  await actions.click(page.locator(applyTimeButtonXPath));
  await waits.waitForNetworkIdle();
  
  this.testData.systemTime = timeString;
});

// TODO: Replace XPath with Object Repository when available
Given('notification services are running and operational', async function () {
  const systemStatusXPath = '//div[@id="system-status"]';
  await actions.click(page.locator(systemStatusXPath));
  await waits.waitForNetworkIdle();
  
  const notificationServiceStatusXPath = '//span[@id="notification-service-status"]';
  await assertions.assertContainsText(page.locator(notificationServiceStatusXPath), 'running');
});

// TODO: Replace XPath with Object Repository when available
When('user waits until system time reaches {string}', async function (targetTime: string) {
  await page.waitForTimeout(5000);
  
  const currentTimeXPath = '//span[@id="current-system-time"]';
  await assertions.assertContainsText(page.locator(currentTimeXPath), targetTime);
});

// TODO: Replace XPath with Object Repository when available
When('user modifies the appointment scheduled for tomorrow', async function () {
  const editAppointmentButtonXPath = `//button[@id="edit-appointment-${this.testData.tomorrowAppointmentId}"]`;
  await actions.click(page.locator(editAppointmentButtonXPath));
  await waits.waitForNetworkIdle();
  
  const appointmentTimeFieldXPath = '//input[@id="appointment-time"]';
  await actions.clearAndFill(page.locator(appointmentTimeFieldXPath), '11:00 AM');
  
  const saveChangesButtonXPath = '//button[@id="save-appointment-changes"]';
  await actions.click(page.locator(saveChangesButtonXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('system clock transitions from {string} to {string}', async function (fromTime: string, toTime: string) {
  await page.waitForTimeout(5000);
  
  const currentTimeXPath = '//span[@id="current-system-time"]';
  await waits.waitForVisible(page.locator(currentTimeXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should be delivered to email', async function () {
  const emailInboxXPath = '//div[@id="email-inbox"]';
  await actions.click(page.locator(emailInboxXPath));
  await waits.waitForNetworkIdle();
  
  const emailNotificationXPath = '//div[@class="email-notification"][1]';
  await assertions.assertVisible(page.locator(emailNotificationXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should be delivered to in-app notification center', async function () {
  const notificationCenterIconXPath = '//button[@id="notification-center-icon"]';
  await actions.click(page.locator(notificationCenterIconXPath));
  await waits.waitForNetworkIdle();
  
  const inAppNotificationXPath = '//div[@class="inapp-notification"][1]';
  await assertions.assertVisible(page.locator(inAppNotificationXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('notification timestamp should reflect correct date after midnight transition', async function () {
  const notificationTimestampXPath = '//div[@class="inapp-notification"][1]//span[@class="notification-timestamp"]';
  const timestampText = await page.locator(notificationTimestampXPath).textContent();
  
  const currentDate = new Date();
  const expectedDateString = currentDate.toISOString().split('T')[0];
  
  expect(timestampText).toContain(expectedDateString);
});

// TODO: Replace XPath with Object Repository when available
Then('notification content should display correct date for modified appointment', async function () {
  const notificationContentXPath = '//div[@class="inapp-notification"][1]//div[@class="notification-content"]';
  const contentText = await page.locator(notificationContentXPath).textContent();
  
  const tomorrow = new Date();
  tomorrow.setDate(tomorrow.getDate() + 1);
  const tomorrowDateString = tomorrow.toLocaleDateString();
  
  expect(contentText).toBeTruthy();
});

// TODO: Replace XPath with Object Repository when available
Then('no timezone-related errors should occur', async function () {
  const errorMessagesXPath = '//div[@class="error-message"]';
  const errorCount = await page.locator(errorMessagesXPath).count();
  
  expect(errorCount).toBe(0);
});

// TODO: Replace XPath with Object Repository when available
Then('no date calculation issues should be present', async function () {
  const notificationContentXPath = '//div[@class="inapp-notification"][1]//div[@class="notification-content"]';
  const contentText = await page.locator(notificationContentXPath).textContent();
  
  expect(contentText).not.toContain('Invalid Date');
  expect(contentText).not.toContain('NaN');
});

// TODO: Replace XPath with Object Repository when available
Then('notification log should record correct timestamp', async function () {
  const notificationLogsXPath = '//div[@id="notification-logs"]';
  await actions.click(page.locator(notificationLogsXPath));
  await waits.waitForNetworkIdle();
  
  const latestLogEntryXPath = '//div[@class="log-entry"][1]//span[@class="log-timestamp"]';
  await assertions.assertVisible(page.locator(latestLogEntryXPath));
  
  const logTimestamp = await page.locator(latestLogEntryXPath).textContent();
  expect(logTimestamp).toBeTruthy();
});

/**************************************************/
/*  TEST CASE: TC-EDGE-003
/*  Title: New notification delivers successfully when user has 100+ pending unread notifications
/*  Priority: Medium
/*  Category: Edge Cases
/*  Description: Validates notification delivery with high volume of unread notifications
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user has {int} unread notifications in notification center', async function (notificationCount: number) {
  const notificationCenterIconXPath = '//button[@id="notification-center-icon"]';
  await actions.click(page.locator(notificationCenterIconXPath));
  await waits.waitForNetworkIdle();
  
  const unreadCountBadgeXPath = '//span[@id="unread-notification-count"]';
  const currentCount = parseInt(await page.locator(unreadCountBadgeXPath).textContent() || '0');
  
  if (currentCount < notificationCount) {
    const generateNotificationsXPath = '//button[@id="generate-test-notifications"]';
    await actions.click(page.locator(generateNotificationsXPath));
    
    const countInputXPath = '//input[@id="notification-count-input"]';
    await actions.fill(page.locator(countInputXPath), (notificationCount - currentCount).toString());
    
    const generateButtonXPath = '//button[@id="confirm-generate"]';
    await actions.click(page.locator(generateButtonXPath));
    await waits.waitForNetworkIdle();
  }
  
  this.testData.initialUnreadCount = notificationCount;
});

// TODO: Replace XPath with Object Repository when available
Given('user has not acknowledged any existing notifications', async function () {
  const notificationCenterXPath = '//div[@id="notification-center"]';
  await waits.waitForVisible(page.locator(notificationCenterXPath));
  
  const unreadNotificationsXPath = '//div[@class="inapp-notification unread"]';
  const unreadCount = await page.locator(unreadNotificationsXPath).count();
  
  expect(unreadCount).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Given('email inbox has storage capacity available', async function () {
  const emailStorageStatusXPath = '//div[@id="email-storage-status"]';
  await actions.click(page.locator(emailStorageStatusXPath));
  await waits.waitForNetworkIdle();
  
  const storageAvailableXPath = '//span[@id="storage-available"]';
  await assertions.assertContainsText(page.locator(storageAvailableXPath), 'available');
});

// TODO: Replace XPath with Object Repository when available
When('user navigates to notification center', async function () {
  const notificationCenterIconXPath = '//button[@id="notification-center-icon"]';
  await actions.click(page.locator(notificationCenterIconXPath));
  await waits.waitForNetworkIdle();
  
  const notificationCenterPanelXPath = '//div[@id="notification-center-panel"]';
  await waits.waitForVisible(page.locator(notificationCenterPanelXPath));
});

// TODO: Replace XPath with Object Repository when available
When('user creates schedule change by modifying an existing appointment', async function () {
  const appointmentsMenuXPath = '//a[@id="appointments-menu"]';
  await actions.click(page.locator(appointmentsMenuXPath));
  await waits.waitForNetworkIdle();
  
  const firstAppointmentEditXPath = '//div[@class="appointment-item"][1]//button[@class="edit-button"]';
  await actions.click(page.locator(firstAppointmentEditXPath));
  await waits.waitForNetworkIdle();
  
  const appointmentTimeFieldXPath = '//input[@id="appointment-time"]';
  await actions.clearAndFill(page.locator(appointmentTimeFieldXPath), '3:00 PM');
  
  const saveChangesButtonXPath = '//button[@id="save-appointment-changes"]';
  await actions.click(page.locator(saveChangesButtonXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
Then('new notification should appear in notification center', async function () {
  const notificationCenterIconXPath = '//button[@id="notification-center-icon"]';
  await actions.click(page.locator(notificationCenterIconXPath));
  await waits.waitForNetworkIdle();
  
  const latestNotificationXPath = '//div[@class="inapp-notification"][1]';
  await assertions.assertVisible(page.locator(latestNotificationXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('total unread notifications count should be {int}', async function (expectedCount: number) {
  const unreadCountBadgeXPath = '//span[@id="unread-notification-count"]';
  await assertions.assertContainsText(page.locator(unreadCountBadgeXPath), expectedCount.toString());
});

// TODO: Replace XPath with Object Repository when available
Then('email notification should be delivered successfully', async function () {
  const emailInboxXPath = '//div[@id="email-inbox"]';
  await actions.click(page.locator(emailInboxXPath));
  await waits.waitForNetworkIdle();
  
  const latestEmailXPath = '//div[@class="email-notification"][1]';
  await assertions.assertVisible(page.locator(latestEmailXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('new notification should be displayed at top of notification list', async function () {
  const notificationCenterIconXPath = '//button[@id="notification-center-icon"]';
  await actions.click(page.locator(notificationCenterIconXPath));
  await waits.waitForNetworkIdle();
  
  const firstNotificationXPath = '//div[@class="inapp-notification"][1]';
  const notificationText = await page.locator(firstNotificationXPath).textContent();
  
  expect(notificationText).toContain('schedule');
});

// TODO: Replace XPath with Object Repository when available
Then('notification should contain correct schedule change details', async function () {
  const firstNotificationXPath = '//div[@class="inapp-notification"][1]//div[@class="notification-content"]';
  const contentText = await page.locator(firstNotificationXPath).textContent();
  
  expect(contentText).toContain('3:00 PM');
});

// TODO: Replace XPath with Object Repository when available
Then('notification center should load within {int} seconds', async function (maxSeconds: number) {
  const startTime = Date.now();
  
  const notificationCenterPanelXPath = '//div[@id="notification-center-panel"]';
  await waits.waitForVisible(page.locator(notificationCenterPanelXPath));
  
  const loadTime = (Date.now() - startTime) / 1000;
  expect(loadTime).toBeLessThanOrEqual(maxSeconds);
});

// TODO: Replace XPath with Object Repository when available
Then('system performance should remain stable', async function () {
  const performanceMetricsXPath = '//div[@id="performance-metrics"]';
  await actions.click(page.locator(performanceMetricsXPath));
  await waits.waitForNetworkIdle();
  
  const cpuUsageXPath = '//span[@id="cpu-usage"]';
  const cpuUsageText = await page.locator(cpuUsageXPath).textContent();
  const cpuUsage = parseInt(cpuUsageText?.replace('%', '') || '0');
  
  expect(cpuUsage).toBeLessThan(90);
});

/**************************************************/
/*  TEST CASE: TC-EDGE-004
/*  Title: Notification displays special characters and Unicode correctly in appointment details
/*  Priority: High
/*  Category: Edge Cases
/*  Description: Validates proper rendering of special characters and Unicode in notifications
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user has an appointment with title {string}', async function (appointmentTitle: string) {
  const appointmentsMenuXPath = '//a[@id="appointments-menu"]';
  await actions.click(page.locator(appointmentsMenuXPath));
  await waits.waitForNetworkIdle();
  
  const createAppointmentButtonXPath = '//button[@id="create-appointment"]';
  await actions.click(page.locator(createAppointmentButtonXPath));
  await waits.waitForNetworkIdle();
  
  const appointmentTitleXPath = '//input[@id="appointment-title"]';
  await actions.fill(page.locator(appointmentTitleXPath), appointmentTitle);
  
  const appointmentTimeXPath = '//input[@id="appointment-time"]';
  await actions.fill(page.locator(appointmentTimeXPath), '2:00 PM');
  
  const saveAppointmentButtonXPath = '//button[@id="save-appointment"]';
  await actions.click(page.locator(saveAppointmentButtonXPath));
  await waits.waitForNetworkIdle();
  
  this.testData.specialCharAppointmentId = await page.locator('//div[@class="appointment-item"][1]').getAttribute('data-appointment-id');
  this.testData.specialCharAppointmentTitle = appointmentTitle;
});

// TODO: Replace XPath with Object Repository when available
Given('notification services support UTF-8 encoding', async function () {
  const systemConfigXPath = '//div[@id="system-configuration"]';
  await actions.click(page.locator(systemConfigXPath));
  await waits.waitForNetworkIdle();
  
  const encodingSettingXPath = '//span[@id="notification-encoding"]';
  await assertions.assertContainsText(page.locator(encodingSettingXPath), 'UTF-8');
});

// TODO: Replace XPath with Object Repository when available
Given('email client supports HTML and Unicode characters', async function () {
  const emailClientSettingsXPath = '//div[@id="email-client-settings"]';
  await actions.click(page.locator(emailClientSettingsXPath));
  await waits.waitForNetworkIdle();
  
  const htmlSupportXPath = '//span[@id="html-support"]';
  await assertions.assertContainsText(page.locator(htmlSupportXPath), 'enabled');
  
  const unicodeSupportXPath = '//span[@id="unicode-support"]';
  await assertions.assertContainsText(page.locator(unicodeSupportXPath), 'enabled');
});

// TODO: Replace XPath with Object Repository when available
Then('in-app notification should display appointment title {string}', async function (expectedTitle: string) {
  const notificationCenterIconXPath = '//button[@id="notification-center-icon"]';
  await actions.click(page.locator(notificationCenterIconXPath));
  await waits.waitForNetworkIdle();
  
  const latestNotificationXPath = '//div[@class="inapp-notification"][1]//div[@class="notification-content"]';
  await assertions.assertContainsText(page.locator(latestNotificationXPath), expectedTitle);
});

// TODO: Replace XPath with Object Repository when available
Then('email notification should display appointment title {string}', async function (expectedTitle: string) {
  const emailInboxXPath = '//div[@id="email-inbox"]';
  await actions.click(page.locator(emailInboxXPath));
  await waits.waitForNetworkIdle();
  
  const latestEmailContentXPath = '//div[@class="email-notification"][1]//div[@class="email-body"]';
  await assertions.assertContainsText(page.locator(latestEmailContentXPath), expectedTitle);
});

// TODO: Replace XPath with Object Repository when available
Then('all special characters should render correctly: {string}', async function (specialChars: string) {
  const notificationContentXPath = '//div[@class="inapp-notification"][1]//div[@class="notification-content"]';
  const contentText = await page.locator(notificationContentXPath).textContent();
  
  const charArray = specialChars.split(' ');
  for (const char of charArray) {
    expect(contentText).toContain(char);
  }
});

// TODO: Replace XPath with Object Repository when available
Then('notification should include time change details {string}', async function (timeChangeDetails: string) {
  const notificationContentXPath = '//div[@class="inapp-notification"][1]//div[@class="notification-content"]';
  await assertions.assertContainsText(page.locator(notificationContentXPath), timeChangeDetails);
});

// TODO: Replace XPath with Object Repository when available
Then('no encoding errors should be present', async function () {
  const notificationContentXPath = '//div[@class="inapp-notification"][1]//div[@class="notification-content"]';
  const contentText = await page.locator(notificationContentXPath).textContent();
  
  expect(contentText).not.toContain('�');
  expect(contentText).not.toContain('&#');
  expect(contentText).not.toContain('&amp;');
});

// TODO: Replace XPath with Object Repository when available
Then('no HTML injection vulnerabilities should be present', async function () {
  const notificationContentXPath = '//div[@class="inapp-notification"][1]//div[@class="notification-content"]';
  const innerHTML = await page.locator(notificationContentXPath).innerHTML();
  
  expect(innerHTML).not.toContain('<script>');
  expect(innerHTML).not.toContain('javascript:');
  expect(innerHTML).not.toContain('onerror=');
});

// TODO: Replace XPath with Object Repository when available
Then('no XSS vulnerabilities should be present', async function () {
  const notificationContentXPath = '//div[@class="inapp-notification"][1]//div[@class="notification-content"]';
  const innerHTML = await page.locator(notificationContentXPath).innerHTML();
  
  expect(innerHTML).not.toContain('<img src=x onerror=');
  expect(innerHTML).not.toContain('alert(');
  expect(innerHTML).not.toContain('eval(');
});

// TODO: Replace XPath with Object Repository when available
Then('Unicode emoji should render correctly across all notification channels', async function () {
  const inAppNotificationXPath = '//div[@class="inapp-notification"][1]//div[@class="notification-content"]';
  const inAppText = await page.locator(inAppNotificationXPath).textContent();
  expect(inAppText).toContain('☕');
  
  const emailInboxXPath = '//div[@id="email-inbox"]';
  await actions.click(page.locator(emailInboxXPath));
  await waits.waitForNetworkIdle();
  
  const emailContentXPath = '//div[@class="email-notification"][1]//div[@class="email-body"]';
  const emailText = await page.locator(emailContentXPath).textContent();
  expect(emailText).toContain('☕');
});

// TODO: Replace XPath with Object Repository when available
Then('accented characters should render correctly across all notification channels', async function () {
  const inAppNotificationXPath = '//div[@class="inapp-notification"][1]//div[@class="notification-content"]';
  const inAppText = await page.locator(inAppNotificationXPath).textContent();
  expect(inAppText).toContain('é');
  
  const emailContentXPath = '//div[@class="email-notification"][1]//div[@class="email-body"]';
  const emailText = await page.locator(emailContentXPath).textContent();
  expect(emailText).toContain('é');
});

/**************************************************/
/*  TEST CASE: TC-EDGE-005
/*  Title: In-app notification delivers when email address becomes invalid before notification delivery
/*  Priority: High
/*  Category: Edge Cases
/*  Description: Validates notification resilience when email delivery fails
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user has email address {string}', async function (emailAddress: string) {
  const userProfileXPath = '//div[@id="user-profile"]';
  await actions.click(page.locator(userProfileXPath));
  await waits.waitForNetworkIdle();
  
  const emailFieldXPath = '//input[@id="user-email"]';
  await actions.clearAndFill(page.locator(emailFieldXPath), emailAddress);
  
  const saveProfileButtonXPath = '//button[@id="save-profile"]';
  await actions.click(page.locator(saveProfileButtonXPath));
  await waits.waitForNetworkIdle();
  
  this.testData.userEmail = emailAddress;
});

// TODO: Replace XPath with Object Repository when available
Given('user has a scheduled appointment in the system', async function () {
  const appointmentsMenuXPath = '//a[@id="appointments-menu"]';
  await actions.click(page.locator(appointmentsMenuXPath));
  await waits.waitForNetworkIdle();
  
  const appointmentItemsXPath = '//div[@class="appointment-item"]';
  const appointmentCount = await page.locator(appointmentItemsXPath).count();
  
  if (appointmentCount === 0) {
    const createAppointmentButtonXPath = '//button[@id="create-appointment"]';
    await actions.click(page.locator(createAppointmentButtonXPath));
    await waits.waitForNetworkIdle();
    
    const appointmentTitleXPath = '//input[@id="appointment-title"]';
    await actions.fill(page.locator(appointmentTitleXPath), 'Test Appointment');
    
    const appointmentTimeXPath = '//input[@id="appointment-time"]';
    await actions.fill(page.locator(appointmentTimeXPath), '10:00 AM');
    
    const saveAppointmentButtonXPath = '//button[@id="save-appointment"]';
    await actions.click(page.locator(saveAppointmentButtonXPath));
    await waits.waitForNetworkIdle();
  }
  
  this.testData.appointmentId = await page.locator('//div[@class="appointment-item"][1]').getAttribute('data-appointment-id');
});

// TODO: Replace XPath with Object Repository when available
Given('user has both email and in-app notifications enabled', async function () {
  const settingsButtonXPath = '//button[@id="settings"]';
  await actions.click(page.locator(settingsButtonXPath));
  await waits.waitForNetworkIdle();
  
  const emailNotificationXPath = '//input[@id="notification-email-enabled"]';
  const emailCheckbox = page.locator(emailNotificationXPath);
  if (await emailCheckbox.isChecked() === false) {
    await actions.check(emailCheckbox);
  }
  
  const inAppNotificationXPath = '//input[@id="notification-inapp-enabled"]';
  const inAppCheckbox = page.locator(inAppNotificationXPath);
  if (await inAppCheckbox.isChecked() === false) {
    await actions.check(inAppCheckbox);
  }
  
  const saveButtonXPath = '//button[@id="save-preferences"]';
  await actions.click(page.locator(saveButtonXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('within {int} seconds user\'s email address is updated to invalid format {string}', async function (seconds: number, invalidEmail: string) {
  await page.waitForTimeout(3000);
  
  const userProfileXPath = '//div[@id="user-profile"]';
  await actions.click(page.locator(userProfileXPath));
  await waits.waitForNetworkIdle();
  
  const emailFieldXPath = '//input[@id="user-email"]';
  await actions.clearAndFill(page.locator(emailFieldXPath), invalidEmail);
  
  const saveProfileButtonXPath = '//button[@id="save-profile"]';
  await actions.click(page.locator(saveProfileButtonXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
Then('email notification delivery should fail', async function () {
  const notificationLogsXPath = '//div[@id="notification-logs"]';
  await actions.click(page.locator(notificationLogsXPath));
  await waits.waitForNetworkIdle();
  
  const emailFailureLogXPath = '//div[@class="log-entry"][contains(., "email") and contains(., "failed")]';
  await assertions.assertVisible(page.locator(emailFailureLogXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('system should log email delivery failure', async function () {
  const notificationLogsXPath = '//div[@id="notification-logs"]';
  const logEntries = page.locator(notificationLogsXPath);
  
  const logText = await logEntries.textContent();
  expect(logText).toContain('email');
  expect(logText).toContain('failed');
});

// TODO: Replace XPath with Object Repository when available
Then('in-app notification should be delivered successfully', async function () {
  const notificationCenterIconXPath = '//button[@id="notification-center-icon"]';
  await actions.click(page.locator(notificationCenterIconXPath));
  await waits.waitForNetworkIdle();
  
  const latestNotificationXPath = '//div[@class="inapp-notification"][1]';
  await assertions.assertVisible(page.locator(latestNotificationXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('in-app notification should contain complete schedule change details', async function () {
  const notificationContentXPath = '//div[@class="inapp-notification"][1]//div[@class="notification-content"]';
  const contentText = await page.locator(notificationContentXPath).textContent();
  
  expect(contentText).toContain('10:00 AM');
  expect(contentText).toContain('11:00 AM');
});

// TODO: Replace XPath with Object Repository when available
Then('system logs should show email delivery failure with error message', async function () {
  const notificationLogsXPath = '//div[@id="notification-logs"]';
  await actions.click(page.locator(notificationLogsXPath));
  await waits.waitForNetworkIdle();
  
  const errorLogXPath = '//div[@class="log-entry error"]';
  await assertions.assertVisible(page.locator(errorLogXPath));
  
  const errorText = await page.locator(errorLogXPath).textContent();
  expect(errorText).toContain('email');
  expect(errorText).toContain('invalid');
});

// TODO: Replace XPath with Object Repository when available
Then('system logs should show in-app notification successful delivery', async function () {
  const notificationLogsXPath = '//div[@id="notification-logs"]';
  const logEntries = page.locator(notificationLogsXPath);
  
  const successLogXPath = '//div[@class="log-entry success"][contains(., "in-app")]';
  await assertions.assertVisible(page.locator(successLogXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('notification delivery status records should be maintained', async function () {
  const deliveryStatusXPath = '//div[@id="notification-delivery-status"]';
  await actions.click(page.locator(deliveryStatusXPath));
  await waits.waitForNetworkIdle();
  
  const statusRecordsXPath = '//div[@class="status-record"]';
  const recordCount = await page.locator(statusRecordsXPath).count();
  
  expect(recordCount).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Then('system should not crash due to email delivery failure', async function () {
  const systemHealthXPath = '//div[@id="system-health"]';
  await actions.click(page.locator(systemHealthXPath));
  await waits.waitForNetworkIdle();
  
  const systemStatusXPath = '//span[@id="system-status"]';
  await assertions.assertContainsText(page.locator(systemStatusXPath), 'operational');
});

// TODO: Replace XPath with Object Repository when available
When('user\'s email address is corrected to valid format', async function () {
  const userProfileXPath = '//div[@id="user-profile"]';
  await actions.click(page.locator(userProfileXPath));
  await waits.waitForNetworkIdle();
  
  const emailFieldXPath = '//input[@id="user-email"]';
  await actions.clearAndFill(page.locator(emailFieldXPath), 'user@example.com');
  
  const saveProfileButtonXPath = '//button[@id="save-profile"]';
  await actions.click(page.locator(saveProfileButtonXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user triggers another schedule change', async function () {
  const appointmentsMenuXPath = '//a[@id="appointments-menu"]';
  await actions.click(page.locator(appointmentsMenuXPath));
  await waits.waitForNetworkIdle();
  
  const editAppointmentButtonXPath = `//button[@id="edit-appointment-${this.testData.appointmentId}"]`;
  await actions.click(page.locator(editAppointmentButtonXPath));
  await waits.waitForNetworkIdle();
  
  const appointmentTimeFieldXPath = '//input[@id="appointment-time"]';
  await actions.clearAndFill(page.locator(appointmentTimeFieldXPath), '12:00 PM');
  
  const saveChangesButtonXPath = '//button[@id="save-appointment-changes"]';
  await actions.click(page.locator(saveChangesButtonXPath));
  await waits.waitForNetworkIdle();
  
  await page.waitForTimeout(60000);
});

// TODO: Replace XPath with Object Repository when available
Then('subsequent notifications should be delivered to both email and in-app channels', async function () {
  const notificationCenterIconXPath = '//button[@id="notification-center-icon"]';
  await actions.click(page.locator(notificationCenterIconXPath));
  await waits.waitForNetworkIdle();
  
  const latestInAppNotificationXPath = '//div[@class="inapp-notification"][1]';
  await assertions.assertVisible(page.locator(latestInAppNotificationXPath));
  
  const emailInboxXPath = '//div[@id="email-inbox"]';
  await actions.click(page.locator(emailInboxXPath));
  await waits.waitForNetworkIdle();
  
  const latestEmailNotificationXPath = '//div[@class="email-notification"][1]';
  await assertions.assertVisible(page.locator(latestEmailNotificationXPath));
});

/**************************************************/
/*  TEST CASE: TC-EDGE-006
/*  Title: System handles 1000 simultaneous schedule changes across different users
/*  Priority: High
/*  Category: Edge Cases
/*  Description: Validates system performance and stability under high load
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('system has {int} active user accounts with scheduled appointments', async function (userCount: number) {
  const adminPanelXPath = '//div[@id="admin-panel"]';
  await actions.click(page.locator(adminPanelXPath));
  await waits.waitForNetworkIdle();
  
  const userManagementXPath = '//a[@id="user-management"]';
  await actions.click(page.locator(userManagementXPath));
  await waits.waitForNetworkIdle();
  
  const totalUsersXPath = '//span[@id="total-users-count"]';
  const currentUserCount = parseInt(await page.locator(totalUsersXPath).textContent() || '0');
  
  if (currentUserCount < userCount) {
    const generateUsersXPath = '//button[@id="generate-test-users"]';
    await actions.click(page.locator(generateUsersXPath));
    
    const userCountInputXPath = '//input[@id="user-count-input"]';
    await actions.fill(page.locator(userCountInputXPath), userCount.toString());
    
    const withAppointmentsCheckboxXPath = '//input[@id="with-appointments"]';
    await actions.check(page.locator(withAppointmentsCheckboxXPath));
    
    const generateButtonXPath = '//button[@id="confirm-generate-users"]';
    await actions.click(page.locator(generateButtonXPath));
    await waits.waitForNetworkIdle();
  }
  
  this.testData.totalTestUsers = userCount;
});

// TODO: Replace XPath with Object Repository when available
Given('all users have notification preferences enabled', async function () {
  const bulkSettingsXPath = '//button[@id="bulk-settings"]';
  await actions.click(page.locator(bulkSettingsXPath));
  await waits.waitForNetworkIdle();
  
  const enableAllNotificationsXPath = '//button[@id="enable-all-notifications"]';
  await actions.click(page.locator(enableAllNotificationsXPath));
  await waits.waitForNetworkIdle();
  
  const confirmButtonXPath = '//button[@id="confirm-bulk-action"]';
  await actions.click(page.locator(confirmButtonXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
Given('system load testing environment is configured', async function () {
  const loadTestConfigXPath = '//div[@id="load-test-configuration"]';
  await actions.click(page.locator(loadTestConfigXPath));
  await waits.waitForNetworkIdle();
  
  const configStatusXPath = '//span[@id="config-status"]';
  await assertions.assertContainsText(page.locator(configStatusXPath), 'configured');
});

// TODO: Replace XPath with Object Repository when available
Given('database connection pool has sufficient capacity', async function () {
  const databaseSettingsXPath = '//div[@id="database-settings"]';
  await actions.click(page.locator(databaseSettingsXPath));
  await waits.waitForNetworkIdle();
  
  const connectionPoolSizeXPath = '//span[@id="connection-pool-size"]';
  const poolSize = parseInt(await page.locator(connectionPoolSizeXPath).textContent() || '0');
  
  expect(poolSize).toBeGreaterThanOrEqual(100);
});

// TODO: Replace XPath with Object Repository when available
When('automated script triggers {int} schedule changes simultaneously', async function (changeCount: number) {
  const loadTestingXPath = '//div[@id="load-testing"]';
  await actions.click(page.locator(loadTestingXPath));
  await waits.waitForNetworkIdle();
  
  const simultaneousChangesInputXPath = '//input[@id="simultaneous-changes-count"]';
  await actions.fill(page.locator(simultaneousChangesInputXPath), changeCount.toString());
  
  const triggerLoadTestXPath = '//button[@id="trigger-load-test"]';
  await actions.click(page.locator(triggerLoadTestXPath));
  await waits.waitForNetworkIdle();
  
  this.testData.loadTestStartTime = Date.now();
});

// TODO: Replace XPath with Object Repository when available
When('user waits for {int} minutes', async function (minutes: number) {
  await page.waitForTimeout(minutes * 60000);
});

// TODO: Replace XPath with Object Repository when available
Then('all {int} schedule changes should be saved to database successfully', async function (expectedCount: number) {
  const loadTestResultsXPath = '//div[@id="load-test-results"]';
  await actions.click(page.locator(loadTestResultsXPath));
  await waits.waitForNetworkIdle();
  
  const successfulChangesXPath = '//span[@id="successful-changes-count"]';
  const successCount = parseInt(await page.locator(successfulChangesXPath).textContent() || '0');
  
  expect(successCount).toBe(expectedCount);
});

// TODO: Replace XPath with Object Repository when available
Then('notification system should process all {int} notifications without crashing', async function (expectedCount: number) {
  const notificationSystemStatusXPath = '//span[@id="notification-system-status"]';
  await assertions.assertContainsText(page.locator(notificationSystemStatusStatusXPath), 'operational');
  
  const processedNotificationsXPath = '//span[@id="processed-notifications-count"]';
  const processedCount = parseInt(await page.locator(processedNotificationsXPath).textContent() || '0');
  
  expect(processedCount).toBe(expectedCount);
});

// TODO: Replace XPath with Object Repository when available
Then('at least {int} percent of users should receive in-app notifications within {int} minute', async function (percentage: number, minutes: number) {
  const inAppDeliveryRateXPath = '//span[@id="inapp-delivery-rate"]';
  const deliveryRate = parseFloat(await page.locator(inAppDeliveryRateXPath).textContent() || '0');
  
  expect(deliveryRate).toBeGreaterThanOrEqual(percentage);
});

// TODO: Replace XPath with Object Repository when available
Then('at least {int} percent of users should receive email notifications within {int} minutes', async function (percentage: number, minutes: number) {
  const emailDeliveryRateXPath = '//span[@id="email-delivery-rate"]';
  const deliveryRate = parseFloat(await page.locator(emailDeliveryRateXPath).textContent() || '0');
  
  expect(deliveryRate).toBeGreaterThanOrEqual(percentage);
});

// TODO: Replace XPath with Object Repository when available
Then('system CPU usage should remain below {int} percent', async function (maxPercentage: number) {
  const cpuUsageXPath = '//span[@id="cpu-usage"]';
  const cpuUsageText = await page.locator(cpuUsageXPath).textContent();
  const cpuUsage = parseFloat(cpuUsageText?.replace('%', '') || '0');
  
  expect(cpuUsage).toBeLessThan(maxPercentage);
});

// TODO: Replace XPath with Object Repository when available
Then('memory usage should remain within acceptable limits', async function () {
  const memoryUsageXPath = '//span[@id="memory-usage"]';
  const memoryUsageText = await page.locator(memoryUsageXPath).textContent();
  const memoryUsage = parseFloat(memoryUsageText?.replace('%', '') || '0');
  
  expect(memoryUsage).toBeLessThan(85);
});

// TODO: Replace XPath with Object Repository when available
Then('no database deadlocks should occur', async function () {
  const databaseLogsXPath = '//div[@id="database-logs"]';
  await actions.click(page.locator(databaseLogsXPath));
  await waits.waitForNetworkIdle();
  
  const deadlockEntriesXPath = '//div[@class="log-entry"][contains(., "deadlock")]';
  const deadlockCount = await page.locator(deadlockEntriesXPath).count();
  
  expect(deadlockCount).toBe(0);
});

// TODO: Replace XPath with Object Repository when available
Then('random sample of {int} notifications should contain correct schedule change details', async function (sampleSize: number) {
  const sampleNotificationsXPath = '//button[@id="sample-notifications"]';
  await actions.click(page.locator(sampleNotificationsXPath));
  await waits.waitForNetworkIdle();
  
  const sampleSizeInputXPath = '//input[@id="sample-size"]';
  await actions.fill(page.locator(sampleSizeInputXPath), sampleSize.toString());
  
  const generateSampleXPath = '//button[@id="generate-sample"]';
  await actions.click(page.locator(generateSampleXPath));
  await waits.waitForNetworkIdle();
  
  const sampleNotificationItemsXPath = '//div[@class="sample-notification-item"]';
  const sampleCount = await page.locator(sampleNotificationItemsXPath).count();
  
  expect(sampleCount).toBe(sampleSize);
  
  for (let i = 0; i < sampleCount; i++) {
    const notificationContent = await page.locator(sampleNotificationItemsXPath).nth(i).textContent();
    expect(notificationContent).toContain('schedule');
  }
});

// TODO: Replace XPath with Object Repository when available
Then('no notifications should be lost', async function () {
  const expectedNotificationsXPath = '//span[@id="expected-notifications-count"]';
  const expectedCount = parseInt(await page.locator(expectedNotificationsXPath).textContent() || '0');
  
  const deliveredNotificationsXPath = '//span[@id="delivered-notifications-count"]';
  const deliveredCount = parseInt(await page.locator(deliveredNotificationsXPath).textContent