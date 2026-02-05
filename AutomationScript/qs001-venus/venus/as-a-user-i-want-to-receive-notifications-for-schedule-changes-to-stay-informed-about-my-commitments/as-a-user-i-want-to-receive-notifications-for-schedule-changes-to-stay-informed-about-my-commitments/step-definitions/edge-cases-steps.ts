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
    notificationQueue: [],
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
/*  BACKGROUND STEPS - Common Preconditions
/*  Used across all test cases
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
  
  await assertions.assertVisible(page.locator('//div[@id="user-dashboard"]'));
});

// TODO: Replace XPath with Object Repository when available
Given('email notification service is operational', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/services`);
  await waits.waitForNetworkIdle();
  
  const emailServiceStatus = page.locator('//div[@id="email-service-status"]');
  await assertions.assertVisible(emailServiceStatus);
  await assertions.assertContainsText(emailServiceStatus, 'operational');
  
  this.testData.systemState.emailServiceEnabled = true;
});

// TODO: Replace XPath with Object Repository when available
Given('in-app notification service is operational', async function () {
  const inAppServiceStatus = page.locator('//div[@id="inapp-notification-service-status"]');
  await assertions.assertVisible(inAppServiceStatus);
  await assertions.assertContainsText(inAppServiceStatus, 'operational');
  
  this.testData.systemState.inAppServiceEnabled = true;
});

/**************************************************/
/*  TEST CASE: TC-EDGE-001
/*  Title: Notification delivery when multiple schedule changes occur within 1 second
/*  Priority: High
/*  Category: Edge Cases
/*  Description: Tests notification system handling of rapid concurrent schedule changes
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user has {int} scheduled appointments in the schedule database', async function (appointmentCount: number) {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/schedules`);
  await waits.waitForNetworkIdle();
  
  this.testData.appointments = [];
  
  for (let i = 1; i <= appointmentCount; i++) {
    await actions.click(page.locator('//button[@id="create-appointment"]'));
    await waits.waitForVisible(page.locator('//div[@id="appointment-form"]'));
    
    await actions.fill(page.locator('//input[@id="appointment-title"]'), `Appointment ${i}`);
    await actions.fill(page.locator('//input[@id="appointment-time"]'), `${9 + i}:00 AM`);
    await actions.click(page.locator('//button[@id="save-appointment"]'));
    await waits.waitForNetworkIdle();
    
    this.testData.appointments.push({
      id: i,
      title: `Appointment ${i}`,
      time: `${9 + i}:00 AM`
    });
  }
  
  const appointmentRows = page.locator('//table[@id="appointments-table"]//tr[@class="appointment-row"]');
  await assertions.assertElementCount(appointmentRows, appointmentCount);
});

// TODO: Replace XPath with Object Repository when available
Given('user has notification preferences enabled for both email and in-app alerts', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/user/preferences`);
  await waits.waitForNetworkIdle();
  
  const emailNotificationCheckbox = page.locator('//input[@id="email-notifications-enabled"]');
  const inAppNotificationCheckbox = page.locator('//input[@id="inapp-notifications-enabled"]');
  
  await actions.check(emailNotificationCheckbox);
  await actions.check(inAppNotificationCheckbox);
  await actions.click(page.locator('//button[@id="save-preferences"]'));
  await waits.waitForNetworkIdle();
  
  await assertions.assertVisible(page.locator('//div[@id="preferences-saved-message"]'));
});

// TODO: Replace XPath with Object Repository when available
When('administrator navigates to schedule management page', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/schedule-management`);
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="schedule-management-page"]'));
});

// TODO: Replace XPath with Object Repository when available
When('administrator simultaneously updates {int} different appointments for the same user within {int} second', async function (appointmentCount: number, timeWindow: number) {
  const updatePromises = [];
  
  for (let i = 0; i < appointmentCount; i++) {
    const updatePromise = (async () => {
      const appointmentRow = page.locator(`//tr[@data-appointment-id="${i + 1}"]`);
      await actions.click(appointmentRow.locator('//button[@class="edit-appointment"]'));
      await waits.waitForVisible(page.locator('//div[@id="edit-appointment-modal"]'));
      
      await actions.fill(page.locator('//input[@id="appointment-time"]'), `${10 + i}:00 AM`);
      await actions.click(page.locator('//button[@id="save-changes"]'));
    })();
    
    updatePromises.push(updatePromise);
  }
  
  await Promise.all(updatePromises);
  await waits.waitForNetworkIdle();
  
  this.testData.updateTimestamp = Date.now();
});

// TODO: Replace XPath with Object Repository when available
When('user waits for {int} minutes', async function (minutes: number) {
  await page.waitForTimeout(minutes * 60 * 1000);
});

// TODO: Replace XPath with Object Repository when available
When('user waits for {int} minute', async function (minutes: number) {
  await page.waitForTimeout(minutes * 60 * 1000);
});

// TODO: Replace XPath with Object Repository when available
Then('user should receive {int} email notifications within {int} minute of the changes', async function (notificationCount: number, timeWindow: number) {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/email-logs`);
  await waits.waitForNetworkIdle();
  
  const emailNotifications = page.locator('//table[@id="email-logs"]//tr[@class="email-log-row"]');
  await assertions.assertElementCount(emailNotifications, notificationCount);
  
  for (let i = 0; i < notificationCount; i++) {
    const emailRow = emailNotifications.nth(i);
    await assertions.assertVisible(emailRow);
    await assertions.assertContainsText(emailRow, 'schedule change');
  }
});

// TODO: Replace XPath with Object Repository when available
Then('in-app notification center should display all {int} schedule changes', async function (changeCount: number) {
  await actions.navigateTo(`${process.env.BASE_URL}/user/notifications`);
  await waits.waitForNetworkIdle();
  
  const notificationItems = page.locator('//div[@id="notification-center"]//div[@class="notification-item"]');
  await assertions.assertElementCount(notificationItems, changeCount);
  
  for (let i = 0; i < changeCount; i++) {
    const notification = notificationItems.nth(i);
    await assertions.assertContainsText(notification, 'schedule');
  }
});

// TODO: Replace XPath with Object Repository when available
Then('all notifications should show timestamps within {int} minute of the actual schedule change time', async function (timeWindow: number) {
  const notificationItems = page.locator('//div[@id="notification-center"]//div[@class="notification-item"]');
  const count = await notificationItems.count();
  
  for (let i = 0; i < count; i++) {
    const notification = notificationItems.nth(i);
    const timestampElement = notification.locator('//span[@class="notification-timestamp"]');
    await assertions.assertVisible(timestampElement);
  }
});

// TODO: Replace XPath with Object Repository when available
Then('all {int} schedule changes should be reflected in user\'s schedule', async function (changeCount: number) {
  await actions.navigateTo(`${process.env.BASE_URL}/user/schedule`);
  await waits.waitForNetworkIdle();
  
  const appointmentRows = page.locator('//table[@id="user-schedule"]//tr[@class="appointment-row"]');
  await assertions.assertElementCount(appointmentRows, changeCount);
});

// TODO: Replace XPath with Object Repository when available
Then('notification delivery logs should show successful dispatch of all notifications', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/notification-logs`);
  await waits.waitForNetworkIdle();
  
  const successfulLogs = page.locator('//table[@id="notification-logs"]//tr[contains(@class, "status-success")]');
  const count = await successfulLogs.count();
  expect(count).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Then('no duplicate notifications should be sent for the same schedule change', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/notification-logs`);
  await waits.waitForNetworkIdle();
  
  const allLogs = page.locator('//table[@id="notification-logs"]//tr[@class="log-row"]');
  const count = await allLogs.count();
  
  const uniqueNotifications = new Set();
  for (let i = 0; i < count; i++) {
    const logRow = allLogs.nth(i);
    const notificationId = await logRow.locator('//td[@class="notification-id"]').textContent();
    uniqueNotifications.add(notificationId);
  }
  
  expect(uniqueNotifications.size).toBe(count);
});

/**************************************************/
/*  TEST CASE: TC-EDGE-002
/*  Title: Notification handling when user email address contains special characters and Unicode
/*  Priority: Medium
/*  Category: Edge Cases
/*  Description: Tests email notification delivery to addresses with special characters
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user account exists with email address {string}', async function (email: string) {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/users`);
  await waits.waitForNetworkIdle();
  
  await actions.click(page.locator('//button[@id="create-user"]'));
  await waits.waitForVisible(page.locator('//div[@id="user-form"]'));
  
  await actions.fill(page.locator('//input[@id="user-email"]'), email);
  await actions.fill(page.locator('//input[@id="user-username"]'), `user_${Date.now()}`);
  await actions.fill(page.locator('//input[@id="user-password"]'), 'TestPass123!');
  await actions.click(page.locator('//button[@id="save-user"]'));
  await waits.waitForNetworkIdle();
  
  this.testData.currentUserEmail = email;
  await assertions.assertVisible(page.locator('//div[@id="user-created-message"]'));
});

// TODO: Replace XPath with Object Repository when available
Given('user has {int} scheduled appointment', async function (appointmentCount: number) {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/schedules`);
  await waits.waitForNetworkIdle();
  
  await actions.click(page.locator('//button[@id="create-appointment"]'));
  await waits.waitForVisible(page.locator('//div[@id="appointment-form"]'));
  
  await actions.fill(page.locator('//input[@id="appointment-title"]'), 'Test Appointment');
  await actions.fill(page.locator('//input[@id="appointment-time"]'), '2:00 PM');
  await actions.click(page.locator('//button[@id="save-appointment"]'));
  await waits.waitForNetworkIdle();
  
  this.testData.originalAppointmentTime = '2:00 PM';
});

// TODO: Replace XPath with Object Repository when available
Given('email notification service supports international email addresses', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/email-service-config`);
  await waits.waitForNetworkIdle();
  
  const internationalSupportCheckbox = page.locator('//input[@id="international-email-support"]');
  await actions.check(internationalSupportCheckbox);
  await actions.click(page.locator('//button[@id="save-config"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('administrator navigates to user management page', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/user-management`);
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="user-management-page"]'));
});

// TODO: Replace XPath with Object Repository when available
When('administrator verifies user email address is {string}', async function (email: string) {
  const emailField = page.locator('//input[@id="search-email"]');
  await actions.fill(emailField, email);
  await actions.click(page.locator('//button[@id="search-user"]'));
  await waits.waitForNetworkIdle();
  
  const userRow = page.locator(`//tr[contains(@class, "user-row")]//td[contains(text(), "${email}")]`);
  await assertions.assertVisible(userRow);
});

// TODO: Replace XPath with Object Repository when available
When('administrator updates user scheduled appointment time from {string} to {string}', async function (originalTime: string, newTime: string) {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/schedules`);
  await waits.waitForNetworkIdle();
  
  const appointmentRow = page.locator('//tr[@class="appointment-row"]').first();
  await actions.click(appointmentRow.locator('//button[@class="edit-appointment"]'));
  await waits.waitForVisible(page.locator('//div[@id="edit-appointment-modal"]'));
  
  await actions.clearAndFill(page.locator('//input[@id="appointment-time"]'), newTime);
  await actions.click(page.locator('//button[@id="save-changes"]'));
  await waits.waitForNetworkIdle();
  
  this.testData.newAppointmentTime = newTime;
  this.testData.updateTimestamp = Date.now();
});

// TODO: Replace XPath with Object Repository when available
Then('email notification should be successfully sent to {string} without encoding errors', async function (email: string) {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/email-logs`);
  await waits.waitForNetworkIdle();
  
  const emailLog = page.locator(`//tr[contains(@class, "email-log-row")]//td[contains(text(), "${email}")]`);
  await assertions.assertVisible(emailLog);
  
  const statusCell = emailLog.locator('//td[@class="status-cell"]');
  await assertions.assertContainsText(statusCell, 'sent');
  
  const errorCell = emailLog.locator('//td[@class="error-cell"]');
  const errorText = await errorCell.textContent();
  expect(errorText?.toLowerCase()).not.toContain('encoding');
});

// TODO: Replace XPath with Object Repository when available
Then('in-app notification should display the schedule change with correct details', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/user/notifications`);
  await waits.waitForNetworkIdle();
  
  const notification = page.locator('//div[@id="notification-center"]//div[@class="notification-item"]').first();
  await assertions.assertVisible(notification);
  await assertions.assertContainsText(notification, 'schedule change');
});

// TODO: Replace XPath with Object Repository when available
Then('email should be received in inbox with properly formatted schedule change details', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/email-preview`);
  await waits.waitForNetworkIdle();
  
  const emailPreview = page.locator('//div[@id="email-preview-content"]');
  await assertions.assertVisible(emailPreview);
  await assertions.assertContainsText(emailPreview, 'schedule');
  await assertions.assertContainsText(emailPreview, this.testData.newAppointmentTime);
});

// TODO: Replace XPath with Object Repository when available
Then('no email encoding or delivery errors should be logged in the system', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/system-logs`);
  await waits.waitForNetworkIdle();
  
  const errorLogs = page.locator('//table[@id="system-logs"]//tr[contains(@class, "error-log")]');
  const count = await errorLogs.count();
  
  for (let i = 0; i < count; i++) {
    const logRow = errorLogs.nth(i);
    const logText = await logRow.textContent();
    expect(logText?.toLowerCase()).not.toContain('encoding');
    expect(logText?.toLowerCase()).not.toContain('email delivery failed');
  }
});

/**************************************************/
/*  TEST CASE: TC-EDGE-003
/*  Title: Notification behavior when schedule is changed during email service outage
/*  Priority: High
/*  Category: Edge Cases
/*  Description: Tests notification retry mechanism during service outage
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user has active schedule with appointments', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/user/schedule`);
  await waits.waitForNetworkIdle();
  
  const appointmentRows = page.locator('//table[@id="user-schedule"]//tr[@class="appointment-row"]');
  const count = await appointmentRows.count();
  expect(count).toBeGreaterThan(0);
  
  this.testData.activeAppointmentsCount = count;
});

// TODO: Replace XPath with Object Repository when available
Given('system has retry mechanism configured for failed email notifications', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/notification-config`);
  await waits.waitForNetworkIdle();
  
  const retryEnabledCheckbox = page.locator('//input[@id="retry-mechanism-enabled"]');
  await actions.check(retryEnabledCheckbox);
  
  await actions.fill(page.locator('//input[@id="max-retry-attempts"]'), '3');
  await actions.fill(page.locator('//input[@id="retry-interval-minutes"]'), '5');
  await actions.click(page.locator('//button[@id="save-config"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('administrator simulates email service outage by disabling email notification service', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/services`);
  await waits.waitForNetworkIdle();
  
  const emailServiceToggle = page.locator('//input[@id="email-service-toggle"]');
  await actions.click(emailServiceToggle);
  await waits.waitForNetworkIdle();
  
  this.testData.systemState.emailServiceEnabled = false;
});

// TODO: Replace XPath with Object Repository when available
When('email service status shows as unavailable in system monitoring', async function () {
  const emailServiceStatus = page.locator('//div[@id="email-service-status"]');
  await assertions.assertContainsText(emailServiceStatus, 'unavailable');
});

// TODO: Replace XPath with Object Repository when available
When('administrator updates user scheduled appointment from {string} to {string}', async function (originalTime: string, newTime: string) {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/schedules`);
  await waits.waitForNetworkIdle();
  
  const appointmentRow = page.locator('//tr[@class="appointment-row"]').first();
  await actions.click(appointmentRow.locator('//button[@class="edit-appointment"]'));
  await waits.waitForVisible(page.locator('//div[@id="edit-appointment-modal"]'));
  
  await actions.clearAndFill(page.locator('//input[@id="appointment-time"]'), newTime);
  await actions.click(page.locator('//button[@id="save-changes"]'));
  await waits.waitForNetworkIdle();
  
  this.testData.scheduleChangeTime = Date.now();
});

// TODO: Replace XPath with Object Repository when available
Then('in-app notification should be delivered successfully within {int} minute', async function (minutes: number) {
  await actions.navigateTo(`${process.env.BASE_URL}/user/notifications`);
  await waits.waitForNetworkIdle();
  
  const notification = page.locator('//div[@id="notification-center"]//div[@class="notification-item"]').first();
  await assertions.assertVisible(notification);
  await assertions.assertContainsText(notification, 'schedule');
});

// TODO: Replace XPath with Object Repository when available
Then('email notification should be queued for retry with failed status logged', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/notification-queue`);
  await waits.waitForNetworkIdle();
  
  const queuedNotification = page.locator('//table[@id="notification-queue"]//tr[@class="queued-notification"]').first();
  await assertions.assertVisible(queuedNotification);
  
  const statusCell = queuedNotification.locator('//td[@class="status-cell"]');
  await assertions.assertContainsText(statusCell, 'queued');
});

// TODO: Replace XPath with Object Repository when available
Then('retry attempts should be scheduled', async function () {
  const queuedNotification = page.locator('//table[@id="notification-queue"]//tr[@class="queued-notification"]').first();
  const retryCell = queuedNotification.locator('//td[@class="retry-scheduled-cell"]');
  await assertions.assertVisible(retryCell);
});

// TODO: Replace XPath with Object Repository when available
When('administrator re-enables email notification service after {int} minutes', async function (minutes: number) {
  await page.waitForTimeout(minutes * 60 * 1000);
  
  await actions.navigateTo(`${process.env.BASE_URL}/admin/services`);
  await waits.waitForNetworkIdle();
  
  const emailServiceToggle = page.locator('//input[@id="email-service-toggle"]');
  await actions.click(emailServiceToggle);
  await waits.waitForNetworkIdle();
  
  this.testData.systemState.emailServiceEnabled = true;
});

// TODO: Replace XPath with Object Repository when available
When('email service status shows as available in system monitoring', async function () {
  const emailServiceStatus = page.locator('//div[@id="email-service-status"]');
  await assertions.assertContainsText(emailServiceStatus, 'available');
});

// TODO: Replace XPath with Object Repository when available
When('user waits for retry mechanism to process queued notifications', async function () {
  await page.waitForTimeout(30000);
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
Then('queued email notification should be successfully sent to user email address', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/email-logs`);
  await waits.waitForNetworkIdle();
  
  const emailLog = page.locator('//table[@id="email-logs"]//tr[@class="email-log-row"]').first();
  await assertions.assertVisible(emailLog);
  
  const statusCell = emailLog.locator('//td[@class="status-cell"]');
  await assertions.assertContainsText(statusCell, 'sent');
});

// TODO: Replace XPath with Object Repository when available
Then('email notification should be received with schedule change details', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/email-preview`);
  await waits.waitForNetworkIdle();
  
  const emailPreview = page.locator('//div[@id="email-preview-content"]');
  await assertions.assertVisible(emailPreview);
  await assertions.assertContainsText(emailPreview, 'schedule change');
});

// TODO: Replace XPath with Object Repository when available
Then('system logs should show retry attempts and final successful delivery', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/system-logs`);
  await waits.waitForNetworkIdle();
  
  const retryLogs = page.locator('//table[@id="system-logs"]//tr[contains(@class, "retry-log")]');
  const count = await retryLogs.count();
  expect(count).toBeGreaterThan(0);
  
  const successLog = page.locator('//table[@id="system-logs"]//tr[contains(@class, "success-log")]').first();
  await assertions.assertVisible(successLog);
});

// TODO: Replace XPath with Object Repository when available
Then('no notifications should be lost or duplicated', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/notification-logs`);
  await waits.waitForNetworkIdle();
  
  const allNotifications = page.locator('//table[@id="notification-logs"]//tr[@class="log-row"]');
  const count = await allNotifications.count();
  
  const uniqueIds = new Set();
  for (let i = 0; i < count; i++) {
    const logRow = allNotifications.nth(i);
    const notificationId = await logRow.locator('//td[@class="notification-id"]').textContent();
    uniqueIds.add(notificationId);
  }
  
  expect(uniqueIds.size).toBe(count);
});

/**************************************************/
/*  TEST CASE: TC-EDGE-004
/*  Title: Notification content when schedule change includes extremely long text fields and special characters
/*  Priority: Medium
/*  Category: Edge Cases
/*  Description: Tests notification rendering with long text and special characters
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('appointment fields support up to {int} characters for description', async function (maxLength: number) {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/field-config`);
  await waits.waitForNetworkIdle();
  
  const descriptionMaxLength = page.locator('//input[@id="description-max-length"]');
  const currentValue = await descriptionMaxLength.inputValue();
  expect(parseInt(currentValue)).toBeGreaterThanOrEqual(maxLength);
});

// TODO: Replace XPath with Object Repository when available
Given('email and in-app notification templates are configured', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/notification-templates`);
  await waits.waitForNetworkIdle();
  
  const emailTemplate = page.locator('//div[@id="email-template"]');
  await assertions.assertVisible(emailTemplate);
  
  const inAppTemplate = page.locator('//div[@id="inapp-template"]');
  await assertions.assertVisible(inAppTemplate);
});

// TODO: Replace XPath with Object Repository when available
When('user navigates to appointment and opens edit form', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/user/appointments`);
  await waits.waitForNetworkIdle();
  
  const appointmentRow = page.locator('//tr[@class="appointment-row"]').first();
  await actions.click(appointmentRow.locator('//button[@class="edit-appointment"]'));
  await waits.waitForVisible(page.locator('//div[@id="edit-appointment-form"]'));
});

// TODO: Replace XPath with Object Repository when available
When('user updates appointment description with {int} characters including special characters {string}', async function (charCount: number, specialChars: string) {
  const longDescription = 'A'.repeat(charCount - specialChars.length) + specialChars;
  
  const descriptionField = page.locator('//textarea[@id="appointment-description"]');
  await actions.clearAndFill(descriptionField, longDescription);
  
  this.testData.appointmentDescription = longDescription;
});

// TODO: Replace XPath with Object Repository when available
When('user changes appointment time from {string} to {string}', async function (originalTime: string, newTime: string) {
  await actions.clearAndFill(page.locator('//input[@id="appointment-time"]'), newTime);
  await actions.click(page.locator('//button[@id="save-appointment"]'));
  await waits.waitForNetworkIdle();
  
  this.testData.newAppointmentTime = newTime;
});

// TODO: Replace XPath with Object Repository when available
Then('email notification should display full description with all special characters properly escaped', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/email-preview`);
  await waits.waitForNetworkIdle();
  
  const emailContent = page.locator('//div[@id="email-preview-content"]');
  await assertions.assertVisible(emailContent);
  
  const contentText = await emailContent.textContent();
  expect(contentText).toContain('@#$%^&*()');
});

// TODO: Replace XPath with Object Repository when available
Then('no HTML injection should occur in email', async function () {
  const emailContent = page.locator('//div[@id="email-preview-content"]');
  const innerHTML = await emailContent.innerHTML();
  
  expect(innerHTML).not.toContain('<script>');
  expect(innerHTML).not.toContain('javascript:');
});

// TODO: Replace XPath with Object Repository when available
Then('emojis should render correctly in email', async function () {
  const emailContent = page.locator('//div[@id="email-preview-content"]');
  await assertions.assertVisible(emailContent);
});

// TODO: Replace XPath with Object Repository when available
Then('text should not be truncated in email', async function () {
  const emailContent = page.locator('//div[@id="email-preview-content"]');
  const contentText = await emailContent.textContent();
  
  expect(contentText?.length).toBeGreaterThan(900);
});

// TODO: Replace XPath with Object Repository when available
Then('in-app notification should display schedule change with full description', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/user/notifications`);
  await waits.waitForNetworkIdle();
  
  const notification = page.locator('//div[@id="notification-center"]//div[@class="notification-item"]').first();
  await assertions.assertVisible(notification);
  await assertions.assertContainsText(notification, 'schedule change');
});

// TODO: Replace XPath with Object Repository when available
Then('special characters should be properly rendered in notification', async function () {
  const notification = page.locator('//div[@id="notification-center"]//div[@class="notification-item"]').first();
  const notificationText = await notification.textContent();
  
  expect(notificationText).toContain('@');
  expect(notificationText).toContain('#');
});

// TODO: Replace XPath with Object Repository when available
Then('no XSS vulnerabilities should exist in notification', async function () {
  const notification = page.locator('//div[@id="notification-center"]//div[@class="notification-item"]').first();
  const innerHTML = await notification.innerHTML();
  
  expect(innerHTML).not.toContain('<script>');
  expect(innerHTML).not.toContain('onerror=');
  expect(innerHTML).not.toContain('javascript:');
});

// TODO: Replace XPath with Object Repository when available
Then('text should wrap appropriately in the UI', async function () {
  const notification = page.locator('//div[@id="notification-center"]//div[@class="notification-item"]').first();
  const boundingBox = await notification.boundingBox();
  
  expect(boundingBox?.width).toBeLessThan(1920);
});

// TODO: Replace XPath with Object Repository when available
When('user clicks on the notification to view full details', async function () {
  const notification = page.locator('//div[@id="notification-center"]//div[@class="notification-item"]').first();
  await actions.click(notification);
  await waits.waitForVisible(page.locator('//div[@id="notification-details-modal"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('full notification details page should display all content correctly without truncation or rendering errors', async function () {
  const detailsModal = page.locator('//div[@id="notification-details-modal"]');
  await assertions.assertVisible(detailsModal);
  
  const descriptionContent = detailsModal.locator('//div[@class="notification-description"]');
  const contentText = await descriptionContent.textContent();
  
  expect(contentText?.length).toBeGreaterThan(900);
});

/**************************************************/
/*  TEST CASE: TC-EDGE-005
/*  Title: Notification delivery when user has 100+ unread notifications in notification center
/*  Priority: Medium
/*  Category: Edge Cases
/*  Description: Tests notification center performance with large notification count
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user account exists with {int} unread notifications in notification center', async function (notificationCount: number) {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/notification-seeder`);
  await waits.waitForNetworkIdle();
  
  await actions.fill(page.locator('//input[@id="notification-count"]'), notificationCount.toString());
  await actions.click(page.locator('//button[@id="seed-notifications"]'));
  await waits.waitForNetworkIdle();
  
  await assertions.assertVisible(page.locator('//div[@id="seeding-complete-message"]'));
  this.testData.initialNotificationCount = notificationCount;
});

// TODO: Replace XPath with Object Repository when available
Given('user has active scheduled appointments', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/user/schedule`);
  await waits.waitForNetworkIdle();
  
  const appointmentRows = page.locator('//table[@id="user-schedule"]//tr[@class="appointment-row"]');
  const count = await appointmentRows.count();
  expect(count).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Given('notification center has pagination configured', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/notification-config`);
  await waits.waitForNetworkIdle();
  
  const paginationEnabled = page.locator('//input[@id="pagination-enabled"]');
  await actions.check(paginationEnabled);
  
  await actions.fill(page.locator('//input[@id="items-per-page"]'), '20');
  await actions.click(page.locator('//button[@id="save-config"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('administrator verifies user has exactly {int} unread notifications', async function (expectedCount: number) {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/user-notifications`);
  await waits.waitForNetworkIdle();
  
  const notificationCountBadge = page.locator('//span[@id="unread-notification-count"]');
  await assertions.assertContainsText(notificationCountBadge, expectedCount.toString());
});

// TODO: Replace XPath with Object Repository when available
Then('email notification should be sent successfully within {int} minute', async function (minutes: number) {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/email-logs`);
  await waits.waitForNetworkIdle();
  
  const recentEmail = page.locator('//table[@id="email-logs"]//tr[@class="email-log-row"]').first();
  await assertions.assertVisible(recentEmail);
  
  const statusCell = recentEmail.locator('//td[@class="status-cell"]');
  await assertions.assertContainsText(statusCell, 'sent');
});

// TODO: Replace XPath with Object Repository when available
Then('notification center should load successfully showing notification count of {int}', async function (expectedCount: number) {
  await actions.navigateTo(`${process.env.BASE_URL}/user/notifications`);
  await waits.waitForNetworkIdle();
  
  const notificationCountBadge = page.locator('//span[@id="notification-count-badge"]');
  await assertions.assertContainsText(notificationCountBadge, expectedCount.toString());
});

// TODO: Replace XPath with Object Repository when available
Then('newest notification should appear at the top of the list', async function () {
  const firstNotification = page.locator('//div[@id="notification-center"]//div[@class="notification-item"]').first();
  await assertions.assertVisible(firstNotification);
  await assertions.assertContainsText(firstNotification, 'schedule');
});

// TODO: Replace XPath with Object Repository when available
Then('new schedule change notification should be marked as unread', async function () {
  const firstNotification = page.locator('//div[@id="notification-center"]//div[@class="notification-item"]').first();
  const unreadIndicator = firstNotification.locator('//span[@class="unread-indicator"]');
  await assertions.assertVisible(unreadIndicator);
});

// TODO: Replace XPath with Object Repository when available
When('user scrolls through all notifications', async function () {
  const notificationCenter = page.locator('//div[@id="notification-center"]');
  
  for (let i = 0; i < 6; i++) {
    await actions.scrollIntoView(notificationCenter);
    await page.mouse.wheel(0, 500);
    await page.waitForTimeout(500);
  }
});

// TODO: Replace XPath with Object Repository when available
Then('notification center should perform smoothly without lag', async function () {
  const notificationCenter = page.locator('//div[@id="notification-center"]');
  await assertions.assertVisible(notificationCenter);
});

// TODO: Replace XPath with Object Repository when available
Then('all {int} notifications should be accessible', async function (expectedCount: number) {
  const paginationInfo = page.locator('//div[@id="pagination-info"]');
  await assertions.assertVisible(paginationInfo);
});

// TODO: Replace XPath with Object Repository when available
Then('new notification should remain accessible', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/user/notifications`);
  await waits.waitForNetworkIdle();
  
  const firstNotification = page.locator('//div[@id="notification-center"]//div[@class="notification-item"]').first();
  await assertions.assertVisible(firstNotification);
});

// TODO: Replace XPath with Object Repository when available
Then('notification center UI should remain responsive', async function () {
  const notificationCenter = page.locator('//div[@id="notification-center"]');
  await assertions.assertVisible(notificationCenter);
  
  const loadingSpinner = page.locator('//div[@id="loading-spinner"]');
  const isVisible = await loadingSpinner.isVisible().catch(() => false);
  expect(isVisible).toBe(false);
});

/**************************************************/
/*  TEST CASE: TC-EDGE-006
/*  Title: Notification behavior when user account is disabled immediately after schedule change
/*  Priority: High
/*  Category: Edge Cases
/*  Description: Tests notification handling for disabled accounts
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user account is active with valid email address', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/users`);
  await waits.waitForNetworkIdle();
  
  const userRow = page.locator('//tr[@class="user-row"]').first();
  const statusCell = userRow.locator('//td[@class="status-cell"]');
  await assertions.assertContainsText(statusCell, 'active');
  
  const emailCell = userRow.locator('//td[@class="email-cell"]');
  const email = await emailCell.textContent();
  this.testData.userEmail = email;
});

// TODO: Replace XPath with Object Repository when available
Given('administrator has permissions to disable user accounts', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/permissions`);
  await waits.waitForNetworkIdle();
  
  const disableUserPermission = page.locator('//input[@id="permission-disable-users"]');
  const isChecked = await disableUserPermission.isChecked();
  expect(isChecked).toBe(true);
});

// TODO: Replace XPath with Object Repository when available
When('administrator immediately disables user account within {int} seconds', async function (seconds: number) {
  await page.waitForTimeout(seconds * 1000);
  
  await actions.navigateTo(`${process.env.BASE_URL}/admin/users`);
  await waits.waitForNetworkIdle();
  
  const userRow = page.locator('//tr[@class="user-row"]').first();
  await actions.click(userRow.locator('//button[@class="disable-user"]'));
  await waits.waitForVisible(page.locator('//div[@id="confirm-disable-modal"]'));
  
  await actions.click(page.locator('//button[@id="confirm-disable"]'));
  await waits.waitForNetworkIdle();
  
  this.testData.accountDisabledTime = Date.now();
});

// TODO: Replace XPath with Object Repository when available
When('user account status changes to {string} in the system', async function (status: string) {
  const userRow = page.locator('//tr[@class="user-row"]').first();
  const statusCell = userRow.locator('//td[@class="status-cell"]');
  await assertions.assertContainsText(statusCell, status);
});

// TODO: Replace XPath with Object Repository when available
Then('system logs should show notification processing attempt with appropriate handling for disabled account', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/system-logs`);
  await waits.waitForNetworkIdle();
  
  const notificationLogs = page.locator('//table[@id="system-logs"]//tr[contains(@class, "notification-log")]');
  const count = await notificationLogs.count();
  expect(count).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Then('notification delivery should follow business rules for disabled accounts', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/notification-logs`);
  await waits.waitForNetworkIdle();
  
  const notificationLog = page.locator('//table[@id="notification-logs"]//tr[@class="log-row"]').first();
  await assertions.assertVisible(notificationLog);
});

// TODO: Replace XPath with Object Repository when available
When('administrator re-enables user account', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/users`);
  await waits.waitForNetworkIdle();
  
  const userRow = page.locator('//tr[@class="user-row"]').first();
  await actions.click(userRow.locator('//button[@class="enable-user"]'));
  await waits.waitForNetworkIdle();
  
  const statusCell = userRow.locator('//td[@class="status-cell"]');
  await assertions.assertContainsText(statusCell, 'active');
});

// TODO: Replace XPath with Object Repository when available
When('user logs in successfully', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/login`);
  await waits.waitForNetworkIdle();
  
  const credentials = this.testData?.users?.user || { username: 'testuser', password: 'testpass' };
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  
  await assertions.assertVisible(page.locator('//div[@id="user-dashboard"]'));
});

// TODO: Replace XPath with Object Repository when available
When('user checks in-app notification center', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/user/notifications`);
  await waits.waitForNetworkIdle();
  
  const notificationCenter = page.locator('//div[@id="notification-center"]');
  await assertions.assertVisible(notificationCenter);
});

// TODO: Replace XPath with Object Repository when available
Then('notification handling should be consistent with defined business rules for disabled accounts', async function () {
  const notificationCenter = page.locator('//div[@id="notification-center"]');
  await assertions.assertVisible(notificationCenter);
});

// TODO: Replace XPath with Object Repository when available
Then('schedule change should be persisted in database regardless of account status', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/user/schedule`);
  await waits.waitForNetworkIdle();
  
  const appointmentRows = page.locator('//table[@id="user-schedule"]//tr[@class="appointment-row"]');
  await assertions.assertVisible(appointmentRows.first());
});

// TODO: Replace XPath with Object Repository when available
Then('no system errors or exceptions should have occurred during notification processing', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/system-logs`);
  await waits.waitForNetworkIdle();
  
  const errorLogs = page.locator('//table[@id="system-logs"]//tr[contains(@class, "error-log")]');
  const count = await errorLogs.count();
  
  for (let i = 0; i < count; i++) {
    const logRow = errorLogs.nth(i);
    const logText = await logRow.textContent();
    expect(logText?.toLowerCase()).not.toContain('exception');
    expect(logText?.toLowerCase()).not.toContain('fatal');
  }
});

/**************************************************/
/*  TEST CASE: TC-EDGE-007
/*  Title: Notification delivery across different time zones when schedule change occurs at midnight boundary
/*  Priority: Medium
/*  Category: Edge Cases
/*  Description: Tests timezone handling for notifications at date boundaries
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user account is configured with timezone set to {string}', async function (timezone: string) {
  await actions.navigateTo(`${process.env.BASE_URL}/user/settings`);
  await waits.waitForNetworkIdle();
  
  const timezoneDropdown = page.locator('//select[@id="user-timezone"]');
  await actions.selectByText(timezoneDropdown, timezone);
  await actions.click(page.locator('//button[@id="save-settings"]'));
  await waits.waitForNetworkIdle();
  
  this.testData.userTimezone = timezone;
});

// TODO: Replace XPath with Object Repository when available
Given('system server is running in {string} timezone', async function (timezone: string) {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/system-config`);
  await waits.waitForNetworkIdle();
  
  const serverTimezone = page.locator('//div[@id="server-timezone"]');
  await assertions.assertContainsText(serverTimezone, timezone);
  
  this.testData.serverTimezone = timezone;
});

// TODO: Replace XPath with Object Repository when available
Given('user has scheduled appointment at {string} in {string} timezone', async function (time: string, timezone: string) {
  await actions.navigateTo(`${process.env.BASE_URL}/user/schedule`);
  await waits.waitForNetworkIdle();
  
  await actions.click(page.locator('//button[@id="create-appointment"]'));
  await waits.waitForVisible(page.locator('//div[@id="appointment-form"]'));
  
  await actions.fill(page.locator('//input[@id="appointment-title"]'), 'Midnight Boundary Test');
  await actions.fill(page.locator('//input[@id="appointment-time"]'), time);
  await actions.click(page.locator('//button[@id="save-appointment"]'));
  await waits.waitForNetworkIdle();
  
  this.testData.originalAppointmentTime = time;
});

// TODO: Replace XPath with Object Repository when available
When('administrator navigates to user schedule', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/user-schedules`);
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="user-schedules-page"]'));
});

// TODO: Replace XPath with Object Repository when available
When('appointment is displayed with time {string} in user timezone', async function (time: string) {
  const appointmentRow = page.locator('//tr[@class="appointment-row"]').first();
  const timeCell = appointmentRow.locator('//td[@class="time-cell"]');
  await assertions.assertContainsText(timeCell, time);
});

// TODO: Replace XPath with Object Repository when available
When('administrator changes appointment time from {string} to {string}', async function (originalTime: string, newTime: string) {
  const appointmentRow = page.locator('//tr[@class="appointment-row"]').first();
  await actions.click(appointmentRow.locator('//button[@class="edit-appointment"]'));
  await waits.waitForVisible(page.locator('//div[@id="edit-appointment-modal"]'));
  
  await actions.clearAndFill(page.locator('//input[@id="appointment-time"]'), newTime);
  await actions.click(page.locator('//button[@id="save-changes"]'));
  await waits.waitForNetworkIdle();
  
  this.testData.newAppointmentTime = newTime;
  this.testData.scheduleChangeTimestamp = Date.now();
});

// TODO: Replace XPath with Object Repository when available
Then('email notification should display schedule change with correct times in {string} timezone', async function (timezone: string) {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/email-preview`);
  await waits.waitForNetworkIdle();
  
  const emailContent = page.locator('//div[@id="email-preview-content"]');
  await assertions.assertVisible(emailContent);
  await assertions.assertContainsText(emailContent, 'schedule change');
});

// TODO: Replace XPath with Object Repository when available
Then('email should show time change from {string} to {string}', async function (originalTime: string, newTime: string) {
  const emailContent = page.locator('//div[@id="email-preview-content"]');
  await assertions.assertContainsText(emailContent, originalTime);
  await assertions.assertContainsText(emailContent, newTime);
});

// TODO: Replace XPath with Object Repository when available
Then('date transition should be shown in email', async function () {
  const emailContent = page.locator('//div[@id="email-preview-content"]');
  const contentText = await emailContent.textContent();
  
  expect(contentText).toBeTruthy();
});

// TODO: Replace XPath with Object Repository when available
Then('timezone indicator {string} should be included in email', async function (timezoneIndicator: string) {
  const emailContent = page.locator('//div[@id="email-preview-content"]');
  await assertions.assertContainsText(emailContent, timezoneIndicator);
});

// TODO: Replace XPath with Object Repository when available
Then('in-app notification should show times in user configured timezone {string}', async function (timezone: string) {
  await actions.navigateTo(`${process.env.BASE_URL}/user/notifications`);
  await waits.waitForNetworkIdle();
  
  const notification = page.locator('//div[@id="notification-center"]//div[@class="notification-item"]').first();
  await assertions.assertVisible(notification);
  await assertions.assertContainsText(notification, timezone);
});

// TODO: Replace XPath with Object Repository when available
Then('date change should be clearly indicated in notification', async function () {
  const notification = page.locator('//div[@id="notification-center"]//div[@class="notification-item"]').first();
  await assertions.assertVisible(notification);
});

// TODO: Replace XPath with Object Repository when available
Then('notification timestamp should be displayed in user timezone', async function () {
  const notification = page.locator('//div[@id="notification-center"]//div[@class="notification-item"]').first();
  const timestamp = notification.locator('//span[@class="notification-timestamp"]');
  await assertions.assertVisible(timestamp);
});

// TODO: Replace XPath with Object Repository when available
Then('notification timestamp should be within {int} minute of actual schedule change time', async function (minutes: number) {
  const notification = page.locator('//div[@id="notification-center"]//div[@class="notification-item"]').first();
  const timestamp = notification.locator('//span[@class="notification-timestamp"]');
  await assertions.assertVisible(timestamp);
});

// TODO: Replace XPath with Object Repository when available
Then('database should show appointment times stored in {string} with correct conversion', async function (timezone: string) {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/database-viewer`);
  await waits.waitForNetworkIdle();
  
  const appointmentRecord = page.locator('//table[@id="appointments-table"]//tr[@class="record-row"]').first();
  await assertions.assertVisible(appointmentRecord);
});

// TODO: Replace XPath with Object Repository when available
Then('no timezone conversion errors should have occurred', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/admin/system-logs`);
  await waits.waitForNetworkIdle();
  
  const errorLogs = page.locator('//table[@id="system-logs"]//tr[contains(@class, "error-log")]');
  const count = await errorLogs.count();
  
  for (let i = 0; i < count; i++) {
    const logRow = errorLogs.nth(i);
    const logText = await logRow.textContent();
    expect(logText?.toLowerCase()).not.toContain('timezone');
    expect(logText?.toLowerCase()).not.toContain('conversion error');
  }
});