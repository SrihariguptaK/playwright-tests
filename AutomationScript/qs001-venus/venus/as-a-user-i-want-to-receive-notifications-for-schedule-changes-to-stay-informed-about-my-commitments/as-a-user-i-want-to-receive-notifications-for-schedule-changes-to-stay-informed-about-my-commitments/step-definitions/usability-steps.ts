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
    appointments: {
      default: { title: 'Team Meeting', location: 'Conference Room A', organizer: 'John Doe' }
    }
  };
  
  this.notificationData = {};
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

/**************************************************/
/*  BACKGROUND STEPS - Common Preconditions
/*  Used across multiple test cases
/**************************************************/

Given('user account is active and authenticated', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  const credentials = this.testData?.users?.user || { username: 'testuser', password: 'testpass' };
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="user-dashboard"]'));
});

Given('notification service is operational', async function () {
  await assertions.assertVisible(page.locator('//div[@id="notification-service-status"]'));
  const statusText = await page.locator('//div[@id="notification-service-status"]').textContent();
  expect(statusText).toContain('operational');
});

/**************************************************/
/*  TEST CASE: TC-001
/*  Title: Real-time notification delivery with complete schedule change details
/*  Priority: Critical
/*  Category: Usability - Smoke
/**************************************************/

Given('user has at least one scheduled appointment in the system', async function () {
  await actions.click(page.locator('//button[@id="appointments"]'));
  await waits.waitForNetworkIdle();
  const appointmentCount = await page.locator('//div[@class="appointment-item"]').count();
  if (appointmentCount === 0) {
    await actions.click(page.locator('//button[@id="create-appointment"]'));
    await actions.fill(page.locator('//input[@id="appointment-title"]'), 'Team Meeting');
    await actions.fill(page.locator('//input[@id="appointment-time"]'), '2:00 PM');
    await actions.click(page.locator('//button[@id="save-appointment"]'));
    await waits.waitForNetworkIdle();
  }
  this.systemState.appointmentExists = true;
});

Given('notification preferences are enabled for both email and in-app alerts', async function () {
  await actions.click(page.locator('//button[@id="settings"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//a[@id="notification-settings"]'));
  await waits.waitForNetworkIdle();
  const emailCheckbox = page.locator('//input[@id="email-notifications"]');
  const inAppCheckbox = page.locator('//input[@id="inapp-notifications"]');
  if (!(await emailCheckbox.isChecked())) {
    await actions.check(emailCheckbox);
  }
  if (!(await inAppCheckbox.isChecked())) {
    await actions.check(inAppCheckbox);
  }
  await actions.click(page.locator('//button[@id="save-settings"]'));
  await waits.waitForNetworkIdle();
  this.systemState.emailEnabled = true;
  this.systemState.inAppEnabled = true;
});

Given('user has an appointment scheduled at {string}', async function (appointmentTime: string) {
  await actions.click(page.locator('//button[@id="appointments"]'));
  await waits.waitForNetworkIdle();
  const existingAppointment = page.locator(`//div[@class="appointment-item" and contains(., "${appointmentTime}")]`);
  if (await existingAppointment.count() === 0) {
    await actions.click(page.locator('//button[@id="create-appointment"]'));
    await actions.fill(page.locator('//input[@id="appointment-title"]'), 'Team Meeting');
    await actions.fill(page.locator('//input[@id="appointment-time"]'), appointmentTime);
    await actions.click(page.locator('//button[@id="save-appointment"]'));
    await waits.waitForNetworkIdle();
  }
  this.notificationData.originalTime = appointmentTime;
});

/**************************************************/
/*  TEST CASE: TC-002
/*  Title: User control over notification preferences by channel
/*  Priority: High
/*  Category: Usability - Functional
/**************************************************/

Given('user is logged into the system', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  const credentials = this.testData?.users?.user || { username: 'testuser', password: 'testpass' };
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

Given('both email and in-app notification channels are enabled', async function () {
  await actions.click(page.locator('//button[@id="settings"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//a[@id="notification-settings"]'));
  await waits.waitForNetworkIdle();
  const emailCheckbox = page.locator('//input[@id="email-notifications"]');
  const inAppCheckbox = page.locator('//input[@id="inapp-notifications"]');
  if (!(await emailCheckbox.isChecked())) {
    await actions.check(emailCheckbox);
  }
  if (!(await inAppCheckbox.isChecked())) {
    await actions.check(inAppCheckbox);
  }
  await actions.click(page.locator('//button[@id="save-settings"]'));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-003
/*  Title: Undo dismissed notification within time window
/*  Priority: High
/*  Category: Usability - Functional
/**************************************************/

Given('user has {int} unread notifications', async function (notificationCount: number) {
  await actions.click(page.locator('//button[@id="notifications"]'));
  await waits.waitForNetworkIdle();
  const currentCount = await page.locator('//div[@class="notification-item unread"]').count();
  if (currentCount < notificationCount) {
    for (let i = currentCount; i < notificationCount; i++) {
      await actions.click(page.locator('//button[@id="create-test-notification"]'));
      await waits.waitForNetworkIdle();
    }
  }
  this.notificationData.unreadCount = notificationCount;
});

/**************************************************/
/*  TEST CASE: TC-004
/*  Title: Toggle notification read and unread status
/*  Priority: High
/*  Category: Usability - Functional
/**************************************************/

Given('user has at least one notification', async function () {
  await actions.click(page.locator('//button[@id="notifications"]'));
  await waits.waitForNetworkIdle();
  const notificationCount = await page.locator('//div[@class="notification-item"]').count();
  if (notificationCount === 0) {
    await actions.click(page.locator('//button[@id="create-test-notification"]'));
    await waits.waitForNetworkIdle();
  }
});

/**************************************************/
/*  TEST CASE: TC-005
/*  Title: Access recently dismissed notifications
/*  Priority: High
/*  Category: Usability - Functional
/**************************************************/

Given('user has dismissed notifications within {int} days', async function (days: number) {
  await actions.click(page.locator('//button[@id="notifications"]'));
  await waits.waitForNetworkIdle();
  const dismissedCount = await page.locator('//div[@class="notification-item dismissed"]').count();
  if (dismissedCount === 0) {
    await actions.click(page.locator('//button[@id="create-test-notification"]'));
    await waits.waitForNetworkIdle();
    await actions.click(page.locator('//button[@class="dismiss-notification"]').first());
    await waits.waitForNetworkIdle();
  }
  this.notificationData.dismissedWithinDays = days;
});

/**************************************************/
/*  TEST CASE: TC-006
/*  Title: Complete context visibility for schedule time change notification
/*  Priority: High
/*  Category: Usability - Recognition
/**************************************************/

Given('user has multiple appointments scheduled', async function () {
  await actions.click(page.locator('//button[@id="appointments"]'));
  await waits.waitForNetworkIdle();
  const appointmentCount = await page.locator('//div[@class="appointment-item"]').count();
  if (appointmentCount < 2) {
    for (let i = appointmentCount; i < 3; i++) {
      await actions.click(page.locator('//button[@id="create-appointment"]'));
      await actions.fill(page.locator('//input[@id="appointment-title"]'), `Meeting ${i + 1}`);
      await actions.fill(page.locator('//input[@id="appointment-time"]'), `${i + 2}:00 PM`);
      await actions.click(page.locator('//button[@id="save-appointment"]'));
      await waits.waitForNetworkIdle();
    }
  }
});

Given('user receives a notification about schedule time change', async function () {
  await actions.click(page.locator('//button[@id="appointments"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//div[@class="appointment-item"]').first());
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="appointment-time"]'), '4:00 PM');
  await actions.click(page.locator('//button[@id="save-appointment"]'));
  await waits.waitForNetworkIdle();
  this.notificationData.changeType = 'time_change';
});

/**************************************************/
/*  TEST CASE: TC-007
/*  Title: Clear cancelled appointment notification details
/*  Priority: High
/*  Category: Usability - Recognition
/**************************************************/

Given('user receives a notification about cancelled appointment', async function () {
  await actions.click(page.locator('//button[@id="appointments"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//div[@class="appointment-item"]').first());
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//button[@id="cancel-appointment"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//button[@id="confirm-cancel"]'));
  await waits.waitForNetworkIdle();
  this.notificationData.changeType = 'cancelled';
});

/**************************************************/
/*  TEST CASE: TC-008
/*  Title: Historical notifications retain full context
/*  Priority: High
/*  Category: Usability - Recognition
/**************************************************/

Given('user has notifications from {int} weeks ago', async function (weeks: number) {
  await actions.click(page.locator('//button[@id="notifications"]'));
  await waits.waitForNetworkIdle();
  const historicalNotifications = page.locator('//div[@class="notification-item historical"]');
  await assertions.assertVisible(historicalNotifications.first());
  this.notificationData.historicalWeeks = weeks;
});

/**************************************************/
/*  TEST CASE: TC-009
/*  Title: Expanded notification view with complete details and actions
/*  Priority: High
/*  Category: Usability - Recognition
/**************************************************/

/**************************************************/
/*  TEST CASE: TC-010
/*  Title: Multiple changes to same appointment shown with timeline
/*  Priority: High
/*  Category: Usability - Recognition
/**************************************************/

Given('user has an appointment that changed multiple times', async function () {
  await actions.click(page.locator('//button[@id="appointments"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//div[@class="appointment-item"]').first());
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="appointment-time"]'), '2:00 PM');
  await actions.click(page.locator('//button[@id="save-appointment"]'));
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="appointment-time"]'), '3:00 PM');
  await actions.click(page.locator('//button[@id="save-appointment"]'));
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="appointment-time"]'), '3:30 PM');
  await actions.click(page.locator('//button[@id="save-appointment"]'));
  await waits.waitForNetworkIdle();
  this.notificationData.multipleChanges = true;
});

/**************************************************/
/*  TEST CASE: TC-011
/*  Title: Notification preferences respected for different channel combinations
/*  Priority: High
/*  Category: Usability - Edge Case
/**************************************************/

Given('email notifications are {string}', async function (status: string) {
  await actions.click(page.locator('//button[@id="settings"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//a[@id="notification-settings"]'));
  await waits.waitForNetworkIdle();
  const emailCheckbox = page.locator('//input[@id="email-notifications"]');
  if (status === 'enabled' && !(await emailCheckbox.isChecked())) {
    await actions.check(emailCheckbox);
  } else if (status === 'disabled' && (await emailCheckbox.isChecked())) {
    await actions.click(emailCheckbox);
  }
  await actions.click(page.locator('//button[@id="save-settings"]'));
  await waits.waitForNetworkIdle();
  this.systemState.emailStatus = status;
});

Given('in-app notifications are {string}', async function (status: string) {
  const inAppCheckbox = page.locator('//input[@id="inapp-notifications"]');
  if (status === 'enabled' && !(await inAppCheckbox.isChecked())) {
    await actions.check(inAppCheckbox);
  } else if (status === 'disabled' && (await inAppCheckbox.isChecked())) {
    await actions.click(inAppCheckbox);
  }
  await actions.click(page.locator('//button[@id="save-settings"]'));
  await waits.waitForNetworkIdle();
  this.systemState.inAppStatus = status;
});

/**************************************************/
/*  TEST CASE: TC-012
/*  Title: Notification delivery status visible when email fails
/*  Priority: Medium
/*  Category: Usability - Negative
/**************************************************/

Given('email service is temporarily unavailable', async function () {
  await actions.click(page.locator('//button[@id="admin-controls"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//button[@id="disable-email-service"]'));
  await waits.waitForNetworkIdle();
  this.systemState.emailServiceDown = true;
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  GENERIC WHEN STEPS - Reusable across test cases
/**************************************************/

When('user modifies the appointment time from {string} to {string}', async function (oldTime: string, newTime: string) {
  await actions.click(page.locator('//button[@id="appointments"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator(`//div[@class="appointment-item" and contains(., "${oldTime}")]`));
  await waits.waitForNetworkIdle();
  await actions.clearAndFill(page.locator('//input[@id="appointment-time"]'), newTime);
  await actions.click(page.locator('//button[@id="save-appointment"]'));
  await waits.waitForNetworkIdle();
  this.notificationData.oldTime = oldTime;
  this.notificationData.newTime = newTime;
});

When('user navigates to notification history section', async function () {
  await actions.click(page.locator('//button[@id="notifications"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//a[@id="notification-history"]'));
  await waits.waitForNetworkIdle();
});

When('user navigates to notification settings page', async function () {
  await actions.click(page.locator('//button[@id="settings"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//a[@id="notification-settings"]'));
  await waits.waitForNetworkIdle();
});

When('user disables email notifications', async function () {
  const emailCheckbox = page.locator('//input[@id="email-notifications"]');
  if (await emailCheckbox.isChecked()) {
    await actions.click(emailCheckbox);
  }
  this.systemState.emailEnabled = false;
});

When('user keeps in-app notifications enabled', async function () {
  const inAppCheckbox = page.locator('//input[@id="inapp-notifications"]');
  if (!(await inAppCheckbox.isChecked())) {
    await actions.check(inAppCheckbox);
  }
  this.systemState.inAppEnabled = true;
});

When('user clicks {string} button', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
  await waits.waitForNetworkIdle();
});

When('user triggers a schedule change', async function () {
  await actions.click(page.locator('//button[@id="appointments"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//div[@class="appointment-item"]').first());
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="appointment-time"]'), '5:00 PM');
  await actions.click(page.locator('//button[@id="save-appointment"]'));
  await waits.waitForNetworkIdle();
});

When('user dismisses a schedule change notification', async function () {
  await actions.click(page.locator('//button[@id="notifications"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//button[@class="dismiss-notification"]').first());
  await waits.waitForNetworkIdle();
  this.notificationData.dismissed = true;
});

When('user clicks {string} button within the time window', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
  await waits.waitForNetworkIdle();
});

When('user marks a notification as read', async function () {
  await actions.click(page.locator('//button[@id="notifications"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//div[@class="notification-item unread"]').first());
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//button[@id="mark-as-read"]'));
  await waits.waitForNetworkIdle();
  this.notificationData.markedAsRead = true;
});

When('user attempts to mark it as unread again', async function () {
  await actions.click(page.locator('//button[@id="notification-context-menu"]'));
  await waits.waitForNetworkIdle();
});

When('user navigates to {string} section', async function (sectionName: string) {
  const sectionIdXPath = `//a[@id='${sectionName.toLowerCase().replace(/\s+/g, '-')}']`;
  const sections = page.locator(sectionIdXPath);
  if (await sections.count() > 0) {
    await actions.click(sections);
  } else {
    await actions.click(page.locator(`//a[contains(text(),'${sectionName}')]`));
  }
  await waits.waitForNetworkIdle();
});

When('user views the notification in notification panel without clicking through', async function () {
  await actions.click(page.locator('//button[@id="notifications"]'));
  await waits.waitForNetworkIdle();
  await actions.hover(page.locator('//div[@class="notification-item"]').first());
  await waits.waitForVisible(page.locator('//div[@class="notification-preview"]'));
});

When('user opens notification history', async function () {
  await actions.click(page.locator('//button[@id="notifications"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//a[@id="notification-history"]'));
  await waits.waitForNetworkIdle();
});

When('user scans through past notifications', async function () {
  await actions.scrollIntoView(page.locator('//div[@class="notification-history-container"]'));
  await waits.waitForVisible(page.locator('//div[@class="notification-item historical"]'));
});

When('user clicks on a notification to view full details', async function () {
  await actions.click(page.locator('//button[@id="notifications"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//div[@class="notification-item"]').first());
  await waits.waitForNetworkIdle();
});

When('user receives notification for the appointment', async function () {
  await actions.click(page.locator('//button[@id="notifications"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@class="notification-item"]').first());
});

When('user modifies an appointment time', async function () {
  await actions.click(page.locator('//button[@id="appointments"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//div[@class="appointment-item"]').first());
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="appointment-time"]'), '6:00 PM');
  await actions.click(page.locator('//button[@id="save-appointment"]'));
  await waits.waitForNetworkIdle();
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  GENERIC THEN STEPS - Reusable across test cases
/**************************************************/

Then('system should immediately display a processing indicator', async function () {
  await assertions.assertVisible(page.locator('//div[@id="processing-indicator"]'));
});

Then('in-app notification should appear within {int} minute', async function (minutes: number) {
  await waits.waitForVisible(page.locator('//div[@class="notification-toast"]'));
  await assertions.assertVisible(page.locator('//div[@class="notification-toast"]'));
});

Then('in-app notification should display appointment name', async function () {
  const notificationText = await page.locator('//div[@class="notification-toast"]').textContent();
  expect(notificationText).toContain('Team Meeting');
});

Then('in-app notification should show old time {string} and new time {string}', async function (oldTime: string, newTime: string) {
  const notificationText = await page.locator('//div[@class="notification-toast"]').textContent();
  expect(notificationText).toContain(oldTime);
  expect(notificationText).toContain(newTime);
});

Then('in-app notification should display timestamp of when notification was sent', async function () {
  await assertions.assertVisible(page.locator('//span[@class="notification-timestamp"]'));
});

Then('in-app notification should display visual indicator distinguishing it from other notification types', async function () {
  await assertions.assertVisible(page.locator('//div[@class="notification-toast schedule-change"]'));
});

Then('email notification should be received within {int} minute', async function (minutes: number) {
  await waits.waitForVisible(page.locator('//div[@id="email-notification-status"]'));
  const statusText = await page.locator('//div[@id="email-notification-status"]').textContent();
  expect(statusText).toContain('sent');
});

Then('email subject line should clearly indicate schedule change', async function () {
  await assertions.assertVisible(page.locator('//div[@id="email-subject"]'));
  const subjectText = await page.locator('//div[@id="email-subject"]').textContent();
  expect(subjectText).toContain('Schedule Change');
});

Then('email body should contain old time {string} and new time {string}', async function (oldTime: string, newTime: string) {
  const emailBody = await page.locator('//div[@id="email-body"]').textContent();
  expect(emailBody).toContain(oldTime);
  expect(emailBody).toContain(newTime);
});

Then('email should display timestamp of change', async function () {
  await assertions.assertVisible(page.locator('//span[@class="email-timestamp"]'));
});

Then('schedule change notification should be visible in history', async function () {
  await assertions.assertVisible(page.locator('//div[@class="notification-item schedule-change"]'));
});

Then('notification should display delivery status {string}', async function (status: string) {
  await assertions.assertContainsText(page.locator('//div[@class="delivery-status"]'), status);
});

Then('notification should display timestamp', async function () {
  await assertions.assertVisible(page.locator('//span[@class="notification-timestamp"]'));
});

Then('system should show loading indicators during any processing delays', async function () {
  const loadingIndicators = page.locator('//div[@class="loading-indicator"]');
  if (await loadingIndicators.count() > 0) {
    await assertions.assertVisible(loadingIndicators.first());
  }
});

Then('settings page should display option to enable or disable email notifications', async function () {
  await assertions.assertVisible(page.locator('//input[@id="email-notifications"]'));
  await assertions.assertVisible(page.locator('//label[@for="email-notifications"]'));
});

Then('settings page should display option to enable or disable in-app notifications', async function () {
  await assertions.assertVisible(page.locator('//input[@id="inapp-notifications"]'));
  await assertions.assertVisible(page.locator('//label[@for="inapp-notifications"]'));
});

Then('{string} button should be visible', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  if (await buttons.count() > 0) {
    await assertions.assertVisible(buttons);
  } else {
    await assertions.assertVisible(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
});

Then('in-app notification should be received', async function () {
  await waits.waitForVisible(page.locator('//div[@class="notification-toast"]'));
  await assertions.assertVisible(page.locator('//div[@class="notification-toast"]'));
});

Then('email notification should not be sent', async function () {
  const emailStatus = page.locator('//div[@id="email-notification-status"]');
  if (await emailStatus.count() > 0) {
    const statusText = await emailStatus.textContent();
    expect(statusText).not.toContain('sent');
  }
});

Then('settings should be respected without requiring logout', async function () {
  await assertions.assertVisible(page.locator('//div[@id="settings-saved-confirmation"]'));
});

Then('{string} button should be visible for {int} seconds', async function (buttonText: string, seconds: number) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  if (await buttons.count() > 0) {
    await assertions.assertVisible(buttons);
  } else {
    await assertions.assertVisible(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
});

Then('notification should be restored to its previous state', async function () {
  await assertions.assertVisible(page.locator('//div[@class="notification-item"]'));
});

Then('notification read status should be preserved', async function () {
  const notification = page.locator('//div[@class="notification-item"]').first();
  await assertions.assertVisible(notification);
});

Then('{string} message should be displayed', async function (message: string) {
  await assertions.assertContainsText(page.locator('//div[@class="toast-message"]'), message);
});

Then('context menu should allow toggling between read and unread states', async function () {
  await assertions.assertVisible(page.locator('//button[@id="mark-as-unread"]'));
  await assertions.assertVisible(page.locator('//button[@id="mark-as-read"]'));
});

Then('visual indicator should update immediately', async function () {
  await waits.waitForVisible(page.locator('//div[@class="notification-item read"]'));
  await assertions.assertVisible(page.locator('//div[@class="notification-item read"]'));
});

Then('dismissed notifications should be visible', async function () {
  await assertions.assertVisible(page.locator('//div[@class="notification-item dismissed"]'));
});

Then('option to restore should be available for each notification', async function () {
  const restoreButtons = page.locator('//button[@class="restore-notification"]');
  expect(await restoreButtons.count()).toBeGreaterThan(0);
});

Then('notification should display appointment title', async function () {
  await assertions.assertVisible(page.locator('//div[@class="notification-appointment-title"]'));
});

Then('notification should display original date and time with strikethrough', async function () {
  await assertions.assertVisible(page.locator('//span[@class="original-time strikethrough"]'));
});

Then('notification should display new date and time highlighted', async function () {
  await assertions.assertVisible(page.locator('//span[@class="new-time highlighted"]'));
});

Then('notification should display location if applicable', async function () {
  const locationElement = page.locator('//div[@class="notification-location"]');
  if (await locationElement.count() > 0) {
    await assertions.assertVisible(locationElement);
  }
});

Then('notification should display organizer names', async function () {
  await assertions.assertVisible(page.locator('//div[@class="notification-organizer"]'));
});

Then('notification should display participant names', async function () {
  await assertions.assertVisible(page.locator('//div[@class="notification-participants"]'));
});

Then('notification should display reason for change if provided', async function () {
  const reasonElement = page.locator('//div[@class="notification-reason"]');
  if (await reasonElement.count() > 0) {
    await assertions.assertVisible(reasonElement);
  }
});

Then('notification should clearly show {string} status', async function (status: string) {
  await assertions.assertContainsText(page.locator('//div[@class="notification-status"]'), status);
});

Then('notification should display original appointment date', async function () {
  await assertions.assertVisible(page.locator('//span[@class="original-date"]'));
});

Then('notification should display original appointment time', async function () {
  await assertions.assertVisible(page.locator('//span[@class="original-time"]'));
});

Then('notification should display original appointment title', async function () {
  await assertions.assertVisible(page.locator('//div[@class="notification-appointment-title"]'));
});

Then('each historical notification should display old values', async function () {
  const historicalNotifications = page.locator('//div[@class="notification-item historical"]');
  const firstNotification = historicalNotifications.first();
  await assertions.assertVisible(firstNotification.locator('//span[@class="old-value"]'));
});

Then('each historical notification should display new values', async function () {
  const historicalNotifications = page.locator('//div[@class="notification-item historical"]');
  const firstNotification = historicalNotifications.first();
  await assertions.assertVisible(firstNotification.locator('//span[@class="new-value"]'));
});

Then('each historical notification should display appointment details', async function () {
  const historicalNotifications = page.locator('//div[@class="notification-item historical"]');
  const firstNotification = historicalNotifications.first();
  await assertions.assertVisible(firstNotification.locator('//div[@class="appointment-details"]'));
});

Then('notifications should be grouped by {string}', async function (groupName: string) {
  const groupIdXPath = `//div[@class='notification-group' and contains(., '${groupName}')]`;
  await assertions.assertVisible(page.locator(groupIdXPath));
});

Then('expanded view should display complete appointment card', async function () {
  await assertions.assertVisible(page.locator('//div[@class="appointment-card-expanded"]'));
});

Then('expanded view should display full description', async function () {
  await assertions.assertVisible(page.locator('//div[@class="appointment-description"]'));
});

Then('expanded view should display participants', async function () {
  await assertions.assertVisible(page.locator('//div[@class="appointment-participants"]'));
});

Then('expanded view should display location', async function () {
  await assertions.assertVisible(page.locator('//div[@class="appointment-location"]'));
});

Then('expanded view should display attachments', async function () {
  const attachmentsElement = page.locator('//div[@class="appointment-attachments"]');
  if (await attachmentsElement.count() > 0) {
    await assertions.assertVisible(attachmentsElement);
  }
});

Then('notification should display change history timeline', async function () {
  await assertions.assertVisible(page.locator('//div[@class="change-history-timeline"]'));
});

Then('timeline should show progression {string}', async function (progression: string) {
  await assertions.assertContainsText(page.locator('//div[@class="change-history-timeline"]'), progression);
});

Then('notification should not create separate confusing notifications', async function () {
  const notificationCount = await page.locator('//div[@class="notification-item"]').count();
  expect(notificationCount).toBeLessThanOrEqual(1);
});

Then('email notification should be {string}', async function (status: string) {
  if (status === 'received') {
    await waits.waitForVisible(page.locator('//div[@id="email-notification-status"]'));
    const statusText = await page.locator('//div[@id="email-notification-status"]').textContent();
    expect(statusText).toContain('sent');
  } else if (status === 'not received') {
    const emailStatus = page.locator('//div[@id="email-notification-status"]');
    if (await emailStatus.count() > 0) {
      const statusText = await emailStatus.textContent();
      expect(statusText).not.toContain('sent');
    }
  }
});

Then('in-app notification should be {string}', async function (status: string) {
  if (status === 'received') {
    await waits.waitForVisible(page.locator('//div[@class="notification-toast"]'));
    await assertions.assertVisible(page.locator('//div[@class="notification-toast"]'));
  } else if (status === 'not received') {
    const inAppNotification = page.locator('//div[@class="notification-toast"]');
    expect(await inAppNotification.count()).toBe(0);
  }
});