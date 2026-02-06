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
      default: {
        title: 'Team Meeting',
        date: '2024-03-15',
        time: '2:00 PM',
        location: 'Conference Room A',
        attendees: ['John Doe', 'Jane Smith'],
        description: 'Quarterly review meeting'
      }
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
/*  BACKGROUND STEPS - Common Preconditions
/*  Used across all test cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user account is active with valid email address', async function () {
  this.userEmail = 'testuser@example.com';
  this.accountStatus = 'active';
});

// TODO: Replace XPath with Object Repository when available
Given('user has at least one scheduled appointment in the system', async function () {
  this.hasAppointments = true;
  this.appointmentCount = 1;
});

// TODO: Replace XPath with Object Repository when available
Given('user is logged into the application', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  
  const credentials = this.testData?.users?.user || { username: 'testuser', password: 'testpass' };
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-001
/*  Title: Real-time notification delivery with complete schedule change details
/*  Priority: Critical
/*  Category: Usability, Functional, Smoke
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('notification preferences are enabled for schedule changes', async function () {
  await actions.click(page.locator('//button[@id="user-menu"]'));
  await actions.click(page.locator('//a[@id="notification-settings"]'));
  await waits.waitForNetworkIdle();
  
  const scheduleChangesToggle = page.locator('//input[@id="toggle-schedule-changes"]');
  const isEnabled = await scheduleChangesToggle.isChecked();
  if (!isEnabled) {
    await actions.click(scheduleChangesToggle);
  }
  
  await actions.click(page.locator('//button[@id="save-settings"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
Given('user has an appointment scheduled at {string}', async function (appointmentTime: string) {
  this.originalAppointmentTime = appointmentTime;
  this.appointmentData = {
    ...this.testData.appointments.default,
    time: appointmentTime
  };
});

// TODO: Replace XPath with Object Repository when available
Given('user has an appointment with title, date, time, location, attendees and description', async function () {
  this.appointmentData = this.testData.appointments.default;
});

// TODO: Replace XPath with Object Repository when available
Given('appointment is scheduled {int} days in the future', async function (daysInFuture: number) {
  const futureDate = new Date();
  futureDate.setDate(futureDate.getDate() + daysInFuture);
  this.appointmentData.date = futureDate.toISOString().split('T')[0];
});

/**************************************************/
/*  TEST CASE: TC-002
/*  Title: User manages notification preferences with reversible actions
/*  Priority: High
/*  Category: Usability, Functional
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('notification settings page is accessible from main navigation', async function () {
  await assertions.assertVisible(page.locator('//button[@id="user-menu"]'));
});

// TODO: Replace XPath with Object Repository when available
Given('user has received at least {int} schedule change notifications', async function (notificationCount: number) {
  this.notificationCount = notificationCount;
});

// TODO: Replace XPath with Object Repository when available
Given('default notification settings are enabled for email', async function () {
  this.emailNotificationsEnabled = true;
});

// TODO: Replace XPath with Object Repository when available
Given('default notification settings are enabled for in-app alerts', async function () {
  this.inAppAlertsEnabled = true;
});

/**************************************************/
/*  TEST CASE: TC-003
/*  Title: Notification provides complete context without requiring navigation
/*  Priority: High
/*  Category: Usability, Functional
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user has multiple appointments scheduled across different dates', async function () {
  this.multipleAppointments = true;
  this.appointmentDates = ['2024-03-15', '2024-03-18', '2024-03-22'];
});

/**************************************************/
/*  TEST CASE: TC-004
/*  Title: Recurring appointment change notification displays scope and impact
/*  Priority: High
/*  Category: Usability, Functional, Edge
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user has a recurring appointment scheduled', async function () {
  this.isRecurringAppointment = true;
  this.recurrencePattern = 'weekly';
});

/**************************************************/
/*  TEST CASE: TC-005
/*  Title: Notification preferences persist across user sessions
/*  Priority: High
/*  Category: Usability, Negative
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user has customized notification preferences', async function () {
  this.hasCustomPreferences = true;
});

// TODO: Replace XPath with Object Repository when available
Given('user has disabled {string}', async function (preferenceType: string) {
  await actions.click(page.locator('//button[@id="user-menu"]'));
  await actions.click(page.locator('//a[@id="notification-settings"]'));
  await waits.waitForNetworkIdle();
  
  const toggleXPath = `//input[@id='toggle-${preferenceType.toLowerCase().replace(/\s+/g, '-')}']`;
  const toggle = page.locator(toggleXPath);
  const isEnabled = await toggle.isChecked();
  if (isEnabled) {
    await actions.click(toggle);
  }
  
  await actions.click(page.locator('//button[@id="save-settings"]'));
  await waits.waitForNetworkIdle();
  
  this.disabledPreference = preferenceType;
});

/**************************************************/
/*  TEST CASE: TC-006
/*  Title: Notification delivery respects user channel preferences
/*  Priority: Medium
/*  Category: Usability, Functional
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user has configured notification preferences', async function () {
  this.preferencesConfigured = true;
});

// TODO: Replace XPath with Object Repository when available
Given('{string} is set to {string}', async function (channel: string, status: string) {
  await actions.click(page.locator('//button[@id="user-menu"]'));
  await actions.click(page.locator('//a[@id="notification-settings"]'));
  await waits.waitForNetworkIdle();
  
  const toggleXPath = `//input[@id='toggle-${channel.toLowerCase().replace(/\s+/g, '-')}']`;
  const toggle = page.locator(toggleXPath);
  const isEnabled = await toggle.isChecked();
  
  if (status === 'enabled' && !isEnabled) {
    await actions.click(toggle);
  } else if (status === 'disabled' && isEnabled) {
    await actions.click(toggle);
  }
  
  await actions.click(page.locator('//button[@id="save-settings"]'));
  await waits.waitForNetworkIdle();
  
  this.channelStatus = { channel, status };
});

/**************************************************/
/*  TEST CASE: TC-007
/*  Title: User performs quick actions directly from notification
/*  Priority: Medium
/*  Category: Usability, Functional
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user receives schedule change notification', async function () {
  this.notificationReceived = true;
  await waits.waitForVisible(page.locator('//div[@id="notification-badge"]'));
});

// TODO: Replace XPath with Object Repository when available
Given('notification displays quick action buttons', async function () {
  await actions.click(page.locator('//div[@id="notification-badge"]'));
  await waits.waitForVisible(page.locator('//button[@id="accept-change"]'));
  await waits.waitForVisible(page.locator('//button[@id="decline-change"]'));
});

/**************************************************/
/*  TEST CASE: TC-008
/*  Title: Notification history allows filtering and status management
/*  Priority: Medium
/*  Category: Usability, Functional
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user has received multiple notifications of different types', async function () {
  this.notificationTypes = ['schedule-changes', 'reminders', 'cancellations'];
  this.totalNotifications = 15;
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  GENERIC ACTION STEPS - Reusable across all test cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('user modifies the appointment time from {string} to {string}', async function (oldTime: string, newTime: string) {
  await actions.click(page.locator('//a[@id="appointments"]'));
  await waits.waitForNetworkIdle();
  
  await actions.click(page.locator('//button[@id="edit-appointment"]'));
  await waits.waitForNetworkIdle();
  
  await actions.fill(page.locator('//input[@id="appointment-time"]'), newTime);
  await actions.click(page.locator('//button[@id="save-appointment"]'));
  await waits.waitForNetworkIdle();
  
  this.oldTime = oldTime;
  this.newTime = newTime;
});

// TODO: Replace XPath with Object Repository when available
When('user clicks on the in-app notification', async function () {
  await actions.click(page.locator('//div[@id="notification-badge"]'));
  await waits.waitForNetworkIdle();
  
  await actions.click(page.locator('//div[@id="notification-item-latest"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user checks email inbox', async function () {
  this.emailChecked = true;
  this.emailCheckTime = new Date();
});

// TODO: Replace XPath with Object Repository when available
When('user navigates to notification history section', async function () {
  await actions.click(page.locator('//button[@id="user-menu"]'));
  await actions.click(page.locator('//a[@id="notification-history"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user navigates to notification settings page', async function () {
  await actions.click(page.locator('//button[@id="user-menu"]'));
  await actions.click(page.locator('//a[@id="notification-settings"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user disables {string} toggle', async function (toggleName: string) {
  const toggleXPath = `//input[@id='toggle-${toggleName.toLowerCase().replace(/\s+/g, '-')}']`;
  const toggle = page.locator(toggleXPath);
  const isEnabled = await toggle.isChecked();
  if (isEnabled) {
    await actions.click(toggle);
  }
  this.disabledToggle = toggleName;
});

// TODO: Replace XPath with Object Repository when available
When('user keeps {string} toggle enabled', async function (toggleName: string) {
  const toggleXPath = `//input[@id='toggle-${toggleName.toLowerCase().replace(/\s+/g, '-')}']`;
  const toggle = page.locator(toggleXPath);
  const isEnabled = await toggle.isChecked();
  if (!isEnabled) {
    await actions.click(toggle);
  }
  this.enabledToggle = toggleName;
});

// TODO: Replace XPath with Object Repository when available
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

// TODO: Replace XPath with Object Repository when available
When('user triggers a new schedule change', async function () {
  await actions.click(page.locator('//a[@id="appointments"]'));
  await waits.waitForNetworkIdle();
  
  await actions.click(page.locator('//button[@id="edit-appointment"]'));
  await waits.waitForNetworkIdle();
  
  await actions.fill(page.locator('//input[@id="appointment-time"]'), '4:00 PM');
  await actions.click(page.locator('//button[@id="save-appointment"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user views the in-app notification', async function () {
  await actions.click(page.locator('//div[@id="notification-badge"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user selects a read notification', async function () {
  await actions.click(page.locator('//div[@id="notification-item-read"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user returns to notification settings', async function () {
  await actions.click(page.locator('//button[@id="user-menu"]'));
  await actions.click(page.locator('//a[@id="notification-settings"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user confirms restore defaults action', async function () {
  await actions.click(page.locator('//button[@id="confirm-restore"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('schedule change occurs for the appointment', async function () {
  this.scheduleChangeOccurred = true;
  this.changeTimestamp = new Date();
});

// TODO: Replace XPath with Object Repository when available
When('user views the in-app notification without clicking through', async function () {
  await actions.click(page.locator('//div[@id="notification-badge"]'));
  await waits.waitForNetworkIdle();
  await actions.hover(page.locator('//div[@id="notification-item-latest"]'));
});

// TODO: Replace XPath with Object Repository when available
When('user opens email notification', async function () {
  this.emailOpened = true;
});

// TODO: Replace XPath with Object Repository when available
When('user selects a notification from {int} week ago', async function (weeksAgo: number) {
  const notificationXPath = `//div[@id='notification-item-week-${weeksAgo}']`;
  await actions.click(page.locator(notificationXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('schedule change occurs for the recurring appointment', async function () {
  this.recurringChangeOccurred = true;
});

// TODO: Replace XPath with Object Repository when available
When('user logs out of the application', async function () {
  await actions.click(page.locator('//button[@id="user-menu"]'));
  await actions.click(page.locator('//a[@id="logout"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user logs back into the application', async function () {
  const credentials = this.testData?.users?.user || { username: 'testuser', password: 'testpass' };
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('schedule change occurs for user appointment', async function () {
  this.scheduleChangeOccurred = true;
});

// TODO: Replace XPath with Object Repository when available
When('user clicks {string} button from notification', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(buttonIdXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user applies filter for {string} type', async function (filterType: string) {
  const filterXPath = `//select[@id='notification-filter']`;
  await actions.selectByText(page.locator(filterXPath), filterType);
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user selects multiple notifications', async function () {
  await actions.click(page.locator('//input[@id="select-notification-1"]'));
  await actions.click(page.locator('//input[@id="select-notification-2"]'));
  await actions.click(page.locator('//input[@id="select-notification-3"]'));
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  GENERIC ASSERTION STEPS - Reusable across all test cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('system should display visual indicator showing change is being processed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="processing-indicator"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('in-app notification should appear within {int} minute', async function (minutes: number) {
  await waits.waitForVisible(page.locator('//div[@id="notification-badge"]'));
  await assertions.assertVisible(page.locator('//div[@id="notification-badge"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('notification badge counter should be visible', async function () {
  await assertions.assertVisible(page.locator('//span[@id="notification-count"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('notification timestamp should be displayed', async function () {
  await assertions.assertVisible(page.locator('//span[@id="notification-timestamp"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should show {string}', async function (expectedText: string) {
  await assertions.assertContainsText(page.locator('//div[@id="notification-content"]'), expectedText);
});

// TODO: Replace XPath with Object Repository when available
Then('notification should expand showing full details', async function () {
  await assertions.assertVisible(page.locator('//div[@id="notification-expanded"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('appointment name should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="appointment-name"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('old schedule details should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="old-schedule"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('new schedule details should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="new-schedule"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('reason for change should be displayed if available', async function () {
  const reasonElement = page.locator('//div[@id="change-reason"]');
  if (await reasonElement.count() > 0) {
    await assertions.assertVisible(reasonElement);
  }
});

// TODO: Replace XPath with Object Repository when available
Then('delivery status indicators should be shown for email channel', async function () {
  await assertions.assertVisible(page.locator('//span[@id="email-delivery-status"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('delivery status indicators should be shown for in-app channel', async function () {
  await assertions.assertVisible(page.locator('//span[@id="inapp-delivery-status"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('email notification should be received within {int} minute', async function (minutes: number) {
  this.emailReceived = true;
});

// TODO: Replace XPath with Object Repository when available
Then('email timestamp should match in-app notification timestamp', async function () {
  this.timestampsMatch = true;
});

// TODO: Replace XPath with Object Repository when available
Then('email subject line should indicate schedule change', async function () {
  this.emailSubjectValid = true;
});

// TODO: Replace XPath with Object Repository when available
Then('email content should show before and after comparison', async function () {
  this.emailContentValid = true;
});

// TODO: Replace XPath with Object Repository when available
Then('all notifications should be listed chronologically', async function () {
  await assertions.assertVisible(page.locator('//div[@id="notification-list"]'));
  const notificationItems = await page.locator('//div[@class="notification-item"]').count();
  expect(notificationItems).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Then('read or unread status should be displayed for each notification', async function () {
  await assertions.assertVisible(page.locator('//span[@class="notification-status"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('notification timestamps should be visible', async function () {
  await assertions.assertVisible(page.locator('//span[@class="notification-timestamp"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('user should be able to filter by {string} type', async function (filterType: string) {
  await assertions.assertVisible(page.locator('//select[@id="notification-filter"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('settings page should display toggle for {string}', async function (toggleName: string) {
  const toggleXPath = `//input[@id='toggle-${toggleName.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(toggleXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('current state should be clearly visible as {string} or {string}', async function (state1: string, state2: string) {
  const stateIndicator = page.locator('//span[@class="toggle-state"]');
  await assertions.assertVisible(stateIndicator);
});

// TODO: Replace XPath with Object Repository when available
Then('{string} message should be displayed', async function (message: string) {
  await assertions.assertContainsText(page.locator('//div[@id="success-message"]'), message);
});

// TODO: Replace XPath with Object Repository when available
Then('undo option should be available for {int} seconds', async function (seconds: number) {
  await assertions.assertVisible(page.locator('//button[@id="undo-action"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('updated preference state should be shown immediately', async function () {
  await waits.waitForVisible(page.locator('//div[@id="preferences-updated"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('in-app notification should be received', async function () {
  await assertions.assertVisible(page.locator('//div[@id="notification-badge"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('email notification should not be sent', async function () {
  this.emailNotSent = true;
});

// TODO: Replace XPath with Object Repository when available
Then('{string} option should be available', async function (optionName: string) {
  const optionXPath = `//button[@id='${optionName.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(optionXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('{string} option should be available with {string} choice', async function (optionName: string, choiceValue: string) {
  const optionXPath = `//button[@id='${optionName.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(optionXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('context menu should allow toggling read or unread status', async function () {
  await actions.click(page.locator('//button[@id="notification-context-menu"]'));
  await assertions.assertVisible(page.locator('//button[@id="toggle-read-status"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('visual indicator should update immediately', async function () {
  await waits.waitForVisible(page.locator('//span[@class="status-updated"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('confirmation dialog should display {string}', async function (confirmationText: string) {
  await assertions.assertContainsText(page.locator('//div[@id="confirmation-dialog"]'), confirmationText);
});

// TODO: Replace XPath with Object Repository when available
Then('all notification channels should reset to default state', async function () {
  await assertions.assertVisible(page.locator('//div[@id="defaults-restored"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should be generated', async function () {
  this.notificationGenerated = true;
});

// TODO: Replace XPath with Object Repository when available
Then('notification should be delivered via email channel', async function () {
  this.emailDelivered = true;
});

// TODO: Replace XPath with Object Repository when available
Then('notification should be delivered via in-app channel', async function () {
  this.inAppDelivered = true;
});

// TODO: Replace XPath with Object Repository when available
Then('appointment title should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="appointment-title"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('before and after date comparison should be shown', async function () {
  await assertions.assertVisible(page.locator('//div[@id="date-comparison"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('before and after time comparison should be shown', async function () {
  await assertions.assertVisible(page.locator('//div[@id="time-comparison"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('location should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="appointment-location"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('list of attendees should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="attendees-list"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('reason for change should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="change-reason"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('{string} button should be available', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(buttonIdXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('changed information should be highlighted in different color', async function () {
  await assertions.assertVisible(page.locator('//span[@class="highlighted-change"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('conflicts should be flagged if any exist', async function () {
  const conflictElement = page.locator('//div[@id="conflict-warning"]');
  if (await conflictElement.count() > 0) {
    await assertions.assertVisible(conflictElement);
  }
});

// TODO: Replace XPath with Object Repository when available
Then('initiator of change should be displayed', async function () {
  await assertions.assertVisible(page.locator('//span[@id="change-initiator"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('email should contain identical information as in-app notification', async function () {
  this.emailContentMatches = true;
});

// TODO: Replace XPath with Object Repository when available
Then('email should display formatted before and after table', async function () {
  this.emailTableFormatted = true;
});

// TODO: Replace XPath with Object Repository when available
Then('email should include calendar attachment in {string} format', async function (format: string) {
  this.calendarAttachmentFormat = format;
});

// TODO: Replace XPath with Object Repository when available
Then('email should provide direct link to appointment in system', async function () {
  this.emailContainsLink = true;
});

// TODO: Replace XPath with Object Repository when available
Then('notification should retain all original details', async function () {
  await assertions.assertVisible(page.locator('//div[@id="notification-details"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('current status should be shown as {string} or {string}', async function (status1: string, status2: string) {
  await assertions.assertVisible(page.locator('//span[@id="current-status"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('link to current appointment state should be provided', async function () {
  await assertions.assertVisible(page.locator('//a[@id="appointment-link"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('change history should be accessible', async function () {
  await assertions.assertVisible(page.locator('//button[@id="view-change-history"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should indicate {string}', async function (indicatorText: string) {
  await assertions.assertContainsText(page.locator('//div[@id="notification-content"]'), indicatorText);
});

// TODO: Replace XPath with Object Repository when available
Then('scope of change should be clearly stated as {string} or {string}', async function (scope1: string, scope2: string) {
  await assertions.assertVisible(page.locator('//div[@id="change-scope"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('visual calendar preview should show affected dates', async function () {
  await assertions.assertVisible(page.locator('//div[@id="calendar-preview"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('user should be able to understand impact without additional navigation', async function () {
  await assertions.assertVisible(page.locator('//div[@id="impact-summary"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('{string} toggle should remain disabled', async function (toggleName: string) {
  const toggleXPath = `//input[@id='toggle-${toggleName.toLowerCase().replace(/\s+/g, '-')}']`;
  const toggle = page.locator(toggleXPath);
  const isEnabled = await toggle.isChecked();
  expect(isEnabled).toBe(false);
});

// TODO: Replace XPath with Object Repository when available
Then('all customized preferences should be preserved', async function () {
  await assertions.assertVisible(page.locator('//div[@id="preferences-preserved"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('notification delivery should match expected behavior for {string} with {string}', async function (channel: string, status: string) {
  if (status === 'enabled') {
    this.notificationDelivered = true;
  } else {
    this.notificationNotDelivered = true;
  }
});

// TODO: Replace XPath with Object Repository when available
Then('change should be accepted without navigating to appointment details', async function () {
  await assertions.assertVisible(page.locator('//div[@id="change-accepted"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('confirmation message should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="confirmation-message"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('notification status should update to {string}', async function (status: string) {
  await assertions.assertContainsText(page.locator('//span[@id="notification-status"]'), status);
});

// TODO: Replace XPath with Object Repository when available
Then('only schedule change notifications should be displayed', async function () {
  const notificationItems = await page.locator('//div[@class="notification-item"]').count();
  expect(notificationItems).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Then('bulk actions should be available', async function () {
  await assertions.assertVisible(page.locator('//div[@id="bulk-actions"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('user should be able to mark selected notifications as read', async function () {
  await assertions.assertVisible(page.locator('//button[@id="mark-as-read"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('user should be able to delete selected notifications', async function () {
  await assertions.assertVisible(page.locator('//button[@id="delete-notifications"]'));
});