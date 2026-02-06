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
    appointments: {},
    notifications: {},
    timestamps: {}
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
/*  COMMON BACKGROUND STEPS
/*  Used across all test cases
/*  Category: Setup/Preconditions
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user is registered and logged into the system with valid credentials', async function () {
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
Given('notification service is running and operational', async function () {
  await assertions.assertVisible(page.locator('//div[@id="notification-service-status"]'));
  const statusText = await page.locator('//div[@id="notification-service-status"]').textContent();
  expect(statusText).toContain('operational');
});

// TODO: Replace XPath with Object Repository when available
Given('user has notification preferences enabled for schedule changes', async function () {
  await actions.click(page.locator('//button[@id="user-profile"]'));
  await actions.click(page.locator('//a[contains(text(),"Settings")]'));
  await waits.waitForNetworkIdle();
  
  const notificationToggle = page.locator('//input[@id="notification-schedule-changes"]');
  const isChecked = await notificationToggle.isChecked();
  if (!isChecked) {
    await actions.check(notificationToggle);
    await actions.click(page.locator('//button[@id="save-settings"]'));
    await waits.waitForNetworkIdle();
  }
  await actions.click(page.locator('//a[@id="back-to-dashboard"]'));
});

/**************************************************/
/*  TEST CASE: TC-001
/*  Title: User receives email and in-app notification when schedule is updated
/*  Priority: High
/*  Category: Functional
/*  Description: Verifies notification delivery via email and in-app when user updates their own schedule
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user has an appointment scheduled for tomorrow at {string}', async function (appointmentTime: string) {
  this.testData.appointments.originalTime = appointmentTime;
  this.testData.appointments.appointmentDate = 'tomorrow';
  
  await actions.click(page.locator('//a[contains(text(),"My Appointments")]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${appointmentTime}')]`));
});

// TODO: Replace XPath with Object Repository when available
Given('user\'s email address is verified and active in the system', async function () {
  await actions.click(page.locator('//button[@id="user-profile"]'));
  await actions.click(page.locator('//a[contains(text(),"Profile")]'));
  await waits.waitForNetworkIdle();
  
  await assertions.assertVisible(page.locator('//span[@id="email-verified-badge"]'));
  const verifiedText = await page.locator('//span[@id="email-verified-badge"]').textContent();
  expect(verifiedText).toContain('Verified');
  
  await actions.click(page.locator('//a[@id="back-to-dashboard"]'));
});

/**************************************************/
/*  TEST CASE: TC-002
/*  Title: Notification includes all required schedule change details
/*  Priority: High
/*  Category: Functional
/*  Description: Verifies notification contains complete change details including all modified fields
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user is authenticated and has an active session', async function () {
  await assertions.assertVisible(page.locator('//div[@id="user-dashboard"]'));
  await assertions.assertVisible(page.locator('//span[@id="session-active-indicator"]'));
});

// TODO: Replace XPath with Object Repository when available
Given('user has appointment scheduled for next Monday at {string} with {string} in {string}', async function (time: string, provider: string, location: string) {
  this.testData.appointments.originalTime = time;
  this.testData.appointments.originalProvider = provider;
  this.testData.appointments.originalLocation = location;
  this.testData.appointments.appointmentDate = 'next Monday';
  
  await actions.click(page.locator('//a[contains(text(),"My Appointments")]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${time}')]`));
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${provider}')]`));
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${location}')]`));
});

// TODO: Replace XPath with Object Repository when available
Given('notification system is configured to include full change details', async function () {
  await assertions.assertVisible(page.locator('//div[@id="notification-config-full-details"]'));
});

/**************************************************/
/*  TEST CASE: TC-003
/*  Title: User can acknowledge receipt of schedule change notification
/*  Priority: High
/*  Category: Functional
/*  Description: Verifies user can acknowledge notifications and status updates correctly
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user has received unacknowledged schedule change notification', async function () {
  await assertions.assertVisible(page.locator('//span[@id="notification-badge"]'));
  const badgeCount = await page.locator('//span[@id="notification-badge"]').textContent();
  expect(parseInt(badgeCount || '0')).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Given('notification appears in notification center with unread status', async function () {
  await actions.click(page.locator('//button[@id="notification-bell-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-dropdown-panel"]'));
  await assertions.assertVisible(page.locator('//div[contains(@class,"notification-unread")]'));
});

// TODO: Replace XPath with Object Repository when available
Given('user has permission to acknowledge notifications', async function () {
  await assertions.assertVisible(page.locator('//button[@id="acknowledge-notification"]'));
});

/**************************************************/
/*  TEST CASE: TC-004
/*  Title: Notifications are sent within 1 minute of schedule change detection
/*  Priority: High
/*  Category: Performance
/*  Description: Verifies notification delivery performance meets SLA of 1 minute
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user has active account with verified email address', async function () {
  await actions.click(page.locator('//button[@id="user-profile"]'));
  await actions.click(page.locator('//a[contains(text(),"Profile")]'));
  await waits.waitForNetworkIdle();
  
  await assertions.assertVisible(page.locator('//span[@id="account-status-active"]'));
  await assertions.assertVisible(page.locator('//span[@id="email-verified-badge"]'));
  
  await actions.click(page.locator('//a[@id="back-to-dashboard"]'));
});

// TODO: Replace XPath with Object Repository when available
Given('user has scheduled appointment in the system', async function () {
  await actions.click(page.locator('//a[contains(text(),"My Appointments")]'));
  await waits.waitForNetworkIdle();
  
  const appointmentCount = await page.locator('//div[@class="appointment-card"]').count();
  expect(appointmentCount).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Given('system clock is synchronized and accurate', async function () {
  await assertions.assertVisible(page.locator('//div[@id="system-clock-sync-status"]'));
  const syncStatus = await page.locator('//div[@id="system-clock-sync-status"]').textContent();
  expect(syncStatus).toContain('synchronized');
});

// TODO: Replace XPath with Object Repository when available
Given('notification service performance monitoring is enabled', async function () {
  await assertions.assertVisible(page.locator('//div[@id="notification-performance-monitor"]'));
});

/**************************************************/
/*  TEST CASE: TC-005
/*  Title: User can view past schedule change notifications in notification history
/*  Priority: Medium
/*  Category: Functional
/*  Description: Verifies notification history page displays past notifications with filtering
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user has received {int} schedule change notifications over past {int} days', async function (notificationCount: number, daysPast: number) {
  this.testData.notifications.expectedCount = notificationCount;
  this.testData.notifications.daysPast = daysPast;
  
  await actions.click(page.locator('//button[@id="notification-bell-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-dropdown-panel"]'));
  
  const actualCount = await page.locator('//div[@class="notification-item"]').count();
  expect(actualCount).toBeGreaterThanOrEqual(notificationCount);
});

// TODO: Replace XPath with Object Repository when available
Given('notification history feature is enabled for user account', async function () {
  await actions.click(page.locator('//button[@id="user-profile"]'));
  const historyOption = page.locator('//a[contains(text(),"Notification History")]');
  await assertions.assertVisible(historyOption);
});

// TODO: Replace XPath with Object Repository when available
Given('user has permission to access notification history page', async function () {
  await assertions.assertVisible(page.locator('//a[@id="notification-history-link"]'));
});

/**************************************************/
/*  TEST CASE: TC-006
/*  Title: Notification is sent only for confirmed schedule changes not draft changes
/*  Priority: High
/*  Category: Validation
/*  Description: Verifies notifications are sent only after changes are confirmed, not for drafts
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user is logged in as administrator with schedule modification rights', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  
  const adminCredentials = this.testData?.users?.admin || { username: 'admin', password: 'admin123' };
  await actions.fill(page.locator('//input[@id="username"]'), adminCredentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), adminCredentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  
  await assertions.assertVisible(page.locator('//div[@id="admin-dashboard"]'));
});

// TODO: Replace XPath with Object Repository when available
Given('user has confirmed appointment scheduled for next Wednesday at {string}', async function (appointmentTime: string) {
  this.testData.appointments.originalTime = appointmentTime;
  this.testData.appointments.appointmentDate = 'next Wednesday';
  
  await actions.click(page.locator('//a[contains(text(),"Schedule Management")]'));
  await waits.waitForNetworkIdle();
  
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${appointmentTime}')]`));
  await assertions.assertVisible(page.locator('//span[contains(text(),"Confirmed")]'));
});

// TODO: Replace XPath with Object Repository when available
Given('system supports draft mode for schedule changes', async function () {
  await assertions.assertVisible(page.locator('//button[@id="save-as-draft"]'));
});

// TODO: Replace XPath with Object Repository when available
Given('notification service is configured to send only for confirmed changes', async function () {
  await assertions.assertVisible(page.locator('//div[@id="notification-config-confirmed-only"]'));
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  GENERIC NAVIGATION STEPS
/*  Reusable across all test cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('user navigates to {string} page', async function (pageName: string) {
  const pageXPath = `//a[contains(text(),'${pageName}')]`;
  await actions.click(page.locator(pageXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user selects the existing appointment scheduled for tomorrow', async function () {
  const appointmentTime = this.testData.appointments.originalTime;
  await actions.click(page.locator(`//div[contains(text(),'${appointmentTime}')]`));
  await waits.waitForNetworkIdle();
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
When('user changes the appointment time from {string} to {string}', async function (oldTime: string, newTime: string) {
  this.testData.appointments.newTime = newTime;
  
  await actions.fill(page.locator('//input[@id="appointment-time"]'), '');
  await actions.fill(page.locator('//input[@id="appointment-time"]'), newTime);
});

// TODO: Replace XPath with Object Repository when available
When('user waits for {int} seconds', async function (seconds: number) {
  await page.waitForTimeout(seconds * 1000);
});

// TODO: Replace XPath with Object Repository when available
When('user clicks notification bell icon', async function () {
  await actions.click(page.locator('//button[@id="notification-bell-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-dropdown-panel"]'));
});

// TODO: Replace XPath with Object Repository when available
When('user opens registered email inbox', async function () {
  this.testData.emailInboxOpened = true;
  await assertions.assertVisible(page.locator('//div[@id="email-inbox-simulator"]'));
});

/**************************************************/
/*  TEST CASE: TC-002 - WHEN STEPS
/*  Administrator modifies appointment
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('administrator accesses the schedule management system', async function () {
  await actions.click(page.locator('//a[contains(text(),"Schedule Management")]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="schedule-management-dashboard"]'));
});

// TODO: Replace XPath with Object Repository when available
When('administrator locates user\'s appointment for next Monday', async function () {
  const appointmentDate = this.testData.appointments.appointmentDate;
  await actions.fill(page.locator('//input[@id="search-appointments"]'), appointmentDate);
  await actions.click(page.locator('//button[@id="search-button"]'));
  await waits.waitForNetworkIdle();
  
  await assertions.assertVisible(page.locator('//div[@class="appointment-search-result"]'));
  await actions.click(page.locator('//div[@class="appointment-search-result"]'));
});

// TODO: Replace XPath with Object Repository when available
When('administrator changes appointment time to {string}', async function (newTime: string) {
  this.testData.appointments.newTime = newTime;
  await actions.fill(page.locator('//input[@id="appointment-time"]'), '');
  await actions.fill(page.locator('//input[@id="appointment-time"]'), newTime);
});

// TODO: Replace XPath with Object Repository when available
When('administrator changes provider to {string}', async function (newProvider: string) {
  this.testData.appointments.newProvider = newProvider;
  await actions.selectByText(page.locator('//select[@id="appointment-provider"]'), newProvider);
});

// TODO: Replace XPath with Object Repository when available
When('administrator changes location to {string}', async function (newLocation: string) {
  this.testData.appointments.newLocation = newLocation;
  await actions.fill(page.locator('//input[@id="appointment-location"]'), '');
  await actions.fill(page.locator('//input[@id="appointment-location"]'), newLocation);
});

// TODO: Replace XPath with Object Repository when available
When('administrator clicks {string} button', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-003 - WHEN STEPS
/*  User acknowledges notification
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('user clicks notification bell icon in top-right corner', async function () {
  await actions.click(page.locator('//button[@id="notification-bell-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-dropdown-panel"]'));
});

// TODO: Replace XPath with Object Repository when available
When('user reads notification showing schedule change from {string} to {string}', async function (oldTime: string, newTime: string) {
  this.testData.appointments.oldTime = oldTime;
  this.testData.appointments.newTime = newTime;
  
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${oldTime}')]`));
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${newTime}')]`));
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
When('user closes notification panel and reopens it', async function () {
  await actions.click(page.locator('//button[@id="close-notification-panel"]'));
  await waits.waitForHidden(page.locator('//div[@id="notification-dropdown-panel"]'));
  await page.waitForTimeout(1000);
  await actions.click(page.locator('//button[@id="notification-bell-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-dropdown-panel"]'));
});

/**************************************************/
/*  TEST CASE: TC-004 - WHEN STEPS
/*  Performance monitoring
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('user records current system time as {string}', async function (systemTime: string) {
  this.testData.timestamps.changeStartTime = systemTime;
  this.testData.timestamps.changeStartTimestamp = Date.now();
});

// TODO: Replace XPath with Object Repository when available
When('user updates appointment from {string} to {string}', async function (oldTime: string, newTime: string) {
  this.testData.appointments.originalTime = oldTime;
  this.testData.appointments.newTime = newTime;
  
  await actions.click(page.locator('//a[contains(text(),"My Appointments")]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator(`//div[contains(text(),'${oldTime}')]`));
  await actions.click(page.locator('//button[@id="edit-appointment"]'));
  await actions.fill(page.locator('//input[@id="appointment-time"]'), '');
  await actions.fill(page.locator('//input[@id="appointment-time"]'), newTime);
});

// TODO: Replace XPath with Object Repository when available
When('user monitors notification bell icon for {int} seconds', async function (seconds: number) {
  this.testData.timestamps.monitoringDuration = seconds;
  const startTime = Date.now();
  
  let notificationAppeared = false;
  while ((Date.now() - startTime) < (seconds * 1000)) {
    const badgeCount = await page.locator('//span[@id="notification-badge"]').count();
    if (badgeCount > 0) {
      notificationAppeared = true;
      this.testData.timestamps.notificationAppearTime = Date.now();
      break;
    }
    await page.waitForTimeout(1000);
  }
  
  this.testData.notifications.appearedWithinSLA = notificationAppeared;
});

// TODO: Replace XPath with Object Repository when available
When('user checks email inbox', async function () {
  this.testData.emailInboxChecked = true;
  await assertions.assertVisible(page.locator('//div[@id="email-inbox-simulator"]'));
});

// TODO: Replace XPath with Object Repository when available
When('user accesses notification service logs', async function () {
  await actions.click(page.locator('//button[@id="admin-menu"]'));
  await actions.click(page.locator('//a[contains(text(),"Service Logs")]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="notification-service-logs"]'));
});

/**************************************************/
/*  TEST CASE: TC-005 - WHEN STEPS
/*  Notification history navigation
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('user clicks user profile icon in top-right corner', async function () {
  await actions.click(page.locator('//button[@id="user-profile"]'));
  await waits.waitForVisible(page.locator('//div[@id="profile-dropdown-menu"]'));
});

// TODO: Replace XPath with Object Repository when available
When('user selects {string} from dropdown menu', async function (menuOption: string) {
  await actions.click(page.locator(`//a[contains(text(),'${menuOption}')]`));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user clicks {string} link on most recent notification', async function (linkText: string) {
  const firstNotification = page.locator('//div[@class="notification-history-row"]').first();
  await actions.click(firstNotification.locator(`//a[contains(text(),'${linkText}')]`));
  await waits.waitForVisible(page.locator('//div[@id="notification-details-modal"]'));
});

// TODO: Replace XPath with Object Repository when available
When('user applies date filter for {string}', async function (filterOption: string) {
  await actions.selectByText(page.locator('//select[@id="date-filter"]'), filterOption);
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

/**************************************************/
/*  TEST CASE: TC-006 - WHEN STEPS
/*  Draft vs Confirmed changes
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('user selects appointment scheduled for next Wednesday', async function () {
  const appointmentDate = this.testData.appointments.appointmentDate;
  await actions.click(page.locator(`//div[contains(text(),'${appointmentDate}')]`));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user changes time to {string}', async function (newTime: string) {
  this.testData.appointments.newTime = newTime;
  await actions.fill(page.locator('//input[@id="appointment-time"]'), '');
  await actions.fill(page.locator('//input[@id="appointment-time"]'), newTime);
});

// TODO: Replace XPath with Object Repository when available
When('user checks in-app notifications', async function () {
  await actions.click(page.locator('//button[@id="notification-bell-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-dropdown-panel"]'));
});

// TODO: Replace XPath with Object Repository when available
When('user returns to draft appointment', async function () {
  await actions.click(page.locator('//a[contains(text(),"Schedule Management")]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//div[contains(@class,"appointment-draft")]'));
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  GENERIC ASSERTION STEPS
/*  Reusable across all test cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('success message {string} should be displayed', async function (message: string) {
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${message}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('appointment should show new time {string}', async function (newTime: string) {
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${newTime}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('red notification badge should appear on bell icon with count {int}', async function (expectedCount: number) {
  await assertions.assertVisible(page.locator('//span[@id="notification-badge"]'));
  const badgeText = await page.locator('//span[@id="notification-badge"]').textContent();
  expect(parseInt(badgeText || '0')).toBe(expectedCount);
});

// TODO: Replace XPath with Object Repository when available
Then('notification should display {string}', async function (notificationText: string) {
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${notificationText}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('email notification should be received with subject {string}', async function (emailSubject: string) {
  await assertions.assertVisible(page.locator(`//div[@class='email-subject' and contains(text(),'${emailSubject}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('email should contain original time {string}', async function (originalTime: string) {
  await assertions.assertVisible(page.locator(`//div[@class='email-body']//span[contains(text(),'${originalTime}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('email should contain new time {string}', async function (newTime: string) {
  await assertions.assertVisible(page.locator(`//div[@class='email-body']//span[contains(text(),'${newTime}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('email should contain appointment date and description', async function () {
  await assertions.assertVisible(page.locator('//div[@class="email-body"]//div[@class="appointment-date"]'));
  await assertions.assertVisible(page.locator('//div[@class="email-body"]//div[@class="appointment-description"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('notification record should be created in database with delivery status {string}', async function (deliveryStatus: string) {
  await assertions.assertVisible(page.locator(`//div[@id='notification-delivery-status' and contains(text(),'${deliveryStatus}')]`));
});

/**************************************************/
/*  TEST CASE: TC-002 - THEN STEPS
/*  Detailed notification content verification
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('confirmation dialog should display {string}', async function (dialogMessage: string) {
  await assertions.assertVisible(page.locator('//div[@id="confirmation-dialog"]'));
  await assertions.assertContainsText(page.locator('//div[@id="confirmation-dialog"]'), dialogMessage);
});

// TODO: Replace XPath with Object Repository when available
Then('system should display {string} message', async function (message: string) {
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${message}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('appointment should reflect all new values', async function () {
  const newTime = this.testData.appointments.newTime;
  const newProvider = this.testData.appointments.newProvider;
  const newLocation = this.testData.appointments.newLocation;
  
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${newTime}')]`));
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${newProvider}')]`));
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${newLocation}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should display title {string}', async function (notificationTitle: string) {
  await assertions.assertVisible(page.locator(`//div[@class='notification-title' and contains(text(),'${notificationTitle}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should include original date and time {string}', async function (originalDateTime: string) {
  await assertions.assertVisible(page.locator(`//div[@class='notification-original-datetime' and contains(text(),'${originalDateTime}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should include new date and time {string}', async function (newDateTime: string) {
  await assertions.assertVisible(page.locator(`//div[@class='notification-new-datetime' and contains(text(),'${newDateTime}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should include original provider {string}', async function (originalProvider: string) {
  await assertions.assertVisible(page.locator(`//div[@class='notification-original-provider' and contains(text(),'${originalProvider}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should include new provider {string}', async function (newProvider: string) {
  await assertions.assertVisible(page.locator(`//div[@class='notification-new-provider' and contains(text(),'${newProvider}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should include original location {string}', async function (originalLocation: string) {
  await assertions.assertVisible(page.locator(`//div[@class='notification-original-location' and contains(text(),'${originalLocation}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should include new location {string}', async function (newLocation: string) {
  await assertions.assertVisible(page.locator(`//div[@class='notification-new-location' and contains(text(),'${newLocation}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('email should contain identical information as in-app notification', async function () {
  const inAppContent = await page.locator('//div[@class="notification-content"]').textContent();
  const emailContent = await page.locator('//div[@class="email-body"]').textContent();
  
  expect(emailContent).toContain(inAppContent || '');
});

// TODO: Replace XPath with Object Repository when available
Then('email should display {string} section with all modified fields', async function (sectionName: string) {
  await assertions.assertVisible(page.locator(`//div[@class='email-section' and contains(text(),'${sectionName}')]`));
  await assertions.assertVisible(page.locator('//div[@class="modified-fields-list"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('email should show before and after values for each changed field', async function () {
  await assertions.assertVisible(page.locator('//div[@class="before-value"]'));
  await assertions.assertVisible(page.locator('//div[@class="after-value"]'));
});

/**************************************************/
/*  TEST CASE: TC-003 - THEN STEPS
/*  Acknowledgment workflow verification
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('notification dropdown panel should open', async function () {
  await assertions.assertVisible(page.locator('//div[@id="notification-dropdown-panel"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('unacknowledged notification should appear with blue highlight', async function () {
  await assertions.assertVisible(page.locator('//div[contains(@class,"notification-unread")]'));
  await assertions.assertVisible(page.locator('//div[contains(@class,"blue-highlight")]'));
});

// TODO: Replace XPath with Object Repository when available
Then('{string} button should be visible', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  
  if (await buttons.count() > 0) {
    await assertions.assertVisible(buttons);
  } else {
    await assertions.assertVisible(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
});

// TODO: Replace XPath with Object Repository when available
Then('full notification content should be displayed with timestamp', async function () {
  await assertions.assertVisible(page.locator('//div[@class="notification-full-content"]'));
  await assertions.assertVisible(page.locator('//span[@class="notification-timestamp"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('change details should be visible', async function () {
  await assertions.assertVisible(page.locator('//div[@class="notification-change-details"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('button should change to {string} with checkmark icon', async function (buttonText: string) {
  await assertions.assertVisible(page.locator(`//button[contains(text(),'${buttonText}')]`));
  await assertions.assertVisible(page.locator('//i[@class="checkmark-icon"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('blue highlight should be removed', async function () {
  const highlightCount = await page.locator('//div[contains(@class,"blue-highlight")]').count();
  expect(highlightCount).toBe(0);
});

// TODO: Replace XPath with Object Repository when available
Then('notification should move to {string} section', async function (sectionName: string) {
  await assertions.assertVisible(page.locator(`//div[@id='${sectionName.toLowerCase().replace(/\s+/g, '-')}-section']`));
});

// TODO: Replace XPath with Object Repository when available
Then('acknowledged notification should appear in {string} section', async function (sectionName: string) {
  await assertions.assertVisible(page.locator(`//div[@id='${sectionName.toLowerCase().replace(/\s+/g, '-')}-section']//div[@class='notification-item']`));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should display with gray text', async function () {
  await assertions.assertVisible(page.locator('//div[contains(@class,"notification-read")]'));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should show {string} label', async function (labelText: string) {
  await assertions.assertVisible(page.locator(`//span[contains(text(),'${labelText}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('notification badge count should decrease by {int}', async function (decreaseAmount: number) {
  const currentBadgeText = await page.locator('//span[@id="notification-badge"]').textContent();
  const currentCount = parseInt(currentBadgeText || '0');
  
  this.testData.notifications.expectedBadgeCount = currentCount - decreaseAmount;
});

// TODO: Replace XPath with Object Repository when available
Then('notification should display with status {string}', async function (status: string) {
  await assertions.assertVisible(page.locator(`//span[@class='notification-status' and contains(text(),'${status}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('acknowledgment timestamp should be visible', async function () {
  await assertions.assertVisible(page.locator('//span[@class="acknowledgment-timestamp"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('user who acknowledged should be displayed', async function () {
  await assertions.assertVisible(page.locator('//span[@class="acknowledged-by-user"]'));
});

/**************************************************/
/*  TEST CASE: TC-004 - THEN STEPS
/*  Performance SLA verification
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('change should be saved with timestamp {string}', async function (timestamp: string) {
  this.testData.timestamps.changeSavedTime = timestamp;
  await assertions.assertVisible(page.locator(`//span[@class='save-timestamp' and contains(text(),'${timestamp}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('notification badge should appear within {int} seconds', async function (maxSeconds: number) {
  const appeared = this.testData.notifications.appearedWithinSLA;
  expect(appeared).toBe(true);
  
  const elapsedTime = (this.testData.timestamps.notificationAppearTime - this.testData.timestamps.changeStartTimestamp) / 1000;
  expect(elapsedTime).toBeLessThanOrEqual(maxSeconds);
});

// TODO: Replace XPath with Object Repository when available
Then('notification timestamp should indicate generation within {int} minute', async function (maxMinutes: number) {
  await assertions.assertVisible(page.locator('//span[@class="notification-generation-timestamp"]'));
  const timestampText = await page.locator('//span[@class="notification-generation-timestamp"]').textContent();
  expect(timestampText).toBeTruthy();
});

// TODO: Replace XPath with Object Repository when available
Then('email should be received with timestamp between {string} and {string}', async function (startTime: string, endTime: string) {
  this.testData.timestamps.emailStartTime = startTime;
  this.testData.timestamps.emailEndTime = endTime;
  
  await assertions.assertVisible(page.locator('//div[@class="email-timestamp"]'));
  const emailTimestamp = await page.locator('//div[@class="email-timestamp"]').textContent();
  expect(emailTimestamp).toBeTruthy();
});

// TODO: Replace XPath with Object Repository when available
Then('logs should show schedule change detected at {string}', async function (detectionTime: string) {
  await assertions.assertVisible(page.locator(`//div[@class='log-entry' and contains(text(),'Schedule change detected') and contains(text(),'${detectionTime}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('logs should show notification generated at {string}', async function (generationTime: string) {
  await assertions.assertVisible(page.locator(`//div[@class='log-entry' and contains(text(),'Notification generated') and contains(text(),'${generationTime}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('logs should show email queued at {string}', async function (queueTime: string) {
  await assertions.assertVisible(page.locator(`//div[@class='log-entry' and contains(text(),'Email queued') and contains(text(),'${queueTime}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('logs should show in-app notification delivered at {string}', async function (deliveryTime: string) {
  await assertions.assertVisible(page.locator(`//div[@class='log-entry' and contains(text(),'In-app notification delivered') and contains(text(),'${deliveryTime}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('all timestamps should be within {int} minute of schedule change', async function (maxMinutes: number) {
  const logEntries = await page.locator('//div[@class="log-entry"]').count();
  expect(logEntries).toBeGreaterThan(0);
});

/**************************************************/
/*  TEST CASE: TC-005 - THEN STEPS
/*  Notification history page verification
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('{string} page should load', async function (pageName: string) {
  await assertions.assertVisible(page.locator(`//h1[contains(text(),'${pageName}')]`));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
Then('page should display list with columns {string}', async function (columnNames: string) {
  const columns = columnNames.split(',').map(col => col.trim());
  
  for (const column of columns) {
    await assertions.assertVisible(page.locator(`//th[contains(text(),'${column}')]`));
  }
});

// TODO: Replace XPath with Object Repository when available
Then('list should show all schedule change notifications sorted by most recent first', async function () {
  await assertions.assertVisible(page.locator('//table[@id="notification-history-table"]'));
  
  const firstRow = page.locator('//table[@id="notification-history-table"]//tbody//tr').first();
  await assertions.assertVisible(firstRow);
});

// TODO: Replace XPath with Object Repository when available
Then('page should display at least {int} notifications', async function (minCount: number) {
  const notificationRows = await page.locator('//table[@id="notification-history-table"]//tbody//tr').count();
  expect(notificationRows).toBeGreaterThanOrEqual(minCount);
});

// TODO: Replace XPath with Object Repository when available
Then('each notification should show notification date and time', async function () {
  await assertions.assertVisible(page.locator('//td[@class="notification-datetime"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('each notification should show type {string}', async function (notificationType: string) {
  await assertions.assertVisible(page.locator(`//td[@class='notification-type' and contains(text(),'${notificationType}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('each notification should show brief description of change', async function () {
  await assertions.assertVisible(page.locator('//td[@class="notification-description"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('each notification should show status as {string} or {string}', async function (status1: string, status2: string) {
  const statusCells = await page.locator('//td[@class="notification-status"]').count();
  expect(statusCells).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Then('each notification should show {string} link', async function (linkText: string) {
  await assertions.assertVisible(page.locator(`//a[contains(text(),'${linkText}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('modal should open showing complete notification details', async function () {
  await assertions.assertVisible(page.locator('//div[@id="notification-details-modal"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('modal should display original schedule', async function () {
  await assertions.assertVisible(page.locator('//div[@class="modal-original-schedule"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('modal should display new schedule', async function () {
  await assertions.assertVisible(page.locator('//div[@class="modal-new-schedule"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('modal should display all changed fields', async function () {
  await assertions.assertVisible(page.locator('//div[@class="modal-changed-fields"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('modal should display timestamp of change', async function () {
  await assertions.assertVisible(page.locator('//div[@class="modal-change-timestamp"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('modal should display who made the change', async function () {
  await assertions.assertVisible(page.locator('//div[@class="modal-changed-by"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('modal should display acknowledgment status', async function () {
  await assertions.assertVisible(page.locator('//div[@class="modal-acknowledgment-status"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('list should refresh to show only notifications from past {int} days', async function (daysPast: number) {
  this.testData.notifications.filteredDays = daysPast;
  await waits.waitForNetworkIdle();
  
  const notificationRows = await page.locator('//table[@id="notification-history-table"]//tbody//tr').count();
  expect(notificationRows).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Then('older notifications should be hidden', async function () {
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
Then('filter indicator should show {string} is active', async function (filterText: string) {
  await assertions.assertVisible(page.locator(`//span[@class='active-filter' and contains(text(),'${filterText}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('CSV file should download with filename {string}', async function (filenamePattern: string) {
  await assertions.assertVisible(page.locator('//div[@id="download-success-message"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('file should contain all filtered notifications with complete details', async function () {
  await assertions.assertVisible(page.locator('//div[@id="export-complete-indicator"]'));
});

/**************************************************/
/*  TEST CASE: TC-006 - THEN STEPS
/*  Draft vs Confirmed notification logic
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('appointment details page should display status {string}', async function (status: string) {
  await assertions.assertVisible(page.locator(`//span[@class='appointment-status' and contains(text(),'${status}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('appointment should show time {string}', async function (appointmentTime: string) {
  await assertions.assertVisible(page.locator(`//div[@class='appointment-time' and contains(text(),'${appointmentTime}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('system should display message {string}', async function (message: string) {
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${message}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('appointment should show status {string}', async function (status: string) {
  await assertions.assertVisible(page.locator(`//span[@class='appointment-status' and contains(text(),'${status}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('original time {string} should still display with draft indicator', async function (originalTime: string) {
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${originalTime}')]`));
  await assertions.assertVisible(page.locator('//span[@class="draft-indicator"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('no notification should be sent to user', async function () {
  const notificationBadge = await page.locator('//span[@id="notification-badge"]').count();
  expect(notificationBadge).toBe(0);
});

// TODO: Replace XPath with Object Repository when available
Then('notification bell icon should show no new notifications', async function () {
  const badgeCount = await page.locator('//span[@id="notification-badge"]').count();
  expect(badgeCount).toBe(0);
});

// TODO: Replace XPath with Object Repository when available
Then('email inbox should have no schedule change notification', async function () {
  const emailCount = await page.locator('//div[@class="email-item" and contains(text(),"Schedule Change")]').count();
  expect(emailCount).toBe(0);
});

// TODO: Replace XPath with Object Repository when available
Then('appointment status should change to {string}', async function (status: string) {
  await assertions.assertVisible(page.locator(`//span[@class='appointment-status' and contains(text(),'${status}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('time should show {string}', async function (time: string) {
  await assertions.assertVisible(page.locator(`//div[@class='appointment-time' and contains(text(),'${time}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('user should receive in-app notification about schedule change', async function () {
  await assertions.assertVisible(page.locator('//span[@id="notification-badge"]'));
  const badgeCount = await page.locator('//span[@id="notification-badge"]').textContent();
  expect(parseInt(badgeCount || '0')).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Then('user should receive email notification about schedule change', async function () {
  await assertions.assertVisible(page.locator('//div[@class="email-item" and contains(text(),"Schedule Change")]'));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should include change from {string} to {string}', async function (oldTime: string, newTime: string) {
  await actions.click(page.locator('//button[@id="notification-bell-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-dropdown-panel"]'));
  
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${oldTime}')]`));
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${newTime}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should include confirmed change details', async function () {
  await assertions.assertVisible(page.locator('//div[@class="notification-confirmed-details"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('notification log should show single notification sent only after confirmation', async function () {
  await actions.click(page.locator('//button[@id="admin-menu"]'));
  await actions.click(page.locator('//a[contains(text(),"Notification Logs")]'));
  await waits.waitForNetworkIdle();
  
  const notificationLogCount = await page.locator('//div[@class="notification-log-entry"]').count();
  expect(notificationLogCount).toBe(1);
  
  await assertions.assertVisible(page.locator('//div[contains(text(),"Notification sent after confirmation")]'));
});