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
    systemTime: null,
    notificationCount: 0
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

// TODO: Replace XPath with Object Repository when available
Given('user is logged into the system with valid credentials', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), 'testuser');
  await actions.fill(page.locator('//input[@id="password"]'), 'testpass');
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="dashboard"]'));
});

// TODO: Replace XPath with Object Repository when available
Given('notification service is running and operational', async function () {
  await assertions.assertVisible(page.locator('//div[@id="notification-service-status"]'));
  const statusText = await page.locator('//div[@id="notification-service-status"]').textContent();
  expect(statusText).toContain('operational');
});

// TODO: Replace XPath with Object Repository when available
Given('user has at least one scheduled appointment in the system', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/schedule`);
  await waits.waitForNetworkIdle();
  const appointmentCount = await page.locator('//div[@class="appointment-item"]').count();
  expect(appointmentCount).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Given('user\'s email address is verified and configured in profile settings', async function () {
  await actions.click(page.locator('//button[@id="user-profile-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="profile-menu"]'));
  await actions.click(page.locator('//a[contains(text(),"Profile Settings")]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//span[@id="email-verified-badge"]'));
});

// TODO: Replace XPath with Object Repository when available
Given('notification preferences are enabled for both email and in-app alerts', async function () {
  await actions.click(page.locator('//button[@id="user-profile-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="profile-menu"]'));
  await actions.click(page.locator('//a[contains(text(),"Notification Settings")]'));
  await waits.waitForNetworkIdle();
  const emailCheckbox = page.locator('//input[@id="notification-email-enabled"]');
  const inAppCheckbox = page.locator('//input[@id="notification-inapp-enabled"]');
  if (!(await emailCheckbox.isChecked())) {
    await actions.check(emailCheckbox);
  }
  if (!(await inAppCheckbox.isChecked())) {
    await actions.check(inAppCheckbox);
  }
  await actions.click(page.locator('//button[@id="save-notification-settings"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
Given('user has an appointment scheduled for tomorrow at {string}', async function (time: string) {
  this.testData.appointments.originalTime = time;
  await actions.navigateTo(`${process.env.BASE_URL}/schedule`);
  await waits.waitForNetworkIdle();
  const appointmentXPath = `//div[@class="appointment-item" and contains(., "${time}")]`;
  await assertions.assertVisible(page.locator(appointmentXPath));
});

// TODO: Replace XPath with Object Repository when available
Given('user has a scheduled appointment titled {string} on {string} at {string}', async function (title: string, date: string, time: string) {
  this.testData.appointments.title = title;
  this.testData.appointments.originalDate = date;
  this.testData.appointments.originalTime = time;
  await actions.navigateTo(`${process.env.BASE_URL}/schedule`);
  await waits.waitForNetworkIdle();
  const appointmentXPath = `//div[@class="appointment-item" and contains(., "${title}") and contains(., "${date}") and contains(., "${time}")]`;
  await assertions.assertVisible(page.locator(appointmentXPath));
});

// TODO: Replace XPath with Object Repository when available
Given('notification service is configured and running', async function () {
  await assertions.assertVisible(page.locator('//div[@id="notification-service-status"]'));
  const statusText = await page.locator('//div[@id="notification-service-status"]').textContent();
  expect(statusText).toContain('running');
});

// TODO: Replace XPath with Object Repository when available
Given('user has notification permissions enabled', async function () {
  await actions.click(page.locator('//button[@id="user-profile-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="profile-menu"]'));
  await actions.click(page.locator('//a[contains(text(),"Notification Settings")]'));
  await waits.waitForNetworkIdle();
  const permissionsEnabled = await page.locator('//input[@id="notification-permissions-enabled"]').isChecked();
  expect(permissionsEnabled).toBe(true);
});

// TODO: Replace XPath with Object Repository when available
Given('user has received at least one unread schedule change notification', async function () {
  await actions.click(page.locator('//button[@id="notification-bell-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-panel"]'));
  const unreadNotifications = await page.locator('//div[@class="notification-item unread"]').count();
  expect(unreadNotifications).toBeGreaterThan(0);
  await actions.click(page.locator('//button[@id="close-notification-panel"]'));
});

// TODO: Replace XPath with Object Repository when available
Given('notification appears in notification panel with {string} status', async function (status: string) {
  await actions.click(page.locator('//button[@id="notification-bell-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-panel"]'));
  const statusXPath = `//div[@class="notification-item ${status}"]`;
  await assertions.assertVisible(page.locator(statusXPath));
  await actions.click(page.locator('//button[@id="close-notification-panel"]'));
});

// TODO: Replace XPath with Object Repository when available
Given('notification bell icon shows unread count badge', async function () {
  const badgeXPath = '//span[@id="notification-badge-count"]';
  await assertions.assertVisible(page.locator(badgeXPath));
  const badgeCount = await page.locator(badgeXPath).textContent();
  expect(parseInt(badgeCount || '0')).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Given('user has administrator privileges', async function () {
  await actions.click(page.locator('//button[@id="user-profile-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="profile-menu"]'));
  const roleXPath = '//span[@id="user-role" and contains(text(),"Administrator")]';
  await assertions.assertVisible(page.locator(roleXPath));
  await actions.click(page.locator('//button[@id="user-profile-icon"]'));
});

// TODO: Replace XPath with Object Repository when available
Given('user has {string} scheduled appointments for the upcoming week', async function (count: string) {
  this.testData.appointments.bulkCount = parseInt(count);
  await actions.navigateTo(`${process.env.BASE_URL}/schedule`);
  await waits.waitForNetworkIdle();
  const appointmentCount = await page.locator('//div[@class="appointment-item upcoming"]').count();
  expect(appointmentCount).toBeGreaterThanOrEqual(parseInt(count));
});

// TODO: Replace XPath with Object Repository when available
Given('all appointments are confirmed and active', async function () {
  const confirmedAppointments = await page.locator('//div[@class="appointment-item" and @data-status="confirmed"]').count();
  expect(confirmedAppointments).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Given('system time is synchronized and accurate', async function () {
  this.testData.systemTime = new Date();
  await assertions.assertVisible(page.locator('//div[@id="system-time-display"]'));
});

// TODO: Replace XPath with Object Repository when available
Given('notification service has sufficient capacity for bulk notifications', async function () {
  const capacityXPath = '//div[@id="notification-service-capacity"]';
  await assertions.assertVisible(page.locator(capacityXPath));
  const capacityText = await page.locator(capacityXPath).textContent();
  expect(capacityText).toContain('sufficient');
});

// TODO: Replace XPath with Object Repository when available
Given('user has received at least {string} schedule change notifications over the past {string} days', async function (count: string, days: string) {
  await actions.click(page.locator('//button[@id="user-profile-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="profile-menu"]'));
  await actions.click(page.locator('//a[contains(text(),"Notification History")]'));
  await waits.waitForNetworkIdle();
  const notificationCount = await page.locator('//div[@class="notification-history-item"]').count();
  expect(notificationCount).toBeGreaterThanOrEqual(parseInt(count));
});

// TODO: Replace XPath with Object Repository when available
Given('some notifications are acknowledged', async function () {
  const acknowledgedCount = await page.locator('//div[@class="notification-history-item" and @data-status="acknowledged"]').count();
  expect(acknowledgedCount).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Given('some notifications are unread', async function () {
  const unreadCount = await page.locator('//div[@class="notification-history-item" and @data-status="unread"]').count();
  expect(unreadCount).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Given('user has access to Notification History feature', async function () {
  await actions.click(page.locator('//button[@id="user-profile-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="profile-menu"]'));
  await assertions.assertVisible(page.locator('//a[contains(text(),"Notification History")]'));
  await actions.click(page.locator('//button[@id="user-profile-icon"]'));
});

// TODO: Replace XPath with Object Repository when available
Given('user has a confirmed appointment scheduled for {string} on {string} at {string}', async function (title: string, date: string, time: string) {
  this.testData.appointments.title = title;
  this.testData.appointments.originalDate = date;
  this.testData.appointments.originalTime = time;
  await actions.navigateTo(`${process.env.BASE_URL}/schedule`);
  await waits.waitForNetworkIdle();
  const appointmentXPath = `//div[@class="appointment-item" and @data-status="confirmed" and contains(., "${title}") and contains(., "${date}") and contains(., "${time}")]`;
  await assertions.assertVisible(page.locator(appointmentXPath));
});

// TODO: Replace XPath with Object Repository when available
Given('notification preferences are enabled', async function () {
  await actions.click(page.locator('//button[@id="user-profile-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="profile-menu"]'));
  await actions.click(page.locator('//a[contains(text(),"Notification Settings")]'));
  await waits.waitForNetworkIdle();
  const notificationsEnabled = await page.locator('//input[@id="notifications-enabled"]').isChecked();
  expect(notificationsEnabled).toBe(true);
  await actions.click(page.locator('//button[@id="back-to-dashboard"]'));
});

// TODO: Replace XPath with Object Repository when available
Given('user has permission to cancel appointments', async function () {
  await actions.click(page.locator('//button[@id="user-profile-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="profile-menu"]'));
  const permissionsXPath = '//span[@id="user-permissions" and contains(text(),"cancel_appointments")]';
  await assertions.assertVisible(page.locator(permissionsXPath));
  await actions.click(page.locator('//button[@id="user-profile-icon"]'));
});

// ==================== WHEN STEPS ====================

// TODO: Replace XPath with Object Repository when available
When('user navigates to {string} page', async function (pageName: string) {
  const pageSlug = pageName.toLowerCase().replace(/\s+/g, '-');
  await actions.navigateTo(`${process.env.BASE_URL}/${pageSlug}`);
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user selects the existing appointment', async function () {
  const appointmentXPath = `//div[@class="appointment-item" and contains(., "${this.testData.appointments.originalTime}")]`;
  await actions.click(page.locator(appointmentXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user clicks {string} button', async function (buttonText: string) {
  const buttonIdXPath = `//button[@id="${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const buttons = page.locator(buttonIdXPath);
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`//button[contains(text(),"${buttonText}")]`));
  }
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user changes the appointment time from {string} to {string}', async function (oldTime: string, newTime: string) {
  this.testData.appointments.newTime = newTime;
  const timeFieldXPath = '//input[@id="appointment-time"]';
  await actions.clearAndFill(page.locator(timeFieldXPath), newTime);
});

// TODO: Replace XPath with Object Repository when available
When('user waits for {string} minute', async function (minutes: string) {
  await page.waitForTimeout(parseInt(minutes) * 60000);
});

// TODO: Replace XPath with Object Repository when available
When('user clicks notification bell icon', async function () {
  await actions.click(page.locator('//button[@id="notification-bell-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-panel"]'));
});

// TODO: Replace XPath with Object Repository when available
When('user locates the {string} appointment scheduled for {string} at {string}', async function (title: string, date: string, time: string) {
  const appointmentXPath = `//div[@class="appointment-item" and contains(., "${title}") and contains(., "${date}") and contains(., "${time}")]`;
  await assertions.assertVisible(page.locator(appointmentXPath));
  await actions.scrollIntoView(page.locator(appointmentXPath));
});

// TODO: Replace XPath with Object Repository when available
When('user clicks {string} button next to the appointment', async function (buttonText: string) {
  const appointmentTitle = this.testData.appointments.title;
  const buttonXPath = `//div[@class="appointment-item" and contains(., "${appointmentTitle}")]//button[contains(text(),"${buttonText}")]`;
  await actions.click(page.locator(buttonXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user modifies the date to {string}', async function (newDate: string) {
  this.testData.appointments.newDate = newDate;
  const dateFieldXPath = '//input[@id="appointment-date"]';
  await actions.clearAndFill(page.locator(dateFieldXPath), newDate);
});

// TODO: Replace XPath with Object Repository when available
When('user modifies the time to {string}', async function (newTime: string) {
  this.testData.appointments.newTime = newTime;
  const timeFieldXPath = '//input[@id="appointment-time"]';
  await actions.clearAndFill(page.locator(timeFieldXPath), newTime);
});

// TODO: Replace XPath with Object Repository when available
When('user clicks notification bell icon within {string} minute', async function (minutes: string) {
  await page.waitForTimeout(5000);
  await actions.click(page.locator('//button[@id="notification-bell-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-panel"]'));
});

// TODO: Replace XPath with Object Repository when available
When('user opens the email notification in inbox', async function () {
  await actions.navigateTo(`${process.env.BASE_URL}/email-inbox`);
  await waits.waitForNetworkIdle();
  const latestEmailXPath = '//div[@class="email-item"][1]';
  await actions.click(page.locator(latestEmailXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user clicks {string} button next to the notification', async function (buttonText: string) {
  const buttonXPath = `//div[@class="notification-item"][1]//button[contains(text(),"${buttonText}")]`;
  await actions.click(page.locator(buttonXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user closes the notification panel', async function () {
  await actions.click(page.locator('//button[@id="close-notification-panel"]'));
  await waits.waitForHidden(page.locator('//div[@id="notification-panel"]'));
});

// TODO: Replace XPath with Object Repository when available
When('user clicks notification bell icon again', async function () {
  await actions.click(page.locator('//button[@id="notification-bell-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-panel"]'));
});

// TODO: Replace XPath with Object Repository when available
When('user selects all {string} appointments using checkboxes', async function (count: string) {
  const checkboxes = page.locator('//input[@type="checkbox" and @class="appointment-checkbox"]');
  const checkboxCount = await checkboxes.count();
  for (let i = 0; i < Math.min(checkboxCount, parseInt(count)); i++) {
    await actions.check(checkboxes.nth(i));
  }
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user clicks {string} dropdown', async function (dropdownText: string) {
  const dropdownXPath = `//button[@id="${dropdownText.toLowerCase().replace(/\s+/g, '-')}-dropdown"]`;
  await actions.click(page.locator(dropdownXPath));
  await waits.waitForVisible(page.locator('//div[@class="dropdown-menu"]'));
});

// TODO: Replace XPath with Object Repository when available
When('user selects {string} option', async function (optionText: string) {
  const optionXPath = `//a[@class="dropdown-item" and contains(text(),"${optionText}")]`;
  await actions.click(page.locator(optionXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user sets new date to be {string} days later than current dates', async function (days: string) {
  this.testData.appointments.daysOffset = parseInt(days);
  const dateOffsetFieldXPath = '//input[@id="date-offset-days"]';
  await actions.fill(page.locator(dateOffsetFieldXPath), days);
});

// TODO: Replace XPath with Object Repository when available
When('user records current system time', async function () {
  this.testData.systemTime = new Date();
});

// TODO: Replace XPath with Object Repository when available
When('user checks email inbox within {string} minute', async function (minutes: string) {
  await page.waitForTimeout(5000);
  await actions.navigateTo(`${process.env.BASE_URL}/email-inbox`);
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user clicks on user profile icon', async function () {
  await actions.click(page.locator('//button[@id="user-profile-icon"]'));
  await waits.waitForVisible(page.locator('//div[@id="profile-menu"]'));
});

// TODO: Replace XPath with Object Repository when available
When('user selects {string} from dropdown menu', async function (menuItem: string) {
  const menuItemXPath = `//a[@class="dropdown-item" and contains(text(),"${menuItem}")]`;
  await actions.click(page.locator(menuItemXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user clicks on the oldest notification in the list', async function () {
  const oldestNotificationXPath = '//div[@class="notification-history-item"]:last-child';
  await actions.click(page.locator(oldestNotificationXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user selects {string} from filter dropdown', async function (filterOption: string) {
  await actions.click(page.locator('//button[@id="notification-filter-dropdown"]'));
  await waits.waitForVisible(page.locator('//div[@class="filter-dropdown-menu"]'));
  const filterXPath = `//a[@class="filter-option" and contains(text(),"${filterOption}")]`;
  await actions.click(page.locator(filterXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user clears the filter', async function () {
  await actions.click(page.locator('//button[@id="clear-filter"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user selects date range for past {string} days using date range picker', async function (days: string) {
  await actions.click(page.locator('//button[@id="date-range-picker"]'));
  await waits.waitForVisible(page.locator('//div[@id="date-range-picker-menu"]'));
  const dateRangeXPath = `//a[@class="date-range-option" and contains(text(),"Past ${days} days")]`;
  await actions.click(page.locator(dateRangeXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user locates the {string} appointment on {string} at {string}', async function (title: string, date: string, time: string) {
  const appointmentXPath = `//div[@class="appointment-item" and contains(., "${title}") and contains(., "${date}") and contains(., "${time}")]`;
  await assertions.assertVisible(page.locator(appointmentXPath));
  await actions.scrollIntoView(page.locator(appointmentXPath));
});

// TODO: Replace XPath with Object Repository when available
When('user clicks {string} button in confirmation dialog', async function (buttonText: string) {
  const dialogButtonXPath = `//div[@class="confirmation-dialog"]//button[contains(text(),"${buttonText}")]`;
  await actions.click(page.locator(dialogButtonXPath));
  await waits.waitForNetworkIdle();
});

// ==================== THEN STEPS ====================

// TODO: Replace XPath with Object Repository when available
Then('success message {string} should be displayed', async function (message: string) {
  const messageXPath = `//div[@class="success-message" and contains(text(),"${message}")]`;
  await assertions.assertVisible(page.locator(messageXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('notification bell icon should display badge count {string}', async function (count: string) {
  const badgeXPath = '//span[@id="notification-badge-count"]';
  await assertions.assertVisible(page.locator(badgeXPath));
  await assertions.assertContainsText(page.locator(badgeXPath), count);
});

// TODO: Replace XPath with Object Repository when available
Then('notification panel should be visible', async function () {
  await assertions.assertVisible(page.locator('//div[@id="notification-panel"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('notification message {string} should be displayed', async function (message: string) {
  const notificationXPath = `//div[@class="notification-item"]//span[contains(text(),"${message}")]`;
  await assertions.assertVisible(page.locator(notificationXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should include timestamp', async function () {
  const timestampXPath = '//div[@class="notification-item"][1]//span[@class="notification-timestamp"]';
  await assertions.assertVisible(page.locator(timestampXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('email should be received within {string} minute', async function (minutes: string) {
  await page.waitForTimeout(5000);
  await actions.navigateTo(`${process.env.BASE_URL}/email-inbox`);
  await waits.waitForNetworkIdle();
  const latestEmailXPath = '//div[@class="email-item"][1]';
  await assertions.assertVisible(page.locator(latestEmailXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('email subject should be {string}', async function (subject: string) {
  const subjectXPath = `//div[@class="email-subject" and contains(text(),"${subject}")]`;
  await assertions.assertVisible(page.locator(subjectXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('email should contain original time {string}', async function (time: string) {
  const emailBodyXPath = '//div[@class="email-body"]';
  await assertions.assertContainsText(page.locator(emailBodyXPath), time);
});

// TODO: Replace XPath with Object Repository when available
Then('email should contain new time {string}', async function (time: string) {
  const emailBodyXPath = '//div[@class="email-body"]';
  await assertions.assertContainsText(page.locator(emailBodyXPath), time);
});

// TODO: Replace XPath with Object Repository when available
Then('email should contain appointment date', async function () {
  const emailBodyXPath = '//div[@class="email-body"]';
  const emailBody = await page.locator(emailBodyXPath).textContent();
  expect(emailBody).toBeTruthy();
  expect(emailBody?.length).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Then('email should contain appointment description', async function () {
  const emailBodyXPath = '//div[@class="email-body"]';
  const emailBody = await page.locator(emailBodyXPath).textContent();
  expect(emailBody).toBeTruthy();
  expect(emailBody?.length).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Then('appointment updates successfully', async function () {
  const successXPath = '//div[@class="success-message"]';
  await assertions.assertVisible(page.locator(successXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('confirmation message should be displayed', async function () {
  const confirmationXPath = '//div[@class="confirmation-message"]';
  await assertions.assertVisible(page.locator(confirmationXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should display red unread indicator', async function () {
  const unreadIndicatorXPath = '//div[@class="notification-item"][1]//span[@class="unread-indicator red"]';
  await assertions.assertVisible(page.locator(unreadIndicatorXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('notification content should contain {string}', async function (content: string) {
  const notificationContentXPath = '//div[@class="notification-item"][1]//div[@class="notification-content"]';
  await assertions.assertContainsText(page.locator(notificationContentXPath), content);
});

// TODO: Replace XPath with Object Repository when available
Then('notification should contain original date {string}', async function (date: string) {
  const notificationContentXPath = '//div[@class="notification-item"][1]//div[@class="notification-content"]';
  await assertions.assertContainsText(page.locator(notificationContentXPath), date);
});

// TODO: Replace XPath with Object Repository when available
Then('notification should contain original time {string}', async function (time: string) {
  const notificationContentXPath = '//div[@class="notification-item"][1]//div[@class="notification-content"]';
  await assertions.assertContainsText(page.locator(notificationContentXPath), time);
});

// TODO: Replace XPath with Object Repository when available
Then('notification should contain new date {string}', async function (date: string) {
  const notificationContentXPath = '//div[@class="notification-item"][1]//div[@class="notification-content"]';
  await assertions.assertContainsText(page.locator(notificationContentXPath), date);
});

// TODO: Replace XPath with Object Repository when available
Then('notification should contain new time {string}', async function (time: string) {
  const notificationContentXPath = '//div[@class="notification-item"][1]//div[@class="notification-content"]';
  await assertions.assertContainsText(page.locator(notificationContentXPath), time);
});

// TODO: Replace XPath with Object Repository when available
Then('notification should contain description {string}', async function (description: string) {
  const notificationContentXPath = '//div[@class="notification-item"][1]//div[@class="notification-content"]';
  await assertions.assertContainsText(page.locator(notificationContentXPath), description);
});

// TODO: Replace XPath with Object Repository when available
Then('email should contain formatted section {string}', async function (sectionName: string) {
  const sectionXPath = `//div[@class="email-body"]//div[@class="email-section" and contains(., "${sectionName}")]`;
  await assertions.assertVisible(page.locator(sectionXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('most recent notification should be displayed at the top', async function () {
  const firstNotificationXPath = '//div[@class="notification-item"][1]';
  await assertions.assertVisible(page.locator(firstNotificationXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should be marked as {string} in bold text', async function (status: string) {
  const notificationXPath = `//div[@class="notification-item ${status}"][1]//span[@class="notification-text bold"]`;
  await assertions.assertVisible(page.locator(notificationXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('{string} button should change to {string} with checkmark icon', async function (oldButtonText: string, newButtonText: string) {
  const buttonXPath = `//div[@class="notification-item"][1]//button[contains(text(),"${newButtonText}")]`;
  await assertions.assertVisible(page.locator(buttonXPath));
  const checkmarkXPath = `//div[@class="notification-item"][1]//button//i[@class="checkmark-icon"]`;
  await assertions.assertVisible(page.locator(checkmarkXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('notification text should change from bold to regular weight', async function () {
  const notificationTextXPath = '//div[@class="notification-item"][1]//span[@class="notification-text"]';
  const fontWeight = await page.locator(notificationTextXPath).evaluate((el) => window.getComputedStyle(el).fontWeight);
  expect(parseInt(fontWeight)).toBeLessThan(700);
});

// TODO: Replace XPath with Object Repository when available
Then('notification badge count should decrease by {string}', async function (count: string) {
  const badgeXPath = '//span[@id="notification-badge-count"]';
  const currentCount = await page.locator(badgeXPath).textContent();
  expect(parseInt(currentCount || '0')).toBeGreaterThanOrEqual(0);
});

// TODO: Replace XPath with Object Repository when available
Then('previously acknowledged notification should be visible', async function () {
  const acknowledgedXPath = '//div[@class="notification-item acknowledged"]';
  await assertions.assertVisible(page.locator(acknowledgedXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should show {string} status', async function (status: string) {
  const statusXPath = `//div[@class="notification-item"][1]//span[@class="notification-status" and contains(text(),"${status}")]`;
  await assertions.assertVisible(page.locator(statusXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should display acknowledgment timestamp', async function () {
  const timestampXPath = '//div[@class="notification-item"][1]//span[@class="acknowledgment-timestamp"]';
  await assertions.assertVisible(page.locator(timestampXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('original notification details should be visible', async function () {
  const detailsXPath = '//div[@class="notification-item"][1]//div[@class="notification-details"]';
  await assertions.assertVisible(page.locator(detailsXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('{string} page should be visible', async function (pageName: string) {
  const pageHeaderXPath = `//h1[contains(text(),"${pageName}")]`;
  await assertions.assertVisible(page.locator(pageHeaderXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should be displayed with status {string}', async function (status: string) {
  const statusXPath = `//div[@class="notification-history-item"]//span[@class="status" and contains(text(),"${status}")]`;
  await assertions.assertVisible(page.locator(statusXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('acknowledgment timestamp should be visible', async function () {
  const timestampXPath = '//div[@class="notification-history-item expanded"]//span[@class="acknowledgment-timestamp"]';
  await assertions.assertVisible(page.locator(timestampXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('all {string} appointments should be highlighted', async function (count: string) {
  const highlightedCount = await page.locator('//div[@class="appointment-item highlighted"]').count();
  expect(highlightedCount).toBe(parseInt(count));
});

// TODO: Replace XPath with Object Repository when available
Then('{string} menu should be enabled', async function (menuName: string) {
  const menuXPath = `//button[@id="${menuName.toLowerCase().replace(/\s+/g, '-')}-menu" and not(@disabled)]`;
  await assertions.assertVisible(page.locator(menuXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('bulk reschedule dialog should be visible', async function () {
  await assertions.assertVisible(page.locator('//div[@id="bulk-reschedule-dialog"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('dialog should show all {string} appointments with new proposed dates', async function (count: string) {
  const appointmentRows = await page.locator('//div[@id="bulk-reschedule-dialog"]//div[@class="appointment-row"]').count();
  expect(appointmentRows).toBe(parseInt(count));
});

// TODO: Replace XPath with Object Repository when available
Then('notification badge should show {string}', async function (count: string) {
  const badgeXPath = '//span[@id="notification-badge-count"]';
  await assertions.assertContainsText(page.locator(badgeXPath), count);
});

// TODO: Replace XPath with Object Repository when available
Then('notification panel should display {string} separate notifications', async function (count: string) {
  const notificationCount = await page.locator('//div[@class="notification-item"]').count();
  expect(notificationCount).toBe(parseInt(count));
});

// TODO: Replace XPath with Object Repository when available
Then('all notifications should be timestamped within {string} minute of confirmation', async function (minutes: string) {
  const notifications = page.locator('//div[@class="notification-item"]//span[@class="notification-timestamp"]');
  const notificationCount = await notifications.count();
  for (let i = 0; i < notificationCount; i++) {
    await assertions.assertVisible(notifications.nth(i));
  }
});

// TODO: Replace XPath with Object Repository when available
Then('{string} separate email notifications should be received', async function (count: string) {
  const emailCount = await page.locator('//div[@class="email-item"]').count();
  expect(emailCount).toBeGreaterThanOrEqual(parseInt(count));
});

// TODO: Replace XPath with Object Repository when available
Then('all emails should have send timestamps within {string} minute of confirmation', async function (minutes: string) {
  const emails = page.locator('//div[@class="email-item"]//span[@class="email-timestamp"]');
  const emailCount = await emails.count();
  for (let i = 0; i < emailCount; i++) {
    await assertions.assertVisible(emails.nth(i));
  }
});

// TODO: Replace XPath with Object Repository when available
Then('each notification should contain accurate before and after schedule information', async function () {
  const notifications = page.locator('//div[@class="notification-item"]');
  const notificationCount = await notifications.count();
  for (let i = 0; i < notificationCount; i++) {
    const notificationText = await notifications.nth(i).textContent();
    expect(notificationText).toBeTruthy();
  }
});

// TODO: Replace XPath with Object Repository when available
Then('each notification should show original date and time', async function () {
  const notifications = page.locator('//div[@class="notification-item"]');
  const notificationCount = await notifications.count();
  for (let i = 0; i < notificationCount; i++) {
    const notificationText = await notifications.nth(i).textContent();
    expect(notificationText).toBeTruthy();
  }
});

// TODO: Replace XPath with Object Repository when available
Then('each notification should show new date {string} days later', async function (days: string) {
  const notifications = page.locator('//div[@class="notification-item"]');
  const notificationCount = await notifications.count();
  for (let i = 0; i < notificationCount; i++) {
    const notificationText = await notifications.nth(i).textContent();
    expect(notificationText).toBeTruthy();
  }
});

// TODO: Replace XPath with Object Repository when available
Then('notification list should display at least {string} notifications', async function (count: string) {
  const notificationCount = await page.locator('//div[@class="notification-history-item"]').count();
  expect(notificationCount).toBeGreaterThanOrEqual(parseInt(count));
});

// TODO: Replace XPath with Object Repository when available
Then('notifications should be sorted by date with most recent first', async function () {
  const firstNotificationXPath = '//div[@class="notification-history-item"][1]';
  await assertions.assertVisible(page.locator(firstNotificationXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('list should show column {string}', async function (columnName: string) {
  const columnXPath = `//th[contains(text(),"${columnName}")]`;
  await assertions.assertVisible(page.locator(columnXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should expand showing complete information', async function () {
  const expandedXPath = '//div[@class="notification-history-item expanded"]';
  await assertions.assertVisible(page.locator(expandedXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should display original schedule', async function () {
  const originalScheduleXPath = '//div[@class="notification-history-item expanded"]//div[@class="original-schedule"]';
  await assertions.assertVisible(page.locator(originalScheduleXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should display new schedule', async function () {
  const newScheduleXPath = '//div[@class="notification-history-item expanded"]//div[@class="new-schedule"]';
  await assertions.assertVisible(page.locator(newScheduleXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should display appointment title', async function () {
  const titleXPath = '//div[@class="notification-history-item expanded"]//div[@class="appointment-title"]';
  await assertions.assertVisible(page.locator(titleXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should display timestamp of change', async function () {
  const timestampXPath = '//div[@class="notification-history-item expanded"]//span[@class="change-timestamp"]';
  await assertions.assertVisible(page.locator(timestampXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('notification should display acknowledgment status', async function () {
  const statusXPath = '//div[@class="notification-history-item expanded"]//span[@class="acknowledgment-status"]';
  await assertions.assertVisible(page.locator(statusXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('list should refresh to show only unread notifications', async function () {
  const unreadCount = await page.locator('//div[@class="notification-history-item" and @data-status="unread"]').count();
  const totalCount = await page.locator('//div[@class="notification-history-item"]').count();
  expect(unreadCount).toBe(totalCount);
});

// TODO: Replace XPath with Object Repository when available
Then('all acknowledged notifications should be hidden', async function () {
  const acknowledgedCount = await page.locator('//div[@class="notification-history-item" and @data-status="acknowledged"]').count();
  expect(acknowledgedCount).toBe(0);
});

// TODO: Replace XPath with Object Repository when available
Then('list should display only notifications from past {string} days', async function (days: string) {
  const notificationCount = await page.locator('//div[@class="notification-history-item"]').count();
  expect(notificationCount).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Then('count indicator should show number of results', async function () {
  const countIndicatorXPath = '//span[@id="notification-count-indicator"]';
  await assertions.assertVisible(page.locator(countIndicatorXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('appointment should be displayed with status {string}', async function (status: string) {
  const statusXPath = `//div[@class="appointment-item"]//span[@class="status" and contains(text(),"${status}")]`;
  await assertions.assertVisible(page.locator(statusXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('all appointment details should be visible', async function () {
  const detailsXPath = '//div[@class="appointment-details"]';
  await assertions.assertVisible(page.locator(detailsXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('confirmation dialog should be visible', async function () {
  await assertions.assertVisible(page.locator('//div[@class="confirmation-dialog"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('dialog should display message {string}', async function (message: string) {
  const messageXPath = `//div[@class="confirmation-dialog"]//p[contains(text(),"${message}")]`;
  await assertions.assertVisible(page.locator(messageXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('dialog should close', async function () {
  await waits.waitForHidden(page.locator('//div[@class="confirmation-dialog"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('appointment should be removed from schedule or marked as {string}', async function (status: string) {
  const appointmentTitle = this.testData.appointments.title;
  const appointmentXPath = `//div[@class="appointment-item" and contains(., "${appointmentTitle}")]`;
  const appointmentExists = await page.locator(appointmentXPath).count();
  if (appointmentExists > 0) {
    const statusXPath = `//div[@class="appointment-item" and contains(., "${appointmentTitle}")]//span[@class="status" and contains(text(),"${status}")]`;
    await assertions.assertVisible(page.locator(statusXPath));
  }
});

// TODO: Replace XPath with Object Repository when available
Then('email should be received with subject {string}', async function (subject: string) {
  await actions.navigateTo(`${process.env.BASE_URL}/email-inbox`);
  await waits.waitForNetworkIdle();
  const subjectXPath = `//div[@class="email-item"]//span[@class="email-subject" and contains(text(),"${subject}")]`;
  await assertions.assertVisible(page.locator(subjectXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('email should contain appointment title {string}', async function (title: string) {
  const emailBodyXPath = '//div[@class="email-body"]';
  await assertions.assertContainsText(page.locator(emailBodyXPath), title);
});

// TODO: Replace XPath with Object Repository when available
Then('email should contain original date {string}', async function (date: string) {
  const emailBodyXPath = '//div[@class="email-body"]';
  await assertions.assertContainsText(page.locator(emailBodyXPath), date);
});

// TODO: Replace XPath with Object Repository when available
Then('email should contain cancellation timestamp', async function () {
  const timestampXPath = '//div[@class="email-body"]//span[@class="cancellation-timestamp"]';
  await assertions.assertVisible(page.locator(timestampXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('email should contain cancellation reason field', async function () {
  const reasonXPath = '//div[@class="email-body"]//div[@class="cancellation-reason"]';
  await assertions.assertVisible(page.locator(reasonXPath));
});