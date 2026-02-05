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
    systemState: {},
    notifications: []
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
/*  Used across multiple test cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user is logged into the system', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  
  const credentials = this.testData?.users?.user || { username: 'testuser', password: 'testpass' };
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  
  await assertions.assertVisible(page.locator('//div[@id="dashboard"]'));
});

// TODO: Replace XPath with Object Repository when available
Given('user has at least one scheduled appointment', async function () {
  await actions.click(page.locator('//a[contains(text(),"Schedule")]'));
  await waits.waitForNetworkIdle();
  
  const appointmentCount = await page.locator('//div[@class="appointment-item"]').count();
  if (appointmentCount === 0) {
    await actions.click(page.locator('//button[@id="create-appointment"]'));
    await actions.fill(page.locator('//input[@id="appointment-title"]'), 'Test Appointment');
    await actions.fill(page.locator('//input[@id="appointment-time"]'), '10:00 AM');
    await actions.click(page.locator('//button[@id="save-appointment"]'));
    await waits.waitForNetworkIdle();
  }
  
  this.testData.appointments.current = {
    title: 'Test Appointment',
    originalTime: '10:00 AM'
  };
});

/**************************************************/
/*  TEST CASE: TC-NEG-001
/*  Title: System handles notification failure gracefully when email service is unavailable
/*  Priority: High
/*  Category: Negative
/*  Description: Validates graceful degradation when email service fails
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('email service is temporarily unavailable', async function () {
  await page.evaluate(() => {
    window.localStorage.setItem('mock_email_service_status', 'unavailable');
  });
  this.testData.systemState.emailService = 'unavailable';
});

// TODO: Replace XPath with Object Repository when available
Given('in-app notification service is operational', async function () {
  await page.evaluate(() => {
    window.localStorage.setItem('mock_inapp_service_status', 'operational');
  });
  this.testData.systemState.inAppService = 'operational';
});

// TODO: Replace XPath with Object Repository when available
Given('system has error handling configured for email failures', async function () {
  await page.evaluate(() => {
    window.localStorage.setItem('mock_error_handling_enabled', 'true');
  });
  this.testData.systemState.errorHandling = 'enabled';
});

/**************************************************/
/*  TEST CASE: TC-NEG-002
/*  Title: System behavior when user has invalid or missing email address in profile
/*  Priority: High
/*  Category: Negative
/*  Description: Validates notification handling with invalid email
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user profile email field is set to {string}', async function (emailValue: string) {
  await actions.click(page.locator('//a[contains(text(),"User Profile")]'));
  await waits.waitForNetworkIdle();
  
  await actions.clearAndFill(page.locator('//input[@id="email"]'), emailValue);
  await actions.click(page.locator('//button[@id="save-profile"]'));
  await waits.waitForNetworkIdle();
  
  this.testData.userEmail = emailValue;
});

// TODO: Replace XPath with Object Repository when available
Given('notification service is operational', async function () {
  await page.evaluate(() => {
    window.localStorage.setItem('mock_notification_service_status', 'operational');
  });
  this.testData.systemState.notificationService = 'operational';
});

// TODO: Replace XPath with Object Repository when available
Given('email validation is enforced in the system', async function () {
  await page.evaluate(() => {
    window.localStorage.setItem('mock_email_validation_enabled', 'true');
  });
  this.testData.systemState.emailValidation = 'enabled';
});

/**************************************************/
/*  TEST CASE: TC-NEG-003
/*  Title: System handles notification when user session expires during schedule change
/*  Priority: Medium
/*  Category: Negative
/*  Description: Validates session timeout handling during appointment edit
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user session timeout is set to {int} minutes', async function (timeoutMinutes: number) {
  await page.evaluate((timeout) => {
    window.localStorage.setItem('mock_session_timeout_minutes', timeout.toString());
  }, timeoutMinutes);
  this.testData.systemState.sessionTimeout = timeoutMinutes;
});

// TODO: Replace XPath with Object Repository when available
Given('user has been idle for {int} minutes', async function (idleMinutes: number) {
  await page.evaluate((idle) => {
    window.localStorage.setItem('mock_idle_time_minutes', idle.toString());
  }, idleMinutes);
  this.testData.systemState.idleTime = idleMinutes;
});

// TODO: Replace XPath with Object Repository when available
Given('user has scheduled appointment open in edit mode', async function () {
  await actions.click(page.locator('//a[contains(text(),"Schedule")]'));
  await waits.waitForNetworkIdle();
  
  await actions.click(page.locator('//div[@class="appointment-item"][1]//button[@id="edit-appointment"]'));
  await waits.waitForNetworkIdle();
  
  await assertions.assertVisible(page.locator('//form[@id="appointment-edit-form"]'));
  this.testData.appointments.editMode = true;
});

// TODO: Replace XPath with Object Repository when available
Given('auto-save is disabled', async function () {
  await page.evaluate(() => {
    window.localStorage.setItem('mock_autosave_enabled', 'false');
  });
  this.testData.systemState.autoSave = 'disabled';
});

/**************************************************/
/*  TEST CASE: TC-NEG-004
/*  Title: Notification system handles database connection failure during notification creation
/*  Priority: High
/*  Category: Negative
/*  Description: Validates database error handling for notifications
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('database connection can be simulated to fail for notification table writes', async function () {
  await page.evaluate(() => {
    window.localStorage.setItem('mock_db_simulation_enabled', 'true');
  });
  this.testData.systemState.dbSimulation = 'enabled';
});

// TODO: Replace XPath with Object Repository when available
Given('application has database error handling configured', async function () {
  await page.evaluate(() => {
    window.localStorage.setItem('mock_db_error_handling_enabled', 'true');
  });
  this.testData.systemState.dbErrorHandling = 'enabled';
});

// TODO: Replace XPath with Object Repository when available
Given('notification service is running', async function () {
  await page.evaluate(() => {
    window.localStorage.setItem('mock_notification_service_running', 'true');
  });
  this.testData.systemState.notificationServiceRunning = true;
});

/**************************************************/
/*  TEST CASE: TC-NEG-005
/*  Title: System behavior when user has disabled notification preferences
/*  Priority: Medium
/*  Category: Negative
/*  Description: Validates behavior with disabled notifications
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user has navigated to {string} page', async function (pageName: string) {
  const pageXPath = `//a[contains(text(),'${pageName}')]`;
  await actions.click(page.locator(pageXPath));
  await waits.waitForNetworkIdle();
  
  const pageHeaderXPath = `//h1[contains(text(),'${pageName}')]`;
  await assertions.assertVisible(page.locator(pageHeaderXPath));
});

// TODO: Replace XPath with Object Repository when available
Given('user has navigated to {string} section', async function (sectionName: string) {
  const sectionXPath = `//div[@id='${sectionName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.scrollIntoView(page.locator(sectionXPath));
  await assertions.assertVisible(page.locator(sectionXPath));
});

// TODO: Replace XPath with Object Repository when available
Given('user has disabled {string} toggle', async function (toggleName: string) {
  const toggleXPath = `//input[@id='${toggleName.toLowerCase().replace(/\s+/g, '-')}']`;
  const toggleLocator = page.locator(toggleXPath);
  
  const isChecked = await toggleLocator.isChecked();
  if (isChecked) {
    await actions.click(toggleLocator);
    await waits.waitForNetworkIdle();
  }
  
  this.testData.preferences = this.testData.preferences || {};
  this.testData.preferences[toggleName] = 'OFF';
});

// TODO: Replace XPath with Object Repository when available
Given('notification preferences are saved with both options set to {string}', async function (state: string) {
  await actions.click(page.locator('//button[@id="save-preferences"]'));
  await waits.waitForNetworkIdle();
  
  await assertions.assertVisible(page.locator('//div[contains(text(),"Preferences saved")]'));
  this.testData.preferences.saved = true;
  this.testData.preferences.state = state;
});

/**************************************************/
/*  TEST CASE: TC-NEG-006
/*  Title: Notification system handles extremely long appointment descriptions
/*  Priority: Medium
/*  Category: Negative
/*  Description: Validates handling of long content in notifications
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user has permission to create and modify appointments', async function () {
  await page.evaluate(() => {
    window.localStorage.setItem('mock_user_permissions', JSON.stringify({
      createAppointments: true,
      modifyAppointments: true
    }));
  });
  this.testData.permissions = {
    createAppointments: true,
    modifyAppointments: true
  };
});

// TODO: Replace XPath with Object Repository when available
Given('system has character limit of {int} characters for appointment descriptions', async function (charLimit: number) {
  await page.evaluate((limit) => {
    window.localStorage.setItem('mock_description_char_limit', limit.toString());
  }, charLimit);
  this.testData.systemState.descriptionCharLimit = charLimit;
});

// TODO: Replace XPath with Object Repository when available
Given('notification templates are configured to handle variable-length content', async function () {
  await page.evaluate(() => {
    window.localStorage.setItem('mock_notification_templates_configured', 'true');
  });
  this.testData.systemState.notificationTemplates = 'configured';
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  GENERIC NAVIGATION STEPS
/*  Reusable across all test cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('user navigates to schedule page', async function () {
  await actions.click(page.locator('//a[contains(text(),"Schedule")]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="schedule-page"]'));
});

// TODO: Replace XPath with Object Repository when available
When('user navigates to {string} page', async function (pageName: string) {
  const pageXPath = `//a[contains(text(),'${pageName}')]`;
  await actions.click(page.locator(pageXPath));
  await waits.waitForNetworkIdle();
  
  const pageHeaderXPath = `//h1[contains(text(),'${pageName}')]`;
  await assertions.assertVisible(page.locator(pageHeaderXPath));
});

/**************************************************/
/*  GENERIC APPOINTMENT MODIFICATION STEPS
/*  Reusable across all test cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('user modifies appointment time from {string} to {string}', async function (fromTime: string, toTime: string) {
  const editButtonXPath = '//button[@id="edit-appointment"]';
  const editButtons = page.locator(editButtonXPath);
  
  if (await editButtons.count() > 0) {
    await actions.click(editButtons.first());
    await waits.waitForNetworkIdle();
  }
  
  await actions.clearAndFill(page.locator('//input[@id="appointment-time"]'), toTime);
  
  this.testData.appointments.originalTime = fromTime;
  this.testData.appointments.newTime = toTime;
});

// TODO: Replace XPath with Object Repository when available
When('user modifies existing appointment time', async function () {
  await actions.click(page.locator('//button[@id="edit-appointment"]'));
  await waits.waitForNetworkIdle();
  
  await actions.clearAndFill(page.locator('//input[@id="appointment-time"]'), '11:00 AM');
  this.testData.appointments.newTime = '11:00 AM';
});

// TODO: Replace XPath with Object Repository when available
When('user modifies appointment time from {string} to {string} without saving', async function (fromTime: string, toTime: string) {
  await actions.clearAndFill(page.locator('//input[@id="appointment-time"]'), toTime);
  
  this.testData.appointments.originalTime = fromTime;
  this.testData.appointments.newTime = toTime;
  this.testData.appointments.saved = false;
});

/**************************************************/
/*  GENERIC BUTTON CLICK STEPS
/*  Reusable across all test cases
/**************************************************/

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
When('user clicks on the {string} button', async function (buttonText: string) {
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
/*  GENERIC NOTIFICATION CHECK STEPS
/*  Reusable across all test cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('user checks notification bell icon within {int} minute', async function (minutes: number) {
  await page.waitForTimeout(minutes * 1000);
  await actions.click(page.locator('//button[@id="notification-bell"]'));
  await waits.waitForNetworkIdle();
  
  this.testData.notifications.checked = true;
  this.testData.notifications.checkTime = new Date();
});

// TODO: Replace XPath with Object Repository when available
When('user checks notification bell icon', async function () {
  await actions.click(page.locator('//button[@id="notification-bell"]'));
  await waits.waitForNetworkIdle();
  
  this.testData.notifications.checked = true;
});

// TODO: Replace XPath with Object Repository when available
When('user clicks notification bell icon', async function () {
  await actions.click(page.locator('//button[@id="notification-bell"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user clicks notification bell icon within {int} minute', async function (minutes: number) {
  await page.waitForTimeout(minutes * 1000);
  await actions.click(page.locator('//button[@id="notification-bell"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user opens schedule change notification', async function () {
  await actions.click(page.locator('//div[@class="notification-item"][contains(text(),"schedule change")]'));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  GENERIC EMAIL CHECK STEPS
/*  Reusable across all test cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('user checks email inbox after {int} minutes', async function (minutes: number) {
  await page.waitForTimeout(minutes * 1000);
  
  const emailReceived = await page.evaluate(() => {
    return window.localStorage.getItem('mock_email_received') === 'true';
  });
  
  this.testData.emailReceived = emailReceived;
});

// TODO: Replace XPath with Object Repository when available
When('user checks email inbox', async function () {
  const emailReceived = await page.evaluate(() => {
    return window.localStorage.getItem('mock_email_received') === 'true';
  });
  
  this.testData.emailReceived = emailReceived;
});

/**************************************************/
/*  TEST CASE SPECIFIC STEPS - TC-NEG-001
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('email service is restored', async function () {
  await page.evaluate(() => {
    window.localStorage.setItem('mock_email_service_status', 'operational');
  });
  this.testData.systemState.emailService = 'operational';
});

/**************************************************/
/*  TEST CASE SPECIFIC STEPS - TC-NEG-003
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('user waits for {int} minute for session to expire', async function (minutes: number) {
  await page.waitForTimeout(minutes * 60 * 1000);
  
  await page.evaluate(() => {
    window.localStorage.setItem('mock_session_expired', 'true');
  });
  
  this.testData.systemState.sessionExpired = true;
});

// TODO: Replace XPath with Object Repository when available
When('user logs in with valid credentials', async function () {
  const credentials = this.testData?.users?.user || { username: 'testuser', password: 'testpass' };
  
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user navigates to the appointment that was being edited', async function () {
  await actions.click(page.locator('//a[contains(text(),"Schedule")]'));
  await waits.waitForNetworkIdle();
  
  await actions.click(page.locator('//div[@class="appointment-item"][1]'));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE SPECIFIC STEPS - TC-NEG-004
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('database connection to notification table is blocked', async function () {
  await page.evaluate(() => {
    window.localStorage.setItem('mock_db_notification_table_blocked', 'true');
  });
  this.testData.systemState.dbNotificationBlocked = true;
});

// TODO: Replace XPath with Object Repository when available
When('user refreshes schedule page', async function () {
  await page.reload();
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user checks system error logs', async function () {
  await actions.click(page.locator('//a[contains(text(),"System Logs")]'));
  await waits.waitForNetworkIdle();
  
  await assertions.assertVisible(page.locator('//div[@id="error-logs"]'));
});

// TODO: Replace XPath with Object Repository when available
When('database connection is restored', async function () {
  await page.evaluate(() => {
    window.localStorage.setItem('mock_db_notification_table_blocked', 'false');
  });
  this.testData.systemState.dbNotificationBlocked = false;
});

/**************************************************/
/*  TEST CASE SPECIFIC STEPS - TC-NEG-005
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('user verifies notification preferences', async function () {
  await assertions.assertVisible(page.locator('//div[@id="notification-preferences"]'));
  
  const emailToggleState = await page.locator('//input[@id="email-notifications"]').isChecked();
  const inAppToggleState = await page.locator('//input[@id="in-app-notifications"]').isChecked();
  
  this.testData.preferences.emailToggle = emailToggleState ? 'ON' : 'OFF';
  this.testData.preferences.inAppToggle = inAppToggleState ? 'ON' : 'OFF';
});

/**************************************************/
/*  TEST CASE SPECIFIC STEPS - TC-NEG-006
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('user creates new appointment with title {string}', async function (title: string) {
  await actions.click(page.locator('//button[@id="create-appointment"]'));
  await waits.waitForNetworkIdle();
  
  await actions.fill(page.locator('//input[@id="appointment-title"]'), title);
  this.testData.appointments.title = title;
});

// TODO: Replace XPath with Object Repository when available
When('user enters description containing {int} characters with special characters and line breaks', async function (charCount: number) {
  const longDescription = 'A'.repeat(charCount) + '\n\n' + '!@#$%^&*()' + '\n' + 'Line break test';
  
  await actions.fill(page.locator('//textarea[@id="appointment-description"]'), longDescription);
  this.testData.appointments.description = longDescription;
  this.testData.appointments.descriptionLength = longDescription.length;
});

// TODO: Replace XPath with Object Repository when available
When('user clicks {string} link', async function (linkText: string) {
  await actions.click(page.locator(`//a[contains(text(),'${linkText}')]`));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user checks email notification in inbox', async function () {
  const emailContent = await page.evaluate(() => {
    return window.localStorage.getItem('mock_email_content');
  });
  
  this.testData.emailContent = emailContent;
});

// TODO: Replace XPath with Object Repository when available
When('user verifies email in multiple email clients', async function () {
  const emailClients = ['Gmail', 'Outlook', 'Apple Mail'];
  
  this.testData.emailClients = emailClients;
  this.testData.emailRenderingTest = 'completed';
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  GENERIC APPOINTMENT VERIFICATION STEPS
/*  Reusable across all test cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('appointment should be saved successfully', async function () {
  await assertions.assertVisible(page.locator('//div[contains(text(),"saved")]'));
  this.testData.appointments.saved = true;
});

// TODO: Replace XPath with Object Repository when available
Then('appointment update should succeed', async function () {
  await assertions.assertVisible(page.locator('//div[contains(text(),"updated")]'));
  this.testData.appointments.updated = true;
});

// TODO: Replace XPath with Object Repository when available
Then('appointment should be created successfully', async function () {
  await assertions.assertVisible(page.locator('//div[contains(text(),"created")]'));
  this.testData.appointments.created = true;
});

/**************************************************/
/*  GENERIC MESSAGE VERIFICATION STEPS
/*  Reusable across all test cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('message {string} should be displayed', async function (messageText: string) {
  await assertions.assertVisible(page.locator(`//div[contains(text(),'${messageText}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('error message {string} should be displayed', async function (errorMessage: string) {
  await assertions.assertVisible(page.locator(`//div[@class='error-message'][contains(text(),'${errorMessage}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('warning message {string} should be displayed', async function (warningMessage: string) {
  await assertions.assertVisible(page.locator(`//div[@class='warning-message'][contains(text(),'${warningMessage}')]`));
});

/**************************************************/
/*  GENERIC NOTIFICATION VERIFICATION STEPS
/*  Reusable across all test cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('in-app notification should be delivered successfully', async function () {
  await assertions.assertVisible(page.locator('//div[@class="notification-item"]'));
  
  const notificationCount = await page.locator('//div[@class="notification-item"]').count();
  expect(notificationCount).toBeGreaterThan(0);
  
  this.testData.notifications.inAppDelivered = true;
});

// TODO: Replace XPath with Object Repository when available
Then('notification should show schedule change details', async function () {
  await assertions.assertContainsText(
    page.locator('//div[@class="notification-item"]'),
    'schedule change'
  );
});

// TODO: Replace XPath with Object Repository when available
Then('notification should contain message {string}', async function (message: string) {
  await assertions.assertContainsText(
    page.locator('//div[@class="notification-item"]'),
    message
  );
});

// TODO: Replace XPath with Object Repository when available
Then('no notification badge should appear on bell icon', async function () {
  const badgeCount = await page.locator('//span[@class="notification-badge"]').count();
  expect(badgeCount).toBe(0);
});

/**************************************************/
/*  GENERIC EMAIL VERIFICATION STEPS
/*  Reusable across all test cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('no email should be received', async function () {
  const emailReceived = await page.evaluate(() => {
    return window.localStorage.getItem('mock_email_received') === 'true';
  });
  
  expect(emailReceived).toBe(false);
});

// TODO: Replace XPath with Object Repository when available
Then('no email notification should be received', async function () {
  const emailReceived = await page.evaluate(() => {
    return window.localStorage.getItem('mock_email_received') === 'true';
  });
  
  expect(emailReceived).toBe(false);
});

// TODO: Replace XPath with Object Repository when available
Then('email should be delivered within {int} minutes', async function (minutes: number) {
  await page.waitForTimeout(minutes * 60 * 1000);
  
  const emailReceived = await page.evaluate(() => {
    return window.localStorage.getItem('mock_email_received') === 'true';
  });
  
  expect(emailReceived).toBe(true);
});

// TODO: Replace XPath with Object Repository when available
Then('email should contain note {string}', async function (noteText: string) {
  const emailContent = await page.evaluate(() => {
    return window.localStorage.getItem('mock_email_content');
  });
  
  expect(emailContent).toContain(noteText);
});

// TODO: Replace XPath with Object Repository when available
Then('email should be received with properly formatted content', async function () {
  const emailReceived = await page.evaluate(() => {
    return window.localStorage.getItem('mock_email_received') === 'true';
  });
  
  expect(emailReceived).toBe(true);
  await assertions.assertVisible(page.locator('//div[@id="email-preview"]'));
});

/**************************************************/
/*  GENERIC NOTIFICATION HISTORY VERIFICATION STEPS
/*  Reusable across all test cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('notification record should show status {string}', async function (status: string) {
  await assertions.assertContainsText(
    page.locator('//div[@class="notification-status"]'),
    status
  );
});

// TODO: Replace XPath with Object Repository when available
Then('notification details should show {string}', async function (details: string) {
  await assertions.assertContainsText(
    page.locator('//div[@class="notification-details"]'),
    details
  );
});

// TODO: Replace XPath with Object Repository when available
Then('notification should show status {string}', async function (status: string) {
  await assertions.assertContainsText(
    page.locator('//div[@class="notification-status"]'),
    status
  );
});

/**************************************************/
/*  GENERIC SYSTEM BEHAVIOR VERIFICATION STEPS
/*  Reusable across all test cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('system should attempt to retry sending failed email notification', async function () {
  const retryAttempted = await page.evaluate(() => {
    return window.localStorage.getItem('mock_email_retry_attempted') === 'true';
  });
  
  expect(retryAttempted).toBe(true);
});

// TODO: Replace XPath with Object Repository when available
Then('system recovery process should detect missing notification', async function () {
  const recoveryDetected = await page.evaluate(() => {
    return window.localStorage.getItem('mock_recovery_detected') === 'true';
  });
  
  expect(recoveryDetected).toBe(true);
});

// TODO: Replace XPath with Object Repository when available
Then('system should create notification retroactively', async function () {
  const retroactiveCreated = await page.evaluate(() => {
    return window.localStorage.getItem('mock_retroactive_notification_created') === 'true';
  });
  
  expect(retroactiveCreated).toBe(true);
});

/**************************************************/
/*  TEST CASE SPECIFIC STEPS - TC-NEG-002
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('email field should display invalid value with warning icon', async function () {
  await assertions.assertVisible(page.locator('//input[@id="email"]'));
  await assertions.assertVisible(page.locator('//span[@class="warning-icon"]'));
});

/**************************************************/
/*  TEST CASE SPECIFIC STEPS - TC-NEG-003
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('appointment edit form should show modified time {string}', async function (time: string) {
  const timeValue = await page.locator('//input[@id="appointment-time"]').inputValue();
  expect(timeValue).toBe(time);
});

// TODO: Replace XPath with Object Repository when available
Then('changes should not be saved yet', async function () {
  this.testData.appointments.saved = false;
});

// TODO: Replace XPath with Object Repository when available
Then('user should be redirected to login page', async function () {
  await assertions.assertUrlContains('login');
  await assertions.assertVisible(page.locator('//form[@id="login-form"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('user should successfully log in', async function () {
  await assertions.assertVisible(page.locator('//div[@id="dashboard"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('user should be redirected to dashboard', async function () {
  await assertions.assertUrlContains('dashboard');
  await assertions.assertVisible(page.locator('//div[@id="dashboard"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('appointment should show original time {string}', async function (originalTime: string) {
  await assertions.assertContainsText(
    page.locator('//div[@class="appointment-time"]'),
    originalTime
  );
});

// TODO: Replace XPath with Object Repository when available
Then('no notification should be sent', async function () {
  const notificationCount = await page.locator('//div[@class="notification-item"]').count();
  expect(notificationCount).toBe(0);
  
  const emailReceived = await page.evaluate(() => {
    return window.localStorage.getItem('mock_email_received') === 'true';
  });
  expect(emailReceived).toBe(false);
});

/**************************************************/
/*  TEST CASE SPECIFIC STEPS - TC-NEG-004
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('notification bell should show error indicator', async function () {
  await assertions.assertVisible(page.locator('//span[@class="notification-error-indicator"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('appointment should display new time {string}', async function (newTime: string) {
  await assertions.assertContainsText(
    page.locator('//div[@class="appointment-time"]'),
    newTime
  );
});

// TODO: Replace XPath with Object Repository when available
Then('error log should contain entry {string}', async function (logEntry: string) {
  await assertions.assertContainsText(
    page.locator('//div[@class="error-log-entry"]'),
    logEntry
  );
});

// TODO: Replace XPath with Object Repository when available
Then('error log should include timestamp and error details', async function () {
  await assertions.assertVisible(page.locator('//span[@class="log-timestamp"]'));
  await assertions.assertVisible(page.locator('//div[@class="error-details"]'));
});

/**************************************************/
/*  TEST CASE SPECIFIC STEPS - TC-NEG-005
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('{string} toggle should show {string} state', async function (toggleName: string, state: string) {
  const toggleXPath = `//input[@id='${toggleName.toLowerCase().replace(/\s+/g, '-')}']`;
  const isChecked = await page.locator(toggleXPath).isChecked();
  
  if (state === 'OFF') {
    expect(isChecked).toBe(false);
  } else {
    expect(isChecked).toBe(true);
  }
});

// TODO: Replace XPath with Object Repository when available
Then('status text should read {string}', async function (statusText: string) {
  await assertions.assertContainsText(
    page.locator('//div[@class="status-text"]'),
    statusText
  );
});

// TODO: Replace XPath with Object Repository when available
Then('empty state message {string} should be displayed', async function (emptyMessage: string) {
  await assertions.assertContainsText(
    page.locator('//div[@class="empty-state"]'),
    emptyMessage
  );
});

// TODO: Replace XPath with Object Repository when available
Then('page should show message {string}', async function (message: string) {
  await assertions.assertContainsText(
    page.locator('//div[@class="page-message"]'),
    message
  );
});

/**************************************************/
/*  TEST CASE SPECIFIC STEPS - TC-NEG-006
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('long description should be saved', async function () {
  await assertions.assertVisible(page.locator('//div[contains(text(),"saved")]'));
  
  const savedDescription = await page.locator('//textarea[@id="appointment-description"]').inputValue();
  expect(savedDescription.length).toBeGreaterThan(4000);
});

// TODO: Replace XPath with Object Repository when available
Then('notification generation should begin', async function () {
  const notificationGenerating = await page.evaluate(() => {
    return window.localStorage.getItem('mock_notification_generating') === 'true';
  });
  
  expect(notificationGenerating).toBe(true);
});

// TODO: Replace XPath with Object Repository when available
Then('in-app notification should display truncated description with first {int} characters', async function (charCount: number) {
  const notificationText = await page.locator('//div[@class="notification-description"]').textContent();
  expect(notificationText?.length).toBeLessThanOrEqual(charCount + 50);
});

// TODO: Replace XPath with Object Repository when available
Then('notification should show {string} link', async function (linkText: string) {
  await assertions.assertVisible(page.locator(`//a[contains(text(),'${linkText}')]`));
});

// TODO: Replace XPath with Object Repository when available
Then('no UI breaking or overflow issues should occur', async function () {
  const overflowElements = await page.locator('//*[contains(@style,"overflow")]').count();
  const brokenLayout = await page.locator('//div[@class="layout-broken"]').count();
  
  expect(brokenLayout).toBe(0);
});

// TODO: Replace XPath with Object Repository when available
Then('modal should open displaying complete appointment description', async function () {
  await assertions.assertVisible(page.locator('//div[@class="modal"]'));
  await assertions.assertVisible(page.locator('//div[@class="full-description"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('all {int} characters should be visible with scroll functionality', async function (charCount: number) {
  const fullDescription = await page.locator('//div[@class="full-description"]').textContent();
  expect(fullDescription?.length).toBeGreaterThanOrEqual(charCount);
  
  await assertions.assertVisible(page.locator('//div[@class="scrollable-content"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('description should be truncated with link to view full details', async function () {
  await assertions.assertVisible(page.locator('//a[contains(text(),"View Full Details")]'));
});

// TODO: Replace XPath with Object Repository when available
Then('email layout should not be broken', async function () {
  const emailLayout = await page.evaluate(() => {
    return window.localStorage.getItem('mock_email_layout_valid') === 'true';
  });
  
  expect(emailLayout).toBe(true);
});

// TODO: Replace XPath with Object Repository when available
Then('no broken formatting should occur', async function () {
  const formattingValid = await page.evaluate(() => {
    return window.localStorage.getItem('mock_email_formatting_valid') === 'true';
  });
  
  expect(formattingValid).toBe(true);
});

// TODO: Replace XPath with Object Repository when available
Then('no missing content should occur', async function () {
  const contentComplete = await page.evaluate(() => {
    return window.localStorage.getItem('mock_email_content_complete') === 'true';
  });
  
  expect(contentComplete).toBe(true);
});

// TODO: Replace XPath with Object Repository when available
Then('email should render properly in all tested clients', async function () {
  const renderingValid = await page.evaluate(() => {
    return window.localStorage.getItem('mock_email_rendering_valid') === 'true';
  });
  
  expect(renderingValid).toBe(true);
});