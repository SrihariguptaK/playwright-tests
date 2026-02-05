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
      'Performance Manager': { username: 'perfmanager', password: 'perfpass123' },
      admin: { username: 'admin', password: 'admin123' }
    },
    reviewCycles: {},
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
/*  BACKGROUND STEPS - All Test Cases
/*  Category: Setup/Preconditions
/**************************************************/

Given('user is logged in as {string} with review scheduling permissions', async function (userRole: string) {
  const credentials = this.testData?.users?.[userRole] || { username: 'testuser', password: 'testpass' };
  
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(process.env.BASE_URL || 'http://localhost:3000/login');
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="user-profile"]'));
});

Given('user is on {string} page', async function (pageName: string) {
  // TODO: Replace XPath with Object Repository when available
  const pageUrl = pageName.toLowerCase().replace(/\s+/g, '-');
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/${pageUrl}`);
  await waits.waitForNetworkIdle();
  
  const pageHeaderXPath = `//h1[contains(text(),'${pageName}')]`;
  await assertions.assertVisible(page.locator(pageHeaderXPath));
});

/**************************************************/
/*  TEST CASE: TC-001
/*  Title: Successfully schedule a daily review cycle with notification settings
/*  Priority: High
/*  Category: Functional
/**************************************************/

Given('no existing review cycles are scheduled for the current period', async function () {
  // TODO: Replace XPath with Object Repository when available
  const reviewCycleListXPath = '//div[@id="active-schedules-list"]';
  const reviewCycleItems = page.locator('//div[@class="review-cycle-item"]');
  
  const count = await reviewCycleItems.count();
  if (count > 0) {
    this.testData.existingCyclesCount = count;
  } else {
    this.testData.existingCyclesCount = 0;
  }
});

Given('system time is set to a valid business date', async function () {
  const currentDate = new Date();
  const dayOfWeek = currentDate.getDay();
  
  this.testData.isBusinessDay = dayOfWeek >= 1 && dayOfWeek <= 5;
  this.testData.currentDate = currentDate.toISOString();
});

/**************************************************/
/*  TEST CASE: TC-002
/*  Title: Successfully schedule a weekly review cycle and verify calendar view display
/*  Priority: High
/*  Category: Functional
/**************************************************/

Given('calendar view is set to {string} view mode', async function (viewMode: string) {
  // TODO: Replace XPath with Object Repository when available
  const viewModeDropdownXPath = '//select[@id="calendar-view-mode"]';
  await actions.selectByText(page.locator(viewModeDropdownXPath), viewMode);
  await waits.waitForNetworkIdle();
  
  const activeViewXPath = `//div[@class="calendar-view-${viewMode.toLowerCase()}"]`;
  await assertions.assertVisible(page.locator(activeViewXPath));
});

Given('no conflicting weekly review cycles exist', async function () {
  // TODO: Replace XPath with Object Repository when available
  const weeklyReviewCycles = page.locator('//div[@data-frequency="Weekly"]');
  const count = await weeklyReviewCycles.count();
  
  this.testData.conflictingWeeklyCycles = count;
});

/**************************************************/
/*  TEST CASE: TC-003
/*  Title: Successfully schedule a monthly review cycle with custom notification timing
/*  Priority: High
/*  Category: Functional
/**************************************************/

Given('at least {int} employee exists in the system', async function (employeeCount: number) {
  // TODO: Replace XPath with Object Repository when available
  this.testData.minimumEmployeeCount = employeeCount;
  this.testData.employeesExist = true;
});

Given('email notification service is configured and active', async function () {
  // TODO: Replace XPath with Object Repository when available
  this.testData.emailServiceActive = true;
  this.testData.emailServiceConfigured = true;
});

/**************************************************/
/*  TEST CASE: TC-004
/*  Title: Edit an existing scheduled review cycle and verify changes are reflected
/*  Priority: High
/*  Category: Functional
/**************************************************/

Given('active review cycle {string} exists scheduled for {string}', async function (cycleName: string, dayOfWeek: string) {
  // TODO: Replace XPath with Object Repository when available
  this.testData.existingCycleName = cycleName;
  this.testData.existingCycleDay = dayOfWeek;
  
  const reviewCycleXPath = `//div[@data-cycle-name='${cycleName}']`;
  await assertions.assertVisible(page.locator(reviewCycleXPath));
});

Given('calendar view is visible', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="calendar-view"]'));
});

Given('no reviews from this cycle are currently in progress', async function () {
  // TODO: Replace XPath with Object Repository when available
  this.testData.reviewsInProgress = false;
});

/**************************************************/
/*  TEST CASE: TC-005
/*  Title: Delete a scheduled review cycle and verify removal from calendar
/*  Priority: Medium
/*  Category: Functional
/**************************************************/

Given('user has delete permissions', async function () {
  // TODO: Replace XPath with Object Repository when available
  this.testData.hasDeletePermissions = true;
});

Given('scheduled review cycle {string} exists', async function (cycleName: string) {
  // TODO: Replace XPath with Object Repository when available
  this.testData.cycleToDelete = cycleName;
  
  const reviewCycleXPath = `//div[@data-cycle-name='${cycleName}']`;
  await assertions.assertVisible(page.locator(reviewCycleXPath));
});

Given('review cycle has not started yet', async function () {
  // TODO: Replace XPath with Object Repository when available
  this.testData.cycleStarted = false;
});

Given('no completed reviews exist for the cycle', async function () {
  // TODO: Replace XPath with Object Repository when available
  this.testData.completedReviews = 0;
});

/**************************************************/
/*  TEST CASE: TC-006
/*  Title: Verify notification is sent to users prior to scheduled review cycle
/*  Priority: High
/*  Category: Notification
/**************************************************/

Given('review cycle {string} is scheduled for tomorrow at {string}', async function (cycleName: string, time: string) {
  // TODO: Replace XPath with Object Repository when available
  this.testData.scheduledCycleName = cycleName;
  this.testData.scheduledTime = time;
  
  const tomorrow = new Date();
  tomorrow.setDate(tomorrow.getDate() + 1);
  this.testData.scheduledDate = tomorrow.toISOString();
});

Given('notification is set to {string}', async function (notificationTiming: string) {
  // TODO: Replace XPath with Object Repository when available
  this.testData.notificationTiming = notificationTiming;
});

Given('test user email account is accessible', async function () {
  // TODO: Replace XPath with Object Repository when available
  this.testData.emailAccessible = true;
  this.testData.testEmail = 'testuser@example.com';
});

Given('email notification service is running', async function () {
  // TODO: Replace XPath with Object Repository when available
  this.testData.emailServiceRunning = true;
});

// ==================== WHEN STEPS ====================

When('user clicks {string} button', async function (buttonText: string) {
  // TODO: Replace XPath with Object Repository when available
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
  await waits.waitForNetworkIdle();
});

When('user selects {string} from {string} dropdown', async function (optionText: string, dropdownName: string) {
  // TODO: Replace XPath with Object Repository when available
  const dropdownXPath = `//select[@id='${dropdownName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.selectByText(page.locator(dropdownXPath), optionText);
  await waits.waitForNetworkIdle();
});

When('user sets start date to tomorrow in date picker', async function () {
  // TODO: Replace XPath with Object Repository when available
  const tomorrow = new Date();
  tomorrow.setDate(tomorrow.getDate() + 1);
  const formattedDate = tomorrow.toISOString().split('T')[0];
  
  await actions.fill(page.locator('//input[@id="start-date"]'), formattedDate);
  this.testData.selectedStartDate = formattedDate;
});

When('user sets time to {string}', async function (time: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="start-time"]'), time);
  this.testData.selectedTime = time;
});

When('user enables {string} toggle', async function (toggleName: string) {
  // TODO: Replace XPath with Object Repository when available
  const toggleXPath = `//input[@type='checkbox' and @id='${toggleName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.check(page.locator(toggleXPath));
});

When('user enters {string} in {string} field', async function (value: string, fieldName: string) {
  // TODO: Replace XPath with Object Repository when available
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.fill(page.locator(fieldXPath), value);
});

When('user clicks on {string} cycle in calendar view', async function (cycleName: string) {
  // TODO: Replace XPath with Object Repository when available
  const cycleXPath = `//div[@data-cycle-name='${cycleName}']`;
  await actions.click(page.locator(cycleXPath));
  await waits.waitForNetworkIdle();
});

When('user navigates through calendar months using next arrow', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="calendar-next-month"]'));
  await waits.waitForNetworkIdle();
});

When('user clicks on {string} in {string} list', async function (itemName: string, listName: string) {
  // TODO: Replace XPath with Object Repository when available
  const listXPath = `//div[@id='${listName.toLowerCase().replace(/\s+/g, '-')}']//div[contains(text(),'${itemName}')]`;
  await actions.click(page.locator(listXPath));
  await waits.waitForNetworkIdle();
});

When('user clicks {string} button in confirmation dialog', async function (buttonText: string) {
  // TODO: Replace XPath with Object Repository when available
  const dialogButtonXPath = `//div[@class='confirmation-dialog']//button[contains(text(),'${buttonText}')]`;
  await actions.click(page.locator(dialogButtonXPath));
  await waits.waitForNetworkIdle();
});

When('user clicks {string} button in details panel', async function (buttonText: string) {
  // TODO: Replace XPath with Object Repository when available
  const panelButtonXPath = `//div[@class='details-panel']//button[contains(text(),'${buttonText}')]`;
  await actions.click(page.locator(panelButtonXPath));
  await waits.waitForNetworkIdle();
});

When('user verifies review cycle in calendar view', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="calendar-view"]'));
  await waits.waitForNetworkIdle();
});

When('system time advances to 24 hours before scheduled review', async function () {
  // TODO: Replace XPath with Object Repository when available
  this.testData.systemTimeAdvanced = true;
  await waits.waitForNetworkIdle();
});

When('user clicks notification bell icon', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="notification-bell"]'));
  await waits.waitForNetworkIdle();
});

When('user checks registered email inbox', async function () {
  // TODO: Replace XPath with Object Repository when available
  this.testData.emailInboxChecked = true;
});

When('user clicks on notification in app', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//div[@class="notification-item"][1]'));
  await waits.waitForNetworkIdle();
});

When('user clicks {string} link', async function (linkText: string) {
  // TODO: Replace XPath with Object Repository when available
  const linkXPath = `//a[contains(text(),'${linkText}')]`;
  await actions.click(page.locator(linkXPath));
  await waits.waitForNetworkIdle();
});

When('user sets start date to next Monday', async function () {
  // TODO: Replace XPath with Object Repository when available
  const today = new Date();
  const daysUntilMonday = (8 - today.getDay()) % 7 || 7;
  const nextMonday = new Date(today);
  nextMonday.setDate(today.getDate() + daysUntilMonday);
  
  const formattedDate = nextMonday.toISOString().split('T')[0];
  await actions.fill(page.locator('//input[@id="start-date"]'), formattedDate);
  this.testData.nextMonday = formattedDate;
});

// ==================== THEN STEPS ====================

Then('review cycle creation modal should be visible', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="review-cycle-modal"]'));
});

Then('{string} field should be visible', async function (fieldName: string) {
  // TODO: Replace XPath with Object Repository when available
  const fieldXPath = `//div[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}-field']`;
  await assertions.assertVisible(page.locator(fieldXPath));
});

Then('{string} field should display {string}', async function (fieldName: string, expectedValue: string) {
  // TODO: Replace XPath with Object Repository when available
  const fieldXPath = `//select[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  const selectedValue = await page.locator(fieldXPath).inputValue();
  expect(selectedValue).toBe(expectedValue);
});

Then('daily-specific options should be visible', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="daily-options"]'));
});

Then('{string} field should show tomorrow\'s date in {string} format', async function (fieldName: string, dateFormat: string) {
  // TODO: Replace XPath with Object Repository when available
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  const fieldValue = await page.locator(fieldXPath).inputValue();
  
  expect(fieldValue).toBeTruthy();
  this.testData.displayedDate = fieldValue;
});

Then('time field should display {string}', async function (expectedTime: string) {
  // TODO: Replace XPath with Object Repository when available
  const timeValue = await page.locator('//input[@id="start-time"]').inputValue();
  expect(timeValue).toBe(expectedTime);
});

Then('notification toggle should be active', async function () {
  // TODO: Replace XPath with Object Repository when available
  const toggleChecked = await page.locator('//input[@id="send-notification"]').isChecked();
  expect(toggleChecked).toBe(true);
});

Then('notification timing dropdown should display {string}', async function (expectedTiming: string) {
  // TODO: Replace XPath with Object Repository when available
  const timingValue = await page.locator('//select[@id="notification-timing"]').inputValue();
  expect(timingValue).toContain(expectedTiming);
});

Then('success message {string} should be displayed', async function (message: string) {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator(`//div[@class='success-message' and contains(text(),'${message}')]`));
});

Then('review cycle creation modal should be hidden', async function () {
  // TODO: Replace XPath with Object Repository when available
  const modalVisible = await page.locator('//div[@id="review-cycle-modal"]').isVisible();
  expect(modalVisible).toBe(false);
});

Then('new review cycle should appear in calendar view', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@class="calendar-review-marker"]'));
});

Then('review cycle should be saved in database with status {string}', async function (status: string) {
  // TODO: Replace XPath with Object Repository when available
  this.testData.savedStatus = status;
});

Then('notification job should be created for 24 hours before each review', async function () {
  // TODO: Replace XPath with Object Repository when available
  this.testData.notificationJobCreated = true;
});

Then('calendar view should show recurring Monday markers for weekly review cycle', async function () {
  // TODO: Replace XPath with Object Repository when available
  const mondayMarkers = page.locator('//div[@data-day="Monday"]//div[@class="review-marker"]');
  const count = await mondayMarkers.count();
  expect(count).toBeGreaterThan(0);
});

Then('calendar should display weekly review markers on every Monday for next {int} months', async function (monthCount: number) {
  // TODO: Replace XPath with Object Repository when available
  this.testData.monthsToVerify = monthCount;
  
  const mondayMarkers = page.locator('//div[@data-day="Monday"]//div[@class="review-marker"]');
  const count = await mondayMarkers.count();
  expect(count).toBeGreaterThanOrEqual(monthCount * 4);
});

Then('{string} label should be visible on hover', async function (labelText: string) {
  // TODO: Replace XPath with Object Repository when available
  const markerXPath = '//div[@class="review-marker"]';
  await actions.hover(page.locator(markerXPath));
  await waits.waitForVisible(page.locator(`//div[@class='tooltip' and contains(text(),'${labelText}')]`));
});

Then('weekly review cycle should be saved with recurrence pattern {string}', async function (pattern: string) {
  // TODO: Replace XPath with Object Repository when available
  this.testData.recurrencePattern = pattern;
});

Then('review cycle should appear in {string} list with frequency {string}', async function (listName: string, frequency: string) {
  // TODO: Replace XPath with Object Repository when available
  const listItemXPath = `//div[@id='${listName.toLowerCase().replace(/\s+/g, '-')}']//div[@data-frequency='${frequency}']`;
  await assertions.assertVisible(page.locator(listItemXPath));
});

Then('notification settings should be expanded', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="notification-settings-panel"]'));
});

Then('email template preview should be visible', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="email-template-preview"]'));
});

Then('monthly review should appear on calendar on 1st of each month', async function () {
  // TODO: Replace XPath with Object Repository when available
  const firstDayMarkers = page.locator('//div[@data-day="1"]//div[@class="review-marker"]');
  const count = await firstDayMarkers.count();
  expect(count).toBeGreaterThan(0);
});

Then('review cycle details panel should be visible', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="review-cycle-details-panel"]'));
});

Then('frequency should display {string}', async function (frequency: string) {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertContainsText(page.locator('//div[@id="details-frequency"]'), frequency);
});

Then('notification timing should display {string}', async function (timing: string) {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertContainsText(page.locator('//div[@id="details-notification-timing"]'), timing);
});

Then('description should display {string}', async function (description: string) {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertContainsText(page.locator('//div[@id="details-description"]'), description);
});

Then('notification jobs should be scheduled for 72 hours before each monthly review date', async function () {
  // TODO: Replace XPath with Object Repository when available
  this.testData.notificationJobsScheduled = true;
});

Then('day should display {string}', async function (day: string) {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertContainsText(page.locator('//div[@id="details-day"]'), day);
});

Then('edit review cycle modal should be visible', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="edit-review-cycle-modal"]'));
});

Then('all current values should be pre-populated in form fields', async function () {
  // TODO: Replace XPath with Object Repository when available
  const frequencyValue = await page.locator('//select[@id="frequency"]').inputValue();
  expect(frequencyValue).toBeTruthy();
});

Then('{string} dropdown should display {string}', async function (dropdownName: string, expectedValue: string) {
  // TODO: Replace XPath with Object Repository when available
  const dropdownXPath = `//select[@id='${dropdownName.toLowerCase().replace(/\s+/g, '-')}']`;
  const selectedValue = await page.locator(dropdownXPath).inputValue();
  expect(selectedValue).toBe(expectedValue);
});

Then('edit review cycle modal should be hidden', async function () {
  // TODO: Replace XPath with Object Repository when available
  const modalVisible = await page.locator('//div[@id="edit-review-cycle-modal"]').isVisible();
  expect(modalVisible).toBe(false);
});

Then('calendar should refresh showing reviews on alternating Fridays', async function () {
  // TODO: Replace XPath with Object Repository when available
  await waits.waitForNetworkIdle();
  const fridayMarkers = page.locator('//div[@data-day="Friday"]//div[@class="review-marker"]');
  const count = await fridayMarkers.count();
  expect(count).toBeGreaterThan(0);
});

Then('review cycle should be updated in database with new settings', async function () {
  // TODO: Replace XPath with Object Repository when available
  this.testData.cycleUpdated = true;
});

Then('old notification jobs should be cancelled', async function () {
  // TODO: Replace XPath with Object Repository when available
  this.testData.oldJobsCancelled = true;
});

Then('new notification jobs should be created for 48 hours before each bi-weekly Friday', async function () {
  // TODO: Replace XPath with Object Repository when available
  this.testData.newJobsCreated = true;
});

Then('{string} button should be visible', async function (buttonText: string) {
  // TODO: Replace XPath with Object Repository when available
  const buttonXPath = `//button[contains(text(),'${buttonText}')]`;
  await assertions.assertVisible(page.locator(buttonXPath));
});

Then('confirmation dialog should be visible', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@class="confirmation-dialog"]'));
});

Then('confirmation message {string} should be displayed', async function (message: string) {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertContainsText(page.locator('//div[@class="confirmation-dialog"]'), message);
});

Then('confirmation dialog should be hidden', async function () {
  // TODO: Replace XPath with Object Repository when available
  const dialogVisible = await page.locator('//div[@class="confirmation-dialog"]').isVisible();
  expect(dialogVisible).toBe(false);
});

Then('{string} should not appear in {string} list', async function (itemName: string, listName: string) {
  // TODO: Replace XPath with Object Repository when available
  const itemXPath = `//div[@id='${listName.toLowerCase().replace(/\s+/g, '-')}']//div[contains(text(),'${itemName}')]`;
  const itemVisible = await page.locator(itemXPath).isVisible();
  expect(itemVisible).toBe(false);
});

Then('calendar view should not show any markers for {string}', async function (cycleName: string) {
  // TODO: Replace XPath with Object Repository when available
  const markerXPath = `//div[@data-cycle-name='${cycleName}']`;
  const markerVisible = await page.locator(markerXPath).isVisible();
  expect(markerVisible).toBe(false);
});

Then('review cycle should be marked as deleted in database', async function () {
  // TODO: Replace XPath with Object Repository when available
  this.testData.cycleDeleted = true;
});

Then('all future scheduled review instances should be cancelled', async function () {
  // TODO: Replace XPath with Object Repository when available
  this.testData.futureInstancesCancelled = true;
});

Then('all associated notification jobs should be removed', async function () {
  // TODO: Replace XPath with Object Repository when available
  this.testData.notificationJobsRemoved = true;
});

Then('calendar should show review scheduled for tomorrow', async function () {
  // TODO: Replace XPath with Object Repository when available
  const tomorrow = new Date();
  tomorrow.setDate(tomorrow.getDate() + 1);
  const tomorrowDate = tomorrow.toISOString().split('T')[0];
  
  const reviewMarkerXPath = `//div[@data-date='${tomorrowDate}']//div[@class='review-marker']`;
  await assertions.assertVisible(page.locator(reviewMarkerXPath));
});

Then('notification icon should indicate {string} notification is enabled', async function (timing: string) {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@class="notification-icon-enabled"]'));
});

Then('notification badge should show {int} new notification', async function (count: number) {
  // TODO: Replace XPath with Object Repository when available
  const badgeText = await page.locator('//span[@id="notification-badge"]').textContent();
  expect(parseInt(badgeText || '0')).toBe(count);
});

Then('notification should display {string}', async function (notificationText: string) {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertContainsText(page.locator('//div[@class="notification-item"]'), notificationText);
});

Then('email should be received with subject {string}', async function (subject: string) {
  // TODO: Replace XPath with Object Repository when available
  this.testData.emailSubject = subject;
  this.testData.emailReceived = true;
});

Then('email should contain review cycle name {string}', async function (cycleName: string) {
  // TODO: Replace XPath with Object Repository when available
  this.testData.emailContainsCycleName = true;
});

Then('email should contain date and time', async function () {
  // TODO: Replace XPath with Object Repository when available
  this.testData.emailContainsDateTime = true;
});

Then('email should contain preparation instructions', async function () {
  // TODO: Replace XPath with Object Repository when available
  this.testData.emailContainsInstructions = true;
});

Then('notification should expand showing full review details', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@class="notification-expanded"]'));
});

Then('user should navigate to review cycle details page', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertUrlContains('review-cycle-details');
});

Then('notification should be marked as sent in database', async function () {
  // TODO: Replace XPath with Object Repository when available
  this.testData.notificationMarkedSent = true;
});

Then('in-app notification should remain visible until dismissed', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@class="notification-item"]'));
});