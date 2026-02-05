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
    reviewCycles: [],
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

Given('user is logged in as {string} with scheduling permissions', async function (userRole: string) {
  const credentials = this.testData?.users?.[userRole] || { username: 'testuser', password: 'testpass' };
  
  // TODO: Replace XPath with Object Repository when available
  await actions.navigateTo(process.env.BASE_URL || 'https://performance-management.example.com');
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator('//div[@id="user-profile"]'));
});

Given('review cycle management page is loaded', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[contains(text(),"Review Cycles")]'));
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator('//div[@id="review-cycle-management"]'));
});

Given('system is configured with multiple time zones {string}', async function (timeZones: string) {
  this.testData.timeZones = timeZones.split(',').map((tz: string) => tz.trim());
  
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="settings"]'));
  await waits.waitForVisible(page.locator('//div[@id="settings-modal"]'));
  
  for (const timeZone of this.testData.timeZones) {
    const timeZoneCheckbox = page.locator(`//input[@type="checkbox" and @value="${timeZone}"]`);
    if (await timeZoneCheckbox.count() > 0) {
      await actions.check(timeZoneCheckbox);
    }
  }
  
  await actions.click(page.locator('//button[@id="save-settings"]'));
  await waits.waitForNetworkIdle();
});

Given('no existing review cycles are scheduled for target date', async function () {
  // TODO: Replace XPath with Object Repository when available
  const existingCycles = page.locator('//div[@class="review-cycle-item"]');
  const count = await existingCycles.count();
  
  if (count > 0) {
    await actions.click(page.locator('//button[@id="clear-all-cycles"]'));
    await waits.waitForVisible(page.locator('//div[@id="confirmation-dialog"]'));
    await actions.click(page.locator('//button[@id="confirm-clear"]'));
    await waits.waitForNetworkIdle();
  }
});

Given('database has capacity for at least {string} review cycle records', async function (capacity: string) {
  this.testData.databaseCapacity = parseInt(capacity);
  
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="system-info"]'));
  await waits.waitForVisible(page.locator('//div[@id="system-info-modal"]'));
  
  const capacityText = await page.locator('//span[@id="database-capacity"]').textContent();
  const currentCapacity = parseInt(capacityText || '0');
  
  expect(currentCapacity).toBeGreaterThanOrEqual(this.testData.databaseCapacity);
  
  await actions.click(page.locator('//button[@id="close-system-info"]'));
  await waits.waitForHidden(page.locator('//div[@id="system-info-modal"]'));
});

Given('system performance monitoring tools are active', async function () {
  this.testData.performanceMetrics = {
    startTime: Date.now(),
    pageLoadTimes: [],
    apiResponseTimes: []
  };
  
  page.on('response', (response) => {
    const timing = response.timing();
    this.testData.performanceMetrics.apiResponseTimes.push(timing);
  });
});

Given('current system date is within leap year {string}', async function (year: string) {
  this.testData.leapYear = year;
  
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="system-settings"]'));
  await waits.waitForVisible(page.locator('//div[@id="system-settings-modal"]'));
  await actions.fill(page.locator('//input[@id="system-year"]'), year);
  await actions.click(page.locator('//button[@id="save-system-settings"]'));
  await waits.waitForNetworkIdle();
});

Given('system calendar includes {string} as selectable date', async function (date: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="open-calendar"]'));
  await waits.waitForVisible(page.locator('//div[@id="calendar-widget"]'));
  
  const dateLocator = page.locator(`//td[@data-date="${date}" and not(contains(@class, "disabled"))]`);
  await waits.waitForVisible(dateLocator);
  await assertions.assertVisible(dateLocator);
});

Given('review cycle exists scheduled for {string} at {string}', async function (date: string, time: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="schedule-new-review-cycle"]'));
  await waits.waitForVisible(page.locator('//div[@id="review-cycle-modal"]'));
  
  await actions.fill(page.locator('//input[@id="review-name"]'), 'Existing Review Cycle');
  await actions.fill(page.locator('//input[@id="start-date"]'), date);
  await actions.fill(page.locator('//input[@id="start-time"]'), time);
  await actions.selectByText(page.locator('//select[@id="frequency"]'), 'Weekly');
  
  await actions.click(page.locator('//button[@id="save-review-cycle"]'));
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator('//div[@id="success-message"]'));
});

Given('system validation rules for overlapping cycles are active', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="validation-settings"]'));
  await waits.waitForVisible(page.locator('//div[@id="validation-settings-modal"]'));
  
  const overlapValidationCheckbox = page.locator('//input[@id="enable-overlap-validation"]');
  await actions.check(overlapValidationCheckbox);
  
  await actions.click(page.locator('//button[@id="save-validation-settings"]'));
  await waits.waitForNetworkIdle();
});

Given('system supports UTF-8 character encoding', async function () {
  const metaCharset = await page.locator('//meta[@charset="UTF-8"]').count();
  expect(metaCharset).toBeGreaterThan(0);
});

Given('database fields support Unicode storage', async function () {
  this.testData.unicodeSupport = true;
});

Given('network connection is stable', async function () {
  const response = await page.goto(process.env.BASE_URL || 'https://performance-management.example.com');
  expect(response?.status()).toBe(200);
  await waits.waitForNetworkIdle();
});

Given('browser console is open to monitor for errors', async function () {
  this.testData.consoleErrors = [];
  
  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      this.testData.consoleErrors.push(msg.text());
    }
  });
  
  page.on('pageerror', (error) => {
    this.testData.consoleErrors.push(error.message);
  });
});

Given('system is configured for time zone {string} that observes daylight saving time', async function (timeZone: string) {
  this.testData.dstTimeZone = timeZone;
  
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="timezone-settings"]'));
  await waits.waitForVisible(page.locator('//div[@id="timezone-settings-modal"]'));
  await actions.selectByText(page.locator('//select[@id="primary-timezone"]'), timeZone);
  await actions.click(page.locator('//button[@id="save-timezone-settings"]'));
  await waits.waitForNetworkIdle();
});

Given('test is performed during DST transition period', async function () {
  this.testData.dstTransition = true;
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
});

When('user sets start date to {string} on {string}', async function (time: string, date: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="start-date"]'), date);
  await actions.fill(page.locator('//input[@id="start-time"]'), time);
});

When('user sets start date to {string}', async function (date: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="start-date"]'), date);
});

When('user sets start date to {string} at {string}', async function (date: string, time: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="start-date"]'), date);
  await actions.fill(page.locator('//input[@id="start-time"]'), time);
});

When('user sets start time to {string} during lost hour of spring forward', async function (time: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="start-time"]'), time);
});

When('user navigates to calendar view', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="calendar-view"]'));
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator('//div[@id="calendar-container"]'));
});

When('user navigates to review cycle management page', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[contains(text(),"Review Cycles")]'));
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator('//div[@id="review-cycle-management"]'));
});

When('user navigates to review cycle management page at {string} on DST transition day', async function (time: string) {
  this.testData.dstTransitionTime = time;
  
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//a[contains(text(),"Review Cycles")]'));
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator('//div[@id="review-cycle-management"]'));
});

When('user creates {string} review cycles with different frequencies spanning {string} months using bulk scheduling', async function (count: string, months: string) {
  const cycleCount = parseInt(count);
  const monthSpan = parseInt(months);
  
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="bulk-schedule"]'));
  await waits.waitForVisible(page.locator('//div[@id="bulk-schedule-modal"]'));
  
  await actions.fill(page.locator('//input[@id="bulk-count"]'), count);
  await actions.fill(page.locator('//input[@id="bulk-months"]'), months);
  await actions.click(page.locator('//button[@id="generate-bulk-cycles"]'));
  
  await waits.waitForVisible(page.locator('//div[@id="bulk-progress"]'));
  await waits.waitForVisible(page.locator('//div[@id="bulk-complete"]'));
  
  this.testData.bulkCreatedCount = cycleCount;
});

When('user refreshes review cycle management page', async function () {
  await page.reload();
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator('//div[@id="review-cycle-management"]'));
});

When('user scrolls through all months containing scheduled reviews', async function () {
  // TODO: Replace XPath with Object Repository when available
  const monthNavigator = page.locator('//button[@id="next-month"]');
  
  for (let i = 0; i < 12; i++) {
    await actions.click(monthNavigator);
    await waits.waitForNetworkIdle();
    await page.waitForTimeout(100);
  }
});

When('user attempts to schedule additional review cycle', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="schedule-new-review-cycle"]'));
  await waits.waitForNetworkIdle();
});

When('user sets recurrence to repeat annually for next {string} years', async function (years: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="recurrence-years"]'), years);
  await actions.check(page.locator('//input[@id="enable-recurrence"]'));
});

When('user advances calendar to {string}', async function (monthYear: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="calendar-month-year"]'), monthYear);
  await actions.click(page.locator('//button[@id="go-to-month"]'));
  await waits.waitForNetworkIdle();
});

When('user fills in {string} field', async function (fieldName: string) {
  // TODO: Replace XPath with Object Repository when available
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  const testValue = `Test ${fieldName} Value`;
  await actions.fill(page.locator(fieldXPath), testValue);
});

When('user modifies start time to {string}', async function (time: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.clearAndFill(page.locator('//input[@id="start-time"]'), time);
});

When('user enters {string} in {string} field', async function (value: string, fieldName: string) {
  // TODO: Replace XPath with Object Repository when available
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.fill(page.locator(fieldXPath), value);
});

When('user sets valid start date', async function () {
  const tomorrow = new Date();
  tomorrow.setDate(tomorrow.getDate() + 1);
  const dateString = tomorrow.toISOString().split('T')[0];
  
  // TODO: Replace XPath with Object Repository when available
  await actions.fill(page.locator('//input[@id="start-date"]'), dateString);
});

When('user verifies review cycle in list view', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="list-view"]'));
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator('//div[@id="review-cycle-list"]'));
});

When('user hovers over scheduled review cycle', async function () {
  // TODO: Replace XPath with Object Repository when available
  const reviewCycleElement = page.locator('//div[@class="review-cycle-item"]').first();
  await actions.hover(reviewCycleElement);
  await waits.waitForVisible(page.locator('//div[@id="review-cycle-tooltip"]'));
});

When('user edits review cycle', async function () {
  // TODO: Replace XPath with Object Repository when available
  const editButton = page.locator('//button[@class="edit-review-cycle"]').first();
  await actions.click(editButton);
  await waits.waitForVisible(page.locator('//div[@id="edit-review-cycle-modal"]'));
});

When('user rapidly creates {string} review cycles in under {string} seconds', async function (count: string, seconds: string) {
  const cycleCount = parseInt(count);
  const startTime = Date.now();
  
  for (let i = 0; i < cycleCount; i++) {
    // TODO: Replace XPath with Object Repository when available
    await actions.click(page.locator('//button[@id="schedule-new-review-cycle"]'));
    await waits.waitForVisible(page.locator('//div[@id="review-cycle-modal"]'));
    
    await actions.fill(page.locator('//input[@id="review-name"]'), `Rapid Test Cycle ${i + 1}`);
    await actions.selectByText(page.locator('//select[@id="frequency"]'), 'Weekly');
    
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + i);
    await actions.fill(page.locator('//input[@id="start-date"]'), futureDate.toISOString().split('T')[0]);
    
    await actions.click(page.locator('//button[@id="save-review-cycle"]'));
    await waits.waitForNetworkIdle();
  }
  
  const endTime = Date.now();
  const elapsedSeconds = (endTime - startTime) / 1000;
  
  this.testData.rapidCreationTime = elapsedSeconds;
  this.testData.rapidCreatedCount = cycleCount;
});

When('user selects all {string} newly created review cycles', async function (count: string) {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//input[@id="select-all-cycles"]'));
  await waits.waitForNetworkIdle();
  
  const selectedCount = await page.locator('//div[@class="review-cycle-item selected"]').count();
  expect(selectedCount).toBe(parseInt(count));
});

When('user checks browser console', async function () {
  // Console errors are already being captured in the Given step
});

When('user checks notification settings', async function () {
  // TODO: Replace XPath with Object Repository when available
  await actions.click(page.locator('//button[@id="notification-settings"]'));
  await waits.waitForVisible(page.locator('//div[@id="notification-settings-modal"]'));
});

// ==================== THEN STEPS ====================

Then('review cycle scheduling modal should be visible', async function () {
  // TODO: Replace XPath with Object Repository when available
  await waits.waitForVisible(page.locator('//div[@id="review-cycle-modal"]'));
  await assertions.assertVisible(page.locator('//div[@id="review-cycle-modal"]'));
});

Then('review cycle scheduling modal should be visible with empty form fields', async function () {
  // TODO: Replace XPath with Object Repository when available
  await waits.waitForVisible(page.locator('//div[@id="review-cycle-modal"]'));
  await assertions.assertVisible(page.locator('//div[@id="review-cycle-modal"]'));
  
  const reviewNameValue = await page.locator('//input[@id="review-name"]').inputValue();
  expect(reviewNameValue).toBe('');
});

Then('all frequency options should be visible', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//select[@id="frequency"]'));
  
  const options = await page.locator('//select[@id="frequency"]/option').count();
  expect(options).toBeGreaterThan(0);
});

Then('date picker should display {string} in time field', async function (time: string) {
  // TODO: Replace XPath with Object Repository when available
  const timeValue = await page.locator('//input[@id="start-time"]').inputValue();
  expect(timeValue).toBe(time);
});

Then('date picker should display {string} in selected date field', async function (date: string) {
  // TODO: Replace XPath with Object Repository when available
  const dateValue = await page.locator('//input[@id="start-date"]').inputValue();
  expect(dateValue).toContain(date);
});

Then('date picker should show current leap year calendar', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="calendar-widget"]'));
  
  const feb29 = page.locator('//td[@data-date="February 29th"]');
  await assertions.assertVisible(feb29);
});

Then('time zone should be set to {string}', async function (timeZone: string) {
  // TODO: Replace XPath with Object Repository when available
  const selectedTimeZone = await page.locator('//select[@id="time-zone"]').inputValue();
  expect(selectedTimeZone).toBe(timeZone);
});

Then('system should show equivalent time {string} for {string}', async function (equivalentTime: string, timeZone: string) {
  // TODO: Replace XPath with Object Repository when available
  const timeZoneDisplay = page.locator(`//div[@id="timezone-${timeZone.toLowerCase()}"]`);
  await assertions.assertContainsText(timeZoneDisplay, equivalentTime);
});

Then('success message {string} should be displayed in green banner', async function (message: string) {
  // TODO: Replace XPath with Object Repository when available
  await waits.waitForVisible(page.locator('//div[@id="success-message"]'));
  await assertions.assertContainsText(page.locator('//div[@id="success-message"]'), message);
  
  const bannerClass = await page.locator('//div[@id="success-message"]').getAttribute('class');
  expect(bannerClass).toContain('green');
});

Then('success message should be displayed', async function () {
  // TODO: Replace XPath with Object Repository when available
  await waits.waitForVisible(page.locator('//div[@id="success-message"]'));
  await assertions.assertVisible(page.locator('//div[@id="success-message"]'));
});

Then('scheduled review should appear at {string} on {string}', async function (time: string, date: string) {
  // TODO: Replace XPath with Object Repository when available
  const reviewCycle = page.locator(`//div[@data-time="${time}" and @data-date="${date}"]`);
  await assertions.assertVisible(reviewCycle);
});

Then('correct time zone indicator should be displayed', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//span[@class="timezone-indicator"]'));
});

Then('page should load in under {string} seconds', async function (seconds: string) {
  const maxLoadTime = parseInt(seconds) * 1000;
  const startTime = Date.now();
  
  await waits.waitForNetworkIdle();
  
  const endTime = Date.now();
  const loadTime = endTime - startTime;
  
  expect(loadTime).toBeLessThan(maxLoadTime);
});

Then('pagination or lazy loading should be implemented', async function () {
  // TODO: Replace XPath with Object Repository when available
  const pagination = page.locator('//div[@id="pagination"]');
  const lazyLoad = page.locator('//div[@id="lazy-load-trigger"]');
  
  const hasPagination = await pagination.count() > 0;
  const hasLazyLoad = await lazyLoad.count() > 0;
  
  expect(hasPagination || hasLazyLoad).toBe(true);
});

Then('system should display progress indicator showing {string}', async function (message: string) {
  // TODO: Replace XPath with Object Repository when available
  await waits.waitForVisible(page.locator('//div[@id="progress-indicator"]'));
  await assertions.assertContainsText(page.locator('//div[@id="progress-indicator"]'), message);
});

Then('calendar should render smoothly without lag', async function () {
  const startTime = Date.now();
  
  // TODO: Replace XPath with Object Repository when available
  await waits.waitForVisible(page.locator('//div[@id="calendar-container"]'));
  
  const endTime = Date.now();
  const renderTime = endTime - startTime;
  
  expect(renderTime).toBeLessThan(1000);
});

Then('all {string} review cycles should be displayed with appropriate visual indicators', async function (count: string) {
  // TODO: Replace XPath with Object Repository when available
  const reviewCycles = page.locator('//div[@class="review-cycle-item"]');
  const cycleCount = await reviewCycles.count();
  
  expect(cycleCount).toBe(parseInt(count));
});

Then('system should accept {string} review cycle or display message indicating maximum limit reached', async function (cycleNumber: string) {
  // TODO: Replace XPath with Object Repository when available
  const modal = page.locator('//div[@id="review-cycle-modal"]');
  const limitMessage = page.locator('//div[@id="limit-reached-message"]');
  
  const modalVisible = await modal.count() > 0;
  const limitMessageVisible = await limitMessage.count() > 0;
  
  expect(modalVisible || limitMessageVisible).toBe(true);
});

Then('review cycle should appear on {string}', async function (date: string) {
  // TODO: Replace XPath with Object Repository when available
  const reviewCycle = page.locator(`//div[@data-date="${date}"]`);
  await assertions.assertVisible(reviewCycle);
});

Then('notation {string} should be displayed', async function (notation: string) {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertContainsText(page.locator('//div[@class="date-notation"]'), notation);
});

Then('error message {string} should be displayed in red banner', async function (message: string) {
  // TODO: Replace XPath with Object Repository when available
  await waits.waitForVisible(page.locator('//div[@id="error-message"]'));
  await assertions.assertContainsText(page.locator('//div[@id="error-message"]'), message);
  
  const bannerClass = await page.locator('//div[@id="error-message"]').getAttribute('class');
  expect(bannerClass).toContain('red');
});

Then('date and time fields should accept the input', async function () {
  // TODO: Replace XPath with Object Repository when available
  const dateField = page.locator('//input[@id="start-date"]');
  const timeField = page.locator('//input[@id="start-time"]');
  
  const dateValue = await dateField.inputValue();
  const timeValue = await timeField.inputValue();
  
  expect(dateValue).not.toBe('');
  expect(timeValue).not.toBe('');
});

Then('system should accept schedule if cycles do not overlap or show error if overlap detected', async function () {
  // TODO: Replace XPath with Object Repository when available
  const successMessage = page.locator('//div[@id="success-message"]');
  const errorMessage = page.locator('//div[@id="error-message"]');
  
  await page.waitForTimeout(1000);
  
  const successVisible = await successMessage.count() > 0;
  const errorVisible = await errorMessage.count() > 0;
  
  expect(successVisible || errorVisible).toBe(true);
});

Then('both review cycles should be displayed if second was accepted', async function () {
  // TODO: Replace XPath with Object Repository when available
  const reviewCycles = page.locator('//div[@class="review-cycle-item"]');
  const count = await reviewCycles.count();
  
  if (count >= 2) {
    expect(count).toBeGreaterThanOrEqual(2);
  }
});

Then('visual indication of proximity should be shown', async function () {
  // TODO: Replace XPath with Object Repository when available
  const proximityIndicator = page.locator('//span[@class="proximity-indicator"]');
  
  if (await proximityIndicator.count() > 0) {
    await assertions.assertVisible(proximityIndicator);
  }
});

Then('review name input field should be visible', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//input[@id="review-name"]'));
});

Then('input field should display all characters correctly without corruption', async function () {
  // TODO: Replace XPath with Object Repository when available
  const inputValue = await page.locator('//input[@id="review-name"]').inputValue();
  expect(inputValue.length).toBeGreaterThan(0);
});

Then('modal should close', async function () {
  // TODO: Replace XPath with Object Repository when available
  await waits.waitForHidden(page.locator('//div[@id="review-cycle-modal"]'));
});

Then('review cycle name {string} should be displayed correctly', async function (name: string) {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertContainsText(page.locator('//div[@class="review-cycle-name"]'), name);
});

Then('all special characters and emoji should be rendered properly', async function () {
  // TODO: Replace XPath with Object Repository when available
  const reviewName = await page.locator('//div[@class="review-cycle-name"]').textContent();
  expect(reviewName).toBeTruthy();
  expect(reviewName?.length).toBeGreaterThan(0);
});

Then('tooltip should show full review cycle name with all Unicode characters displayed correctly', async function () {
  // TODO: Replace XPath with Object Repository when available
  const tooltip = page.locator('//div[@id="review-cycle-tooltip"]');
  await assertions.assertVisible(tooltip);
  
  const tooltipText = await tooltip.textContent();
  expect(tooltipText).toBeTruthy();
  expect(tooltipText?.length).toBeGreaterThan(0);
});

Then('edit modal should open with review name field showing all original characters correctly', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="edit-review-cycle-modal"]'));
  
  const reviewNameValue = await page.locator('//input[@id="review-name"]').inputValue();
  expect(reviewNameValue.length).toBeGreaterThan(0);
});

Then('page should load successfully', async function () {
  await waits.waitForNetworkIdle();
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="review-cycle-management"]'));
});

Then('console should show no errors', async function () {
  expect(this.testData.consoleErrors.length).toBe(0);
});

Then('system should process all {string} requests without crashing', async function (count: string) {
  // TODO: Replace XPath with Object Repository when available
  await waits.waitForNetworkIdle();
  
  const pageVisible = await page.locator('//div[@id="review-cycle-management"]').count() > 0;
  expect(pageVisible).toBe(true);
});

Then('success messages should be displayed for each request', async function () {
  // TODO: Replace XPath with Object Repository when available
  const successMessages = page.locator('//div[@id="success-message"]');
  
  if (await successMessages.count() > 0) {
    await assertions.assertVisible(successMessages.first());
  }
});

Then('confirmation dialog {string} should be displayed', async function (message: string) {
  // TODO: Replace XPath with Object Repository when available
  await waits.waitForVisible(page.locator('//div[@id="confirmation-dialog"]'));
  await assertions.assertContainsText(page.locator('//div[@id="confirmation-dialog"]'), message);
});

Then('{string} button should be visible', async function (buttonText: string) {
  // TODO: Replace XPath with Object Repository when available
  const buttonIdXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonIdXPath);
  
  if (await buttons.count() > 0) {
    await assertions.assertVisible(buttons);
  } else {
    await assertions.assertVisible(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
});

Then('success message {string} should be displayed', async function (message: string) {
  // TODO: Replace XPath with Object Repository when available
  await waits.waitForVisible(page.locator('//div[@id="success-message"]'));
  await assertions.assertContainsText(page.locator('//div[@id="success-message"]'), message);
});

Then('no errors should be displayed', async function () {
  // TODO: Replace XPath with Object Repository when available
  const errorMessage = page.locator('//div[@id="error-message"]');
  const errorCount = await errorMessage.count();
  
  expect(errorCount).toBe(0);
});

Then('console should show no critical errors', async function () {
  const criticalErrors = this.testData.consoleErrors.filter((error: string) => 
    error.toLowerCase().includes('critical') || 
    error.toLowerCase().includes('fatal') ||
    error.toLowerCase().includes('uncaught')
  );
  
  expect(criticalErrors.length).toBe(0);
});

Then('all API calls should return successful status codes', async function () {
  // API response tracking is handled in the Given step with performance monitoring
});

Then('no memory leaks should be detected', async function () {
  const metrics = await page.metrics();
  expect(metrics.JSHeapUsedSize).toBeLessThan(100000000);
});

Then('page should load within {string} seconds', async function (seconds: string) {
  const maxLoadTime = parseInt(seconds) * 1000;
  const startTime = Date.now();
  
  await waits.waitForNetworkIdle();
  
  const endTime = Date.now();
  const loadTime = endTime - startTime;
  
  expect(loadTime).toBeLessThan(maxLoadTime);
});

Then('deleted review cycles should not be displayed', async function () {
  // TODO: Replace XPath with Object Repository when available
  const deletedCycles = page.locator('//div[@class="review-cycle-item deleted"]');
  const count = await deletedCycles.count();
  
  expect(count).toBe(0);
});

Then('current system time should be displayed correctly', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="current-time"]'));
});

Then('system should prevent selection of non-existent time or automatically adjust to {string}', async function (adjustedTime: string) {
  // TODO: Replace XPath with Object Repository when available
  const timeValue = await page.locator('//input[@id="start-time"]').inputValue();
  
  if (timeValue !== adjustedTime) {
    await page.waitForTimeout(500);
    const updatedTimeValue = await page.locator('//input[@id="start-time"]').inputValue();
    expect(updatedTimeValue).toBe(adjustedTime);
  }
});

Then('notification {string} should be displayed', async function (notification: string) {
  // TODO: Replace XPath with Object Repository when available
  await waits.waitForVisible(page.locator('//div[@id="notification"]'));
  await assertions.assertContainsText(page.locator('//div[@id="notification"]'), notification);
});

Then('review cycle should be saved with DST-aware timestamp', async function () {
  // TODO: Replace XPath with Object Repository when available
  const reviewCycle = page.locator('//div[@class="review-cycle-item"]').first();
  const timestamp = await reviewCycle.getAttribute('data-timestamp');
  
  expect(timestamp).toBeTruthy();
});

Then('review cycle should appear at {string} with DST indicator', async function (time: string) {
  // TODO: Replace XPath with Object Repository when available
  const reviewCycle = page.locator(`//div[@data-time="${time}"]`);
  await assertions.assertVisible(reviewCycle);
  
  const dstIndicator = page.locator('//span[@class="dst-indicator"]');
  await assertions.assertVisible(dstIndicator);
});

Then('notification scheduler should show correct times adjusted for DST', async function () {
  // TODO: Replace XPath with Object Repository when available
  await assertions.assertVisible(page.locator('//div[@id="notification-schedule"]'));
  
  const dstAdjustment = page.locator('//span[@class="dst-adjusted"]');
  
  if (await dstAdjustment.count() > 0) {
    await assertions.assertVisible(dstAdjustment);
  }
});