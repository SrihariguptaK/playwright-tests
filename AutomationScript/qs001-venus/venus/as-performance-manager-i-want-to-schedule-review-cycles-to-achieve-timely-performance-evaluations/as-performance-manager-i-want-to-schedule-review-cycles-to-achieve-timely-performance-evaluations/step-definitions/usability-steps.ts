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
    reviewCycles: {
      existing: {
        team: 'Engineering Team',
        startDate: '2024-01-01',
        endDate: '2024-03-31',
        frequency: 'Quarterly'
      }
    }
  };
  
  this.unsavedChanges = false;
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
/*  Used across all test cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user is logged in as {string}', async function (userType: string) {
  const credentials = this.testData?.users?.[userType] || { username: 'testuser', password: 'testpass' };
  
  await actions.navigateTo(process.env.BASE_URL || 'https://performance-management.example.com');
  await waits.waitForNetworkIdle();
  
  const usernameXPath = `//input[@id='username']`;
  const passwordXPath = `//input[@id='password']`;
  const loginButtonXPath = `//button[@id='login']`;
  
  await actions.fill(page.locator(usernameXPath), credentials.username);
  await actions.fill(page.locator(passwordXPath), credentials.password);
  await actions.click(page.locator(loginButtonXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
Given('user has permissions to schedule review cycles', async function () {
  const permissionsIndicatorXPath = `//div[@id='user-permissions']`;
  await assertions.assertVisible(page.locator(permissionsIndicatorXPath));
});

// TODO: Replace XPath with Object Repository when available
Given('review cycle management page is accessible', async function () {
  const pageHeaderXPath = `//h1[@id='review-cycle-management-header']`;
  await assertions.assertVisible(page.locator(pageHeaderXPath));
});

/**************************************************/
/*  TEST CASE: TC-001
/*  Title: System provides clear feedback during review cycle scheduling process
/*  Priority: Critical
/*  Category: Usability, Functional, Smoke
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('at least one team or department is available for scheduling', async function () {
  const teamDropdownXPath = `//select[@id='team']`;
  await waits.waitForVisible(page.locator(teamDropdownXPath));
  
  const options = await page.locator(`${teamDropdownXPath}/option`).count();
  expect(options).toBeGreaterThan(1);
});

/**************************************************/
/*  TEST CASE: TC-002, TC-003, TC-004, TC-005, TC-006
/*  Title: Error prevention and validation scenarios
/*  Priority: Critical
/*  Category: Usability, Negative, Error Prevention
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('at least one existing review cycle is already scheduled', async function () {
  this.existingReviewCycle = this.testData.reviewCycles.existing;
  
  const calendarViewXPath = `//div[@id='calendar-view']`;
  await waits.waitForVisible(page.locator(calendarViewXPath));
  
  const existingCycleXPath = `//div[@id='existing-review-cycle']`;
  await assertions.assertVisible(page.locator(existingCycleXPath));
});

// TODO: Replace XPath with Object Repository when available
Given('system validation rules are active', async function () {
  const validationStatusXPath = `//div[@id='validation-status']`;
  await assertions.assertVisible(page.locator(validationStatusXPath));
});

// TODO: Replace XPath with Object Repository when available
Given('existing review cycle is scheduled from {string} to {string} for {string}', async function (startDate: string, endDate: string, teamName: string) {
  this.existingReviewCycle = {
    team: teamName,
    startDate: startDate,
    endDate: endDate
  };
  
  const existingCycleXPath = `//div[@id='existing-review-cycle']`;
  await assertions.assertContainsText(page.locator(existingCycleXPath), teamName);
  await assertions.assertContainsText(page.locator(existingCycleXPath), startDate);
});

/**************************************************/
/*  TEST CASE: TC-007, TC-008, TC-009, TC-010
/*  Title: User control and edit/delete scenarios
/*  Priority: High
/*  Category: Usability, Functional, User Control
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('at least two review cycles are already scheduled', async function () {
  const reviewCycleItemsXPath = `//div[@class='review-cycle-item']`;
  const cycleCount = await page.locator(reviewCycleItemsXPath).count();
  expect(cycleCount).toBeGreaterThanOrEqual(2);
});

// TODO: Replace XPath with Object Repository when available
Given('user has edit and delete permissions', async function () {
  const editButtonXPath = `//button[@id='edit']`;
  const deleteButtonXPath = `//button[@id='delete']`;
  
  await assertions.assertVisible(page.locator(editButtonXPath).first());
  await assertions.assertVisible(page.locator(deleteButtonXPath).first());
});

// TODO: Replace XPath with Object Repository when available
Given('scheduled review cycle {string} exists', async function (cycleName: string) {
  const cycleXPath = `//div[contains(text(),'${cycleName}')]`;
  await assertions.assertVisible(page.locator(cycleXPath));
  this.selectedCycleName = cycleName;
});

// TODO: Replace XPath with Object Repository when available
Given('{string} already has {int} concurrent review cycles scheduled', async function (teamName: string, cycleCount: number) {
  this.teamName = teamName;
  this.existingConcurrentCycles = cycleCount;
  
  const teamCyclesXPath = `//div[@data-team='${teamName}']//div[@class='review-cycle-item']`;
  const actualCount = await page.locator(teamCyclesXPath).count();
  expect(actualCount).toBe(cycleCount);
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  NAVIGATION AND PAGE INTERACTION STEPS
/*  Generic steps for navigating and interacting with pages
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('user navigates to {string} page', async function (pageName: string) {
  const pageUrlMap: { [key: string]: string } = {
    'Review Cycle Management': '/review-cycles',
    'Dashboard': '/dashboard',
    'Settings': '/settings'
  };
  
  const pageUrl = pageUrlMap[pageName] || `/${pageName.toLowerCase().replace(/\s+/g, '-')}`;
  await actions.navigateTo(`${process.env.BASE_URL || 'https://performance-management.example.com'}${pageUrl}`);
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user selects {string} from {string} dropdown', async function (optionText: string, dropdownName: string) {
  const dropdownXPath = `//select[@id='${dropdownName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.selectByText(page.locator(dropdownXPath), optionText);
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user fills in all required fields', async function () {
  const startDateXPath = `//input[@id='start-date']`;
  const endDateXPath = `//input[@id='end-date']`;
  const teamXPath = `//select[@id='team']`;
  
  await actions.fill(page.locator(startDateXPath), '2024-06-01');
  await actions.fill(page.locator(endDateXPath), '2024-08-31');
  await actions.selectByText(page.locator(teamXPath), 'Engineering Team');
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
When('save operation completes', async function () {
  const loadingIndicatorXPath = `//div[@id='loading-indicator']`;
  await waits.waitForHidden(page.locator(loadingIndicatorXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user opens date picker for {string} field', async function (fieldName: string) {
  const dateFieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(dateFieldXPath));
  
  const datePickerXPath = `//div[@id='date-picker']`;
  await waits.waitForVisible(page.locator(datePickerXPath));
});

// TODO: Replace XPath with Object Repository when available
When('user selects date range that overlaps with existing review cycle', async function () {
  const startDateXPath = `//input[@id='start-date']`;
  const endDateXPath = `//input[@id='end-date']`;
  
  await actions.fill(page.locator(startDateXPath), '2024-02-01');
  await actions.fill(page.locator(endDateXPath), '2024-04-30');
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user is on review cycle scheduling form', async function () {
  const formXPath = `//form[@id='review-cycle-form']`;
  await assertions.assertVisible(page.locator(formXPath));
});

// TODO: Replace XPath with Object Repository when available
When('required fields are not filled', async function () {
  const startDateXPath = `//input[@id='start-date']`;
  const value = await page.locator(startDateXPath).inputValue();
  expect(value).toBe('');
});

// TODO: Replace XPath with Object Repository when available
When('user selects {string} in {string} field', async function (dateValue: string, fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.fill(page.locator(fieldXPath), dateValue);
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user opens {string} date picker', async function (fieldName: string) {
  const dateFieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(dateFieldXPath));
  
  const datePickerXPath = `//div[@id='date-picker']`;
  await waits.waitForVisible(page.locator(datePickerXPath));
});

// TODO: Replace XPath with Object Repository when available
When('user attempts to schedule {int}th concurrent review cycle for {string}', async function (cycleNumber: number, teamName: string) {
  const teamXPath = `//select[@id='team']`;
  await actions.selectByText(page.locator(teamXPath), teamName);
  
  const startDateXPath = `//input[@id='start-date']`;
  const endDateXPath = `//input[@id='end-date']`;
  
  await actions.fill(page.locator(startDateXPath), '2024-09-01');
  await actions.fill(page.locator(endDateXPath), '2024-11-30');
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user clicks {string} button on existing scheduled review cycle', async function (buttonText: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase()}']`;
  await actions.click(page.locator(buttonXPath).first());
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user modifies {string} from {string} to {string}', async function (fieldName: string, oldValue: string, newValue: string) {
  const fieldXPath = `//select[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.selectByText(page.locator(fieldXPath), newValue);
  this.unsavedChanges = true;
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user clicks {string} button in confirmation dialog', async function (buttonText: string) {
  const dialogButtonXPath = `//div[@id='confirmation-dialog']//button[contains(text(),'${buttonText}')]`;
  await actions.click(page.locator(dialogButtonXPath));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user fills in {string} field', async function (fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.fill(page.locator(fieldXPath), 'Test Value');
  this.unsavedChanges = true;
});

// TODO: Replace XPath with Object Repository when available
When('user has unsaved changes', async function () {
  this.unsavedChanges = true;
});

// TODO: Replace XPath with Object Repository when available
When('user presses browser back button', async function () {
  await page.goBack();
  await page.waitForTimeout(500);
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  ASSERTION AND VERIFICATION STEPS
/*  Generic steps for verifying UI state and behavior
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('loading indicator should be displayed during page load', async function () {
  const loadingIndicatorXPath = `//div[@id='loading-indicator']`;
  await assertions.assertVisible(page.locator(loadingIndicatorXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('page should load within {int} seconds', async function (seconds: number) {
  const startTime = Date.now();
  const pageReadyXPath = `//div[@id='page-ready']`;
  await waits.waitForVisible(page.locator(pageReadyXPath));
  const loadTime = (Date.now() - startTime) / 1000;
  expect(loadTime).toBeLessThanOrEqual(seconds);
});

// TODO: Replace XPath with Object Repository when available
Then('clear indication should be displayed when page is ready', async function () {
  const pageReadyXPath = `//div[@id='page-ready']`;
  await assertions.assertVisible(page.locator(pageReadyXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('form fields should provide visual feedback as user interacts with them', async function () {
  const activeFieldXPath = `//input[@class='active']`;
  await assertions.assertVisible(page.locator(activeFieldXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('validation icons should be displayed on form fields', async function () {
  const validationIconXPath = `//span[@class='validation-icon']`;
  await assertions.assertVisible(page.locator(validationIconXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('{string} button should show loading state', async function (buttonText: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase()}']`;
  const loadingClass = await page.locator(buttonXPath).getAttribute('class');
  expect(loadingClass).toContain('loading');
});

// TODO: Replace XPath with Object Repository when available
Then('{string} text should be displayed during processing', async function (text: string) {
  const textXPath = `//*[contains(text(),'${text}')]`;
  await assertions.assertVisible(page.locator(textXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('{string} button should be disabled during processing', async function (buttonText: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase()}']`;
  const isDisabled = await page.locator(buttonXPath).isDisabled();
  expect(isDisabled).toBe(true);
});

// TODO: Replace XPath with Object Repository when available
Then('success message {string} should be displayed', async function (message: string) {
  const successMessageXPath = `//div[@id='success-message']`;
  await assertions.assertVisible(page.locator(successMessageXPath));
  await assertions.assertContainsText(page.locator(successMessageXPath), message);
});

// TODO: Replace XPath with Object Repository when available
Then('scheduled cycle frequency should be displayed in success message', async function () {
  const successMessageXPath = `//div[@id='success-message']`;
  await assertions.assertContainsText(page.locator(successMessageXPath), 'Quarterly');
});

// TODO: Replace XPath with Object Repository when available
Then('scheduled cycle start date should be displayed in success message', async function () {
  const successMessageXPath = `//div[@id='success-message']`;
  await assertions.assertContainsText(page.locator(successMessageXPath), '2024-06-01');
});

// TODO: Replace XPath with Object Repository when available
Then('scheduled cycle next review date should be displayed in success message', async function () {
  const successMessageXPath = `//div[@id='success-message']`;
  await assertions.assertContainsText(page.locator(successMessageXPath), '2024-08-31');
});

// TODO: Replace XPath with Object Repository when available
Then('newly scheduled review cycle should appear immediately in calendar view', async function () {
  const calendarViewXPath = `//div[@id='calendar-view']`;
  const newCycleXPath = `//div[@class='review-cycle-item new']`;
  await assertions.assertVisible(page.locator(newCycleXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('scheduled review cycle should have visual distinction in calendar view', async function () {
  const newCycleXPath = `//div[@class='review-cycle-item new']`;
  const hasDistinction = await page.locator(newCycleXPath).getAttribute('class');
  expect(hasDistinction).toContain('new');
});

// TODO: Replace XPath with Object Repository when available
Then('scheduled review cycle should have color coding in calendar view', async function () {
  const newCycleXPath = `//div[@class='review-cycle-item new']`;
  const colorStyle = await page.locator(newCycleXPath).evaluate((el) => window.getComputedStyle(el).backgroundColor);
  expect(colorStyle).toBeTruthy();
});

// TODO: Replace XPath with Object Repository when available
Then('past dates should be disabled in date picker', async function () {
  const pastDateXPath = `//div[@id='date-picker']//td[@class='past disabled']`;
  await assertions.assertVisible(page.locator(pastDateXPath).first());
});

// TODO: Replace XPath with Object Repository when available
Then('past dates should be grayed out in date picker', async function () {
  const pastDateXPath = `//div[@id='date-picker']//td[@class='past disabled']`;
  const grayedOutStyle = await page.locator(pastDateXPath).first().evaluate((el) => window.getComputedStyle(el).color);
  expect(grayedOutStyle).toContain('gray');
});

// TODO: Replace XPath with Object Repository when available
Then('inline warning message {string} should be displayed immediately', async function (warningMessage: string) {
  const warningXPath = `//div[@id='inline-warning']`;
  await assertions.assertVisible(page.locator(warningXPath));
  await assertions.assertContainsText(page.locator(warningXPath), warningMessage);
});

// TODO: Replace XPath with Object Repository when available
Then('conflicting dates should be highlighted in calendar view', async function () {
  const highlightedDateXPath = `//div[@id='calendar-view']//td[@class='conflicting']`;
  await assertions.assertVisible(page.locator(highlightedDateXPath).first());
});

// TODO: Replace XPath with Object Repository when available
Then('{string} button should be disabled', async function (buttonText: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase()}']`;
  const isDisabled = await page.locator(buttonXPath).isDisabled();
  expect(isDisabled).toBe(true);
});

// TODO: Replace XPath with Object Repository when available
Then('required fields should have asterisk indicators', async function () {
  const asteriskXPath = `//span[@class='required-asterisk']`;
  await assertions.assertVisible(page.locator(asteriskXPath).first());
});

// TODO: Replace XPath with Object Repository when available
Then('required fields should have visual border indicators', async function () {
  const requiredFieldXPath = `//input[@class='required']`;
  const borderStyle = await page.locator(requiredFieldXPath).first().evaluate((el) => window.getComputedStyle(el).borderColor);
  expect(borderStyle).toBeTruthy();
});

// TODO: Replace XPath with Object Repository when available
Then('end date picker should show only dates after {string}', async function (startDate: string) {
  const datePickerXPath = `//div[@id='date-picker']`;
  const enabledDatesXPath = `${datePickerXPath}//td[not(@class='disabled')]`;
  
  const firstEnabledDate = await page.locator(enabledDatesXPath).first().getAttribute('data-date');
  const startDateTime = new Date(startDate).getTime();
  const firstEnabledDateTime = new Date(firstEnabledDate || '').getTime();
  
  expect(firstEnabledDateTime).toBeGreaterThan(startDateTime);
});

// TODO: Replace XPath with Object Repository when available
Then('warning message {string} should be displayed', async function (warningMessage: string) {
  const warningXPath = `//div[@id='warning-message']`;
  await assertions.assertVisible(page.locator(warningXPath));
  await assertions.assertContainsText(page.locator(warningXPath), warningMessage);
});

// TODO: Replace XPath with Object Repository when available
Then('{string} button should be visible', async function (buttonText: string) {
  const buttonXPath = `//button[contains(text(),'${buttonText}')]`;
  await assertions.assertVisible(page.locator(buttonXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('edit form should open with current values pre-populated', async function () {
  const editFormXPath = `//form[@id='edit-review-cycle-form']`;
  await assertions.assertVisible(page.locator(editFormXPath));
  
  const frequencyFieldXPath = `//select[@id='review-cycle-frequency']`;
  const currentValue = await page.locator(frequencyFieldXPath).inputValue();
  expect(currentValue).toBeTruthy();
});

// TODO: Replace XPath with Object Repository when available
Then('{string} button should be clearly visible', async function (buttonText: string) {
  const buttonXPath = `//button[contains(text(),'${buttonText}')]`;
  await assertions.assertVisible(page.locator(buttonXPath));
  
  const opacity = await page.locator(buttonXPath).evaluate((el) => window.getComputedStyle(el).opacity);
  expect(parseFloat(opacity)).toBeGreaterThan(0.9);
});

// TODO: Replace XPath with Object Repository when available
Then('system should return to previous view without saving changes', async function () {
  const listViewXPath = `//div[@id='review-cycle-list']`;
  await assertions.assertVisible(page.locator(listViewXPath));
  this.unsavedChanges = false;
});

// TODO: Replace XPath with Object Repository when available
Then('success message should be displayed', async function () {
  const successMessageXPath = `//div[@id='success-message']`;
  await assertions.assertVisible(page.locator(successMessageXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('{string} link should be displayed in success message', async function (linkText: string) {
  const undoLinkXPath = `//div[@id='success-message']//a[contains(text(),'${linkText}')]`;
  await assertions.assertVisible(page.locator(undoLinkXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('{string} option should be available for {int} seconds', async function (optionText: string, seconds: number) {
  const optionXPath = `//*[contains(text(),'${optionText}')]`;
  await assertions.assertVisible(page.locator(optionXPath));
  
  await page.waitForTimeout(seconds * 1000);
  const isVisible = await page.locator(optionXPath).isVisible();
  expect(isVisible).toBe(false);
});

// TODO: Replace XPath with Object Repository when available
Then('confirmation dialog should appear', async function () {
  const dialogXPath = `//div[@id='confirmation-dialog']`;
  await assertions.assertVisible(page.locator(dialogXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('confirmation message {string} should be displayed', async function (message: string) {
  const dialogMessageXPath = `//div[@id='confirmation-dialog']//p[@class='message']`;
  await assertions.assertContainsText(page.locator(dialogMessageXPath), message);
});

// TODO: Replace XPath with Object Repository when available
Then('{string} button should be displayed as default action', async function (buttonText: string) {
  const defaultButtonXPath = `//div[@id='confirmation-dialog']//button[@class='default' and contains(text(),'${buttonText}')]`;
  await assertions.assertVisible(page.locator(defaultButtonXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('{string} button should be displayed', async function (buttonText: string) {
  const buttonXPath = `//button[contains(text(),'${buttonText}')]`;
  await assertions.assertVisible(page.locator(buttonXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('prompt {string} should be displayed', async function (promptMessage: string) {
  page.on('dialog', async (dialog) => {
    expect(dialog.message()).toContain(promptMessage);
    await dialog.dismiss();
  });
});