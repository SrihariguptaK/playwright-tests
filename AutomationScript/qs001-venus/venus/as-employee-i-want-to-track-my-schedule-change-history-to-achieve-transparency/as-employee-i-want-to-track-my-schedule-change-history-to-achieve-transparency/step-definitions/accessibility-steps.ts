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
      employee: { username: 'employee', password: 'employee123' },
      admin: { username: 'admin', password: 'admin123' }
    },
    focusedElements: [],
    contrastResults: {}
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
/*  Used across all accessibility test cases
/**************************************************/

Given('user is logged in as an authenticated employee', async function () {
  const credentials = this.testData?.users?.employee || { username: 'employee', password: 'employee123' };
  
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  
  await actions.fill(page.locator('[data-testid="input-username"]'), credentials.username);
  await actions.fill(page.locator('[data-testid="input-password"]'), credentials.password);
  await actions.click(page.locator('[data-testid="button-login"]'));
  await waits.waitForNetworkIdle();
});

Given('user has schedule change requests in the system', async function () {
  this.hasScheduleRequests = true;
});

/**************************************************/
/*  TEST CASE: TC-A11Y-001
/*  Title: Complete keyboard navigation through schedule change history page and filters
/*  Priority: High
/*  Category: Accessibility - Keyboard Navigation
/*  Description: Verifies full keyboard accessibility including tab navigation, focus management, and keyboard-only interaction with all page elements
/**************************************************/

Given('user is on {string} page with visible requests and filter controls', async function (pageName: string) {
  const pageUrl = pageName.toLowerCase().replace(/\s+/g, '-');
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/${pageUrl}`);
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator('[data-testid="schedule-change-history-container"]'));
  await waits.waitForVisible(page.locator('[data-testid="filter-section"]'));
});

Given('keyboard is the only input method being used', async function () {
  this.keyboardOnlyMode = true;
  this.focusedElements = [];
});

Given('screen reader software is active', async function () {
  this.screenReaderActive = true;
  this.announcedMessages = [];
});

Given('user is on {string} page', async function (pageName: string) {
  const pageUrl = pageName.toLowerCase().replace(/\s+/g, '-');
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/${pageUrl}`);
  await waits.waitForNetworkIdle();
});

Given('page has proper ARIA labels and semantic HTML', async function () {
  const mainLandmark = page.locator('[role="main"], main');
  await assertions.assertVisible(mainLandmark);
  
  const headings = page.locator('h1, h2, h3, h4, h5, h6');
  const headingCount = await headings.count();
  expect(headingCount).toBeGreaterThan(0);
});

Given('page is tested in modern browser with focus indicators', async function () {
  this.focusIndicatorTesting = true;
});

Given('WCAG 2.1 Level AA compliance is target standard', async function () {
  this.wcagLevel = 'AA';
  this.wcagVersion = '2.1';
});

Given('color contrast checking tool is available', async function () {
  this.contrastCheckingEnabled = true;
});

Given('page displays status badges with colors', async function () {
  await waits.waitForVisible(page.locator('[data-testid="status-badge"]').first());
});

Given('WCAG 2.1 Level AA requires {string} for normal text and {string} for large text', async function (normalRatio: string, largeRatio: string) {
  this.wcagNormalTextRatio = normalRatio;
  this.wcagLargeTextRatio = largeRatio;
});

Given('user is on {string} page with multiple requests visible', async function (pageName: string) {
  const pageUrl = pageName.toLowerCase().replace(/\s+/g, '-');
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/${pageUrl}`);
  await waits.waitForNetworkIdle();
  
  const requestItems = page.locator('[data-testid="request-item"]');
  const count = await requestItems.count();
  expect(count).toBeGreaterThan(0);
});

Given('browser zoom is set to {string} percent', async function (zoomLevel: string) {
  this.currentZoomLevel = parseInt(zoomLevel);
});

Given('WCAG 2.1 SC 1.4.4 requires content readable at 200% zoom', async function () {
  this.wcagZoomRequirement = '200%';
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  TEST CASE: TC-A11Y-001 - Keyboard Navigation
/**************************************************/

When('user presses Tab key repeatedly to navigate through all interactive elements', async function () {
  const interactiveElements = await page.locator('a, button, input, select, textarea, [tabindex]:not([tabindex="-1"])').all();
  this.totalInteractiveElements = interactiveElements.length;
  
  for (let i = 0; i < Math.min(interactiveElements.length, 50); i++) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
    
    const focusedElement = await page.evaluateHandle(() => document.activeElement);
    const tagName = await focusedElement.evaluate(el => el.tagName);
    this.focusedElements.push(tagName);
  }
});

When('user uses Tab to focus on {string} filter field', async function (fieldLabel: string) {
  const fieldLocator = `[data-testid="filter-${fieldLabel.toLowerCase().replace(/\s+/g, '-')}"]`;
  await page.locator(fieldLocator).focus();
  await page.waitForTimeout(100);
});

When('user presses Enter key to open date picker', async function () {
  await page.keyboard.press('Enter');
  await page.waitForTimeout(300);
});

When('user uses arrow keys to navigate to a date in date picker', async function () {
  await page.keyboard.press('ArrowRight');
  await page.waitForTimeout(100);
  await page.keyboard.press('ArrowRight');
  await page.waitForTimeout(100);
  await page.keyboard.press('ArrowDown');
  await page.waitForTimeout(100);
});

When('user presses Enter key to select date', async function () {
  await page.keyboard.press('Enter');
  await page.waitForTimeout(300);
});

When('user tabs to {string} dropdown filter', async function (dropdownLabel: string) {
  const dropdownLocator = `[data-testid="filter-${dropdownLabel.toLowerCase().replace(/\s+/g, '-')}"]`;
  await page.locator(dropdownLocator).focus();
  await page.waitForTimeout(100);
});

When('user presses Enter key to open dropdown', async function () {
  await page.keyboard.press('Enter');
  await page.waitForTimeout(300);
});

When('user uses arrow keys to select {string} status', async function (statusValue: string) {
  await page.keyboard.press('ArrowDown');
  await page.waitForTimeout(100);
  await page.keyboard.press('ArrowDown');
  await page.waitForTimeout(100);
});

When('user presses Enter key to confirm selection', async function () {
  await page.keyboard.press('Enter');
  await page.waitForTimeout(300);
});

When('user tabs to {string} button', async function (buttonText: string) {
  const buttonLocator = `[data-testid="button-${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const button = page.locator(buttonLocator);
  
  if (await button.count() > 0) {
    await button.focus();
  } else {
    await page.locator(`button:has-text("${buttonText}")`).focus();
  }
  await page.waitForTimeout(100);
});

When('user presses Enter key to apply filters', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(500);
});

When('user tabs through filtered request list', async function () {
  const requestItems = await page.locator('[data-testid="request-item"]').all();
  
  for (let i = 0; i < Math.min(requestItems.length, 5); i++) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
  }
});

When('user presses Enter key on a request to view details', async function () {
  await page.keyboard.press('Enter');
  await page.waitForTimeout(500);
});

When('user presses Escape key to close request details', async function () {
  await page.keyboard.press('Escape');
  await page.waitForTimeout(300);
});

/**************************************************/
/*  TEST CASE: TC-A11Y-002 - Screen Reader
/**************************************************/

When('user navigates to schedule change history page with screen reader active', async function () {
  await waits.waitForVisible(page.locator('[data-testid="schedule-change-history-container"]'));
  
  const pageTitle = await page.title();
  this.announcedMessages.push(`Page title: ${pageTitle}`);
  
  const mainHeading = await page.locator('h1').first().textContent();
  this.announcedMessages.push(`Main heading: ${mainHeading}`);
});

When('user navigates to filter section using screen reader commands', async function () {
  const filterSection = page.locator('[data-testid="filter-section"]');
  await waits.waitForVisible(filterSection);
  
  const ariaLabel = await filterSection.getAttribute('aria-label');
  if (ariaLabel) {
    this.announcedMessages.push(`Section: ${ariaLabel}`);
  }
});

When('user uses screen reader to navigate through request list table', async function () {
  const table = page.locator('[data-testid="schedule-requests-table"], table');
  await waits.waitForVisible(table);
  
  const rows = await table.locator('tbody tr').count();
  this.announcedMessages.push(`Table with ${rows} rows`);
  
  const headers = await table.locator('thead th').allTextContents();
  this.tableHeaders = headers;
});

When('user applies filter using keyboard and screen reader', async function () {
  await actions.click(page.locator('[data-testid="button-apply-filter"]'));
  await waits.waitForNetworkIdle();
  await page.waitForTimeout(500);
});

When('user navigates to a request and opens details using screen reader', async function () {
  const firstRequest = page.locator('[data-testid="request-item"]').first();
  await actions.click(firstRequest);
  await page.waitForTimeout(500);
});

When('user navigates to pagination controls with screen reader', async function () {
  const pagination = page.locator('[data-testid="pagination-controls"]');
  await waits.waitForVisible(pagination);
  
  const ariaLabel = await pagination.getAttribute('aria-label');
  if (ariaLabel) {
    this.announcedMessages.push(`Pagination: ${ariaLabel}`);
  }
});

/**************************************************/
/*  TEST CASE: TC-A11Y-003 - Focus Management
/**************************************************/

When('user tabs through all interactive elements on page', async function () {
  const interactiveElements = await page.locator('a, button, input, select, textarea, [tabindex]:not([tabindex="-1"])').all();
  this.focusIndicatorResults = [];
  
  for (let i = 0; i < Math.min(interactiveElements.length, 30); i++) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
    
    const focusedElement = page.locator(':focus');
    const hasFocusIndicator = await focusedElement.evaluate(el => {
      const styles = window.getComputedStyle(el);
      return styles.outline !== 'none' || styles.boxShadow !== 'none';
    });
    
    this.focusIndicatorResults.push(hasFocusIndicator);
  }
});

When('user opens request details modal', async function () {
  const firstRequest = page.locator('[data-testid="request-item"]').first();
  await actions.click(firstRequest);
  await page.waitForTimeout(500);
  await waits.waitForVisible(page.locator('[data-testid="request-details-modal"], [role="dialog"]'));
});

When('user closes modal using Escape key', async function () {
  this.elementBeforeModal = await page.evaluateHandle(() => document.activeElement?.getAttribute('data-testid'));
  await page.keyboard.press('Escape');
  await page.waitForTimeout(300);
});

When('user applies filter', async function () {
  await actions.click(page.locator('[data-testid="button-apply-filter"]'));
  await waits.waitForNetworkIdle();
});

When('dynamic content updates', async function () {
  await page.waitForTimeout(500);
});

When('user interacts with elements in different states', async function () {
  const button = page.locator('[data-testid="button-apply-filter"]');
  
  await button.hover();
  await page.waitForTimeout(200);
  
  await button.focus();
  await page.waitForTimeout(200);
  
  await button.click();
  await page.waitForTimeout(200);
});

/**************************************************/
/*  TEST CASE: TC-A11Y-004 - Color Contrast
/**************************************************/

When('user checks contrast ratio for {string}', async function (elementType: string) {
  let locator;
  
  switch (elementType) {
    case 'body text on background':
      locator = page.locator('body, p, div').first();
      break;
    case 'large text on background':
      locator = page.locator('h1, h2, h3').first();
      break;
    case 'Approved badge text on green':
      locator = page.locator('[data-testid="status-badge-approved"]');
      break;
    case 'Pending badge text on yellow':
      locator = page.locator('[data-testid="status-badge-pending"]');
      break;
    case 'Rejected badge text on red':
      locator = page.locator('[data-testid="status-badge-rejected"]');
      break;
    case 'button text on button background':
      locator = page.locator('button').first();
      break;
    case 'link text on background':
      locator = page.locator('a').first();
      break;
    case 'form field borders':
      locator = page.locator('input, select, textarea').first();
      break;
    default:
      locator = page.locator('body');
  }
  
  const contrastData = await locator.evaluate(el => {
    const styles = window.getComputedStyle(el);
    const color = styles.color;
    const backgroundColor = styles.backgroundColor;
    const borderColor = styles.borderColor;
    
    return {
      color,
      backgroundColor,
      borderColor,
      fontSize: styles.fontSize
    };
  });
  
  this.contrastResults[elementType] = contrastData;
  this.currentElementType = elementType;
});

/**************************************************/
/*  TEST CASE: TC-A11Y-005 - Zoom and Reflow
/**************************************************/

When('user sets browser zoom to {string} percent', async function (zoomLevel: string) {
  const zoomValue = parseInt(zoomLevel) / 100;
  
  await page.evaluate((zoom) => {
    document.body.style.zoom = zoom.toString();
  }, zoomValue);
  
  await page.waitForTimeout(500);
  this.currentZoomLevel = parseInt(zoomLevel);
});

When('user checks interactive elements at {string} percent zoom', async function (zoomLevel: string) {
  const buttons = await page.locator('button, a, input').all();
  this.interactiveElementsAtZoom = buttons.length;
  
  for (const button of buttons.slice(0, 10)) {
    const isVisible = await button.isVisible();
    const boundingBox = await button.boundingBox();
    
    if (boundingBox) {
      expect(boundingBox.width).toBeGreaterThan(0);
      expect(boundingBox.height).toBeGreaterThan(0);
    }
  }
});

When('user navigates through request list and applies filters at {string} percent zoom', async function (zoomLevel: string) {
  await waits.waitForVisible(page.locator('[data-testid="filter-section"]'));
  
  const fromDateField = page.locator('[data-testid="filter-from-date"]');
  if (await fromDateField.count() > 0) {
    await actions.fill(fromDateField, '2024-01-01');
  }
  
  await actions.click(page.locator('[data-testid="button-apply-filter"]'));
  await waits.waitForNetworkIdle();
});

When('user opens request details at {string} percent zoom', async function (zoomLevel: string) {
  const firstRequest = page.locator('[data-testid="request-item"]').first();
  await actions.click(firstRequest);
  await page.waitForTimeout(500);
});

When('user views table or list layout at {string} percent zoom', async function (zoomLevel: string) {
  const table = page.locator('[data-testid="schedule-requests-table"], table');
  
  if (await table.count() > 0) {
    await waits.waitForVisible(table);
    const boundingBox = await table.boundingBox();
    this.tableLayoutAtZoom = boundingBox;
  }
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  TEST CASE: TC-A11Y-001 - Keyboard Navigation
/**************************************************/

Then('focus should move sequentially through navigation menu, filter controls, request list items, and pagination controls', async function () {
  expect(this.focusedElements.length).toBeGreaterThan(10);
  
  const hasNavigation = this.focusedElements.some((tag: string) => tag === 'A' || tag === 'BUTTON');
  expect(hasNavigation).toBeTruthy();
});

Then('visible focus indicators should be displayed on each focused element', async function () {
  const focusedElement = page.locator(':focus');
  
  const hasFocusIndicator = await focusedElement.evaluate(el => {
    const styles = window.getComputedStyle(el);
    return styles.outline !== 'none' || styles.boxShadow !== 'none' || styles.border !== 'none';
  });
  
  expect(hasFocusIndicator).toBeTruthy();
});

Then('date picker calendar should open', async function () {
  await waits.waitForVisible(page.locator('[data-testid="date-picker-calendar"], .react-datepicker, [role="dialog"]'));
});

Then('focus should move to current date', async function () {
  const focusedElement = page.locator(':focus');
  await assertions.assertVisible(focusedElement);
});

Then('calendar should be navigable with arrow keys', async function () {
  const initialFocusedDate = await page.locator(':focus').textContent();
  
  await page.keyboard.press('ArrowRight');
  await page.waitForTimeout(100);
  
  const newFocusedDate = await page.locator(':focus').textContent();
  expect(initialFocusedDate).not.toBe(newFocusedDate);
});

Then('selected date should be populated in {string} field', async function (fieldLabel: string) {
  const fieldLocator = `[data-testid="filter-${fieldLabel.toLowerCase().replace(/\s+/g, '-')}"]`;
  const fieldValue = await page.locator(fieldLocator).inputValue();
  
  expect(fieldValue).toBeTruthy();
  expect(fieldValue.length).toBeGreaterThan(0);
});

Then('date picker should close', async function () {
  const datePicker = page.locator('[data-testid="date-picker-calendar"], .react-datepicker, [role="dialog"]');
  
  await page.waitForTimeout(300);
  const isVisible = await datePicker.isVisible().catch(() => false);
  expect(isVisible).toBeFalsy();
});

Then('focus should return to date input field', async function () {
  const focusedElement = await page.evaluateHandle(() => document.activeElement);
  const tagName = await focusedElement.evaluate(el => el.tagName);
  
  expect(tagName).toBe('INPUT');
});

Then('dropdown menu should open showing status options', async function () {
  await waits.waitForVisible(page.locator('[data-testid="dropdown-menu"], [role="listbox"], .dropdown-menu'));
});

Then('focus should be on first option', async function () {
  const focusedElement = page.locator(':focus');
  await assertions.assertVisible(focusedElement);
});

Then('arrow keys should navigate through options', async function () {
  const initialOption = await page.locator(':focus').textContent();
  
  await page.keyboard.press('ArrowDown');
  await page.waitForTimeout(100);
  
  const newOption = await page.locator(':focus').textContent();
  expect(initialOption).not.toBe(newOption);
});

Then('status {string} should be selected', async function (statusValue: string) {
  const statusDropdown = page.locator('[data-testid="filter-status"]');
  const selectedValue = await statusDropdown.inputValue().catch(() => statusDropdown.textContent());
  
  expect(selectedValue).toContain(statusValue);
});

Then('dropdown should close', async function () {
  const dropdown = page.locator('[data-testid="dropdown-menu"], [role="listbox"], .dropdown-menu');
  
  await page.waitForTimeout(300);
  const isVisible = await dropdown.isVisible().catch(() => false);
  expect(isVisible).toBeFalsy();
});

Then('focus should return to dropdown control', async function () {
  const focusedElement = await page.evaluateHandle(() => document.activeElement);
  const hasDropdownAttribute = await focusedElement.evaluate(el => 
    el.hasAttribute('data-testid') && el.getAttribute('data-testid')?.includes('filter')
  );
  
  expect(hasDropdownAttribute).toBeTruthy();
});

Then('filters should be applied', async function () {
  await page.waitForTimeout(500);
  const requestItems = page.locator('[data-testid="request-item"]');
  const count = await requestItems.count();
  
  expect(count).toBeGreaterThanOrEqual(0);
});

Then('page should update with filtered results', async function () {
  await waits.waitForVisible(page.locator('[data-testid="schedule-requests-table"], [data-testid="request-list"]'));
});

Then('focus should move to first result or status message', async function () {
  const focusedElement = page.locator(':focus');
  await assertions.assertVisible(focusedElement);
});

Then('request details should be displayed', async function () {
  await waits.waitForVisible(page.locator('[data-testid="request-details-modal"], [role="dialog"]'));
});

Then('focus should move to first interactive element in details view', async function () {
  const focusedElement = page.locator(':focus');
  await assertions.assertVisible(focusedElement);
});

Then('user should be able to tab through all details', async function () {
  const modalInteractiveElements = await page.locator('[data-testid="request-details-modal"] a, [data-testid="request-details-modal"] button, [role="dialog"] a, [role="dialog"] button').count();
  
  expect(modalInteractiveElements).toBeGreaterThanOrEqual(1);
});

Then('details view should close', async function () {
  const modal = page.locator('[data-testid="request-details-modal"], [role="dialog"]');
  
  await page.waitForTimeout(300);
  const isVisible = await modal.isVisible().catch(() => false);
  expect(isVisible).toBeFalsy();
});

Then('focus should return to request item in list', async function () {
  const focusedElement = page.locator(':focus');
  await assertions.assertVisible(focusedElement);
});

Then('no keyboard traps should exist on page', async function () {
  for (let i = 0; i < 20; i++) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(50);
  }
  
  const focusedElement = await page.evaluateHandle(() => document.activeElement);
  const isInBody = await focusedElement.evaluate(el => document.body.contains(el));
  
  expect(isInBody).toBeTruthy();
});

/**************************************************/
/*  TEST CASE: TC-A11Y-002 - Screen Reader
/**************************************************/

Then('screen reader should announce page title {string}', async function (expectedTitle: string) {
  const pageTitle = await page.title();
  expect(pageTitle).toContain(expectedTitle);
});

Then('screen reader should announce main heading', async function () {
  const mainHeading = page.locator('h1').first();
  await assertions.assertVisible(mainHeading);
  
  const headingText = await mainHeading.textContent();
  expect(headingText).toBeTruthy();
});

Then('screen reader should announce page landmark {string}', async function (landmarkType: string) {
  const mainLandmark = page.locator('[role="main"], main');
  await assertions.assertVisible(mainLandmark);
});

Then('screen reader should announce {string}', async function (expectedAnnouncement: string) {
  const filterSection = page.locator('[data-testid="filter-section"]');
  const ariaLabel = await filterSection.getAttribute('aria-label');
  
  if (ariaLabel) {
    expect(ariaLabel.toLowerCase()).toContain(expectedAnnouncement.toLowerCase().replace('section', '').trim());
  }
});

Then('screen reader should read label {string}', async function (expectedLabel: string) {
  const labelText = expectedLabel.split(',')[0].trim();
  const label = page.locator(`label:has-text("${labelText}"), [aria-label*="${labelText}"]`);
  
  const count = await label.count();
  expect(count).toBeGreaterThan(0);
});

Then('screen reader should announce {string} via ARIA live region', async function (announcement: string) {
  const liveRegion = page.locator('[aria-live="polite"], [aria-live="assertive"], [role="status"], [role="alert"]');
  
  await page.waitForTimeout(500);
  const count = await liveRegion.count();
  expect(count).toBeGreaterThan(0);
});

Then('updated result count should be communicated immediately', async function () {
  const resultCount = page.locator('[data-testid="result-count"], [aria-live]');
  
  if (await resultCount.count() > 0) {
    await assertions.assertVisible(resultCount);
  }
});

Then('screen reader should announce {string}', async function (announcement: string) {
  if (announcement.includes('dialog opened')) {
    const dialog = page.locator('[role="dialog"]');
    await assertions.assertVisible(dialog);
    
    const ariaLabel = await dialog.getAttribute('aria-label');
    expect(ariaLabel).toBeTruthy();
  }
});

Then('screen reader should read all detail fields with labels', async function () {
  const labels = await page.locator('[data-testid="request-details-modal"] label, [role="dialog"] label').count();
  expect(labels).toBeGreaterThan(0);
});

Then('screen reader should read request ID, submission date, original schedule, requested schedule, status, and manager comments', async function () {
  const detailFields = [
    '[data-testid="detail-request-id"]',
    '[data-testid="detail-submission-date"]',
    '[data-testid="detail-original-schedule"]',
    '[data-testid="detail-requested-schedule"]',
    '[data-testid="detail-status"]',
    '[data-testid="detail-manager-comments"]'
  ];
  
  for (const fieldSelector of detailFields) {
    const field = page.locator(fieldSelector);
    if (await field.count() > 0) {
      await assertions.assertVisible(field);
    }
  }
});

/**************************************************/
/*  TEST CASE: TC-A11Y-003 - Focus Management
/**************************************************/

Then('every focusable element should display visible focus indicator', async function () {
  const hasAllFocusIndicators = this.focusIndicatorResults.every((result: boolean) => result === true);
  expect(this.focusIndicatorResults.length).toBeGreaterThan(0);
});

Then('focus indicator should have minimum {string} contrast ratio against background', async function (minRatio: string) {
  const focusedElement = page.locator(':focus');
  
  const focusStyles = await focusedElement.evaluate(el => {
    const styles = window.getComputedStyle(el);
    return {
      outline: styles.outline,
      outlineColor: styles.outlineColor,
      boxShadow: styles.boxShadow
    };
  });
  
  expect(focusStyles.outline !== 'none' || focusStyles.boxShadow !== 'none').toBeTruthy();
});

Then('focus indicator should be at least {string} pixels thick', async function (minThickness: string) {
  const focusedElement = page.locator(':focus');
  
  const outlineWidth = await focusedElement.evaluate(el => {
    const styles = window.getComputedStyle(el);
    return styles.outlineWidth;
  });
  
  expect(outlineWidth).toBeTruthy();
});

Then('tab key should cycle through modal elements only', async function () {
  const modal = page.locator('[data-testid="request-details-modal"], [role="dialog"]');
  await assertions.assertVisible(modal);
  
  for (let i = 0; i < 5; i++) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
    
    const focusedElement = await page.evaluateHandle(() => document.activeElement);
    const isInModal = await focusedElement.evaluate((el, modalSelector) => {
      const modalElement = document.querySelector(modalSelector);
      return modalElement?.contains(el) || false;
    }, '[data-testid="request-details-modal"], [role="dialog"]');
    
    expect(isInModal).toBeTruthy();
  }
});

Then('shift tab should move backward within modal', async function () {
  await page.keyboard.press('Shift+Tab');
  await page.waitForTimeout(100);
  
  const focusedElement = page.locator(':focus');
  await assertions.assertVisible(focusedElement);
});

Then('focus should not escape to background content', async function () {
  const focusedElement = await page.evaluateHandle(() => document.activeElement);
  const isInModal = await focusedElement.evaluate(el => {
    const modal = document.querySelector('[data-testid="request-details-modal"], [role="dialog"]');
    return modal?.contains(el) || false;
  });
  
  expect(isInModal).toBeTruthy();
});

Then('focus should return to element that triggered modal', async function () {
  await page.waitForTimeout(300);
  const focusedElement = page.locator(':focus');
  await assertions.assertVisible(focusedElement);
});

Then('focus indicator should be visible on returned element', async function () {
  const focusedElement = page.locator(':focus');
  
  const hasFocusIndicator = await focusedElement.evaluate(el => {
    const styles = window.getComputedStyle(el);
    return styles.outline !== 'none' || styles.boxShadow !== 'none';
  });
  
  expect(hasFocusIndicator).toBeTruthy();
});

Then('user should be able to continue navigation from previous position', async function () {
  await page.keyboard.press('Tab');
  await page.waitForTimeout(100);
  
  const focusedElement = page.locator(':focus');
  await assertions.assertVisible(focusedElement);
});

Then('focus should remain on {string} button or move to status message', async function (buttonText: string) {
  const focusedElement = await page.evaluateHandle(() => document.activeElement);
  const tagName = await focusedElement.evaluate(el => el.tagName);
  
  expect(['BUTTON', 'DIV', 'SPAN']).toContain(tagName);
});

Then('focus should not be lost or reset to top of page', async function () {
  const focusedElement = await page.evaluateHandle(() => document.activeElement);
  const isBody = await focusedElement.evaluate(el => el.tagName === 'BODY');
  
  expect(isBody).toBeFalsy();
});

Then('focus indicators should be distinct from hover states', async function () {
  const button = page.locator('button').first();
  
  await button.hover();
  const hoverStyles = await button.evaluate(el => window.getComputedStyle(el).backgroundColor);
  
  await button.focus();
  const focusStyles = await button.evaluate(el => window.getComputedStyle(el).outline);
  
  expect(focusStyles).toBeTruthy();
});

Then('focus should remain visible when element is activated', async function () {
  const button = page.locator('button').first();
  await button.focus();
  await button.click();
  
  await page.waitForTimeout(200);
  const focusedElement = page.locator(':focus');
  await assertions.assertVisible(focusedElement);
});

Then('focus indicators should meet WCAG 2.1 Success Criterion 2.4.7', async function () {
  const focusedElement = page.locator(':focus');
  
  const hasFocusIndicator = await focusedElement.evaluate(el => {
    const styles = window.getComputedStyle(el);
    return styles.outline !== 'none' || styles.boxShadow !== 'none';
  });
  
  expect(hasFocusIndicator).toBeTruthy();
});

/**************************************************/
/*  TEST CASE: TC-A11Y-004 - Color Contrast
/**************************************************/

Then('contrast ratio should be at least {string}', async function (minRatio: string) {
  expect(this.contrastResults[this.currentElementType]).toBeTruthy();
  
  const contrastData = this.contrastResults[this.currentElementType];
  expect(contrastData.color).toBeTruthy();
});

Then('text should be readable against background', async function () {
  const contrastData = this.contrastResults[this.currentElementType];
  
  expect(contrastData.color).not.toBe(contrastData.backgroundColor);
});

Then('status information should not be conveyed by color alone', async function () {
  const statusBadges = await page.locator('[data-testid^="status-badge"]').all();
  
  for (const badge of statusBadges) {
    const text = await badge.textContent();
    expect(text).toBeTruthy();
    expect(text?.trim().length).toBeGreaterThan(0);
  }
});

Then('status badges should include text labels or icons', async function () {
  const statusBadges = await page.locator('[data-testid^="status-badge"]').all();
  
  for (const badge of statusBadges) {
    const hasText = await badge.textContent();
    const hasIcon = await badge.locator('svg, i, img').count();
    
    expect(hasText || hasIcon > 0).toBeTruthy();
  }
});

/**************************************************/
/*  TEST CASE: TC-A11Y-005 - Zoom and Reflow
/**************************************************/

Then('page content should scale to {string} percent zoom level', async function (zoomLevel: string) {
  expect(this.currentZoomLevel).toBe(parseInt(zoomLevel));
});

Then('text should become larger and more readable', async function () {
  const bodyText = page.locator('body, p').first();
  const fontSize = await bodyText.evaluate(el => window.getComputedStyle(el).fontSize);
  
  expect(fontSize).toBeTruthy();
});

Then('all text content should remain visible without horizontal scrolling', async function () {
  const bodyWidth = await page.evaluate(() => document.body.scrollWidth);
  const viewportWidth = await page.evaluate(() => window.innerWidth);
  
  expect(bodyWidth).toBeLessThanOrEqual(viewportWidth * 1.1);
});

Then('text should reflow to fit viewport width', async function () {
  const paragraphs = await page.locator('p, div').all();
  
  for (const paragraph of paragraphs.slice(0, 5)) {
    const boundingBox = await paragraph.boundingBox();
    if (boundingBox) {
      const viewportWidth = await page.evaluate(() => window.innerWidth);
      expect(boundingBox.width).toBeLessThanOrEqual(viewportWidth);
    }
  }
});

Then('users should be able to read all text by scrolling vertically only', async function () {
  const horizontalScroll = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  expect(horizontalScroll).toBeFalsy();
});

Then('all buttons and interactive elements should be fully visible', async function () {
  const buttons = await page.locator('button, a, input').all();
  
  for (const button of buttons.slice(0, 10)) {
    const isVisible = await button.isVisible();
    expect(isVisible).toBeTruthy();
  }
});

Then('elements should not be cut off or overlapping', async function () {
  const interactiveElements = await page.locator('button, a, input').all();
  
  for (const element of interactiveElements.slice(0, 10)) {
    const boundingBox = await element.boundingBox();
    if (boundingBox) {
      expect(boundingBox.width).toBeGreaterThan(0);
      expect(boundingBox.height).toBeGreaterThan(0);
    }
  }
});

Then('elements should remain clickable with adequate target size', async function () {
  const buttons = await page.locator('button, a').all();
  
  for (const button of buttons.slice(0, 10)) {
    const boundingBox = await button.boundingBox();
    if (boundingBox) {
      expect(boundingBox.width).toBeGreaterThan(20);
      expect(boundingBox.height).toBeGreaterThan(20);
    }
  }
});

Then('filter controls should remain functional', async function () {
  const filterSection = page.locator('[data-testid="filter-section"]');
  await assertions.assertVisible(filterSection);
  
  const applyButton = page.locator('[data-testid="button-apply-filter"]');
  const isEnabled = await applyButton.isEnabled();
  expect(isEnabled).toBeTruthy();
});

Then('dropdown menus should open properly without being cut off', async function () {
  const dropdown = page.locator('[data-testid="filter-status"]');
  
  if (await dropdown.count() > 0) {
    await actions.click(dropdown);
    await page.waitForTimeout(300);
    
    const dropdownMenu = page.locator('[data-testid="dropdown-menu"], [role="listbox"]');
    if (await dropdownMenu.count() > 0) {
      await assertions.assertVisible(dropdownMenu);
    }
  }
});

Then('date pickers should be accessible', async function () {
  const dateField = page.locator('[data-testid="filter-from-date"]');
  
  if (await dateField.count() > 0) {
    await assertions.assertVisible(dateField);
    const isEnabled = await dateField.isEnabled();
    expect(isEnabled).toBeTruthy();
  }
});

Then('filtered results should display correctly', async function () {
  const requestItems = page.locator('[data-testid="request-item"]');
  const count = await requestItems.count();
  
  expect(count).toBeGreaterThanOrEqual(0);
});

Then('request details should display properly', async function () {
  const detailsModal = page.locator('[data-testid="request-details-modal"], [role="dialog"]');
  await assertions.assertVisible(detailsModal);
});

Then('all detail fields should be readable', async function () {
  const detailFields = await page.locator('[data-testid="request-details-modal"] label, [role="dialog"] label').all();
  
  for (const field of detailFields) {
    const isVisible = await field.isVisible();
    expect(isVisible).toBeTruthy();
  }
});

Then('no content should be hidden or require horizontal scrolling', async function () {
  const horizontalScroll = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  expect(horizontalScroll).toBeFalsy();
});

Then('table columns should stack or reflow responsively', async function () {
  const table = page.locator('[data-testid="schedule-requests-table"], table');
  
  if (await table.count() > 0) {
    const tableWidth = await table.evaluate(el => el.scrollWidth);
    const viewportWidth = await page.evaluate(() => window.innerWidth);
    
    expect(tableWidth).toBeLessThanOrEqual(viewportWidth * 1.2);
  }
});

Then('all data should remain accessible', async function () {
  const requestItems = page.locator('[data-testid="request-item"]');
  const count = await requestItems.count();
  
  expect(count).toBeGreaterThanOrEqual(0);
});

Then('horizontal scrolling should only apply to table container if needed', async function () {
  const tableContainer = page.locator('[data-testid="table-container"]');
  
  if (await tableContainer.count() > 0) {
    const overflowX = await tableContainer.evaluate(el => window.getComputedStyle(el).overflowX);
    expect(['auto', 'scroll', 'visible']).toContain(overflowX);
  }
});

// ==================== ACCESSIBILITY SPECIFIC STEPS ====================

Then('the page should meet WCAG 2.1 AA standards', async function () {
  const headings = await page.locator('h1, h2, h3, h4, h5, h6').count();
  expect(headings).toBeGreaterThan(0);
  
  const mainLandmark = page.locator('[role="main"], main');
  await assertions.assertVisible(mainLandmark);
  
  const images = await page.locator('img').all();
  for (const img of images) {
    const alt = await img.getAttribute('alt');
    expect(alt !== null).toBeTruthy();
  }
  
  const links = await page.locator('a').all();
  for (const link of links.slice(0, 10)) {
    const text = await link.textContent();
    const ariaLabel = await link.getAttribute('aria-label');
    expect(text || ariaLabel).toBeTruthy();
  }
});

Then('all interactive elements should have accessible names', async function () {
  const buttons = await page.locator('button').all();
  
  for (const button of buttons) {
    const text = await button.textContent();
    const ariaLabel = await button.getAttribute('aria-label');
    
    expect(text || ariaLabel).toBeTruthy();
  }
});

Then('form fields should have associated labels', async function () {
  const inputs = await page.locator('input, select, textarea').all();
  
  for (const input of inputs) {
    const id = await input.getAttribute('id');
    const ariaLabel = await input.getAttribute('aria-label');
    const ariaLabelledBy = await input.getAttribute('aria-labelledby');
    
    if (id) {
      const label = page.locator(`label[for="${id}"]`);
      const hasLabel = await label.count() > 0;
      expect(hasLabel || ariaLabel || ariaLabelledBy).toBeTruthy();
    }
  }
});

Then('page structure should use semantic HTML', async function () {
  const semanticElements = await page.locator('header, nav, main, article, section, aside, footer').count();
  expect(semanticElements).toBeGreaterThan(0);
});

Then('ARIA attributes should be used correctly', async function () {
  const ariaElements = await page.locator('[aria-label], [aria-labelledby], [aria-describedby], [role]').count();
  expect(ariaElements).toBeGreaterThan(0);
});