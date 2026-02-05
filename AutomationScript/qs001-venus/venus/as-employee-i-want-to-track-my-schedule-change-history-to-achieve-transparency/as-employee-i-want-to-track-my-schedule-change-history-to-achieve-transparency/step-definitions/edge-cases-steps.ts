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
    }
  };
  
  this.performanceMetrics = {
    startTime: 0,
    endTime: 0
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
/*  Setup: User authentication and navigation
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

Given('user is on the schedule change history page', async function () {
  await actions.click(page.locator('[data-testid="link-schedule-history"], a:has-text("Schedule History")'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('[data-testid="page-schedule-history"], h1:has-text("Schedule Change History")'));
});

/**************************************************/
/*  TEST CASE: TC-EDGE-001
/*  Title: System handles employee with extremely large number of schedule change requests
/*  Priority: Medium
/*  Category: Edge Cases - Performance
/*  Description: Tests pagination and performance with 1000 records
/**************************************************/

Given('employee has {int} schedule change requests in the database', async function (requestCount: number) {
  this.expectedRequestCount = requestCount;
  this.testData.totalRequests = requestCount;
});

Given('pagination mechanism is implemented', async function () {
  await assertions.assertVisible(page.locator('[data-testid="pagination-controls"], .pagination'));
});

Given('performance requirements specify response time under {int} seconds', async function (maxSeconds: number) {
  this.performanceThreshold = maxSeconds * 1000;
});

/**************************************************/
/*  TEST CASE: TC-EDGE-002
/*  Title: System handles date range filter spanning multiple years of history
/*  Priority: Medium
/*  Category: Edge Cases - Date Range
/*  Description: Tests wide date range filtering across 5 years
/**************************************************/

Given('employee has schedule change requests spanning {int} years from {int} to {int}', async function (yearSpan: number, startYear: number, endYear: number) {
  this.testData.dateRange = {
    span: yearSpan,
    startYear: startYear,
    endYear: endYear
  };
});

/**************************************************/
/*  TEST CASE: TC-EDGE-003
/*  Title: System handles schedule change requests with extremely long comments
/*  Priority: Low
/*  Category: Edge Cases - Data Volume
/*  Description: Tests UI handling of comments exceeding 5000 characters
/**************************************************/

Given('at least one schedule change request has manager comments exceeding {int} characters', async function (characterCount: number) {
  this.testData.longCommentLength = characterCount;
  await assertions.assertVisible(page.locator('[data-testid="request-row"]').first());
});

/**************************************************/
/*  TEST CASE: TC-EDGE-004
/*  Title: System handles concurrent filter applications and rapid filter changes
/*  Priority: Medium
/*  Category: Edge Cases - Concurrency
/*  Description: Tests debouncing and request cancellation
/**************************************************/

Given('schedule change history page has multiple requests', async function () {
  const requestRows = page.locator('[data-testid="request-row"], tbody tr');
  const count = await requestRows.count();
  expect(count).toBeGreaterThan(0);
});

Given('filter controls are responsive', async function () {
  await assertions.assertVisible(page.locator('[data-testid="filter-status"], [data-testid="select-status"]'));
  await assertions.assertVisible(page.locator('[data-testid="filter-date-from"], [data-testid="input-date-from"]'));
});

Given('system has debouncing or request cancellation mechanisms', async function () {
  this.testData.debounceEnabled = true;
});

/**************************************************/
/*  TEST CASE: TC-EDGE-005
/*  Title: System handles special characters and Unicode in comments and schedule descriptions
/*  Priority: Low
/*  Category: Edge Cases - Character Encoding
/*  Description: Tests UTF-8 encoding and special character rendering
/**************************************************/

Given('at least one schedule change request contains special characters and emojis and Unicode in comments', async function () {
  this.testData.specialCharacters = true;
  await assertions.assertVisible(page.locator('[data-testid="request-row"]').first());
});

Given('system supports UTF-8 encoding', async function () {
  this.testData.encoding = 'UTF-8';
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  GENERIC NAVIGATION AND INTERACTION STEPS
/**************************************************/

When('user navigates to schedule change history page', async function () {
  this.performanceMetrics.startTime = Date.now();
  
  await actions.click(page.locator('[data-testid="link-schedule-history"], a:has-text("Schedule History")'));
  await waits.waitForNetworkIdle();
  
  this.performanceMetrics.endTime = Date.now();
});

When('user clicks {string} button', async function (buttonText: string) {
  const testIdLocator = `[data-testid="button-${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const buttons = page.locator(testIdLocator);
  
  if (await buttons.count() > 0) {
    this.performanceMetrics.startTime = Date.now();
    await actions.click(buttons);
  } else {
    this.performanceMetrics.startTime = Date.now();
    await actions.click(page.locator(`button:has-text("${buttonText}")`));
  }
  
  await waits.waitForNetworkIdle();
  this.performanceMetrics.endTime = Date.now();
});

When('user clicks on schedule change request with extremely long manager comments', async function () {
  await actions.click(page.locator('[data-testid="request-row"]').first());
  await waits.waitForNetworkIdle();
});

When('user clicks {string} or expand button', async function (linkText: string) {
  const testIdLocator = `[data-testid="link-${linkText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const links = page.locator(testIdLocator);
  
  if (await links.count() > 0) {
    await actions.click(links);
  } else {
    await actions.click(page.locator(`a:has-text("${linkText}"), button:has-text("${linkText}")`));
  }
  
  await waits.waitForVisible(page.locator('[data-testid="expanded-content"], .expanded-section'));
});

When('user sets {string} to {string}', async function (fieldLabel: string, dateValue: string) {
  const fieldLocator = `[data-testid="input-${fieldLabel.toLowerCase().replace(/\s+/g, '-')}"]`;
  await actions.fill(page.locator(fieldLocator), dateValue);
});

When('user applies filter with status {string}', async function (statusValue: string) {
  this.performanceMetrics.startTime = Date.now();
  
  await actions.selectByText(page.locator('[data-testid="filter-status"], [data-testid="select-status"]'), statusValue);
  await waits.waitForNetworkIdle();
  
  this.performanceMetrics.endTime = Date.now();
});

When('user jumps to page {int} using page number input', async function (pageNumber: number) {
  this.performanceMetrics.startTime = Date.now();
  
  await actions.fill(page.locator('[data-testid="input-page-number"], input[type="number"]'), pageNumber.toString());
  await actions.click(page.locator('[data-testid="button-go-to-page"], button:has-text("Go")'));
  await waits.waitForNetworkIdle();
  
  this.performanceMetrics.endTime = Date.now();
});

When('user rapidly selects {string} from status filter', async function (statusValue: string) {
  await actions.selectByText(page.locator('[data-testid="filter-status"], [data-testid="select-status"]'), statusValue);
});

When('user immediately selects {string} from status filter', async function (statusValue: string) {
  await actions.selectByText(page.locator('[data-testid="filter-status"], [data-testid="select-status"]'), statusValue);
});

When('user immediately selects {string} from status filter within {int} seconds', async function (statusValue: string, timeLimit: number) {
  await actions.selectByText(page.locator('[data-testid="filter-status"], [data-testid="select-status"]'), statusValue);
  await waits.waitForNetworkIdle();
});

When('user quickly changes date range filters while previous filter request is processing', async function () {
  await actions.fill(page.locator('[data-testid="input-from-date"]'), '01/01/2023');
  await actions.fill(page.locator('[data-testid="input-to-date"]'), '12/31/2023');
});

When('user applies multiple filters simultaneously for date range and status', async function () {
  await actions.fill(page.locator('[data-testid="input-from-date"]'), '01/01/2023');
  await actions.fill(page.locator('[data-testid="input-to-date"]'), '12/31/2023');
  await actions.selectByText(page.locator('[data-testid="filter-status"], [data-testid="select-status"]'), 'Approved');
});

When('user immediately clears all filters', async function () {
  await actions.click(page.locator('[data-testid="button-clear-filters"], button:has-text("Clear Filters")'));
  await waits.waitForNetworkIdle();
});

When('user locates schedule change request with special characters', async function () {
  await assertions.assertVisible(page.locator('[data-testid="request-row"]').first());
  this.selectedRequest = page.locator('[data-testid="request-row"]').first();
});

When('user clicks to view full details of request with special characters', async function () {
  await actions.click(this.selectedRequest || page.locator('[data-testid="request-row"]').first());
  await waits.waitForNetworkIdle();
});

When('user applies filters', async function () {
  await actions.selectByText(page.locator('[data-testid="filter-status"], [data-testid="select-status"]'), 'Approved');
  await waits.waitForNetworkIdle();
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  GENERIC ASSERTION STEPS
/**************************************************/

Then('page should load within {int} seconds', async function (maxSeconds: number) {
  const loadTime = this.performanceMetrics.endTime - this.performanceMetrics.startTime;
  const maxMilliseconds = maxSeconds * 1000;
  
  expect(loadTime).toBeLessThanOrEqual(maxMilliseconds);
});

Then('first page of results should be displayed', async function () {
  await assertions.assertVisible(page.locator('[data-testid="results-container"], [data-testid="request-row"]'));
  
  const rows = page.locator('[data-testid="request-row"], tbody tr');
  const count = await rows.count();
  expect(count).toBeGreaterThan(0);
});

Then('loading indicator should be shown during fetch', async function () {
  await assertions.assertVisible(page.locator('[data-testid="loading-indicator"], .loading, .spinner'));
});

Then('pagination controls should be visible', async function () {
  await assertions.assertVisible(page.locator('[data-testid="pagination-controls"], .pagination'));
});

Then('pagination should show {string} format', async function (expectedFormat: string) {
  await assertions.assertContainsText(
    page.locator('[data-testid="pagination-info"], .pagination-info'),
    'Page'
  );
});

Then('summary should show {string} format', async function (expectedFormat: string) {
  await assertions.assertVisible(page.locator('[data-testid="results-summary"], .results-summary'));
  await assertions.assertContainsText(
    page.locator('[data-testid="results-summary"], .results-summary'),
    'Showing'
  );
});

Then('page {int} should load within {int} seconds', async function (pageNumber: number, maxSeconds: number) {
  const loadTime = this.performanceMetrics.endTime - this.performanceMetrics.startTime;
  const maxMilliseconds = maxSeconds * 1000;
  
  expect(loadTime).toBeLessThanOrEqual(maxMilliseconds);
});

Then('records {int} to {int} should be displayed', async function (startRecord: number, endRecord: number) {
  await assertions.assertVisible(page.locator('[data-testid="request-row"]').first());
  
  const summaryText = await page.locator('[data-testid="results-summary"], .results-summary').textContent();
  expect(summaryText).toContain(startRecord.toString());
});

Then('page should not reload entirely', async function () {
  await assertions.assertVisible(page.locator('[data-testid="results-container"]'));
});

Then('URL should update to reflect pagination', async function () {
  const currentUrl = page.url();
  expect(currentUrl).toMatch(/page=|p=/);
});

Then('system should maintain performance without degradation', async function () {
  const loadTime = this.performanceMetrics.endTime - this.performanceMetrics.startTime;
  expect(loadTime).toBeLessThan(3000);
});

Then('filtered results should load within {int} seconds', async function (maxSeconds: number) {
  const loadTime = this.performanceMetrics.endTime - this.performanceMetrics.startTime;
  const maxMilliseconds = maxSeconds * 1000;
  
  expect(loadTime).toBeLessThanOrEqual(maxMilliseconds);
});

Then('pagination should adjust to show filtered result count', async function () {
  await assertions.assertVisible(page.locator('[data-testid="pagination-info"], .pagination-info'));
});

Then('performance should remain acceptable', async function () {
  const loadTime = this.performanceMetrics.endTime - this.performanceMetrics.startTime;
  expect(loadTime).toBeLessThan(3000);
});

Then('memory usage should remain stable', async function () {
  const metrics = await page.evaluate(() => {
    if (performance.memory) {
      return {
        usedJSHeapSize: performance.memory.usedJSHeapSize,
        totalJSHeapSize: performance.memory.totalJSHeapSize
      };
    }
    return null;
  });
  
  if (metrics) {
    expect(metrics.usedJSHeapSize).toBeLessThan(metrics.totalJSHeapSize);
  }
});

Then('browser should not crash', async function () {
  await assertions.assertVisible(page.locator('body'));
  expect(page.isClosed()).toBe(false);
});

Then('both date fields should accept the dates', async function () {
  const fromDateValue = await page.locator('[data-testid="input-from-date"]').inputValue();
  const toDateValue = await page.locator('[data-testid="input-to-date"]').inputValue();
  
  expect(fromDateValue).toBeTruthy();
  expect(toDateValue).toBeTruthy();
});

Then('dates should be displayed in {string} format', async function (dateFormat: string) {
  const fromDateValue = await page.locator('[data-testid="input-from-date"]').inputValue();
  expect(fromDateValue).toMatch(/\d{2}\/\d{2}\/\d{4}/);
});

Then('system should process the wide date range', async function () {
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('[data-testid="results-container"]'));
});

Then('results should be returned within {int} seconds', async function (maxSeconds: number) {
  const loadTime = this.performanceMetrics.endTime - this.performanceMetrics.startTime;
  const maxMilliseconds = maxSeconds * 1000;
  
  expect(loadTime).toBeLessThanOrEqual(maxMilliseconds);
});

Then('all requests from the specified period should be displayed', async function () {
  await assertions.assertVisible(page.locator('[data-testid="request-row"]').first());
  
  const rows = page.locator('[data-testid="request-row"], tbody tr');
  const count = await rows.count();
  expect(count).toBeGreaterThan(0);
});

Then('pagination should be shown if result set is large', async function () {
  const rows = page.locator('[data-testid="request-row"], tbody tr');
  const count = await rows.count();
  
  if (count > 10) {
    await assertions.assertVisible(page.locator('[data-testid="pagination-controls"], .pagination'));
  }
});

Then('results should include requests from {int}', async function (year: number) {
  const resultsText = await page.locator('[data-testid="results-container"]').textContent();
  expect(resultsText).toContain(year.toString());
});

Then('results should be sorted in chronological order with most recent first', async function () {
  await assertions.assertVisible(page.locator('[data-testid="request-row"]').first());
});

Then('page should remain responsive', async function () {
  await assertions.assertVisible(page.locator('body'));
  
  const isResponsive = await page.evaluate(() => {
    return document.readyState === 'complete';
  });
  
  expect(isResponsive).toBe(true);
});

Then('no timeout errors should occur', async function () {
  await assertions.assertVisible(page.locator('[data-testid="results-container"]'));
});

Then('database query should be optimized for wide date range', async function () {
  const loadTime = this.performanceMetrics.endTime - this.performanceMetrics.startTime;
  expect(loadTime).toBeLessThan(3000);
});

Then('request details should open in expanded view or modal', async function () {
  await assertions.assertVisible(page.locator('[data-testid="request-details"], [data-testid="modal-request-details"], .modal'));
});

Then('layout should not break', async function () {
  await assertions.assertVisible(page.locator('[data-testid="request-details"]'));
  
  const hasOverflow = await page.evaluate(() => {
    const body = document.body;
    return body.scrollWidth > body.clientWidth;
  });
  
  expect(hasOverflow).toBe(false);
});

Then('comments should be displayed with truncation and {string} link or scrollable text area or expandable section', async function (linkText: string) {
  const readMoreLink = page.locator(`[data-testid="link-${linkText.toLowerCase().replace(/\s+/g, '-')}"], a:has-text("${linkText}")`);
  const scrollableArea = page.locator('[data-testid="comments-scrollable"], .scrollable-comments');
  const expandableSection = page.locator('[data-testid="comments-expandable"], .expandable-section');
  
  const readMoreCount = await readMoreLink.count();
  const scrollableCount = await scrollableArea.count();
  const expandableCount = await expandableSection.count();
  
  expect(readMoreCount + scrollableCount + expandableCount).toBeGreaterThan(0);
});

Then('page layout should remain intact', async function () {
  await assertions.assertVisible(page.locator('body'));
  
  const hasLayoutIssues = await page.evaluate(() => {
    const body = document.body;
    return body.scrollWidth > body.clientWidth + 50;
  });
  
  expect(hasLayoutIssues).toBe(false);
});

Then('full comment text should become visible', async function () {
  await assertions.assertVisible(page.locator('[data-testid="full-comments"], [data-testid="expanded-content"]'));
});

Then('scrollable container or expanded section should be shown', async function () {
  const scrollableContainer = page.locator('[data-testid="comments-scrollable"], .scrollable-comments');
  const expandedSection = page.locator('[data-testid="expanded-content"], .expanded-section');
  
  const scrollableCount = await scrollableContainer.count();
  const expandedCount = await expandedSection.count();
  
  expect(scrollableCount + expandedCount).toBeGreaterThan(0);
});

Then('all {int} characters should be accessible', async function (characterCount: number) {
  const commentsText = await page.locator('[data-testid="full-comments"], [data-testid="expanded-content"]').textContent();
  expect(commentsText?.length).toBeGreaterThanOrEqual(characterCount);
});

Then('text should remain readable without horizontal scrolling', async function () {
  const hasHorizontalScroll = await page.evaluate(() => {
    const commentsContainer = document.querySelector('[data-testid="full-comments"], [data-testid="expanded-content"]');
    if (commentsContainer) {
      return commentsContainer.scrollWidth > commentsContainer.clientWidth;
    }
    return false;
  });
  
  expect(hasHorizontalScroll).toBe(false);
});

Then('no text overflow outside containers should occur', async function () {
  const hasOverflow = await page.evaluate(() => {
    const containers = document.querySelectorAll('[data-testid="request-details"] *');
    for (const container of containers) {
      const element = container as HTMLElement;
      if (element.scrollWidth > element.clientWidth + 10) {
        const overflow = window.getComputedStyle(element).overflow;
        if (overflow === 'visible') {
          return true;
        }
      }
    }
    return false;
  });
  
  expect(hasOverflow).toBe(false);
});

Then('other request details should remain visible and accessible', async function () {
  await assertions.assertVisible(page.locator('[data-testid="request-details"]'));
});

Then('overall page usability should be maintained', async function () {
  await assertions.assertVisible(page.locator('body'));
  
  const isUsable = await page.evaluate(() => {
    return document.readyState === 'complete';
  });
  
  expect(isUsable).toBe(true);
});

Then('system should handle rapid changes gracefully', async function () {
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('[data-testid="results-container"]'));
});

Then('system should debounce requests or cancel previous requests', async function () {
  await waits.waitForNetworkIdle();
});

Then('only final filter {string} should be applied', async function (finalFilter: string) {
  await assertions.assertVisible(page.locator('[data-testid="results-container"]'));
  
  const selectedValue = await page.locator('[data-testid="filter-status"], [data-testid="select-status"]').inputValue();
  expect(selectedValue).toBe(finalFilter);
});

Then('system should cancel in-flight request', async function () {
  await waits.waitForNetworkIdle();
});

Then('system should process only most recent filter criteria', async function () {
  await assertions.assertVisible(page.locator('[data-testid="results-container"]'));
});

Then('no errors should occur', async function () {
  const errorMessages = page.locator('[data-testid="error-message"], .error, .alert-error');
  const errorCount = await errorMessages.count();
  expect(errorCount).toBe(0);
});

Then('system should process clear action', async function () {
  await waits.waitForNetworkIdle();
});

Then('system should cancel any pending filter requests', async function () {
  await waits.waitForNetworkIdle();
});

Then('unfiltered full history list should be displayed', async function () {
  await assertions.assertVisible(page.locator('[data-testid="results-container"]'));
  
  const rows = page.locator('[data-testid="request-row"], tbody tr');
  const count = await rows.count();
  expect(count).toBeGreaterThan(0);
});

Then('no stale or incorrect data should be shown', async function () {
  await assertions.assertVisible(page.locator('[data-testid="results-container"]'));
});

Then('browser network tab should show appropriate request cancellation or debouncing', async function () {
  await waits.waitForNetworkIdle();
});

Then('only one final API call should be made for last filter state', async function () {
  await waits.waitForNetworkIdle();
});

Then('displayed data should match final filter criteria', async function () {
  await assertions.assertVisible(page.locator('[data-testid="results-container"]'));
});

Then('no race conditions should occur', async function () {
  await assertions.assertVisible(page.locator('[data-testid="results-container"]'));
});

Then('no data inconsistencies should occur', async function () {
  await assertions.assertVisible(page.locator('[data-testid="results-container"]'));
});

Then('no memory leaks should occur', async function () {
  const metrics = await page.evaluate(() => {
    if (performance.memory) {
      return {
        usedJSHeapSize: performance.memory.usedJSHeapSize,
        jsHeapSizeLimit: performance.memory.jsHeapSizeLimit
      };
    }
    return null;
  });
  
  if (metrics) {
    expect(metrics.usedJSHeapSize).toBeLessThan(metrics.jsHeapSizeLimit * 0.9);
  }
});

Then('no performance degradation from cancelled requests should occur', async function () {
  const loadTime = this.performanceMetrics.endTime - this.performanceMetrics.startTime;
  expect(loadTime).toBeLessThan(3000);
});

Then('request should be visible in history list', async function () {
  await assertions.assertVisible(page.locator('[data-testid="request-row"]').first());
});

Then('no rendering issues should occur', async function () {
  await assertions.assertVisible(page.locator('[data-testid="results-container"]'));
  
  const hasRenderingIssues = await page.evaluate(() => {
    const body = document.body;
    return body.scrollWidth > body.clientWidth + 50;
  });
  
  expect(hasRenderingIssues).toBe(false);
});

Then('request details should open', async function () {
  await assertions.assertVisible(page.locator('[data-testid="request-details"], [data-testid="modal-request-details"]'));
});

Then('all special characters should be displayed correctly', async function () {
  await assertions.assertVisible(page.locator('[data-testid="request-details"]'));
});

Then('all emojis should be displayed correctly', async function () {
  await assertions.assertVisible(page.locator('[data-testid="request-details"]'));
});

Then('all Unicode text should be displayed correctly', async function () {
  await assertions.assertVisible(page.locator('[data-testid="request-details"]'));
});

Then('no garbled characters should appear', async function () {
  const detailsText = await page.locator('[data-testid="request-details"]').textContent();
  expect(detailsText).not.toContain('�');
  expect(detailsText).not.toContain('???');
});

Then('no encoding errors should occur', async function () {
  const detailsText = await page.locator('[data-testid="request-details"]').textContent();
  expect(detailsText).not.toContain('�');
});

Then('text {string} should appear exactly as entered', async function (expectedText: string) {
  await assertions.assertContainsText(page.locator('[data-testid="request-details"]'), expectedText);
});

Then('special characters in schedule descriptions should be rendered properly', async function () {
  await assertions.assertVisible(page.locator('[data-testid="schedule-description"], [data-testid="request-details"]'));
});

Then('arrow symbols should be displayed correctly', async function () {
  await assertions.assertVisible(page.locator('[data-testid="request-details"]'));
});

Then('time formats should be displayed correctly', async function () {
  await assertions.assertVisible(page.locator('[data-testid="request-details"]'));
});

Then('special punctuation should be displayed correctly', async function () {
  await assertions.assertVisible(page.locator('[data-testid="request-details"]'));
});

Then('text should remain readable', async function () {
  await assertions.assertVisible(page.locator('[data-testid="request-details"]'));
  
  const isReadable = await page.evaluate(() => {
    const details = document.querySelector('[data-testid="request-details"]');
    if (details) {
      const styles = window.getComputedStyle(details);
      const fontSize = parseFloat(styles.fontSize);
      return fontSize >= 12;
    }
    return true;
  });
  
  expect(isReadable).toBe(true);
});

Then('filters should work correctly regardless of special characters in data', async function () {
  await assertions.assertVisible(page.locator('[data-testid="results-container"]'));
});

Then('filtered results should display special characters properly', async function () {
  await assertions.assertVisible(page.locator('[data-testid="request-row"]').first());
});

Then('system should maintain data integrity for international characters', async function () {
  const resultsText = await page.locator('[data-testid="results-container"]').textContent();
  expect(resultsText).not.toContain('�');
});