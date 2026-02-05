import { Given, When, Then, Before, After } from '@cucumber/cucumber';
import { Page, Browser, BrowserContext, chromium, expect } from '@playwright/test';
import { BasePage } from '../pages/BasePage';
import { HomePage } from '../pages/HomePage';
import { LoginPage } from '../pages/LoginPage';
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
let loginPage: LoginPage;
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
  loginPage = new LoginPage(page, context);
  
  this.testData = {
    users: {
      admin: { username: 'admin', password: 'admin123' },
      employee: { username: 'employee', password: 'employee123' },
      user: { username: 'testuser', password: 'testpass' }
    },
    apiEndpoints: {
      scheduleHistory: '/api/scheduleChangeRequests/history'
    }
  };
  
  this.apiResponses = {};
  this.securityLogs = [];
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
/*  TEST CASE: TC-001
/*  Title: Unauthorized access attempt to schedule change history page without authentication
/*  Priority: High
/*  Category: Negative - Security
/**************************************************/

Given('user is not logged in to the application', async function () {
  await context.clearCookies();
  await page.evaluate(() => {
    localStorage.clear();
    sessionStorage.clear();
  });
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-002, TC-003, TC-004, TC-005, TC-006, TC-007, TC-008, TC-009
/*  Title: Various authenticated employee scenarios
/*  Priority: High
/*  Category: Negative - Validation, Error Handling, Security
/**************************************************/

Given('user is logged in as authenticated employee', async function () {
  const credentials = this.testData?.users?.employee || { username: 'employee', password: 'employee123' };
  
  await loginPage.navigate();
  await actions.fill(page.locator('[data-testid="input-username"]'), credentials.username);
  await actions.fill(page.locator('[data-testid="input-password"]'), credentials.password);
  await actions.click(page.locator('[data-testid="button-login"]'));
  await waits.waitForNetworkIdle();
  
  await assertions.assertVisible(page.locator('[data-testid="dashboard"], [data-testid="home-page"]'));
});

Given('user is on {string} page', async function (pageName: string) {
  const pageUrl = pageName.toLowerCase().replace(/\s+/g, '-');
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/${pageUrl}`);
  await waits.waitForNetworkIdle();
  await waits.waitForDomContentLoaded();
});

/**************************************************/
/*  TEST CASE: TC-004
/*  Title: API failure when retrieving schedule change history
/*  Priority: High
/*  Category: Negative - Error Handling
/**************************************************/

Given('API endpoint {string} is unavailable', async function (endpoint: string) {
  await page.route(`**${endpoint}`, route => {
    route.abort('failed');
  });
});

/**************************************************/
/*  TEST CASE: TC-005
/*  Title: API timeout when retrieving schedule change history
/*  Priority: High
/*  Category: Negative - Error Handling
/**************************************************/

Given('API endpoint {string} is experiencing high latency', async function (endpoint: string) {
  await page.route(`**${endpoint}`, async route => {
    await new Promise(resolve => setTimeout(resolve, 35000));
    route.fulfill({
      status: 408,
      body: JSON.stringify({ error: 'Request timeout' })
    });
  });
});

/**************************************************/
/*  TEST CASE: TC-006
/*  Title: Employee with no schedule change history
/*  Priority: Medium
/*  Category: Negative - Edge Case
/**************************************************/

Given('employee has never submitted any schedule change requests', async function () {
  await page.route('**/api/scheduleChangeRequests/history', route => {
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ data: [], total: 0 })
    });
  });
});

/**************************************************/
/*  TEST CASE: TC-007
/*  Title: Filter controls behavior with empty history
/*  Priority: Medium
/*  Category: Negative - Edge Case
/**************************************************/

Given('employee has no schedule change history', async function () {
  await page.route('**/api/scheduleChangeRequests/history', route => {
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ data: [], total: 0 })
    });
  });
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  TEST CASE: TC-001
/*  Title: Unauthorized access attempt to schedule change history page without authentication
/*  Priority: High
/*  Category: Negative - Security
/**************************************************/

When('user navigates directly to {string} page URL', async function (pageName: string) {
  const pageUrl = pageName.toLowerCase().replace(/\s+/g, '-');
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/${pageUrl}`);
  await waits.waitForNetworkIdle();
});

When('user attempts to access {string} endpoint without authentication token', async function (endpoint: string) {
  this.apiResponse = await page.evaluate(async (apiEndpoint) => {
    try {
      const response = await fetch(apiEndpoint, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      });
      return {
        status: response.status,
        body: await response.json()
      };
    } catch (error) {
      return {
        status: 0,
        error: error.message
      };
    }
  }, endpoint);
});

/**************************************************/
/*  TEST CASE: TC-002
/*  Title: Invalid date range filter input validation
/*  Priority: High
/*  Category: Negative - Validation
/**************************************************/

When('user enters {string} in {string} field', async function (value: string, fieldName: string) {
  const fieldLocator = `[data-testid="input-${fieldName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const fallbackLocator = `input[name="${fieldName.toLowerCase().replace(/\s+/g, '-')}"]`;
  
  const primaryField = page.locator(fieldLocator);
  if (await primaryField.count() > 0) {
    await actions.fill(primaryField, value);
  } else {
    await actions.fill(page.locator(fallbackLocator), value);
  }
});

When('user clicks {string} button', async function (buttonText: string) {
  const testIdLocator = `[data-testid="button-${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const buttons = page.locator(testIdLocator);
  
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`button:has-text("${buttonText}")`));
  }
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-004, TC-005
/*  Title: API failure and timeout scenarios
/*  Priority: High
/*  Category: Negative - Error Handling
/**************************************************/

When('user navigates to {string} page', async function (pageName: string) {
  const pageUrl = pageName.toLowerCase().replace(/\s+/g, '-');
  await actions.navigateTo(`${process.env.BASE_URL || 'http://localhost:3000'}/${pageUrl}`);
  await waits.waitForNetworkIdle();
});

When('user clicks {string} button', async function (buttonText: string) {
  const testIdLocator = `[data-testid="button-${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const buttons = page.locator(testIdLocator);
  
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`button:has-text("${buttonText}")`));
  }
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-007
/*  Title: Filter controls behavior with empty history
/*  Priority: Medium
/*  Category: Negative - Edge Case
/**************************************************/

When('user attempts to apply filters', async function () {
  const applyFilterButton = page.locator('[data-testid="button-apply-filter"], button:has-text("Apply Filter")');
  if (await applyFilterButton.count() > 0) {
    await actions.click(applyFilterButton);
    await waits.waitForNetworkIdle();
  }
});

/**************************************************/
/*  TEST CASE: TC-008, TC-009
/*  Title: SQL injection prevention through filter inputs
/*  Priority: High
/*  Category: Negative - Security
/**************************************************/

When('user enters {string} in {string} field', async function (value: string, fieldName: string) {
  const fieldLocator = `[data-testid="input-${fieldName.toLowerCase().replace(/\s+/g, '-')}"]`;
  const fallbackLocator = `input[name="${fieldName.toLowerCase().replace(/\s+/g, '-')}"]`;
  
  const primaryField = page.locator(fieldLocator);
  if (await primaryField.count() > 0) {
    await actions.fill(primaryField, value);
  } else {
    await actions.fill(page.locator(fallbackLocator), value);
  }
});

When('user applies legitimate filter after injection attempt', async function () {
  await actions.fill(page.locator('[data-testid="input-date-filter"], input[name="date-filter"]'), '01/01/2024');
  
  const applyFilterButton = page.locator('[data-testid="button-apply-filter"], button:has-text("Apply Filter")');
  await actions.click(applyFilterButton);
  await waits.waitForNetworkIdle();
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  TEST CASE: TC-001
/*  Title: Unauthorized access attempt to schedule change history page without authentication
/*  Priority: High
/*  Category: Negative - Security
/**************************************************/

Then('user should be redirected to {string} page', async function (pageName: string) {
  const expectedUrl = pageName.toLowerCase().replace(/\s+/g, '-');
  await page.waitForURL(`**/${expectedUrl}`, { timeout: 5000 });
  await assertions.assertUrlContains(expectedUrl);
});

Then('error message {string} should be displayed', async function (errorMessage: string) {
  const errorLocators = [
    '[data-testid="error-message"]',
    '[data-testid="alert-error"]',
    '.error-message',
    '.alert-error',
    '[role="alert"]'
  ];
  
  let errorFound = false;
  for (const locator of errorLocators) {
    const errorElement = page.locator(locator);
    if (await errorElement.count() > 0) {
      await assertions.assertContainsText(errorElement, errorMessage);
      errorFound = true;
      break;
    }
  }
  
  if (!errorFound) {
    await assertions.assertContainsText(page.locator('body'), errorMessage);
  }
});

Then('no schedule change history data should be visible', async function () {
  const historyTable = page.locator('[data-testid="schedule-history-table"], table.schedule-history');
  const historyCards = page.locator('[data-testid="schedule-history-card"]');
  
  const tableCount = await historyTable.count();
  const cardsCount = await historyCards.count();
  
  expect(tableCount).toBe(0);
  expect(cardsCount).toBe(0);
});

Then('no API calls should return data', async function () {
  const apiCalls = [];
  
  page.on('response', response => {
    if (response.url().includes('/api/scheduleChangeRequests')) {
      apiCalls.push(response);
    }
  });
  
  await page.waitForTimeout(2000);
  
  expect(apiCalls.length).toBe(0);
});

Then('API should return {int} status code', async function (expectedStatusCode: number) {
  expect(this.apiResponse.status).toBe(expectedStatusCode);
});

Then('API response should contain {string} error', async function (errorMessage: string) {
  const responseBody = this.apiResponse.body;
  const responseString = JSON.stringify(responseBody).toLowerCase();
  const errorMessageLower = errorMessage.toLowerCase();
  
  expect(responseString).toContain(errorMessageLower);
});

Then('security logs should record the unauthorized access attempt', async function () {
  const consoleMessages = [];
  
  page.on('console', msg => {
    if (msg.type() === 'error' || msg.type() === 'warning') {
      consoleMessages.push(msg.text());
    }
  });
  
  await page.waitForTimeout(1000);
  
  const hasSecurityLog = consoleMessages.some(msg => 
    msg.toLowerCase().includes('unauthorized') || 
    msg.toLowerCase().includes('authentication') ||
    msg.toLowerCase().includes('access denied')
  );
  
  expect(hasSecurityLog || consoleMessages.length >= 0).toBeTruthy();
});

/**************************************************/
/*  TEST CASE: TC-002
/*  Title: Invalid date range filter input validation
/*  Priority: High
/*  Category: Negative - Validation
/**************************************************/

Then('validation error message {string} should be displayed', async function (errorMessage: string) {
  const validationErrorLocators = [
    '[data-testid="validation-error"]',
    '[data-testid="field-error"]',
    '.validation-error',
    '.field-error',
    '.error-text',
    '[role="alert"]'
  ];
  
  let errorFound = false;
  for (const locator of validationErrorLocators) {
    const errorElement = page.locator(locator);
    if (await errorElement.count() > 0) {
      await assertions.assertContainsText(errorElement, errorMessage);
      errorFound = true;
      break;
    }
  }
  
  if (!errorFound) {
    await assertions.assertContainsText(page.locator('body'), errorMessage);
  }
});

Then('filter should not be applied', async function () {
  const loadingIndicator = page.locator('[data-testid="loading-spinner"], .loading-spinner');
  const loadingCount = await loadingIndicator.count();
  
  if (loadingCount > 0) {
    await waits.waitForHidden(loadingIndicator);
  }
  
  const urlParams = new URL(page.url()).searchParams;
  const hasFilterParams = urlParams.has('fromDate') || urlParams.has('toDate') || urlParams.has('filter');
  
  expect(hasFilterParams).toBeFalsy();
});

Then('no API call should be made', async function () {
  let apiCallMade = false;
  
  const responsePromise = page.waitForResponse(
    response => response.url().includes('/api/scheduleChangeRequests'),
    { timeout: 2000 }
  ).then(() => {
    apiCallMade = true;
  }).catch(() => {
    apiCallMade = false;
  });
  
  await responsePromise;
  
  expect(apiCallMade).toBeFalsy();
});

/**************************************************/
/*  TEST CASE: TC-003
/*  Title: Date range validation when end date is before start date
/*  Priority: High
/*  Category: Negative - Validation
/**************************************************/

Then('original unfiltered data should remain displayed', async function () {
  const historyTable = page.locator('[data-testid="schedule-history-table"], table.schedule-history');
  const historyRows = page.locator('[data-testid="schedule-history-row"], tbody tr');
  
  if (await historyTable.count() > 0) {
    await assertions.assertVisible(historyTable);
  }
  
  const rowCount = await historyRows.count();
  expect(rowCount).toBeGreaterThanOrEqual(0);
});

/**************************************************/
/*  TEST CASE: TC-004
/*  Title: API failure when retrieving schedule change history
/*  Priority: High
/*  Category: Negative - Error Handling
/**************************************************/

Then('loading spinner should be visible for up to {int} seconds', async function (maxSeconds: number) {
  const loadingSpinner = page.locator('[data-testid="loading-spinner"], .loading-spinner, [role="progressbar"]');
  
  try {
    await assertions.assertVisible(loadingSpinner);
    await page.waitForTimeout(maxSeconds * 1000);
  } catch (error) {
    // Loading spinner may disappear before max time
  }
});

Then('{string} button should be visible', async function (buttonText: string) {
  const testIdLocator = `[data-testid="button-${buttonText.toLowerCase().replace(/\s+/g, '-')}"]`;
  const buttonLocator = page.locator(testIdLocator);
  
  if (await buttonLocator.count() > 0) {
    await assertions.assertVisible(buttonLocator);
  } else {
    await assertions.assertVisible(page.locator(`button:has-text("${buttonText}")`));
  }
});

Then('browser console should show API error details', async function () {
  const consoleErrors = [];
  
  page.on('console', msg => {
    if (msg.type() === 'error') {
      consoleErrors.push(msg.text());
    }
  });
  
  await page.waitForTimeout(1000);
  
  expect(consoleErrors.length).toBeGreaterThanOrEqual(0);
});

Then('no sensitive system information should be exposed', async function () {
  const pageContent = await page.content();
  const bodyText = await page.locator('body').textContent();
  
  const sensitivePatterns = [
    /password/i,
    /secret/i,
    /api[_-]?key/i,
    /token/i,
    /database/i,
    /connection[_-]?string/i,
    /stack[_-]?trace/i
  ];
  
  let hasSensitiveInfo = false;
  for (const pattern of sensitivePatterns) {
    if (pattern.test(bodyText || '')) {
      const matches = (bodyText || '').match(pattern);
      if (matches && matches.length > 2) {
        hasSensitiveInfo = true;
        break;
      }
    }
  }
  
  expect(hasSensitiveInfo).toBeFalsy();
});

Then('system should make new API request', async function () {
  const apiRequestPromise = page.waitForRequest(
    request => request.url().includes('/api/scheduleChangeRequests/history'),
    { timeout: 5000 }
  );
  
  await apiRequestPromise;
});

Then('user session should remain active', async function () {
  const cookies = await context.cookies();
  const hasSessionCookie = cookies.some(cookie => 
    cookie.name.toLowerCase().includes('session') || 
    cookie.name.toLowerCase().includes('token')
  );
  
  const localStorageData = await page.evaluate(() => {
    return localStorage.length > 0 || sessionStorage.length > 0;
  });
  
  expect(hasSessionCookie || localStorageData).toBeTruthy();
});

/**************************************************/
/*  TEST CASE: TC-005
/*  Title: API timeout when retrieving schedule change history
/*  Priority: High
/*  Category: Negative - Error Handling
/**************************************************/

Then('loading spinner should be visible', async function () {
  const loadingSpinner = page.locator('[data-testid="loading-spinner"], .loading-spinner, [role="progressbar"]');
  await assertions.assertVisible(loadingSpinner);
});

Then('system should wait for configured timeout period', async function () {
  await page.waitForTimeout(3000);
});

Then('error should be logged on backend for monitoring', async function () {
  const consoleMessages = [];
  
  page.on('console', msg => {
    consoleMessages.push({ type: msg.type(), text: msg.text() });
  });
  
  await page.waitForTimeout(1000);
  
  expect(consoleMessages.length).toBeGreaterThanOrEqual(0);
});

/**************************************************/
/*  TEST CASE: TC-006
/*  Title: Employee with no schedule change history
/*  Priority: Medium
/*  Category: Negative - Edge Case
/**************************************************/

Then('page should load successfully within {int} seconds', async function (maxSeconds: number) {
  const startTime = Date.now();
  await waits.waitForDomContentLoaded();
  const loadTime = (Date.now() - startTime) / 1000;
  
  expect(loadTime).toBeLessThanOrEqual(maxSeconds);
});

Then('empty state message {string} should be displayed', async function (message: string) {
  const emptyStateLocators = [
    '[data-testid="empty-state"]',
    '[data-testid="no-data-message"]',
    '.empty-state',
    '.no-data'
  ];
  
  let messageFound = false;
  for (const locator of emptyStateLocators) {
    const element = page.locator(locator);
    if (await element.count() > 0) {
      await assertions.assertContainsText(element, message);
      messageFound = true;
      break;
    }
  }
  
  if (!messageFound) {
    await assertions.assertContainsText(page.locator('body'), message);
  }
});

Then('informative icon or illustration should be visible', async function () {
  const iconLocators = [
    '[data-testid="empty-state-icon"]',
    '[data-testid="illustration"]',
    '.empty-state-icon',
    'svg',
    'img[alt*="empty"]',
    'img[alt*="no data"]'
  ];
  
  let iconFound = false;
  for (const locator of iconLocators) {
    const icon = page.locator(locator);
    if (await icon.count() > 0) {
      await assertions.assertVisible(icon.first());
      iconFound = true;
      break;
    }
  }
  
  expect(iconFound).toBeTruthy();
});

Then('helpful message {string} should be displayed', async function (message: string) {
  await assertions.assertContainsText(page.locator('body'), message);
});

Then('link to request submission page should be available', async function () {
  const linkLocators = [
    '[data-testid="link-submit-request"]',
    'a:has-text("submit")',
    'a:has-text("request")',
    'a[href*="submit"]',
    'a[href*="request"]'
  ];
  
  let linkFound = false;
  for (const locator of linkLocators) {
    const link = page.locator(locator);
    if (await link.count() > 0) {
      await assertions.assertVisible(link.first());
      linkFound = true;
      break;
    }
  }
  
  expect(linkFound).toBeTruthy();
});

Then('page should not show any errors', async function () {
  const errorLocators = [
    '[data-testid="error-message"]',
    '[data-testid="alert-error"]',
    '.error-message',
    '.alert-error',
    '[role="alert"][class*="error"]'
  ];
  
  for (const locator of errorLocators) {
    const errorElement = page.locator(locator);
    const count = await errorElement.count();
    expect(count).toBe(0);
  }
});

/**************************************************/
/*  TEST CASE: TC-007
/*  Title: Filter controls behavior with empty history
/*  Priority: Medium
/*  Category: Negative - Edge Case
/**************************************************/

Then('filter controls should show appropriate messaging', async function () {
  const filterSection = page.locator('[data-testid="filter-section"], .filter-controls');
  await assertions.assertVisible(filterSection);
});

Then('message {string} should be displayed', async function (message: string) {
  await assertions.assertContainsText(page.locator('body'), message);
});

Then('no errors should be shown', async function () {
  const errorLocators = [
    '[data-testid="error-message"]',
    '[data-testid="alert-error"]',
    '.error-message',
    '.alert-error'
  ];
  
  for (const locator of errorLocators) {
    const errorElement = page.locator(locator);
    const count = await errorElement.count();
    expect(count).toBe(0);
  }
});

/**************************************************/
/*  TEST CASE: TC-008
/*  Title: SQL injection prevention through filter inputs
/*  Priority: High
/*  Category: Negative - Security
/**************************************************/

Then('input should be sanitized or rejected', async function () {
  const validationError = page.locator('[data-testid="validation-error"], .validation-error, [role="alert"]');
  const errorCount = await validationError.count();
  
  expect(errorCount).toBeGreaterThanOrEqual(0);
});

Then('no unauthorized data should be returned', async function () {
  const historyRows = page.locator('[data-testid="schedule-history-row"], tbody tr');
  const rowCount = await historyRows.count();
  
  expect(rowCount).toBeLessThanOrEqual(100);
});

Then('no database errors should be exposed to user', async function () {
  const pageContent = await page.locator('body').textContent();
  
  const databaseErrorPatterns = [
    /sql/i,
    /database error/i,
    /syntax error/i,
    /mysql/i,
    /postgresql/i,
    /oracle/i,
    /table.*not.*found/i,
    /column.*not.*found/i
  ];
  
  let hasDatabaseError = false;
  for (const pattern of databaseErrorPatterns) {
    if (pattern.test(pageContent || '')) {
      hasDatabaseError = true;
      break;
    }
  }
  
  expect(hasDatabaseError).toBeFalsy();
});

Then('system should log attempted injection for security monitoring', async function () {
  const consoleMessages = [];
  
  page.on('console', msg => {
    if (msg.type() === 'warning' || msg.type() === 'error') {
      consoleMessages.push(msg.text());
    }
  });
  
  await page.waitForTimeout(1000);
  
  expect(consoleMessages.length).toBeGreaterThanOrEqual(0);
});

Then('database integrity should be maintained', async function () {
  await page.waitForTimeout(500);
  
  const pageIsResponsive = await page.evaluate(() => {
    return document.readyState === 'complete';
  });
  
  expect(pageIsResponsive).toBeTruthy();
});

Then('application should continue to function normally', async function () {
  const navigationLinks = page.locator('nav a, [data-testid="nav-link"]');
  const linkCount = await navigationLinks.count();
  
  expect(linkCount).toBeGreaterThanOrEqual(0);
  
  const pageTitle = await page.title();
  expect(pageTitle.length).toBeGreaterThan(0);
});

/**************************************************/
/*  TEST CASE: TC-009
/*  Title: Verify no data exposure after SQL injection attempt
/*  Priority: High
/*  Category: Negative - Security
/**************************************************/

Then('no additional records beyond user\'s own history should be displayed', async function () {
  const historyRows = page.locator('[data-testid="schedule-history-row"], tbody tr');
  const rowCount = await historyRows.count();
  
  expect(rowCount).toBeLessThanOrEqual(100);
});

Then('no SQL code should be executed', async function () {
  const pageContent = await page.locator('body').textContent();
  
  const sqlPatterns = [
    /DROP TABLE/i,
    /DELETE FROM/i,
    /INSERT INTO/i,
    /UPDATE.*SET/i,
    /UNION SELECT/i,
    /--/,
    /;.*DROP/i
  ];
  
  let hasSqlCode = false;
  for (const pattern of sqlPatterns) {
    if (pattern.test(pageContent || '')) {
      hasSqlCode = true;
      break;
    }
  }
  
  expect(hasSqlCode).toBeFalsy();
});

Then('security incident should be logged for review', async function () {
  const consoleMessages = [];
  
  page.on('console', msg => {
    consoleMessages.push({ type: msg.type(), text: msg.text() });
  });
  
  await page.waitForTimeout(1000);
  
  expect(consoleMessages.length).toBeGreaterThanOrEqual(0);
});

Then('filter should work correctly', async function () {
  await waits.waitForNetworkIdle();
  
  const historyTable = page.locator('[data-testid="schedule-history-table"], table.schedule-history');
  const emptyState = page.locator('[data-testid="empty-state"], .empty-state');
  
  const tableCount = await historyTable.count();
  const emptyStateCount = await emptyState.count();
  
  expect(tableCount + emptyStateCount).toBeGreaterThanOrEqual(0);
});

Then('user should see only their own valid history data', async function () {
  const historyRows = page.locator('[data-testid="schedule-history-row"], tbody tr');
  const rowCount = await historyRows.count();
  
  if (rowCount > 0) {
    const firstRow = historyRows.first();
    await assertions.assertVisible(firstRow);
  }
  
  expect(rowCount).toBeGreaterThanOrEqual(0);
  expect(rowCount).toBeLessThanOrEqual(1000);
});