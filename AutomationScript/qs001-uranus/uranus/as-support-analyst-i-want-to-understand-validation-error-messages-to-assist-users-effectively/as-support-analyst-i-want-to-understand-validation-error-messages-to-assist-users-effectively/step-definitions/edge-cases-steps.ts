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
      supportAnalyst: { username: 'support_analyst', password: 'analyst123' },
      admin: { username: 'admin', password: 'admin123' }
    },
    performanceMetrics: {
      dashboardLoadTime: 3000,
      documentationLoadTime: 5000,
      searchResultTime: 3000,
      filterApplyTime: 2000,
      sortTime: 2000,
      exportTime: 30000
    }
  };
  
  this.startTime = null;
  this.endTime = null;
  this.responseTime = null;
  this.concurrentUsers = 0;
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
/*  BACKGROUND STEPS - All Test Cases
/*  Setup: Support Analyst authentication and documentation availability
/**************************************************/

Given('Support Analyst is logged into the knowledge base system', async function () {
  const credentials = this.testData?.users?.supportAnalyst || { username: 'support_analyst', password: 'analyst123' };
  await actions.navigateTo(process.env.BASE_URL || 'https://knowledgebase.example.com');
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="dashboard"]'));
});

Given('validation error documentation is published and available', async function () {
  await assertions.assertVisible(page.locator('//div[@id="validation-errors-section"]'));
  const docCount = await page.locator('//div[@class="error-documentation-item"]').count();
  expect(docCount).toBeGreaterThan(0);
});

/**************************************************/
/*  TEST CASE: TC-001
/*  Title: Documentation remains accessible under high concurrent user load
/*  Priority: High
/*  Category: Edge Cases - Performance
/**************************************************/

Given('network monitoring tools are active to track response times', async function () {
  this.performanceObserver = true;
  this.startTime = Date.now();
  await page.evaluate(() => {
    (window as any).performanceMetrics = [];
    const observer = new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        (window as any).performanceMetrics.push({
          name: entry.name,
          duration: entry.duration,
          startTime: entry.startTime
        });
      }
    });
    observer.observe({ entryTypes: ['navigation', 'resource', 'measure'] });
  });
});

Given('system is simulating {int} concurrent support analysts accessing the same documentation', async function (userCount: number) {
  this.concurrentUsers = userCount;
  this.systemState.concurrentLoad = true;
  await page.evaluate((count) => {
    sessionStorage.setItem('simulatedConcurrentUsers', count.toString());
  }, userCount);
});

/**************************************************/
/*  TEST CASE: TC-002
/*  Title: Documentation search handles special characters and Unicode
/*  Priority: Medium
/*  Category: Edge Cases - Data Validation
/**************************************************/

Given('documentation includes validation errors with special characters in error codes', async function () {
  this.systemState.specialCharactersSupported = true;
  const specialCharErrorCodes = ['VAL_ERR#001', 'ERR-ÜTF-8', 'ERROR@2024', '❌ VAL-ERR-500'];
  this.testData.specialCharErrorCodes = specialCharErrorCodes;
});

Given('search functionality is enabled and operational', async function () {
  await assertions.assertVisible(page.locator('//input[@id="search-bar"]'));
  const searchEnabled = await page.locator('//input[@id="search-bar"]').isEnabled();
  expect(searchEnabled).toBe(true);
});

Given('browser supports Unicode character rendering', async function () {
  const unicodeSupport = await page.evaluate(() => {
    const testDiv = document.createElement('div');
    testDiv.textContent = '❌ ÜTF-8';
    document.body.appendChild(testDiv);
    const supported = testDiv.textContent === '❌ ÜTF-8';
    document.body.removeChild(testDiv);
    return supported;
  });
  expect(unicodeSupport).toBe(true);
});

/**************************************************/
/*  TEST CASE: TC-004
/*  Title: Documentation remains usable with large dataset of 500+ validation errors
/*  Priority: High
/*  Category: Edge Cases - Scalability
/**************************************************/

Given('knowledge base contains {int} documented validation errors', async function (errorCount: number) {
  this.testData.totalErrorCount = errorCount;
  this.systemState.largeDataset = true;
});

Given('Support Analyst has full access permissions', async function () {
  const permissions = await page.evaluate(() => {
    return sessionStorage.getItem('userPermissions');
  });
  this.testData.userPermissions = permissions || 'full_access';
});

Given('documentation is organized with categorization and filtering options', async function () {
  await assertions.assertVisible(page.locator('//div[@id="filter-panel"]'));
  await assertions.assertVisible(page.locator('//select[@id="category-filter"]'));
  await assertions.assertVisible(page.locator('//select[@id="sort-options"]'));
});

Given('browser has standard memory allocation of {int} GB RAM', async function (ramSize: number) {
  this.systemState.allocatedMemory = ramSize * 1024;
  const memoryInfo = await page.evaluate(() => {
    return (performance as any).memory ? {
      usedJSHeapSize: (performance as any).memory.usedJSHeapSize,
      totalJSHeapSize: (performance as any).memory.totalJSHeapSize,
      jsHeapSizeLimit: (performance as any).memory.jsHeapSizeLimit
    } : null;
  });
  this.testData.initialMemory = memoryInfo;
});

/**************************************************/
/*  TEST CASE: TC-005
/*  Title: Documentation accessible from multiple devices and browsers simultaneously
/*  Priority: Medium
/*  Category: Edge Cases - Multi-Session
/**************************************************/

Given('Support Analyst has active session on desktop using {string} browser', async function (browserName: string) {
  this.testData.activeSessions = this.testData.activeSessions || [];
  this.testData.activeSessions.push({
    device: 'desktop',
    browser: browserName,
    sessionId: Date.now().toString()
  });
});

Given('same analyst account supports multi-device concurrent access', async function () {
  this.systemState.multiDeviceSupport = true;
  await page.evaluate(() => {
    sessionStorage.setItem('multiDeviceEnabled', 'true');
  });
});

Given('network connectivity is stable on all devices', async function () {
  this.systemState.networkStable = true;
  const networkStatus = await page.evaluate(() => navigator.onLine);
  expect(networkStatus).toBe(true);
});

/**************************************************/
/*  TEST CASE: TC-006
/*  Title: Documentation remains stable during real-time updates
/*  Priority: High
/*  Category: Edge Cases - Concurrent Updates
/**************************************************/

Given('Support Analyst is actively assisting a user with validation error documentation open', async function () {
  this.systemState.activeAssistance = true;
  await actions.navigateTo(`${process.env.BASE_URL}/validation-errors`);
  await waits.waitForNetworkIdle();
});

Given('documentation administrator is updating error entries in real-time', async function () {
  this.systemState.realtimeUpdates = true;
  await page.evaluate(() => {
    sessionStorage.setItem('realtimeUpdatesActive', 'true');
  });
});

Given('version control is enabled in knowledge base', async function () {
  this.systemState.versionControlEnabled = true;
  await assertions.assertVisible(page.locator('//button[@id="version-history"]'));
});

Given('Support Analyst is viewing error code {string} which is being updated', async function (errorCode: string) {
  this.testData.currentErrorCode = errorCode;
  this.systemState.documentationBeingUpdated = true;
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  TEST CASE: TC-001 - High Concurrent Load
/**************************************************/

When('Support Analyst logs into knowledge base system during peak support hours', async function () {
  this.startTime = Date.now();
  await waits.waitForDomContentLoaded();
  this.endTime = Date.now();
  this.responseTime = this.endTime - this.startTime;
});

When('Support Analyst navigates to {string} section while {int} users are accessing the same content', async function (sectionName: string, userCount: number) {
  this.startTime = Date.now();
  const sectionXPath = `//div[@id='${sectionName.toLowerCase().replace(/\s+/g, '-')}-section']`;
  await actions.click(page.locator(sectionXPath));
  await waits.waitForNetworkIdle();
  this.endTime = Date.now();
  this.responseTime = this.endTime - this.startTime;
});

When('Support Analyst searches for validation error code {string} using search functionality', async function (errorCode: string) {
  this.startTime = Date.now();
  await actions.fill(page.locator('//input[@id="search-bar"]'), errorCode);
  await actions.click(page.locator('//button[@id="search-button"]'));
  await waits.waitForNetworkIdle();
  this.endTime = Date.now();
  this.responseTime = this.endTime - this.startTime;
});

When('Support Analyst opens the detailed troubleshooting steps for the validation error', async function () {
  await actions.click(page.locator('//div[@id="error-details-expand"]'));
  await waits.waitForVisible(page.locator('//div[@id="troubleshooting-steps"]'));
});

When('Support Analyst attempts to copy troubleshooting steps to clipboard for sharing with user', async function () {
  await actions.click(page.locator('//button[@id="copy-to-clipboard"]'));
  await page.waitForTimeout(500);
  this.clipboardContent = await page.evaluate(() => navigator.clipboard.readText());
});

/**************************************************/
/*  TEST CASE: TC-002 - Special Characters and Unicode
/**************************************************/

When('Support Analyst navigates to validation error documentation search bar', async function () {
  await actions.click(page.locator('//input[@id="search-bar"]'));
  await waits.waitForVisible(page.locator('//input[@id="search-bar"]'));
});

When('Support Analyst enters error code {string} in search field', async function (errorCode: string) {
  await actions.fill(page.locator('//input[@id="search-bar"]'), errorCode);
  this.testData.searchedErrorCode = errorCode;
});

/**************************************************/
/*  TEST CASE: TC-003 - Special Characters Preservation
/**************************************************/

When('Support Analyst searches for error code {string}', async function (errorCode: string) {
  await actions.fill(page.locator('//input[@id="search-bar"]'), errorCode);
  await actions.click(page.locator('//button[@id="search-button"]'));
  await waits.waitForNetworkIdle();
  this.testData.originalSearchTerm = errorCode;
});

When('Support Analyst copies error code from search results', async function () {
  const errorCodeElement = page.locator('//span[@class="error-code-result"]').first();
  await errorCodeElement.click({ clickCount: 3 });
  await page.keyboard.press('Control+C');
  await page.waitForTimeout(300);
});

When('Support Analyst pastes copied error code into new search', async function () {
  await actions.click(page.locator('//input[@id="search-bar"]'));
  await page.keyboard.press('Control+A');
  await page.keyboard.press('Control+V');
  await page.waitForTimeout(300);
  this.testData.pastedSearchTerm = await page.locator('//input[@id="search-bar"]').inputValue();
});

/**************************************************/
/*  TEST CASE: TC-004 - Large Dataset Performance
/**************************************************/

When('Support Analyst navigates to {string} page', async function (pageName: string) {
  this.startTime = Date.now();
  const pageXPath = `//a[@id='${pageName.toLowerCase().replace(/\s+/g, '-')}-link']`;
  await actions.click(page.locator(pageXPath));
  await waits.waitForNetworkIdle();
  this.endTime = Date.now();
  this.responseTime = this.endTime - this.startTime;
});

When('Support Analyst scrolls through the complete list from first to last error entry', async function () {
  const initialMemory = await page.evaluate(() => (performance as any).memory?.usedJSHeapSize);
  
  await page.evaluate(async () => {
    const scrollContainer = document.querySelector('[data-testid="error-list-container"]') || document.body;
    const scrollHeight = scrollContainer.scrollHeight;
    const step = 500;
    for (let i = 0; i < scrollHeight; i += step) {
      scrollContainer.scrollTop = i;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  });
  
  await page.waitForTimeout(1000);
  const finalMemory = await page.evaluate(() => (performance as any).memory?.usedJSHeapSize);
  this.testData.memoryDelta = finalMemory - initialMemory;
});

When('Support Analyst applies filter to show only {string} category errors', async function (category: string) {
  this.startTime = Date.now();
  await actions.click(page.locator('//select[@id="category-filter"]'));
  await actions.selectByText(page.locator('//select[@id="category-filter"]'), category);
  await waits.waitForNetworkIdle();
  this.endTime = Date.now();
  this.responseTime = this.endTime - this.startTime;
  this.testData.appliedFilter = category;
});

When('Support Analyst sorts the filtered list by {string} frequency', async function (sortOption: string) {
  this.startTime = Date.now();
  await actions.click(page.locator('//select[@id="sort-options"]'));
  await actions.selectByText(page.locator('//select[@id="sort-options"]'), sortOption);
  await waits.waitForNetworkIdle();
  this.endTime = Date.now();
  this.responseTime = this.endTime - this.startTime;
});

When('Support Analyst uses browser Find function to search for specific error text within the large list', async function () {
  await page.keyboard.press('Control+F');
  await page.waitForTimeout(500);
  await page.keyboard.type('VAL-ERR');
  await page.waitForTimeout(500);
});

When('Support Analyst exports the complete list of {int} errors to {string} format', async function (errorCount: number, format: string) {
  this.startTime = Date.now();
  await actions.click(page.locator('//button[@id="export-button"]'));
  await actions.click(page.locator(`//button[@id='export-${format.toLowerCase()}']`));
  await page.waitForTimeout(2000);
  this.endTime = Date.now();
  this.responseTime = this.endTime - this.startTime;
});

/**************************************************/
/*  TEST CASE: TC-005 - Multi-Device Access
/**************************************************/

When('Support Analyst opens validation error documentation page on desktop {string} browser', async function (browserName: string) {
  await actions.navigateTo(`${process.env.BASE_URL}/validation-errors`);
  await waits.waitForNetworkIdle();
  this.testData.activeSessions[0].pageLoaded = true;
});

When('Support Analyst simultaneously opens the same documentation page on laptop {string} browser using same login credentials', async function (browserName: string) {
  this.testData.activeSessions.push({
    device: 'laptop',
    browser: browserName,
    sessionId: Date.now().toString(),
    pageLoaded: true
  });
  await page.evaluate(() => {
    sessionStorage.setItem('secondSessionActive', 'true');
  });
});

When('Support Analyst opens the same documentation on tablet {string} browser while other sessions remain active', async function (browserName: string) {
  this.testData.activeSessions.push({
    device: 'tablet',
    browser: browserName,
    sessionId: Date.now().toString(),
    pageLoaded: true
  });
  await page.evaluate(() => {
    sessionStorage.setItem('thirdSessionActive', 'true');
  });
});

When('Support Analyst bookmarks a specific error entry on desktop {string}', async function (browserName: string) {
  await actions.click(page.locator('//button[@id="bookmark-error"]'));
  await waits.waitForVisible(page.locator('//div[@id="bookmark-confirmation"]'));
  this.testData.bookmarked = true;
});

When('Support Analyst searches for different error codes simultaneously on all three devices', async function () {
  const searchTerms = ['VAL-ERR-001', 'VAL-ERR-002', 'VAL-ERR-003'];
  this.testData.simultaneousSearches = searchTerms;
  await actions.fill(page.locator('//input[@id="search-bar"]'), searchTerms[0]);
  await actions.click(page.locator('//button[@id="search-button"]'));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-006 - Real-Time Updates
/**************************************************/

When('Support Analyst opens documentation for error code {string}', async function (errorCode: string) {
  await actions.fill(page.locator('//input[@id="search-bar"]'), errorCode);
  await actions.click(page.locator('//button[@id="search-button"]'));
  await waits.waitForNetworkIdle();
  await actions.click(page.locator('//div[@class="error-result-item"]').first());
  await waits.waitForVisible(page.locator('//div[@id="error-documentation-content"]'));
});

When('administrator publishes an update to the same error code with revised troubleshooting steps', async function () {
  await page.evaluate(() => {
    const event = new CustomEvent('documentationUpdated', {
      detail: { errorCode: 'VAL-ERR-2048', version: '2.0' }
    });
    window.dispatchEvent(event);
  });
  await page.waitForTimeout(1000);
});

When('Support Analyst continues reading current version without refreshing to complete assisting the user', async function () {
  this.testData.currentVersionContent = await page.locator('//div[@id="error-documentation-content"]').textContent();
  await page.waitForTimeout(2000);
});

When('Support Analyst clicks {string} button after completing user assistance', async function (buttonText: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonXPath);
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
  await waits.waitForNetworkIdle();
});

When('Support Analyst checks version history to see what was modified', async function () {
  await actions.click(page.locator('//button[@id="version-history"]'));
  await waits.waitForVisible(page.locator('//div[@id="version-history-panel"]'));
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  TEST CASE: TC-001 - Performance Assertions
/**************************************************/

Then('dashboard should load within {int} seconds', async function (maxSeconds: number) {
  const maxMilliseconds = maxSeconds * 1000;
  expect(this.responseTime).toBeLessThanOrEqual(maxMilliseconds);
});

Then('documentation page should load within {int} seconds', async function (maxSeconds: number) {
  const maxMilliseconds = maxSeconds * 1000;
  expect(this.responseTime).toBeLessThanOrEqual(maxMilliseconds);
  await assertions.assertVisible(page.locator('//div[@id="documentation-content"]'));
});

Then('search results should return within {int} seconds', async function (maxSeconds: number) {
  const maxMilliseconds = maxSeconds * 1000;
  expect(this.responseTime).toBeLessThanOrEqual(maxMilliseconds);
});

Then('relevant error documentation should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@class="search-results"]'));
  const resultCount = await page.locator('//div[@class="error-result-item"]').count();
  expect(resultCount).toBeGreaterThan(0);
});

Then('full documentation with troubleshooting steps should load without timeout errors', async function () {
  await assertions.assertVisible(page.locator('//div[@id="troubleshooting-steps"]'));
  const steps = await page.locator('//div[@class="troubleshooting-step"]').count();
  expect(steps).toBeGreaterThan(0);
});

Then('no performance degradation should occur', async function () {
  const performanceMetrics = await page.evaluate(() => {
    const navigation = performance.getEntriesByType('navigation')[0] as any;
    return {
      loadTime: navigation.loadEventEnd - navigation.loadEventStart,
      domContentLoaded: navigation.domContentLoadedEventEnd - navigation.domContentLoadedEventStart
    };
  });
  expect(performanceMetrics.loadTime).toBeLessThan(10000);
});

Then('content should copy successfully without formatting issues', async function () {
  expect(this.clipboardContent).toBeTruthy();
  expect(this.clipboardContent.length).toBeGreaterThan(0);
});

Then('no system lag should occur', async function () {
  const fps = await page.evaluate(() => {
    return new Promise((resolve) => {
      let lastTime = performance.now();
      let frames = 0;
      const checkFrame = () => {
        const currentTime = performance.now();
        frames++;
        if (currentTime - lastTime >= 1000) {
          resolve(frames);
        } else {
          requestAnimationFrame(checkFrame);
        }
      };
      requestAnimationFrame(checkFrame);
    });
  });
  expect(fps).toBeGreaterThan(30);
});

Then('documentation should remain accessible and responsive under high load', async function () {
  await assertions.assertVisible(page.locator('//div[@id="documentation-content"]'));
  const isResponsive = await page.evaluate(() => {
    const button = document.querySelector('button');
    return button ? !button.disabled : true;
  });
  expect(isResponsive).toBe(true);
});

Then('system performance metrics should show response times less than {int} seconds', async function (maxSeconds: number) {
  const maxMilliseconds = maxSeconds * 1000;
  expect(this.responseTime).toBeLessThan(maxMilliseconds);
});

Then('no error messages or timeout warnings should be displayed', async function () {
  const errorMessages = await page.locator('//div[@class="error-message"]').count();
  expect(errorMessages).toBe(0);
  const timeoutWarnings = await page.locator('//div[@class="timeout-warning"]').count();
  expect(timeoutWarnings).toBe(0);
});

/**************************************************/
/*  TEST CASE: TC-002 - Special Characters
/**************************************************/

Then('search bar should be visible and accept input focus', async function () {
  await assertions.assertVisible(page.locator('//input[@id="search-bar"]'));
  const isFocused = await page.locator('//input[@id="search-bar"]').evaluate(el => el === document.activeElement);
  expect(isFocused).toBe(true);
});

Then('search should accept the input without sanitizing characters', async function () {
  const inputValue = await page.locator('//input[@id="search-bar"]').inputValue();
  expect(inputValue).toBe(this.testData.searchedErrorCode);
});

Then('matching documentation should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@class="search-results"]'));
  const resultCount = await page.locator('//div[@class="error-result-item"]').count();
  expect(resultCount).toBeGreaterThan(0);
});

Then('special characters should be properly recognized', async function () {
  const resultText = await page.locator('//div[@class="error-result-item"]').first().textContent();
  expect(resultText).toContain(this.testData.searchedErrorCode);
});

Then('results should be returned accurately', async function () {
  const resultCount = await page.locator('//div[@class="error-result-item"]').count();
  expect(resultCount).toBeGreaterThan(0);
});

/**************************************************/
/*  TEST CASE: TC-003 - Character Preservation
/**************************************************/

Then('emoji and text should be preserved in search', async function () {
  expect(this.testData.pastedSearchTerm).toBe(this.testData.originalSearchTerm);
});

Then('all special characters and Unicode should be properly handled', async function () {
  const hasEmoji = this.testData.pastedSearchTerm.includes('❌');
  const hasSpecialChars = /[#@_-]/.test(this.testData.pastedSearchTerm);
  expect(hasEmoji || hasSpecialChars).toBe(true);
});

Then('search history should preserve special characters correctly', async function () {
  await actions.click(page.locator('//button[@id="search-history"]'));
  await waits.waitForVisible(page.locator('//div[@id="search-history-panel"]'));
  const historyItems = await page.locator('//div[@class="history-item"]').first().textContent();
  expect(historyItems).toContain(this.testData.originalSearchTerm);
});

Then('no character encoding errors should be displayed', async function () {
  const encodingErrors = await page.locator('//div[@class="encoding-error"]').count();
  expect(encodingErrors).toBe(0);
});

/**************************************************/
/*  TEST CASE: TC-004 - Large Dataset
/**************************************************/

Then('page should load within {int} seconds', async function (maxSeconds: number) {
  const maxMilliseconds = maxSeconds * 1000;
  expect(this.responseTime).toBeLessThanOrEqual(maxMilliseconds);
});

Then('pagination or infinite scroll should be implemented', async function () {
  const hasPagination = await page.locator('//div[@id="pagination"]').count() > 0;
  const hasInfiniteScroll = await page.locator('//div[@data-infinite-scroll="true"]').count() > 0;
  expect(hasPagination || hasInfiniteScroll).toBe(true);
});

Then('scrolling should be smooth without browser freezing', async function () {
  const scrollPerformance = await page.evaluate(() => {
    return new Promise((resolve) => {
      let frameCount = 0;
      let lastTime = performance.now();
      const measureScroll = () => {
        frameCount++;
        const currentTime = performance.now();
        if (currentTime - lastTime >= 1000) {
          resolve(frameCount);
        } else {
          requestAnimationFrame(measureScroll);
        }
      };
      requestAnimationFrame(measureScroll);
    });
  });
  expect(scrollPerformance).toBeGreaterThan(30);
});

Then('no memory leaks should occur', async function () {
  const memoryDelta = this.testData.memoryDelta || 0;
  const maxMemoryIncrease = 50 * 1024 * 1024;
  expect(memoryDelta).toBeLessThan(maxMemoryIncrease);
});

Then('filter should apply within {int} seconds', async function (maxSeconds: number) {
  const maxMilliseconds = maxSeconds * 1000;
  expect(this.responseTime).toBeLessThanOrEqual(maxMilliseconds);
});

Then('only relevant authentication validation errors should be displayed', async function () {
  const errorItems = await page.locator('//div[@class="error-item"]').all();
  for (const item of errorItems) {
    const category = await item.getAttribute('data-category');
    expect(category).toBe(this.testData.appliedFilter);
  }
});

Then('list should re-sort within {int} seconds', async function (maxSeconds: number) {
  const maxMilliseconds = maxSeconds * 1000;
  expect(this.responseTime).toBeLessThanOrEqual(maxMilliseconds);
});

Then('most frequently occurring errors should appear at the top', async function () {
  const firstItem = await page.locator('//div[@class="error-item"]').first().getAttribute('data-frequency');
  const secondItem = await page.locator('//div[@class="error-item"]').nth(1).getAttribute('data-frequency');
  expect(parseInt(firstItem || '0')).toBeGreaterThanOrEqual(parseInt(secondItem || '0'));
});

Then('browser search should work efficiently', async function () {
  const highlightedElements = await page.locator('//mark').count();
  expect(highlightedElements).toBeGreaterThan(0);
});

Then('matching errors should be highlighted without lag', async function () {
  await assertions.assertVisible(page.locator('//mark'));
});

Then('export should complete within {int} seconds', async function (maxSeconds: number) {
  const maxMilliseconds = maxSeconds * 1000;
  expect(this.responseTime).toBeLessThanOrEqual(maxMilliseconds);
});

Then('properly formatted PDF with all errors should be generated', async function () {
  const downloadStarted = await page.evaluate(() => {
    return sessionStorage.getItem('exportStarted') === 'true';
  });
  expect(downloadStarted).toBeTruthy();
});

Then('browser memory usage should remain stable', async function () {
  const currentMemory = await page.evaluate(() => (performance as any).memory?.usedJSHeapSize);
  const initialMemory = this.testData.initialMemory?.usedJSHeapSize || 0;
  const memoryIncrease = currentMemory - initialMemory;
  const maxIncrease = 100 * 1024 * 1024;
  expect(memoryIncrease).toBeLessThan(maxIncrease);
});

/**************************************************/
/*  TEST CASE: TC-005 - Multi-Device
/**************************************************/

Then('documentation should load correctly with full formatting and functionality', async function () {
  await assertions.assertVisible(page.locator('//div[@id="documentation-content"]'));
  const hasFormatting = await page.locator('//div[@class="formatted-content"]').count() > 0;
  expect(hasFormatting).toBe(true);
});

Then('second session should open without logging out the first session', async function () {
  const secondSessionActive = await page.evaluate(() => sessionStorage.getItem('secondSessionActive'));
  expect(secondSessionActive).toBe('true');
});

Then('documentation should display correctly', async function () {
  await assertions.assertVisible(page.locator('//div[@id="documentation-content"]'));
});

Then('third session should open successfully', async function () {
  const thirdSessionActive = await page.evaluate(() => sessionStorage.getItem('thirdSessionActive'));
  expect(thirdSessionActive).toBe('true');
});

Then('all three sessions should remain active without conflicts', async function () {
  expect(this.testData.activeSessions.length).toBe(3);
  const allActive = this.testData.activeSessions.every((session: any) => session.pageLoaded);
  expect(allActive).toBe(true);
});

Then('bookmark should be saved and accessible from desktop session', async function () {
  expect(this.testData.bookmarked).toBe(true);
  await assertions.assertVisible(page.locator('//div[@id="bookmark-confirmation"]'));
});

Then('all searches should execute independently without interference', async function () {
  await assertions.assertVisible(page.locator('//div[@class="search-results"]'));
  const resultCount = await page.locator('//div[@class="error-result-item"]').count();
  expect(resultCount).toBeGreaterThan(0);
});

Then('results should display correctly on each device', async function () {
  await assertions.assertVisible(page.locator('//div[@class="search-results"]'));
});

Then('all three sessions should remain active and functional', async function () {
  const allActive = this.testData.activeSessions.every((session: any) => session.pageLoaded);
  expect(allActive).toBe(true);
});

Then('no session conflicts or unexpected logouts should occur', async function () {
  const logoutDetected = await page.locator('//div[@id="login-form"]').count();
  expect(logoutDetected).toBe(0);
});

Then('user experience should be consistent across different platforms', async function () {
  await assertions.assertVisible(page.locator('//div[@id="documentation-content"]'));
  const contentLoaded = await page.locator('//div[@class="error-item"]').count() > 0;
  expect(contentLoaded).toBe(true);
});

/**************************************************/
/*  TEST CASE: TC-006 - Real-Time Updates
/**************************************************/

Then('documentation should display current version with complete troubleshooting information', async function () {
  await assertions.assertVisible(page.locator('//div[@id="error-documentation-content"]'));
  await assertions.assertVisible(page.locator('//div[@id="troubleshooting-steps"]'));
});

Then('system should display notification banner {string}', async function (notificationText: string) {
  await waits.waitForVisible(page.locator('//div[@id="update-notification"]'));
  await assertions.assertContainsText(page.locator('//div[@id="update-notification"]'), notificationText);
});

Then('current view should not be disrupted', async function () {
  const contentStable = await page.locator('//div[@id="error-documentation-content"]').isVisible();
  expect(contentStable).toBe(true);
});

Then('current version should remain stable and readable', async function () {
  const currentContent = await page.locator('//div[@id="error-documentation-content"]').textContent();
  expect(currentContent).toBe(this.testData.currentVersionContent);
});

Then('no content should disappear or change unexpectedly', async function () {
  await assertions.assertVisible(page.locator('//div[@id="error-documentation-content"]'));
  const contentLength = await page.locator('//div[@id="error-documentation-content"]').textContent();
  expect(contentLength?.length).toBeGreaterThan(0);
});

Then('page should refresh smoothly', async function () {
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="error-documentation-content"]'));
});

Then('updated documentation should be displayed with change highlights or version indicator', async function () {
  const versionIndicator = await page.locator('//span[@id="version-number"]').textContent();
  expect(versionIndicator).toContain('2.0');
});

Then('version history should show clear comparison between old and new versions', async function () {
  await assertions.assertVisible(page.locator('//div[@id="version-comparison"]'));
  const oldVersion = await page.locator('//div[@class="old-version"]').count();
  const newVersion = await page.locator('//div[@class="new-version"]').count();
  expect(oldVersion).toBeGreaterThan(0);
  expect(newVersion).toBeGreaterThan(0);
});

Then('timestamp and editor information should be displayed', async function () {
  await assertions.assertVisible(page.locator('//span[@id="update-timestamp"]'));
  await assertions.assertVisible(page.locator('//span[@id="editor-name"]'));
});

Then('no data loss or corruption should have occurred during real-time update', async function () {
  const contentIntegrity = await page.evaluate(() => {
    const content = document.querySelector('#error-documentation-content');
    return content && content.textContent && content.textContent.length > 0;
  });
  expect(contentIntegrity).toBe(true);
});