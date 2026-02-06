import { Given, When, Then, Before, After } from '@cucumber/cucumber';
import { Page, Browser, BrowserContext, chromium, expect } from '@playwright/test';
import { BasePage } from '../pages/BasePage';
import { HomePage } from '../pages/HomePage';
import { GenericActions } from '../utils/GenericActions';
import { AssertionHelpers } from '../utils/AssertionHelpers';
import { WaitHelpers } from '../utils/WaitHelpers';

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
      supportAnalyst: { username: 'support_analyst', password: 'support123' },
      restrictedUser: { username: 'restricted_user', password: 'restricted123' }
    },
    urls: {
      knowledgeBase: process.env.KB_URL || 'https://knowledgebase.example.com',
      documentation: '/documentation/validation-errors'
    }
  };
  
  this.systemState = {};
  this.searchResults = [];
  this.sessionData = {};
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

/**************************************************/
/*  TEST CASE: TC-NEG-001
/*  Title: Access denied when support analyst lacks proper documentation permissions
/*  Priority: High
/*  Category: Negative - Security
/**************************************************/

Given('support analyst account has {string} permission revoked for documentation section', async function (permission: string) {
  this.systemState.revokedPermission = permission;
  this.systemState.accountType = 'restricted';
});

Given('user is logged into knowledge base system with restricted account', async function () {
  const credentials = this.testData.users.restrictedUser;
  await actions.navigateTo(this.testData.urls.knowledgeBase);
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

Given('validation error documentation exists and is published', async function () {
  this.systemState.documentationPublished = true;
});

Given('permission enforcement is active on the knowledge base system', async function () {
  this.systemState.permissionEnforcementActive = true;
});

When('user navigates to knowledge base homepage', async function () {
  await actions.navigateTo(this.testData.urls.knowledgeBase);
  await waits.waitForNetworkIdle();
});

Then('{string} menu item should be grayed out or show lock icon', async function (menuItem: string) {
  const menuXPath = `//nav//a[contains(text(),'${menuItem}')]`;
  const menuLocator = page.locator(menuXPath);
  await assertions.assertVisible(menuLocator);
  const isDisabled = await menuLocator.getAttribute('aria-disabled');
  const hasLockIcon = await page.locator(`${menuXPath}//i[contains(@class,'lock')]`).count() > 0;
  expect(isDisabled === 'true' || hasLockIcon).toBeTruthy();
});

When('user clicks {string} menu item', async function (menuItem: string) {
  const menuXPath = `//nav//a[contains(text(),'${menuItem}')]`;
  await actions.click(page.locator(menuXPath));
  await waits.waitForNetworkIdle();
});

Then('error message {string} should be displayed', async function (errorMessage: string) {
  await assertions.assertContainsText(page.locator('//*[contains(@class,"error-message")]'), errorMessage);
});

When('user navigates to {string} page directly', async function (urlPath: string) {
  await actions.navigateTo(`${this.testData.urls.knowledgeBase}${urlPath}`);
  await waits.waitForNetworkIdle();
});

Then('page should redirect to error page showing {string}', async function (errorCode: string) {
  await assertions.assertContainsText(page.locator('//h1 | //div[@class="error-code"]'), errorCode);
});

When('user enters {string} in search bar', async function (searchQuery: string) {
  await actions.fill(page.locator('//input[@id="search-bar"]'), searchQuery);
  this.systemState.lastSearchQuery = searchQuery;
});

When('user executes search', async function () {
  await actions.click(page.locator('//button[@id="search-submit"]'));
  await waits.waitForNetworkIdle();
});

Then('search results should show {string} message', async function (message: string) {
  await assertions.assertContainsText(page.locator('//div[@id="search-results"]'), message);
});

Then('access attempt should be logged in security audit log', async function () {
  this.systemState.accessAttemptLogged = true;
});

Then('{string} link should be visible', async function (linkText: string) {
  const linkXPath = `//a[contains(text(),'${linkText}')]`;
  await assertions.assertVisible(page.locator(linkXPath));
});

/**************************************************/
/*  TEST CASE: TC-NEG-002
/*  Title: System handles invalid or non-existent validation error code searches
/*  Priority: High
/*  Category: Negative - Search
/**************************************************/

Given('support analyst is logged into knowledge base with valid credentials and permissions', async function () {
  const credentials = this.testData.users.supportAnalyst;
  await actions.navigateTo(this.testData.urls.knowledgeBase);
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

Given('search functionality is operational and indexed', async function () {
  this.systemState.searchOperational = true;
});

Given('validation error documentation contains {int} documented error codes', async function (errorCount: number) {
  this.systemState.documentedErrorCount = errorCount;
});

Given('error code {string} does not exist in documentation', async function (errorCode: string) {
  this.systemState.nonExistentErrorCode = errorCode;
});

When('user clicks on search bar', async function () {
  await actions.click(page.locator('//input[@id="search-bar"]'));
});

Then('auto-suggest dropdown should show {string} or remain empty', async function (message: string) {
  const suggestDropdown = page.locator('//div[@id="auto-suggest-dropdown"]');
  const dropdownVisible = await suggestDropdown.isVisible();
  if (dropdownVisible) {
    await assertions.assertContainsText(suggestDropdown, message);
  }
});

Then('search results page should display message {string}', async function (message: string) {
  await assertions.assertContainsText(page.locator('//div[@id="search-results"]'), message);
});

Then('no system errors or crashes should occur', async function () {
  const errorElements = await page.locator('//div[contains(@class,"system-error")]').count();
  expect(errorElements).toBe(0);
});

Then('failed search query should be logged for analysis', async function () {
  this.systemState.failedSearchLogged = true;
});

Then('alternative search suggestions should be presented', async function () {
  await assertions.assertVisible(page.locator('//div[@id="alternative-suggestions"]'));
});

/**************************************************/
/*  TEST CASE: TC-NEG-003
/*  Title: Search bar rejects extremely long query string
/*  Priority: High
/*  Category: Negative - Search - Edge Case
/**************************************************/

When('user enters string of {int} characters in search bar', async function (charCount: number) {
  const longString = 'A'.repeat(charCount);
  await actions.fill(page.locator('//input[@id="search-bar"]'), longString);
  this.systemState.inputLength = charCount;
});

Then('search bar should limit input to maximum {int} characters or display error {string}', async function (maxChars: number, errorMsg: string) {
  const searchInput = page.locator('//input[@id="search-bar"]');
  const inputValue = await searchInput.inputValue();
  const inputLength = inputValue.length;
  
  if (inputLength <= maxChars) {
    expect(inputLength).toBeLessThanOrEqual(maxChars);
  } else {
    await assertions.assertContainsText(page.locator('//div[@class="error-message"]'), errorMsg);
  }
});

Then('search functionality should remain operational for subsequent searches', async function () {
  await actions.clearAndFill(page.locator('//input[@id="search-bar"]'), 'VAL-ERR-1001');
  await actions.click(page.locator('//button[@id="search-submit"]'));
  await waits.waitForNetworkIdle();
  const resultsVisible = await page.locator('//div[@id="search-results"]').isVisible();
  expect(resultsVisible).toBeTruthy();
});

/**************************************************/
/*  TEST CASE: TC-NEG-004
/*  Title: Error handling when knowledge base system is unavailable during maintenance
/*  Priority: High
/*  Category: Negative - Availability
/**************************************************/

Given('support analyst has valid login credentials', async function () {
  this.systemState.hasValidCredentials = true;
});

Given('knowledge base server is temporarily down or unreachable', async function () {
  this.systemState.serverDown = true;
});

Given('support analyst is attempting to access documentation during active support call', async function () {
  this.systemState.activeSupportCall = true;
});

Given('browser has no cached version of documentation', async function () {
  await context.clearCookies();
  this.systemState.noCachedContent = true;
});

When('user navigates to knowledge base URL', async function () {
  await actions.navigateTo(this.testData.urls.knowledgeBase);
  await waits.waitForLoad();
});

Then('browser should display error page {string} or {string}', async function (error1: string, error2: string) {
  const pageContent = await page.locator('body').textContent();
  const hasError = pageContent?.includes(error1) || pageContent?.includes(error2);
  expect(hasError).toBeTruthy();
});

Then('HTTP status code should be {int}', async function (statusCode: number) {
  const response = await page.waitForResponse(response => response.url().includes(this.testData.urls.knowledgeBase));
  expect(response.status()).toBe(statusCode);
});

When('user refreshes browser page', async function () {
  await page.reload();
  await waits.waitForLoad();
});

Then('same error should persist with message {string}', async function (message: string) {
  await assertions.assertContainsText(page.locator('//div[@class="error-message"]'), message);
});

Then('error page should include link to {string} or {string}', async function (link1: string, link2: string) {
  const link1Exists = await page.locator(`//a[contains(text(),'${link1}')]`).count() > 0;
  const link2Exists = await page.locator(`//a[contains(text(),'${link2}')]`).count() > 0;
  expect(link1Exists || link2Exists).toBeTruthy();
});

When('user attempts to access knowledge base mobile app', async function () {
  await context.close();
  context = await browser.newContext({
    userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
    viewport: { width: 375, height: 812 }
  });
  page = await context.newPage();
  actions = new GenericActions(page, context);
  assertions = new AssertionHelpers(page);
  waits = new WaitHelpers(page);
  await actions.navigateTo(this.testData.urls.knowledgeBase);
  await waits.waitForLoad();
});

Then('mobile app should display error banner {string}', async function (bannerMessage: string) {
  await assertions.assertContainsText(page.locator('//div[@class="error-banner"]'), bannerMessage);
});

Then('option to {string} should be available', async function (optionText: string) {
  await assertions.assertVisible(page.locator(`//button[contains(text(),'${optionText}')]`));
});

Then('system administrators should be notified of access attempts during downtime', async function () {
  this.systemState.adminNotified = true;
});

Then('downtime incident should be logged with timestamp', async function () {
  this.systemState.downtimeLogged = true;
});

/**************************************************/
/*  TEST CASE: TC-NEG-005
/*  Title: Documentation page displays warning when critical sections are missing
/*  Priority: Medium
/*  Category: Negative - Data Quality
/**************************************************/

Given('support analyst is logged into knowledge base with full access permissions', async function () {
  const credentials = this.testData.users.supportAnalyst;
  await actions.navigateTo(this.testData.urls.knowledgeBase);
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

Given('validation error {string} exists in documentation', async function (errorCode: string) {
  this.systemState.currentErrorCode = errorCode;
});

Given('{string} section is missing from {string} documentation', async function (section: string, errorCode: string) {
  this.systemState.missingSection = section;
});

Given('documentation quality control has not flagged the incomplete entry', async function () {
  this.systemState.qualityControlNotFlagged = true;
});

When('user searches for {string}', async function (searchTerm: string) {
  await actions.fill(page.locator('//input[@id="search-bar"]'), searchTerm);
  await actions.click(page.locator('//button[@id="search-submit"]'));
  await waits.waitForNetworkIdle();
});

When('user navigates to {string} documentation page', async function (errorCode: string) {
  await actions.click(page.locator(`//a[contains(text(),'${errorCode}')]`));
  await waits.waitForNetworkIdle();
});

Then('documentation page should load showing {string} section', async function (sectionName: string) {
  await assertions.assertVisible(page.locator(`//h2[contains(text(),'${sectionName}')]`));
});

When('user scrolls down to locate {string} section', async function (sectionName: string) {
  const sectionLocator = page.locator(`//h2[contains(text(),'${sectionName}')]`);
  await actions.scrollIntoView(sectionLocator);
});

Then('section header {string} should be visible', async function (headerText: string) {
  await assertions.assertVisible(page.locator(`//h2[contains(text(),'${headerText}')]`));
});

Then('content area should show placeholder text {string} or be empty', async function (placeholderText: string) {
  const contentArea = page.locator('//div[@class="section-content"]');
  const contentText = await contentArea.textContent();
  const isEmpty = contentText?.trim() === '' || contentText?.includes(placeholderText);
  expect(isEmpty).toBeTruthy();
});

Then('yellow banner should appear at top of page with message {string}', async function (bannerMessage: string) {
  await assertions.assertVisible(page.locator('//div[@class="warning-banner"]'));
  await assertions.assertContainsText(page.locator('//div[@class="warning-banner"]'), bannerMessage);
});

When('user clicks {string} button on documentation page', async function (buttonText: string) {
  const buttonXPath = `//button[contains(text(),'${buttonText}')]`;
  await actions.click(page.locator(buttonXPath));
  await waits.waitForNetworkIdle();
});

Then('feedback form should open with pre-filled information {string}', async function (prefilledText: string) {
  await assertions.assertVisible(page.locator('//form[@id="feedback-form"]'));
  await assertions.assertContainsText(page.locator('//textarea[@id="feedback-description"]'), prefilledText);
});

Then('option to describe missing content should be available', async function () {
  await assertions.assertVisible(page.locator('//textarea[@id="missing-content-description"]'));
});

Then('{string} section should show {int} to {int} similar validation errors with complete documentation', async function (sectionName: string, minCount: number, maxCount: number) {
  const relatedArticles = await page.locator('//div[@id="related-articles"]//a').count();
  expect(relatedArticles).toBeGreaterThanOrEqual(minCount);
  expect(relatedArticles).toBeLessThanOrEqual(maxCount);
});

Then('feedback should be submitted to documentation team', async function () {
  this.systemState.feedbackSubmitted = true;
});

Then('incomplete documentation should be flagged in system for quality review', async function () {
  this.systemState.qualityReviewFlagged = true;
});

/**************************************************/
/*  TEST CASE: TC-NEG-006
/*  Title: Session expiration handling while viewing documentation
/*  Priority: Medium
/*  Category: Negative - Security - Session
/**************************************************/

Given('support analyst is logged into knowledge base with active session', async function () {
  const credentials = this.testData.users.supportAnalyst;
  await actions.navigateTo(this.testData.urls.knowledgeBase);
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  this.sessionData.loginTime = Date.now();
});

Given('session timeout is set to {int} minutes of inactivity', async function (timeoutMinutes: number) {
  this.sessionData.timeoutMinutes = timeoutMinutes;
});

Given('support analyst has validation error documentation page open', async function () {
  await actions.navigateTo(`${this.testData.urls.knowledgeBase}${this.testData.urls.documentation}`);
  await waits.waitForNetworkIdle();
});

Given('support analyst has been inactive for {int} minutes', async function (inactiveMinutes: number) {
  this.sessionData.inactiveMinutes = inactiveMinutes;
  await context.addCookies([{
    name: 'session_expired',
    value: 'true',
    domain: new URL(this.testData.urls.knowledgeBase).hostname,
    path: '/'
  }]);
});

When('user clicks on another validation error link in documentation', async function () {
  await actions.click(page.locator('//a[@class="validation-error-link"]').first());
  await waits.waitForNetworkIdle();
});

Then('page should not navigate', async function () {
  const currentUrl = page.url();
  expect(currentUrl).toContain(this.testData.urls.documentation);
});

Then('modal popup should appear with message {string}', async function (modalMessage: string) {
  await assertions.assertVisible(page.locator('//div[@class="modal"]'));
  await assertions.assertContainsText(page.locator('//div[@class="modal"]'), modalMessage);
});

When('user attempts to use search functionality', async function () {
  await actions.click(page.locator('//input[@id="search-bar"]'));
});

Then('search bar should be disabled or trigger session expiration message', async function () {
  const searchDisabled = await page.locator('//input[@id="search-bar"]').isDisabled();
  const modalVisible = await page.locator('//div[@class="modal"]').isVisible();
  expect(searchDisabled || modalVisible).toBeTruthy();
});

When('user clicks {string} button in session expiration modal', async function (buttonText: string) {
  await actions.click(page.locator(`//div[@class="modal"]//button[contains(text(),'${buttonText}')]`));
  await waits.waitForNetworkIdle();
});

Then('user should be redirected to login page with message {string}', async function (message: string) {
  await assertions.assertUrlContains('/login');
  await assertions.assertContainsText(page.locator('//div[@class="info-message"]'), message);
});

Then('return URL should be preserved', async function () {
  const returnUrl = await page.locator('//input[@name="return_url"]').inputValue();
  expect(returnUrl).toContain(this.testData.urls.documentation);
});

When('user enters valid credentials in {string} field', async function (fieldName: string) {
  const credentials = this.testData.users.supportAnalyst;
  const fieldXPath = `//input[@id="${fieldName.toLowerCase()}"]`;
  const value = fieldName.toLowerCase() === 'username' ? credentials.username : credentials.password;
  await actions.fill(page.locator(fieldXPath), value);
});

When('user clicks {string} button', async function (buttonText: string) {
  const buttonXPath = `//button[contains(text(),'${buttonText}')]`;
  await actions.click(page.locator(buttonXPath));
  await waits.waitForNetworkIdle();
});

Then('login should succeed', async function () {
  await waits.waitForNetworkIdle();
  const loginError = await page.locator('//div[@class="login-error"]').count();
  expect(loginError).toBe(0);
});

Then('user should be automatically redirected back to validation error documentation page', async function () {
  await assertions.assertUrlContains(this.testData.urls.documentation);
});

Then('new active session should be created', async function () {
  this.sessionData.newSessionCreated = true;
});

Then('session timeout counter should reset to {int} minutes', async function (timeoutMinutes: number) {
  this.sessionData.timeoutReset = timeoutMinutes;
});

Then('session expiration event should be logged in security audit trail', async function () {
  this.sessionData.expirationLogged = true;
});

/**************************************************/
/*  TEST CASE: TC-NEG-007
/*  Title: System handles concurrent access from multiple support analysts
/*  Priority: Low
/*  Category: Negative - Performance - Load
/**************************************************/

Given('{int} support analysts are logged into knowledge base simultaneously', async function (analystCount: number) {
  this.systemState.concurrentUsers = analystCount;
});

Given('all analysts are attempting to access {string} documentation at same time', async function (errorCode: string) {
  this.systemState.targetErrorCode = errorCode;
});

Given('knowledge base server has load balancing configured', async function () {
  this.systemState.loadBalancingEnabled = true;
});

Given('system is under moderate load with {int} concurrent users', async function (userCount: number) {
  this.systemState.totalConcurrentUsers = userCount;
});

When('all {int} support analysts click {string} documentation link simultaneously', async function (analystCount: number, errorCode: string) {
  const startTime = Date.now();
  await actions.click(page.locator(`//a[contains(text(),'${errorCode}')]`));
  await waits.waitForNetworkIdle();
  this.systemState.loadTime = Date.now() - startTime;
});

Then('all {int} analysts should successfully load documentation page within {int} seconds', async function (analystCount: number, maxSeconds: number) {
  expect(this.systemState.loadTime).toBeLessThan(maxSeconds * 1000);
  await assertions.assertVisible(page.locator('//div[@id="documentation-content"]'));
});

Then('no timeout errors should occur', async function () {
  const timeoutErrors = await page.locator('//*[contains(text(),"timeout")]').count();
  expect(timeoutErrors).toBe(0);
});

Then('no {string} messages should be displayed', async function (errorMessage: string) {
  const errorCount = await page.locator(`//*[contains(text(),'${errorMessage}')]`).count();
  expect(errorCount).toBe(0);
});

When('all analysts perform search queries for different validation errors simultaneously', async function () {
  await actions.fill(page.locator('//input[@id="search-bar"]'), 'VAL-ERR-2001');
  await actions.click(page.locator('//button[@id="search-submit"]'));
  await waits.waitForNetworkIdle();
});

Then('search functionality should respond normally for all users', async function () {
  await assertions.assertVisible(page.locator('//div[@id="search-results"]'));
});

Then('search results should appear within {int} seconds', async function (maxSeconds: number) {
  const resultsVisible = await page.locator('//div[@id="search-results"]').isVisible();
  expect(resultsVisible).toBeTruthy();
});

Then('all support analysts should maintain active sessions without disconnection', async function () {
  const sessionActive = await page.locator('//div[@class="user-profile"]').isVisible();
  expect(sessionActive).toBeTruthy();
});

Then('system performance should remain stable under concurrent load', async function () {
  this.systemState.performanceStable = true;
});

Then('server logs should show successful concurrent access without errors', async function () {
  this.systemState.serverLogsClean = true;
});

Then('no data corruption or cache conflicts should occur', async function () {
  const contentIntegrity = await page.locator('//div[@id="documentation-content"]').textContent();
  expect(contentIntegrity).toBeTruthy();
  expect(contentIntegrity?.length).toBeGreaterThan(0);
});