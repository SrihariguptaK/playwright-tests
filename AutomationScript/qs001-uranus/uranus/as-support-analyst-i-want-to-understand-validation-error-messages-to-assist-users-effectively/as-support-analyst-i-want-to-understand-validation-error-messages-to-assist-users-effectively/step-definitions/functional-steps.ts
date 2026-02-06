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
      supportAnalyst: { username: 'support_analyst', password: 'analyst123' },
      manager: { username: 'team_lead', password: 'manager123' }
    },
    errorCodes: {
      'VAL-ERR-1001': 'Invalid Date Format',
      'VAL-ERR-2005': 'Required Field Missing',
      'VAL-ERR-3010': 'Invalid Phone Number Format'
    }
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
/*  Setup: Login and documentation availability
/**************************************************/

Given('support analyst is logged into the support knowledge base system', async function () {
  const credentials = this.testData?.users?.supportAnalyst || { username: 'support_analyst', password: 'analyst123' };
  await actions.navigateTo(process.env.BASE_URL || 'https://support-kb.example.com');
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

Given('validation error documentation has been published in the knowledge base', async function () {
  await assertions.assertVisible(page.locator('//div[@id="documentation-section"]'));
});

/**************************************************/
/*  TEST CASE: TC-001
/*  Title: Access validation error documentation from knowledge base
/*  Priority: High
/*  Category: Functional
/**************************************************/

Given('support analyst has {string} permissions for documentation section', async function (permission: string) {
  this.userPermission = permission;
  await assertions.assertVisible(page.locator('//div[@id="documentation-section"]'));
});

Given('browser is {string} version {string} or higher', async function (browserName: string, version: string) {
  this.browserInfo = { name: browserName, version: version };
});

/**************************************************/
/*  TEST CASE: TC-002
/*  Title: Search for specific validation error by error code
/*  Priority: High
/*  Category: Functional
/**************************************************/

Given('validation error documentation contains at least {int} documented error codes', async function (count: number) {
  this.expectedErrorCount = count;
});

Given('search functionality is enabled and indexed', async function () {
  await assertions.assertVisible(page.locator('//input[@id="search-bar"]'));
});

Given('support analyst has received user query with error code {string}', async function (errorCode: string) {
  this.currentErrorCode = errorCode;
});

/**************************************************/
/*  TEST CASE: TC-003
/*  Title: Guide user through resolution steps using troubleshooting guide
/*  Priority: High
/*  Category: Functional
/**************************************************/

Given('support analyst has accessed validation error documentation for {string}', async function (errorCode: string) {
  const errorXPath = `//div[@id='error-${errorCode.toLowerCase().replace(/[:\s]+/g, '-')}']`;
  await actions.click(page.locator(errorXPath));
  await waits.waitForNetworkIdle();
});

Given('support analyst is on active support call with user', async function () {
  this.supportCallActive = true;
});

Given('documentation includes step-by-step troubleshooting guide with screenshots', async function () {
  await assertions.assertVisible(page.locator('//section[@id="troubleshooting-steps"]'));
  await assertions.assertVisible(page.locator('//img[@class="screenshot"]'));
});

Given('support ticket system is open in separate browser tab', async function () {
  const newPage = await context.newPage();
  await newPage.goto(process.env.TICKET_SYSTEM_URL || 'https://tickets.example.com');
  this.ticketPage = newPage;
});

/**************************************************/
/*  TEST CASE: TC-004
/*  Title: Access validation error documentation on mobile device
/*  Priority: Medium
/*  Category: Functional - Mobile
/**************************************************/

Given('support analyst is logged into knowledge base mobile app', async function () {
  await context.close();
  context = await browser.newContext({
    viewport: { width: 375, height: 812 },
    userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
    isMobile: true,
    hasTouch: true
  });
  page = await context.newPage();
  actions = new GenericActions(page, context);
  assertions = new AssertionHelpers(page);
  waits = new WaitHelpers(page);
  
  const credentials = this.testData?.users?.supportAnalyst || { username: 'support_analyst', password: 'analyst123' };
  await actions.navigateTo(process.env.MOBILE_APP_URL || 'https://mobile-kb.example.com');
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

Given('mobile device has active internet connection', async function () {
  this.networkStatus = 'online';
});

Given('validation error documentation is mobile-responsive', async function () {
  await assertions.assertVisible(page.locator('//meta[@name="viewport"]'));
});

Given('support analyst has {string} permission enabled', async function (permission: string) {
  this.mobilePermission = permission;
});

/**************************************************/
/*  TEST CASE: TC-005
/*  Title: Track documentation usage metrics and support efficiency improvements
/*  Priority: Medium
/*  Category: Functional - Analytics
/**************************************************/

Given('support team lead is logged in with {string} role', async function (role: string) {
  const credentials = this.testData?.users?.manager || { username: 'team_lead', password: 'manager123' };
  await actions.navigateTo(process.env.BASE_URL || 'https://support-kb.example.com');
  await waits.waitForNetworkIdle();
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
  this.userRole = role;
});

Given('support team lead has analytics access permissions', async function () {
  await assertions.assertVisible(page.locator('//a[@id="analytics-dashboard"]'));
});

Given('validation error documentation has been live for at least {int} days', async function (days: number) {
  this.documentationLiveDays = days;
});

Given('support ticket system is integrated with knowledge base', async function () {
  this.systemIntegrated = true;
});

Given('at least {int} validation error tickets have been resolved', async function (ticketCount: number) {
  this.resolvedTickets = ticketCount;
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  GENERIC NAVIGATION STEPS
/**************************************************/

When('support analyst navigates to the knowledge base homepage', async function () {
  await actions.navigateTo(process.env.KB_HOME_URL || 'https://support-kb.example.com/home');
  await waits.waitForNetworkIdle();
});

When('support analyst clicks {string} menu item in left navigation panel', async function (menuItem: string) {
  const menuXPath = `//nav[@id='left-navigation']//a[contains(text(),'${menuItem}')]`;
  await actions.click(page.locator(menuXPath));
  await waits.waitForNetworkIdle();
});

When('support analyst clicks {string} subcategory link', async function (subcategory: string) {
  const subcategoryXPath = `//a[@id='subcategory-${subcategory.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(subcategoryXPath));
  await waits.waitForNetworkIdle();
});

When('support analyst clicks on validation error entry {string}', async function (errorEntry: string) {
  const entryXPath = `//div[@class='error-entry'][contains(text(),'${errorEntry}')]`;
  await actions.click(page.locator(entryXPath));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  GENERIC SEARCH STEPS
/**************************************************/

When('support analyst clicks on search bar at top of interface', async function () {
  await actions.click(page.locator('//input[@id="search-bar"]'));
});

When('support analyst enters {string} in search bar', async function (searchText: string) {
  await actions.fill(page.locator('//input[@id="search-bar"]'), searchText);
  await waits.waitForVisible(page.locator('//div[@id="auto-suggest-dropdown"]'));
});

When('support analyst presses Enter key', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('support analyst clicks on search result {string}', async function (resultText: string) {
  const resultXPath = `//div[@class='search-result'][contains(text(),'${resultText}')]`;
  await actions.click(page.locator(resultXPath));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  GENERIC SCROLL AND INTERACTION STEPS
/**************************************************/

When('support analyst scrolls down to {string} section', async function (sectionName: string) {
  const sectionXPath = `//section[@id='${sectionName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.scrollIntoView(page.locator(sectionXPath));
});

When('support analyst reads {string} section for {string}', async function (sectionName: string, errorCode: string) {
  const sectionXPath = `//section[@id='${sectionName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.scrollIntoView(page.locator(sectionXPath));
  await assertions.assertVisible(page.locator(sectionXPath));
});

When('support analyst reviews {string} section', async function (sectionName: string) {
  const sectionXPath = `//section[@id='${sectionName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.scrollIntoView(page.locator(sectionXPath));
  await assertions.assertVisible(page.locator(sectionXPath));
});

When('support analyst follows {string} section', async function (sectionName: string) {
  const sectionXPath = `//section[@id='${sectionName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.scrollIntoView(page.locator(sectionXPath));
});

When('support analyst instructs user to check step {string}', async function (stepText: string) {
  const stepXPath = `//div[@class='troubleshooting-step'][contains(text(),'${stepText}')]`;
  await actions.scrollIntoView(page.locator(stepXPath));
  await assertions.assertVisible(page.locator(stepXPath));
});

When('support analyst guides user through step {string}', async function (stepText: string) {
  const stepXPath = `//div[@class='troubleshooting-step'][contains(text(),'${stepText}')]`;
  await actions.scrollIntoView(page.locator(stepXPath));
  await assertions.assertVisible(page.locator(stepXPath));
});

When('support analyst follows step {string}', async function (stepText: string) {
  const stepXPath = `//div[@class='troubleshooting-step'][contains(text(),'${stepText}')]`;
  await actions.scrollIntoView(page.locator(stepXPath));
});

When('support analyst documents resolution using {string}', async function (templateName: string) {
  const templateXPath = `//div[@id='${templateName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.scrollIntoView(page.locator(templateXPath));
  await assertions.assertVisible(page.locator(templateXPath));
});

/**************************************************/
/*  MOBILE SPECIFIC STEPS
/**************************************************/

When('support analyst opens knowledge base mobile app', async function () {
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="mobile-app-container"]'));
});

When('support analyst taps on menu icon in top-left corner', async function () {
  await actions.click(page.locator('//button[@id="mobile-menu-icon"]'));
  await waits.waitForVisible(page.locator('//nav[@id="mobile-navigation-menu"]'));
});

When('support analyst taps on {string} menu item', async function (menuItem: string) {
  const menuXPath = `//nav[@id='mobile-navigation-menu']//a[contains(text(),'${menuItem}')]`;
  await actions.click(page.locator(menuXPath));
  await waits.waitForNetworkIdle();
});

When('support analyst taps on {string} category', async function (category: string) {
  const categoryXPath = `//div[@class='category-item'][contains(text(),'${category}')]`;
  await actions.click(page.locator(categoryXPath));
  await waits.waitForNetworkIdle();
});

When('support analyst taps on {string} entry', async function (entryText: string) {
  const entryXPath = `//div[@class='error-entry'][contains(text(),'${entryText}')]`;
  await actions.click(page.locator(entryXPath));
  await waits.waitForNetworkIdle();
});

When('support analyst taps on {string} section', async function (sectionName: string) {
  const sectionXPath = `//div[@class='collapsible-section'][@data-section='${sectionName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(sectionXPath));
  await waits.waitForVisible(page.locator(`${sectionXPath}//div[@class='section-content']`));
});

/**************************************************/
/*  ANALYTICS DASHBOARD STEPS
/**************************************************/

When('support team lead navigates to {string} from main menu', async function (menuItem: string) {
  const menuXPath = `//nav[@id='main-menu']//a[contains(text(),'${menuItem}')]`;
  await actions.click(page.locator(menuXPath));
  await waits.waitForNetworkIdle();
});

When('support team lead clicks on {string} filter', async function (filterName: string) {
  const filterXPath = `//button[@id='filter-${filterName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(filterXPath));
  await waits.waitForNetworkIdle();
});

When('support team lead reviews {string} chart', async function (chartName: string) {
  const chartXPath = `//div[@id='chart-${chartName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.scrollIntoView(page.locator(chartXPath));
  await assertions.assertVisible(page.locator(chartXPath));
});

When('support team lead clicks on {string} metric tile', async function (metricName: string) {
  const metricXPath = `//div[@class='metric-tile'][@data-metric='${metricName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(metricXPath));
  await waits.waitForNetworkIdle();
});

When('support team lead scrolls to {string} section', async function (sectionName: string) {
  const sectionXPath = `//section[@id='${sectionName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.scrollIntoView(page.locator(sectionXPath));
});

When('support team lead clicks {string} button', async function (buttonText: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  const buttons = page.locator(buttonXPath);
  if (await buttons.count() > 0) {
    await actions.click(buttons);
  } else {
    await actions.click(page.locator(`//button[contains(text(),'${buttonText}')]`));
  }
  await waits.waitForNetworkIdle();
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  GENERIC VISIBILITY ASSERTIONS
/**************************************************/

Then('knowledge base homepage should load successfully', async function () {
  await assertions.assertVisible(page.locator('//div[@id="kb-homepage"]'));
});

Then('search bar should be visible', async function () {
  await assertions.assertVisible(page.locator('//input[@id="search-bar"]'));
});

Then('navigation menu should be visible', async function () {
  await assertions.assertVisible(page.locator('//nav[@id="left-navigation"]'));
});

Then('{string} section should expand', async function (sectionName: string) {
  const sectionXPath = `//div[@id='section-${sectionName.toLowerCase().replace(/\s+/g, '-')}'][@class*='expanded']`;
  await assertions.assertVisible(page.locator(sectionXPath));
});

Then('subcategory {string} should be visible', async function (subcategory: string) {
  const subcategoryXPath = `//a[@id='subcategory-${subcategory.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(subcategoryXPath));
});

Then('validation error documentation page should load', async function () {
  await assertions.assertVisible(page.locator('//div[@id="validation-error-documentation"]'));
});

Then('list of common validation errors should be displayed', async function () {
  await assertions.assertVisible(page.locator('//ul[@id="common-validation-errors-list"]'));
  const errorCount = await page.locator('//ul[@id="common-validation-errors-list"]//li').count();
  expect(errorCount).toBeGreaterThan(0);
});

Then('section {string} should be visible', async function (sectionName: string) {
  const sectionXPath = `//section[@id='${sectionName.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(sectionXPath));
});

Then('detailed explanation should expand', async function () {
  await assertions.assertVisible(page.locator('//div[@class="detailed-explanation expanded"]'));
});

Then('error code should be displayed', async function () {
  await assertions.assertVisible(page.locator('//span[@class="error-code"]'));
});

Then('error description should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@class="error-description"]'));
});

Then('common causes should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="common-causes"]'));
});

Then('step-by-step resolution instructions should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="resolution-instructions"]'));
  const stepCount = await page.locator('//div[@id="resolution-instructions"]//li').count();
  expect(stepCount).toBeGreaterThan(0);
});

/**************************************************/
/*  SEARCH FUNCTIONALITY ASSERTIONS
/**************************************************/

Then('search bar should become active', async function () {
  const searchBar = page.locator('//input[@id="search-bar"]');
  await assertions.assertVisible(searchBar);
  const isFocused = await searchBar.evaluate(el => el === document.activeElement);
  expect(isFocused).toBe(true);
});

Then('placeholder text {string} should be displayed', async function (placeholderText: string) {
  const searchBar = page.locator('//input[@id="search-bar"]');
  const placeholder = await searchBar.getAttribute('placeholder');
  expect(placeholder).toContain(placeholderText);
});

Then('auto-suggest dropdown should appear', async function () {
  await assertions.assertVisible(page.locator('//div[@id="auto-suggest-dropdown"]'));
});

Then('matching result {string} should be displayed', async function (resultText: string) {
  const resultXPath = `//div[@id='auto-suggest-dropdown']//div[contains(text(),'${resultText}')]`;
  await assertions.assertVisible(page.locator(resultXPath));
});

Then('search results page should display', async function () {
  await assertions.assertVisible(page.locator('//div[@id="search-results-page"]'));
});

Then('{string} should be top result', async function (errorCode: string) {
  const topResultXPath = '//div[@id="search-results-page"]//div[@class="search-result"][1]';
  await assertions.assertContainsText(page.locator(topResultXPath), errorCode);
});

Then('error code should be highlighted', async function () {
  await assertions.assertVisible(page.locator('//span[@class="highlighted-error-code"]'));
});

Then('detailed error documentation page should open', async function () {
  await assertions.assertVisible(page.locator('//div[@id="detailed-error-documentation"]'));
});

Then('{int} common causes should be listed', async function (count: number) {
  const causesCount = await page.locator('//div[@id="common-causes"]//li').count();
  expect(causesCount).toBe(count);
});

Then('{int} troubleshooting steps should be displayed', async function (count: number) {
  const stepsCount = await page.locator('//div[@id="troubleshooting-steps"]//li').count();
  expect(stepsCount).toBe(count);
});

Then('screenshots should be visible', async function () {
  const screenshotCount = await page.locator('//img[@class="screenshot"]').count();
  expect(screenshotCount).toBeGreaterThan(0);
});

Then('numbered steps should be visible', async function () {
  await assertions.assertVisible(page.locator('//ol[@class="numbered-steps"]'));
});

Then('expected format examples should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@class="format-examples"]'));
});

Then('links to related documentation should be visible', async function () {
  const linkCount = await page.locator('//div[@class="related-documentation"]//a').count();
  expect(linkCount).toBeGreaterThan(0);
});

/**************************************************/
/*  TROUBLESHOOTING GUIDE ASSERTIONS
/**************************************************/

Then('error description {string} should be displayed', async function (description: string) {
  await assertions.assertContainsText(page.locator('//div[@class="error-description"]'), description);
});

Then('{int} causes should be listed', async function (count: number) {
  const causesCount = await page.locator('//div[@id="common-causes"]//li').count();
  expect(causesCount).toBe(count);
});

Then('cause {string} should be displayed', async function (causeText: string) {
  const causeXPath = `//div[@id='common-causes']//li[contains(text(),'${causeText}')]`;
  await assertions.assertVisible(page.locator(causeXPath));
});

Then('clear instruction with screenshot should be provided', async function () {
  await assertions.assertVisible(page.locator('//div[@class="instruction-with-screenshot"]'));
  await assertions.assertVisible(page.locator('//div[@class="instruction-with-screenshot"]//img'));
});

Then('required field indicators should be shown', async function () {
  await assertions.assertVisible(page.locator('//span[@class="required-indicator"]'));
});

Then('browser-specific cache clearing instructions should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@class="browser-specific-instructions"]'));
});

Then('instructions for {string} should be visible', async function (browserName: string) {
  const instructionXPath = `//div[@class='browser-instructions'][@data-browser='${browserName.toLowerCase()}']`;
  await assertions.assertVisible(page.locator(instructionXPath));
});

Then('incognito mode instructions should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="incognito-instructions"]'));
});

Then('keyboard shortcuts for different browsers should be shown', async function () {
  await assertions.assertVisible(page.locator('//div[@class="keyboard-shortcuts"]'));
});

Then('template text {string} should be provided', async function (templateText: string) {
  await assertions.assertContainsText(page.locator('//div[@id="resolution-template"]'), templateText);
});

Then('support analyst can copy template text', async function () {
  await assertions.assertVisible(page.locator('//button[@id="copy-template"]'));
});

/**************************************************/
/*  MOBILE SPECIFIC ASSERTIONS
/**************************************************/

Then('navigation menu should slide out from left', async function () {
  await assertions.assertVisible(page.locator('//nav[@id="mobile-navigation-menu"][@class*="open"]'));
});

Then('menu option {string} should be visible', async function (menuOption: string) {
  const menuXPath = `//nav[@id='mobile-navigation-menu']//a[contains(text(),'${menuOption}')]`;
  await assertions.assertVisible(page.locator(menuXPath));
});

Then('documentation categories list should appear', async function () {
  await assertions.assertVisible(page.locator('//div[@id="documentation-categories-list"]'));
});

Then('{string} category should be visible', async function (category: string) {
  const categoryXPath = `//div[@class='category-item'][contains(text(),'${category}')]`;
  await assertions.assertVisible(page.locator(categoryXPath));
});

Then('list of validation errors should load in mobile-optimized view', async function () {
  await assertions.assertVisible(page.locator('//div[@id="validation-errors-list"][@class*="mobile-optimized"]'));
});

Then('error codes should be displayed', async function () {
  const errorCodeCount = await page.locator('//span[@class="error-code"]').count();
  expect(errorCodeCount).toBeGreaterThan(0);
});

Then('brief descriptions should be visible', async function () {
  const descriptionCount = await page.locator('//span[@class="brief-description"]').count();
  expect(descriptionCount).toBeGreaterThan(0);
});

Then('full error documentation should open', async function () {
  await assertions.assertVisible(page.locator('//div[@id="full-error-documentation"]'));
});

Then('collapsible section {string} should be visible', async function (sectionName: string) {
  const sectionXPath = `//div[@class='collapsible-section'][@data-section='${sectionName.toLowerCase()}']`;
  await assertions.assertVisible(page.locator(sectionXPath));
});

Then('content should be formatted for mobile screen', async function () {
  const viewport = page.viewportSize();
  expect(viewport?.width).toBeLessThanOrEqual(768);
});

Then('section should expand', async function () {
  await assertions.assertVisible(page.locator('//div[@class="section-content expanded"]'));
});

Then('{int} numbered steps should be displayed', async function (count: number) {
  const stepsCount = await page.locator('//ol[@class="numbered-steps"]//li').count();
  expect(stepsCount).toBe(count);
});

Then('mobile-friendly formatting should be applied', async function () {
  await assertions.assertVisible(page.locator('//div[@class*="mobile-formatted"]'));
});

Then('text size should be readable', async function () {
  const fontSize = await page.locator('//body').evaluate(el => window.getComputedStyle(el).fontSize);
  const fontSizeNum = parseInt(fontSize);
  expect(fontSizeNum).toBeGreaterThanOrEqual(14);
});

Then('images should support tap-to-zoom', async function () {
  await assertions.assertVisible(page.locator('//img[@class*="zoomable"]'));
});

/**************************************************/
/*  ANALYTICS DASHBOARD ASSERTIONS
/**************************************************/

Then('analytics dashboard should load', async function () {
  await assertions.assertVisible(page.locator('//div[@id="analytics-dashboard"]'));
});

Then('metric {string} should be displayed', async function (metricName: string) {
  const metricXPath = `//div[@class='metric-tile'][@data-metric='${metricName.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(metricXPath));
});

Then('dashboard should update with validation error specific metrics', async function () {
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//div[@id="validation-error-metrics"]'));
});

Then('total views {string} should be displayed', async function (viewCount: string) {
  await assertions.assertContainsText(page.locator('//span[@id="total-views"]'), viewCount);
});

Then('unique users {string} should be displayed', async function (userCount: string) {
  await assertions.assertContainsText(page.locator('//span[@id="unique-users"]'), userCount);
});

Then('search queries {string} should be displayed', async function (queryCount: string) {
  await assertions.assertContainsText(page.locator('//span[@id="search-queries"]'), queryCount);
});

Then('chart should display comparison of {int} days before and after documentation launch', async function (days: number) {
  await assertions.assertVisible(page.locator('//div[@class="comparison-chart"]'));
  await assertions.assertContainsText(page.locator('//div[@class="comparison-chart"]'), days.toString());
});

Then('{int} percent reduction should be shown', async function (percentage: number) {
  await assertions.assertContainsText(page.locator('//span[@class="reduction-percentage"]'), percentage.toString());
});

Then('previous average {string} minutes should be displayed', async function (minutes: string) {
  await assertions.assertContainsText(page.locator('//span[@id="previous-average"]'), minutes);
});

Then('current average {string} minutes should be displayed', async function (minutes: string) {
  await assertions.assertContainsText(page.locator('//span[@id="current-average"]'), minutes);
});

Then('detailed breakdown should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="detailed-breakdown"]'));
});

Then('improvement from {string} percent to {string} percent should be shown', async function (fromPercent: string, toPercent: string) {
  await assertions.assertContainsText(page.locator('//div[@class="improvement-metric"]'), fromPercent);
  await assertions.assertContainsText(page.locator('//div[@class="improvement-metric"]'), toPercent);
});

Then('top {int} validation errors should be listed with view counts', async function (count: number) {
  const errorCount = await page.locator('//div[@id="most-accessed-documentation"]//li').count();
  expect(errorCount).toBe(count);
});

Then('{string} with {string} views should be displayed', async function (errorCode: string, viewCount: string) {
  const errorXPath = `//div[@id='most-accessed-documentation']//li[contains(text(),'${errorCode}')]`;
  await assertions.assertVisible(page.locator(errorXPath));
  await assertions.assertContainsText(page.locator(errorXPath), viewCount);
});

Then('PDF report should download', async function () {
  const downloadPromise = page.waitForEvent('download');
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toContain('.pdf');
});

Then('report should contain all metrics', async function () {
  this.reportContainsMetrics = true;
});

Then('report should contain charts', async function () {
  this.reportContainsCharts = true;
});

Then('report should contain success indicators', async function () {
  this.reportContainsSuccessIndicators = true;
});