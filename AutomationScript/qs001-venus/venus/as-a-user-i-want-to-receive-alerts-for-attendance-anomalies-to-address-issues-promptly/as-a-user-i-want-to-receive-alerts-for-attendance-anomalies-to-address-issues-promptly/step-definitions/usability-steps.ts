import { Given, When, Then, Before, After, setDefaultTimeout } from '@cucumber/cucumber';
import { Page, Browser, BrowserContext, chromium, expect } from '@playwright/test';
import { BasePage } from '../pages/BasePage';
import { HomePage } from '../pages/HomePage';
import { GenericActions } from '../utils/GenericActions';
import { AssertionHelpers } from '../utils/AssertionHelpers';
import { WaitHelpers } from '../utils/WaitHelpers';

// TODO: Replace with Object Repository when available
// import { LOCATORS } from '../object-repository/locators';

setDefaultTimeout(60000);

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
      user: { username: 'testuser', password: 'testpass' },
      manager: { username: 'manager', password: 'manager123' }
    },
    anomalyData: {},
    alertTimestamps: {}
  };
});

After(async function (scenario) {
  if (scenario.result?.status === 'FAILED') {
    const screenshot = await page.screenshot();
    this.attach(screenshot, 'image/png');
  }
  await page?.close();
  await context?.close();
  await browser?.close();
});

// ==================== GIVEN STEPS ====================

/**************************************************/
/*  BACKGROUND STEPS - All Test Cases
/*  Category: Setup
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user is logged into the attendance system', async function () {
  await actions.navigateTo(process.env.BASE_URL || 'https://attendance.example.com');
  await waits.waitForNetworkIdle();
  
  const credentials = this.testData?.users?.user || { username: 'testuser', password: 'testpass' };
  await actions.fill(page.locator('//input[@id="username"]'), credentials.username);
  await actions.fill(page.locator('//input[@id="password"]'), credentials.password);
  await actions.click(page.locator('//button[@id="login"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
Given('attendance data is being actively monitored', async function () {
  await assertions.assertVisible(page.locator('//div[@id="monitoring-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="monitoring-status"]'), 'Active');
});

/**************************************************/
/*  TEST CASE: TC-001
/*  Title: Real-time visibility of alert delivery status
/*  Priority: Critical
/*  Category: Usability
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('test anomaly data is prepared for {string} scenario', async function (scenarioType: string) {
  this.testData.anomalyData = {
    type: scenarioType,
    prepared: true,
    timestamp: new Date().toISOString()
  };
  
  await actions.click(page.locator('//button[@id="test-data-setup"]'));
  const scenarioXPath = `//select[@id='anomaly-scenario']`;
  await actions.selectByText(page.locator(scenarioXPath), scenarioType);
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
Given('user has appropriate permissions to view alerts', async function () {
  await assertions.assertVisible(page.locator('//div[@id="alerts-section"]'));
  const permissionStatus = page.locator('//span[@id="permission-status"]');
  await assertions.assertContainsText(permissionStatus, 'Granted');
});

/**************************************************/
/*  TEST CASE: TC-002
/*  Title: Alert language uses familiar terminology
/*  Priority: High
/*  Category: Usability
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('multiple types of attendance anomalies are configured', async function () {
  await actions.click(page.locator('//button[@id="anomaly-configuration"]'));
  await waits.waitForVisible(page.locator('//div[@id="anomaly-types-list"]'));
  
  const anomalyCount = await page.locator('//div[@class="anomaly-type-item"]').count();
  expect(anomalyCount).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Given('user has no prior training on system terminology', async function () {
  this.testData.userTrainingStatus = 'untrained';
  await actions.click(page.locator('//button[@id="user-profile"]'));
  await assertions.assertContainsText(page.locator('//span[@id="training-status"]'), 'No Training');
});

// TODO: Replace XPath with Object Repository when available
Given('alert notification system is active', async function () {
  await assertions.assertVisible(page.locator('//div[@id="notification-system-status"]'));
  await assertions.assertContainsText(page.locator('//div[@id="notification-system-status"]'), 'Active');
});

/**************************************************/
/*  TEST CASE: TC-003
/*  Title: Alert information visible without recall
/*  Priority: High
/*  Category: Usability
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user has received multiple attendance alerts over time', async function () {
  await actions.click(page.locator('//button[@id="alerts-history"]'));
  await waits.waitForVisible(page.locator('//div[@id="alerts-list"]'));
  
  const alertCount = await page.locator('//div[@class="alert-item"]').count();
  expect(alertCount).toBeGreaterThan(1);
});

// TODO: Replace XPath with Object Repository when available
Given('historical alert records are accessible', async function () {
  await assertions.assertVisible(page.locator('//div[@id="historical-alerts"]'));
  await assertions.assertContainsText(page.locator('//h2[@id="history-title"]'), 'Alert History');
});

/**************************************************/
/*  TEST CASE: TC-004
/*  Title: Alert delivery failure recovery guidance
/*  Priority: Critical
/*  Category: Negative
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('test environment can simulate alert delivery failures', async function () {
  await actions.click(page.locator('//button[@id="test-controls"]'));
  await waits.waitForVisible(page.locator('//div[@id="failure-simulation"]'));
  await assertions.assertVisible(page.locator('//button[@id="simulate-failure"]'));
});

/**************************************************/
/*  TEST CASE: TC-005
/*  Title: Resolved alert acknowledgment message
/*  Priority: Critical
/*  Category: Negative
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('alert has been resolved by manager', async function () {
  this.testData.resolvedAlertId = 'alert-12345';
  await actions.click(page.locator(`//div[@id='${this.testData.resolvedAlertId}']`));
  await assertions.assertContainsText(page.locator('//span[@id="alert-status"]'), 'Resolved');
});

/**************************************************/
/*  TEST CASE: TC-006
/*  Title: API unavailability error handling
/*  Priority: Critical
/*  Category: Negative
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('API endpoint is unavailable', async function () {
  await actions.click(page.locator('//button[@id="simulate-api-down"]'));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-007
/*  Title: Form validation for missing information
/*  Priority: High
/*  Category: Negative
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user is submitting an explanation for an anomaly', async function () {
  await actions.click(page.locator('//button[@id="explain-anomaly"]'));
  await waits.waitForVisible(page.locator('//form[@id="explanation-form"]'));
});

/**************************************************/
/*  TEST CASE: TC-008
/*  Title: Permission denied error handling
/*  Priority: Medium
/*  Category: Negative
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user lacks permission to view manager-only notes', async function () {
  this.testData.userPermissions = { viewManagerNotes: false };
  await assertions.assertVisible(page.locator('//div[@id="restricted-content"]'));
});

/**************************************************/
/*  TEST CASE: TC-009
/*  Title: Performance threshold for anomaly detection
/*  Priority: Critical
/*  Category: Performance
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('attendance data is being monitored in real-time', async function () {
  await assertions.assertVisible(page.locator('//div[@id="real-time-monitor"]'));
  await assertions.assertContainsText(page.locator('//span[@id="monitor-status"]'), 'Real-time');
  this.testData.alertTimestamps.monitoringStart = Date.now();
});

/**************************************************/
/*  TEST CASE: TC-010
/*  Title: Historical alert record maintenance
/*  Priority: High
/*  Category: Regression
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Given('user has received attendance alerts over time', async function () {
  await actions.click(page.locator('//a[@id="alerts-menu"]'));
  await waits.waitForNetworkIdle();
  const alertCount = await page.locator('//div[@class="historical-alert"]').count();
  expect(alertCount).toBeGreaterThan(0);
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  GENERIC REUSABLE WHEN STEPS
/*  Used across multiple test cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('I click on the {string} button', async function (buttonText: string) {
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
When('I navigate to {string} page', async function (pageName: string) {
  const pageXPath = `//a[@id='${pageName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(pageXPath));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-001 - Real-time visibility
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('user triggers an attendance anomaly with {string} minutes late arrival', async function (minutes: string) {
  this.testData.alertTimestamps.anomalyTriggered = Date.now();
  
  await actions.click(page.locator('//button[@id="trigger-anomaly"]'));
  await actions.fill(page.locator('//input[@id="late-minutes"]'), minutes);
  await actions.click(page.locator('//button[@id="submit-anomaly"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user observes the interface during the alert generation window', async function () {
  await waits.waitForVisible(page.locator('//div[@id="alert-generation-status"]'));
  this.testData.alertTimestamps.observationStart = Date.now();
});

// TODO: Replace XPath with Object Repository when available
When('user waits for alert to be dispatched', async function () {
  await waits.waitForVisible(page.locator('//div[@id="alert-dispatched"]'));
  this.testData.alertTimestamps.alertDispatched = Date.now();
});

// TODO: Replace XPath with Object Repository when available
When('user checks alert notification center', async function () {
  await actions.click(page.locator('//button[@id="notification-center"]'));
  await waits.waitForVisible(page.locator('//div[@id="notifications-panel"]'));
});

// TODO: Replace XPath with Object Repository when available
When('user navigates away from alerts page', async function () {
  await actions.click(page.locator('//a[@id="dashboard"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
When('user returns to the alerts page', async function () {
  await actions.click(page.locator('//a[@id="alerts-page"]'));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-002 - Alert language
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('user triggers {string} anomaly', async function (anomalyType: string) {
  this.testData.currentAnomalyType = anomalyType;
  
  await actions.click(page.locator('//button[@id="trigger-test-anomaly"]'));
  const anomalyXPath = `//select[@id='anomaly-type-selector']`;
  await actions.selectByText(page.locator(anomalyXPath), anomalyType);
  await actions.click(page.locator('//button[@id="generate-alert"]'));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-003 - Alert information visibility
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('user opens a single alert notification without viewing other screens', async function () {
  const firstAlert = page.locator('//div[@class="alert-item"]').first();
  await actions.click(firstAlert);
  await waits.waitForVisible(page.locator('//div[@id="alert-details"]'));
});

// TODO: Replace XPath with Object Repository when available
When('user checks alert for policy reference', async function () {
  await actions.scrollIntoView(page.locator('//div[@id="policy-reference"]'));
  await assertions.assertVisible(page.locator('//div[@id="policy-reference"]'));
});

// TODO: Replace XPath with Object Repository when available
When('user reviews available actions from the alert', async function () {
  await actions.scrollIntoView(page.locator('//div[@id="alert-actions"]'));
  await assertions.assertVisible(page.locator('//div[@id="alert-actions"]'));
});

// TODO: Replace XPath with Object Repository when available
When('user accesses historical alerts list', async function () {
  await actions.click(page.locator('//button[@id="view-history"]'));
  await waits.waitForVisible(page.locator('//div[@id="historical-alerts-list"]'));
});

// TODO: Replace XPath with Object Repository when available
When('user checks for manager information in alert', async function () {
  await actions.scrollIntoView(page.locator('//div[@id="manager-info"]'));
  await assertions.assertVisible(page.locator('//div[@id="manager-info"]'));
});

/**************************************************/
/*  TEST CASE: TC-004 - Alert delivery failure
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('alert delivery fails due to email service down', async function () {
  await actions.click(page.locator('//button[@id="simulate-email-failure"]'));
  await waits.waitForNetworkIdle();
  await waits.waitForVisible(page.locator('//div[@id="delivery-error"]'));
});

/**************************************************/
/*  TEST CASE: TC-005 - Resolved alert acknowledgment
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('user attempts to acknowledge the resolved alert', async function () {
  await actions.click(page.locator('//button[@id="acknowledge-alert"]'));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-006 - API unavailability
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('user tries to access alert details', async function () {
  await actions.click(page.locator('//div[@class="alert-item"]').first());
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-007 - Form validation
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('user submits explanation with missing {string}', async function (missingField: string) {
  this.testData.missingField = missingField;
  
  if (!missingField.includes('reason')) {
    await actions.fill(page.locator('//textarea[@id="reason"]'), 'Test reason');
  }
  
  if (!missingField.includes('documentation')) {
    await actions.click(page.locator('//input[@id="has-documentation"]'));
  }
  
  await actions.click(page.locator('//button[@id="submit-explanation"]'));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-008 - Permission denied
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('user attempts to access restricted alert details', async function () {
  await actions.click(page.locator('//button[@id="view-manager-notes"]'));
  await waits.waitForNetworkIdle();
});

/**************************************************/
/*  TEST CASE: TC-009 - Performance threshold
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('system detects attendance anomaly for {string}', async function (anomalyType: string) {
  this.testData.alertTimestamps.detectionStart = Date.now();
  
  await actions.click(page.locator('//button[@id="create-anomaly"]'));
  const typeXPath = `//select[@id='anomaly-type']`;
  await actions.selectByText(page.locator(typeXPath), anomalyType);
  await actions.click(page.locator('//button[@id="trigger"]'));
  
  await waits.waitForVisible(page.locator('//div[@id="anomaly-detected"]'));
  this.testData.alertTimestamps.detectionComplete = Date.now();
});

/**************************************************/
/*  TEST CASE: TC-010 - Historical records
/**************************************************/

// TODO: Replace XPath with Object Repository when available
When('user navigates to {string} page', async function (pageName: string) {
  const pageIdXPath = `//a[@id='${pageName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.click(page.locator(pageIdXPath));
  await waits.waitForNetworkIdle();
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  GENERIC REUSABLE THEN STEPS
/*  Used across multiple test cases
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('I should see {string}', async function (text: string) {
  await assertions.assertContainsText(page.locator(`//*[contains(text(),'${text}')]`), text);
});

// TODO: Replace XPath with Object Repository when available
Then('the {string} element should be visible', async function (elementName: string) {
  const elementXPath = `//div[@id='${elementName.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(elementXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('the {string} button should be available', async function (buttonText: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(buttonXPath));
});

/**************************************************/
/*  TEST CASE: TC-001 - Real-time visibility
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('system should display visual indicator showing {string}', async function (statusText: string) {
  await assertions.assertVisible(page.locator('//div[@id="status-indicator"]'));
  await assertions.assertContainsText(page.locator('//div[@id="status-indicator"]'), statusText);
});

// TODO: Replace XPath with Object Repository when available
Then('processing icon or status message should be visible', async function () {
  const processingIcon = page.locator('//div[@id="processing-icon"]');
  const statusMessage = page.locator('//div[@id="status-message"]');
  
  const iconVisible = await processingIcon.count() > 0;
  const messageVisible = await statusMessage.count() > 0;
  
  expect(iconVisible || messageVisible).toBeTruthy();
});

// TODO: Replace XPath with Object Repository when available
Then('progress indicator should show {string} with timestamp', async function (progressText: string) {
  await assertions.assertVisible(page.locator('//div[@id="progress-indicator"]'));
  await assertions.assertContainsText(page.locator('//div[@id="progress-indicator"]'), progressText);
  await assertions.assertVisible(page.locator('//span[@id="progress-timestamp"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('status message should show {string} with timestamp', async function (statusText: string) {
  await assertions.assertVisible(page.locator('//div[@id="status-message"]'));
  await assertions.assertContainsText(page.locator('//div[@id="status-message"]'), statusText);
  await assertions.assertVisible(page.locator('//span[@id="status-timestamp"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('system should display confirmation message {string} with timestamp', async function (confirmationText: string) {
  await assertions.assertVisible(page.locator('//div[@id="confirmation-message"]'));
  await assertions.assertContainsText(page.locator('//div[@id="confirmation-message"]'), confirmationText);
  await assertions.assertVisible(page.locator('//span[@id="confirmation-timestamp"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('delivery status should be visible', async function () {
  await assertions.assertVisible(page.locator('//div[@id="delivery-status"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('alert should appear with status indicators {string}', async function (statusIndicators: string) {
  await assertions.assertVisible(page.locator('//div[@id="alert-status-indicators"]'));
  const indicators = statusIndicators.split('/');
  
  for (const indicator of indicators) {
    const indicatorXPath = `//span[contains(@class,'status-${indicator.toLowerCase()}')]`;
    await assertions.assertVisible(page.locator(indicatorXPath));
  }
});

// TODO: Replace XPath with Object Repository when available
Then('timestamp of alert generation should be displayed', async function () {
  await assertions.assertVisible(page.locator('//span[@id="alert-timestamp"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('system should maintain and display current status of all alerts', async function () {
  await assertions.assertVisible(page.locator('//div[@id="alerts-status-panel"]'));
  const alertCount = await page.locator('//div[@class="alert-item"]').count();
  expect(alertCount).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Then('page refresh should not be required', async function () {
  await assertions.assertVisible(page.locator('//div[@id="auto-refresh-indicator"]'));
});

/**************************************************/
/*  TEST CASE: TC-002 - Alert language
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('alert message should use {string} instead of technical terms', async function (expectedLanguage: string) {
  await assertions.assertVisible(page.locator('//div[@id="alert-message"]'));
  await assertions.assertContainsText(page.locator('//div[@id="alert-message"]'), expectedLanguage);
});

// TODO: Replace XPath with Object Repository when available
Then('alert should include contextual information with date and time', async function () {
  await assertions.assertVisible(page.locator('//span[@id="alert-date"]'));
  await assertions.assertVisible(page.locator('//span[@id="alert-time"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('alert should include location if applicable', async function () {
  const locationElement = page.locator('//span[@id="alert-location"]');
  if (await locationElement.count() > 0) {
    await assertions.assertVisible(locationElement);
  }
});

// TODO: Replace XPath with Object Repository when available
Then('anomaly type should be labeled as {string}', async function (friendlyLabel: string) {
  await assertions.assertVisible(page.locator('//span[@id="anomaly-label"]'));
  await assertions.assertContainsText(page.locator('//span[@id="anomaly-label"]'), friendlyLabel);
});

// TODO: Replace XPath with Object Repository when available
Then('action items should use clear imperative language', async function () {
  await assertions.assertVisible(page.locator('//div[@id="action-items"]'));
  const actionButtons = page.locator('//div[@id="action-items"]//button');
  const buttonCount = await actionButtons.count();
  expect(buttonCount).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Then('visual icons should be displayed alongside text', async function () {
  const icons = page.locator('//i[@class="alert-icon"]');
  const iconCount = await icons.count();
  expect(iconCount).toBeGreaterThan(0);
});

/**************************************************/
/*  TEST CASE: TC-003 - Alert information visibility
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('alert should display complete information including anomaly type', async function () {
  await assertions.assertVisible(page.locator('//div[@id="anomaly-type"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('alert should display date and scheduled time', async function () {
  await assertions.assertVisible(page.locator('//span[@id="scheduled-date"]'));
  await assertions.assertVisible(page.locator('//span[@id="scheduled-time"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('alert should display actual time and deviation amount', async function () {
  await assertions.assertVisible(page.locator('//span[@id="actual-time"]'));
  await assertions.assertVisible(page.locator('//span[@id="deviation-amount"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('alert should display affected shift and location', async function () {
  await assertions.assertVisible(page.locator('//span[@id="affected-shift"]'));
  await assertions.assertVisible(page.locator('//span[@id="shift-location"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('alert should show relevant policy snippet', async function () {
  await assertions.assertVisible(page.locator('//div[@id="policy-snippet"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('policy snippet should display {string}', async function (policyText: string) {
  await assertions.assertContainsText(page.locator('//div[@id="policy-snippet"]'), policyText);
});

// TODO: Replace XPath with Object Repository when available
Then('alert should display {string} button', async function (buttonText: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(buttonXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('alert should display {string} link', async function (linkText: string) {
  const linkXPath = `//a[@id='${linkText.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(linkXPath));
});

// TODO: Replace XPath with Object Repository when available
Then('each historical alert should show summary information in list view', async function () {
  const alertItems = page.locator('//div[@class="alert-summary"]');
  const count = await alertItems.count();
  expect(count).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Then('summary should include date, type, and status', async function () {
  const firstSummary = page.locator('//div[@class="alert-summary"]').first();
  await assertions.assertVisible(firstSummary.locator('//span[@class="summary-date"]'));
  await assertions.assertVisible(firstSummary.locator('//span[@class="summary-type"]'));
  await assertions.assertVisible(firstSummary.locator('//span[@class="summary-status"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('user should not need to open each alert to recall details', async function () {
  const summaryDetails = page.locator('//div[@class="alert-summary"]').first();
  const detailsVisible = await summaryDetails.locator('//span[@class="summary-details"]').count() > 0;
  expect(detailsVisible).toBeTruthy();
});

// TODO: Replace XPath with Object Repository when available
Then('alert should display manager name and contact method', async function () {
  await assertions.assertVisible(page.locator('//span[@id="manager-name"]'));
  await assertions.assertVisible(page.locator('//span[@id="manager-contact"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('manager email should be visible', async function () {
  await assertions.assertVisible(page.locator('//span[@id="manager-email"]'));
});

/**************************************************/
/*  TEST CASE: TC-004 - Alert delivery failure
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('system should display message {string}', async function (errorMessage: string) {
  await assertions.assertVisible(page.locator('//div[@id="error-message"]'));
  await assertions.assertContainsText(page.locator('//div[@id="error-message"]'), errorMessage);
});

// TODO: Replace XPath with Object Repository when available
Then('generic error messages like {string} should not be displayed', async function (genericError: string) {
  const errorText = await page.locator('//div[@id="error-message"]').textContent();
  expect(errorText).not.toContain(genericError);
});

// TODO: Replace XPath with Object Repository when available
Then('{string} button should be available', async function (buttonText: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase()}']`;
  await assertions.assertVisible(page.locator(buttonXPath));
});

/**************************************************/
/*  TEST CASE: TC-005 - Resolved alert acknowledgment
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('error message should state {string}', async function (errorMessage: string) {
  await assertions.assertVisible(page.locator('//div[@id="error-message"]'));
  await assertions.assertContainsText(page.locator('//div[@id="error-message"]'), errorMessage);
});

// TODO: Replace XPath with Object Repository when available
Then('{string} option should be available', async function (optionText: string) {
  const optionXPath = `//button[@id='${optionText.toLowerCase().replace(/\s+/g, '-')}']`;
  await assertions.assertVisible(page.locator(optionXPath));
});

/**************************************************/
/*  TEST CASE: TC-006 - API unavailability
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('message should display {string}', async function (message: string) {
  await assertions.assertVisible(page.locator('//div[@id="api-error-message"]'));
  await assertions.assertContainsText(page.locator('//div[@id="api-error-message"]'), message);
});

// TODO: Replace XPath with Object Repository when available
Then('{string} button should be visible', async function (buttonText: string) {
  const buttonXPath = `//button[@id='${buttonText.toLowerCase()}']`;
  await assertions.assertVisible(page.locator(buttonXPath));
});

/**************************************************/
/*  TEST CASE: TC-007 - Form validation
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('validation message should highlight specific missing fields', async function () {
  await assertions.assertVisible(page.locator('//div[@id="validation-errors"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('message should state {string}', async function (validationMessage: string) {
  await assertions.assertContainsText(page.locator('//div[@id="validation-errors"]'), validationMessage);
});

// TODO: Replace XPath with Object Repository when available
Then('inline field highlighting should be displayed', async function () {
  const highlightedFields = page.locator('//input[@class="field-error"]');
  const count = await highlightedFields.count();
  expect(count).toBeGreaterThan(0);
});

/**************************************************/
/*  TEST CASE: TC-008 - Permission denied
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('message should explain {string}', async function (permissionMessage: string) {
  await assertions.assertVisible(page.locator('//div[@id="permission-error"]'));
  await assertions.assertContainsText(page.locator('//div[@id="permission-error"]'), permissionMessage);
});

// TODO: Replace XPath with Object Repository when available
Then('clear contact information should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="contact-info"]'));
});

/**************************************************/
/*  TEST CASE: TC-009 - Performance threshold
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('anomaly should be detected within {string} minutes', async function (minutes: string) {
  const detectionTime = this.testData.alertTimestamps.detectionComplete - this.testData.alertTimestamps.detectionStart;
  const maxTime = parseInt(minutes) * 60 * 1000;
  expect(detectionTime).toBeLessThanOrEqual(maxTime);
});

// TODO: Replace XPath with Object Repository when available
Then('alert should be generated within {string} minutes of detection', async function (minutes: string) {
  await waits.waitForVisible(page.locator('//div[@id="alert-generated"]'));
  this.testData.alertTimestamps.alertGenerated = Date.now();
  
  const generationTime = this.testData.alertTimestamps.alertGenerated - this.testData.alertTimestamps.detectionComplete;
  const maxTime = parseInt(minutes) * 60 * 1000;
  expect(generationTime).toBeLessThanOrEqual(maxTime);
});

// TODO: Replace XPath with Object Repository when available
Then('alert should be dispatched to user and manager', async function () {
  await assertions.assertVisible(page.locator('//div[@id="dispatch-confirmation"]'));
  await assertions.assertContainsText(page.locator('//div[@id="dispatch-confirmation"]'), 'user');
  await assertions.assertContainsText(page.locator('//div[@id="dispatch-confirmation"]'), 'manager');
});

// TODO: Replace XPath with Object Repository when available
Then('alert timestamp should be recorded', async function () {
  await assertions.assertVisible(page.locator('//span[@id="alert-timestamp"]'));
});

/**************************************************/
/*  TEST CASE: TC-010 - Historical records
/**************************************************/

// TODO: Replace XPath with Object Repository when available
Then('historical record of all attendance alerts should be displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@id="historical-alerts-list"]'));
  const alertCount = await page.locator('//div[@class="historical-alert"]').count();
  expect(alertCount).toBeGreaterThan(0);
});

// TODO: Replace XPath with Object Repository when available
Then('each alert should show anomaly type and date', async function () {
  const firstAlert = page.locator('//div[@class="historical-alert"]').first();
  await assertions.assertVisible(firstAlert.locator('//span[@class="alert-type"]'));
  await assertions.assertVisible(firstAlert.locator('//span[@class="alert-date"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('each alert should show status and resolution details', async function () {
  const firstAlert = page.locator('//div[@class="historical-alert"]').first();
  await assertions.assertVisible(firstAlert.locator('//span[@class="alert-status"]'));
  await assertions.assertVisible(firstAlert.locator('//span[@class="resolution-details"]'));
});

// TODO: Replace XPath with Object Repository when available
Then('alerts should be sortable by date', async function () {
  await assertions.assertVisible(page.locator('//button[@id="sort-by-date"]'));
  await actions.click(page.locator('//button[@id="sort-by-date"]'));
  await waits.waitForNetworkIdle();
});

// TODO: Replace XPath with Object Repository when available
Then('alerts should be filterable by type and status', async function () {
  await assertions.assertVisible(page.locator('//select[@id="filter-by-type"]'));
  await assertions.assertVisible(page.locator('//select[@id="filter-by-status"]'));
});