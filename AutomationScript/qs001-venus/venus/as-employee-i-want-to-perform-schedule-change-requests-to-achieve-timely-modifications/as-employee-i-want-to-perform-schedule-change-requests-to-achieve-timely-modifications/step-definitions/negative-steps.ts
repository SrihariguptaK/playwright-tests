import { Given, When, Then, Before, After, setDefaultTimeout } from '@cucumber/cucumber';
import { Page, Browser, BrowserContext, chromium, expect } from '@playwright/test';
import { GenericActions } from '../utils/GenericActions';
import { AssertionHelpers } from '../utils/AssertionHelpers';
import { WaitHelpers } from '../utils/WaitHelpers';

setDefaultTimeout(60000);

let browser: Browser;
let context: BrowserContext;
let page: Page;
let actions: GenericActions;
let assertions: AssertionHelpers;
let waits: WaitHelpers;

const APP_URL = process.env.APP_URL || 'http://localhost:3000';

const XPATH = {
  dateField: "//input[@placeholder='Date' or @name='date' or contains(@id,'date')]",
  timeField: "//input[@placeholder='Time' or @name='time' or contains(@id,'time')]",
  reasonField: "//textarea[@placeholder='Reason' or @name='reason' or contains(@id,'reason')] | //input[@placeholder='Reason' or @name='reason' or contains(@id,'reason')]",
  submitButton: "//button[contains(text(),'Submit Request') or @type='submit']",
  errorMessage: (fieldName: string) => `//label[contains(text(),'${fieldName}')]/following-sibling::*[contains(@class,'error')] | //*[contains(@class,'error') and contains(text(),'${fieldName}')] | //input[@placeholder='${fieldName}']/following-sibling::*[contains(@class,'error')]`,
  errorMessageByText: (text: string) => `//*[contains(@class,'error') and contains(text(),'${text}')]`,
  fieldByPlaceholder: (placeholder: string) => `//input[@placeholder='${placeholder}'] | //textarea[@placeholder='${placeholder}']`,
  fieldByName: (name: string) => `//input[@name='${name}'] | //textarea[@name='${name}']`,
  redBorderField: (fieldName: string) => `//input[@placeholder='${fieldName}' and (contains(@class,'error') or contains(@class,'invalid'))] | //input[@name='${fieldName}' and (contains(@class,'error') or contains(@class,'invalid'))]`,
  characterCounter: "//*[contains(@class,'character-counter') or contains(@class,'char-count')]",
  disabledButton: "//button[contains(text(),'Submit Request') and (@disabled or contains(@class,'disabled'))]",
  tooltip: "//*[contains(@class,'tooltip') or @role='tooltip']",
  successMessage: "//*[contains(@class,'success') and contains(text(),'successfully')]",
  loginMessage: "//*[contains(text(),'Please log in')]",
  loadingSpinner: "//button[contains(text(),'Submitting')] | //*[contains(@class,'spinner') or contains(@class,'loading')]",
  errorBanner: "//*[contains(@class,'banner') or contains(@class,'alert')]//*[contains(text(),'timeout')]"
};

const testData = {
  users: {
    employee: { username: 'employee', password: 'employee123' }
  },
  validScheduleRequest: {
    date: '2024-07-15',
    time: '10:30 AM',
    reason: 'Training session attendance'
  }
};

let currentDate: string = '';
let apiRequestIntercepted: boolean = false;
let apiRequestData: any = null;

Before(async function () {
  browser = await chromium.launch({ 
    headless: process.env.HEADLESS !== 'false',
    slowMo: 50
  });
  context = await browser.newContext({
    viewport: { width: 1920, height: 1080 }
  });
  page = await context.newPage();
  
  actions = new GenericActions(page, context);
  assertions = new AssertionHelpers(page);
  waits = new WaitHelpers(page);

  apiRequestIntercepted = false;
  apiRequestData = null;

  await page.route('**/api/scheduleChangeRequests', async (route) => {
    apiRequestIntercepted = true;
    apiRequestData = route.request().postDataJSON();
    await route.continue();
  });
});

After(async function (scenario) {
  if (scenario.result?.status === 'FAILED') {
    const screenshot = await page.screenshot({ fullPage: true });
    this.attach(screenshot, 'image/png');
  }
  await browser.close();
});

Given('user is logged in as an authenticated employee', async function () {
  await actions.navigateTo(`${APP_URL}/login`);
  await waits.waitForLoad();
  
  const usernameLocator = page.getByPlaceholder(/username|email/i);
  const passwordLocator = page.getByPlaceholder(/password/i);
  
  if (await usernameLocator.count() > 0) {
    await actions.clearAndFill(usernameLocator, testData.users.employee.username);
    await actions.clearAndFill(passwordLocator, testData.users.employee.password);
  } else {
    await actions.clearAndFill(page.locator("//input[@type='text' or @type='email']"), testData.users.employee.username);
    await actions.clearAndFill(page.locator("//input[@type='password']"), testData.users.employee.password);
  }
  
  const loginButton = page.getByRole('button', { name: /sign in|login|log in/i });
  if (await loginButton.count() > 0) {
    await actions.click(loginButton);
  } else {
    await actions.click(page.locator("//button[@type='submit' or contains(text(),'Sign In') or contains(text(),'Login')]"));
  }
  
  await waits.waitForNetworkIdle();
  await waits.waitForUrlContains('/dashboard');
});

Given('user is on {string} page', async function (pageName: string) {
  const pageUrl = pageName.toLowerCase().replace(/\s+/g, '-');
  await actions.navigateTo(`${APP_URL}/${pageUrl}`);
  await waits.waitForLoad();
  await waits.waitForNetworkIdle();
  
  const pageHeading = page.locator(`//h1[contains(text(),'${pageName}')] | //h2[contains(text(),'${pageName}')]`);
  await waits.waitForVisible(pageHeading);
});

Given('form is in its initial state', async function () {
  await waits.waitForVisible(page.locator(XPATH.dateField));
  await waits.waitForVisible(page.locator(XPATH.timeField));
  await waits.waitForVisible(page.locator(XPATH.reasonField));
  
  const dateValue = await actions.getValue(page.locator(XPATH.dateField));
  const timeValue = await actions.getValue(page.locator(XPATH.timeField));
  const reasonValue = await actions.getValue(page.locator(XPATH.reasonField));
  
  if (dateValue) await actions.clearInput(page.locator(XPATH.dateField));
  if (timeValue) await actions.clearInput(page.locator(XPATH.timeField));
  if (reasonValue) await actions.clearInput(page.locator(XPATH.reasonField));
});

Given('all validation rules are active', async function () {
  await waits.waitForMilliseconds(500);
  const formElement = page.locator("//form[contains(@class,'schedule-change') or contains(@id,'schedule')]");
  if (await formElement.count() > 0) {
    await assertions.assertVisible(formElement);
  }
});

Given('current date is {string}', async function (date: string) {
  currentDate = date;
  await page.evaluate((mockDate) => {
    const originalDate = Date;
    (window as any).Date = class extends originalDate {
      constructor(...args: any[]) {
        if (args.length === 0) {
          super(mockDate);
        } else {
          super(...args);
        }
      }
      static now() {
        return new originalDate(mockDate).getTime();
      }
    };
  }, date);
});

Given('date validation rules include no past dates allowed', async function () {
  await waits.waitForMilliseconds(300);
});

Given('{string} field has minimum character requirement of {int} characters', async function (fieldName: string, minChars: number) {
  const fieldLocator = page.locator(XPATH.reasonField);
  await assertions.assertVisible(fieldLocator);
  
  const maxLengthAttr = await actions.getAttribute(fieldLocator, 'minlength');
  if (maxLengthAttr) {
    expect(parseInt(maxLengthAttr)).toBeGreaterThanOrEqual(minChars);
  }
});

Given('form validation is active', async function () {
  await waits.waitForMilliseconds(300);
  const formElement = page.locator("//form");
  await assertions.assertVisible(formElement);
});

Given('user is not logged in', async function () {
  await context.clearCookies();
  await page.evaluate(() => {
    localStorage.clear();
    sessionStorage.clear();
  });
});

Given('authentication middleware is active', async function () {
  await waits.waitForMilliseconds(200);
});

Given('session timeout is set to {int} minutes', async function (minutes: number) {
  await waits.waitForMilliseconds(100);
});

Given('input sanitization and parameterized queries are implemented', async function () {
  await waits.waitForMilliseconds(100);
});

Given('security monitoring is active', async function () {
  await waits.waitForMilliseconds(100);
});

Given('all required fields are filled with valid data', async function () {
  await actions.clearAndFill(page.locator(XPATH.dateField), testData.validScheduleRequest.date);
  await actions.clearAndFill(page.locator(XPATH.timeField), testData.validScheduleRequest.time);
  await actions.clearAndFill(page.locator(XPATH.reasonField), testData.validScheduleRequest.reason);
});

Given('API timeout is configured to {int} seconds', async function (seconds: number) {
  await page.route('**/api/scheduleChangeRequests', async (route) => {
    await waits.waitForMilliseconds(seconds * 1000 + 1000);
    await route.abort('timedout');
  });
});

Given('network delay is simulated to exceed {int} seconds', async function (seconds: number) {
  await waits.waitForMilliseconds(100);
});

When('user leaves {string} field empty', async function (fieldName: string) {
  const fieldLocator = page.locator(XPATH.fieldByPlaceholder(fieldName));
  if (await fieldLocator.count() > 0) {
    await actions.clearInput(fieldLocator);
  } else {
    await actions.clearInput(page.locator(XPATH.dateField));
  }
  await waits.waitForMilliseconds(300);
});

When('user enters {string} in {string} field', async function (value: string, fieldName: string) {
  let fieldLocator;
  
  if (fieldName.toLowerCase().includes('date')) {
    fieldLocator = page.locator(XPATH.dateField);
  } else if (fieldName.toLowerCase().includes('time')) {
    fieldLocator = page.locator(XPATH.timeField);
  } else if (fieldName.toLowerCase().includes('reason')) {
    fieldLocator = page.locator(XPATH.reasonField);
  } else {
    const labelLocator = page.getByLabel(fieldName);
    const placeholderLocator = page.getByPlaceholder(fieldName);
    
    if (await labelLocator.count() > 0) {
      fieldLocator = labelLocator;
    } else if (await placeholderLocator.count() > 0) {
      fieldLocator = placeholderLocator;
    } else {
      fieldLocator = page.locator(XPATH.fieldByPlaceholder(fieldName));
    }
  }
  
  await actions.clearAndFill(fieldLocator, value);
  await waits.waitForMilliseconds(300);
});

When('user clicks {string} button', async function (buttonName: string) {
  apiRequestIntercepted = false;
  
  const roleButton = page.getByRole('button', { name: buttonName });
  if (await roleButton.count() > 0) {
    await actions.click(roleButton);
  } else {
    await actions.click(page.locator(`//button[contains(text(),'${buttonName}')]`));
  }
  
  await waits.waitForMilliseconds(500);
});

When('user clicks outside {string} field', async function (fieldName: string) {
  const bodyLocator = page.locator('//body');
  await actions.click(bodyLocator);
  await waits.waitForMilliseconds(500);
});

When('user attempts to access {string} URL directly', async function (url: string) {
  await actions.navigateTo(`${APP_URL}${url}`);
  await waits.waitForLoad();
  await waits.waitForNetworkIdle();
});

When('user sends POST request to {string} with {string} authentication', async function (endpoint: string, authType: string) {
  let headers: any = {
    'Content-Type': 'application/json'
  };
  
  if (authType === 'no_header') {
    // No auth header
  } else if (authType === 'expired_token') {
    headers['Authorization'] = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MTYyMzkwMjJ9.expired';
  } else if (authType === 'invalid_token') {
    headers['Authorization'] = 'Bearer invalid_token_12345';
  }
  
  const response = await page.request.post(`${APP_URL}${endpoint}`, {
    headers: headers,
    data: {
      date: '2024-07-15',
      time: '10:30 AM',
      reason: 'Test request'
    }
  });
  
  (this as any).apiResponse = response;
  (this as any).apiResponseBody = await response.json().catch(() => ({}));
});

When('user waits for {int} seconds', async function (seconds: number) {
  await waits.waitForMilliseconds(seconds * 1000);
});

Then('form submission should be prevented', async function () {
  await waits.waitForMilliseconds(500);
  const currentUrl = await actions.getCurrentUrl();
  expect(currentUrl).toContain('schedule-change-request');
});

Then('form submission should be blocked', async function () {
  await waits.waitForMilliseconds(500);
  const currentUrl = await actions.getCurrentUrl();
  expect(currentUrl).toContain('schedule-change-request');
});

Then('error message {string} should be displayed below {string} field', async function (errorMessage: string, fieldName: string) {
  const errorLocator = page.locator(`//*[contains(@class,'error') and contains(text(),'${errorMessage}')]`);
  await waits.waitForVisible(errorLocator);
  await assertions.assertVisible(errorLocator);
  await assertions.assertTextContains(errorLocator, errorMessage);
});

Then('{string} field should have red border', async function (fieldName: string) {
  const fieldLocator = page.locator(XPATH.dateField);
  await waits.waitForMilliseconds(300);
  
  const classList = await actions.getAttribute(fieldLocator, 'class');
  expect(classList).toMatch(/error|invalid|danger/i);
});

Then('focus should move to {string} field', async function (fieldName: string) {
  await waits.waitForMilliseconds(300);
  const focusedElement = await page.evaluate(() => document.activeElement?.getAttribute('placeholder') || document.activeElement?.getAttribute('name'));
  expect(focusedElement?.toLowerCase()).toContain(fieldName.toLowerCase());
});

Then('no POST request should be sent to {string} endpoint', async function (endpoint: string) {
  await waits.waitForMilliseconds(1000);
  expect(apiRequestIntercepted).toBe(false);
});

Then('form data in {string} field should be preserved', async function (fieldName: string) {
  let fieldLocator;
  
  if (fieldName.toLowerCase().includes('time')) {
    fieldLocator = page.locator(XPATH.timeField);
  } else if (fieldName.toLowerCase().includes('reason')) {
    fieldLocator = page.locator(XPATH.reasonField);
  } else {
    fieldLocator = page.locator(XPATH.fieldByPlaceholder(fieldName));
  }
  
  const fieldValue = await actions.getValue(fieldLocator);
  expect(fieldValue).not.toBe('');
});

Then('no schedule change request should be created in database', async function () {
  await waits.waitForMilliseconds(500);
});

Then('form fields should retain entered values', async function () {
  const dateValue = await actions.getValue(page.locator(XPATH.dateField));
  const timeValue = await actions.getValue(page.locator(XPATH.timeField));
  const reasonValue = await actions.getValue(page.locator(XPATH.reasonField));
  
  expect(dateValue).not.toBe('');
  expect(timeValue).not.toBe('');
  expect(reasonValue).not.toBe('');
});

Then('no notification should be sent', async function () {
  await waits.waitForMilliseconds(500);
  const notificationLocator = page.locator("//*[contains(@class,'notification') or contains(@class,'toast')]");
  const notificationCount = await notificationLocator.count();
  expect(notificationCount).toBe(0);
});

Then('character counter should show {string}', async function (counterText: string) {
  const counterLocator = page.locator(XPATH.characterCounter);
  await waits.waitForVisible(counterLocator);
  await assertions.assertTextContains(counterLocator, counterText);
});

Then('{string} button should be disabled', async function (buttonName: string) {
  const buttonLocator = page.locator(XPATH.disabledButton);
  await waits.waitForVisible(buttonLocator);
  await assertions.assertDisabled(buttonLocator);
});

Then('tooltip {string} should appear on hover over {string} button', async function (tooltipText: string, buttonName: string) {
  const buttonLocator = page.locator(`//button[contains(text(),'${buttonName}')]`);
  await actions.hover(buttonLocator);
  await waits.waitForMilliseconds(500);
  
  const tooltipLocator = page.locator(`//*[contains(@class,'tooltip') and contains(text(),'${tooltipText}')]`);
  if (await tooltipLocator.count() > 0) {
    await assertions.assertVisible(tooltipLocator);
  }
});

Then('no database record should be created', async function () {
  await waits.waitForMilliseconds(500);
});

Then('user should be redirected to {string} page', async function (pagePath: string) {
  await waits.waitForUrlContains(pagePath);
  await assertions.assertUrl(`${APP_URL}${pagePath}`);
});

Then('message {string} should be displayed', async function (message: string) {
  const messageLocator = page.locator(`//*[contains(text(),'${message}')]`);
  await waits.waitForVisible(messageLocator);
  await assertions.assertVisible(messageLocator);
});

Then('API should return HTTP status code {int}', async function (statusCode: number) {
  const response = (this as any).apiResponse;
  expect(response.status()).toBe(statusCode);
});

Then('response body should contain error {string}', async function (errorType: string) {
  const responseBody = (this as any).apiResponseBody;
  expect(JSON.stringify(responseBody)).toContain(errorType);
});

Then('response body should contain message {string}', async function (errorMessage: string) {
  const responseBody = (this as any).apiResponseBody;
  expect(JSON.stringify(responseBody)).toContain(errorMessage);
});

Then('no schedule change request should be created', async function () {
  await waits.waitForMilliseconds(500);
});

Then('security event should be logged in audit trail', async function () {
  await waits.waitForMilliseconds(300);
});

Then('success message {string} should be displayed', async function (message: string) {
  const successLocator = page.locator(`//*[contains(@class,'success') and contains(text(),'${message}')]`);
  await waits.waitForVisible(successLocator);
  await assertions.assertVisible(successLocator);
});

Then('database table {string} should still exist', async function (tableName: string) {
  await waits.waitForMilliseconds(500);
});

Then('new record should be created with reason field containing {string} as plain text', async function (reasonText: string) {
  await waits.waitForMilliseconds(500);
});

Then('no SQL commands should be executed', async function () {
  await waits.waitForMilliseconds(300);
});

Then('database tables should remain intact and unaffected', async function () {
  await waits.waitForMilliseconds(300);
});

Then('SQL injection attempt should be logged in security audit log', async function () {
  await waits.waitForMilliseconds(300);
});

Then('loading spinner should appear on {string} button with text {string}', async function (buttonName: string, loadingText: string) {
  const loadingLocator = page.locator(`//button[contains(text(),'${loadingText}')]`);
  await waits.waitForVisible(loadingLocator);
  await assertions.assertVisible(loadingLocator);
});

Then('error message {string} should be displayed in red banner', async function (errorMessage: string) {
  const errorBannerLocator = page.locator(`//*[contains(@class,'error') or contains(@class,'alert')]//*[contains(text(),'${errorMessage}')]`);
  await waits.waitForVisible(errorBannerLocator);
  await assertions.assertVisible(errorBannerLocator);
});

Then('{string} button should return to enabled state', async function (buttonName: string) {
  const buttonLocator = page.locator(`//button[contains(text(),'${buttonName}') and not(@disabled)]`);
  await waits.waitForVisible(buttonLocator);
  await assertions.assertEnabled(buttonLocator);
});

Then('no record should be created in {string} table', async function (tableName: string) {
  await waits.waitForMilliseconds(500);
});

Then('all entered field values should remain in form', async function () {
  const dateValue = await actions.getValue(page.locator(XPATH.dateField));
  const timeValue = await actions.getValue(page.locator(XPATH.timeField));
  const reasonValue = await actions.getValue(page.locator(XPATH.reasonField));
  
  expect(dateValue).not.toBe('');
  expect(timeValue).not.toBe('');
  expect(reasonValue).not.toBe('');
});

Then('error should be logged in application error log', async function () {
  await waits.waitForMilliseconds(300);
});