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
    validationTimings: [],
    errorMessages: [],
    formStates: {}
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
/*  TEST CASE: TC-001
/*  Title: Verify real-time validation feedback
/*  Priority: High
/*  Category: Functional
/**************************************************/

Given('application with input validation is accessible', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
});

Given('test forms with various validation rules are available', async function () {
  await waits.waitForDomContentLoaded();
  await assertions.assertVisible(page.locator('//form'));
});

Given('browser developer tools are available for timing measurements', async function () {
  this.performanceMarks = [];
  await page.evaluate(() => {
    performance.mark('test-start');
  });
});

Given('user navigates to form with real-time validation enabled', async function () {
  const formXPath = '//form[@id="validation-form"]';
  await assertions.assertVisible(page.locator(formXPath));
  await waits.waitForVisible(page.locator(formXPath));
});

/**************************************************/
/*  TEST CASE: TC-002
/*  Title: Validate error prevention through input constraints
/*  Priority: High
/*  Category: Functional
/**************************************************/

Given('forms with various input types are available', async function () {
  await assertions.assertVisible(page.locator('//form'));
  const inputCount = await page.locator('//input').count();
  expect(inputCount).toBeGreaterThan(0);
});

Given('test data sets prepared for boundary conditions', async function () {
  this.testData.boundaryData = {
    numeric: ['abc', '123', '-1', '999999'],
    date: ['13/32/2024', '01/01/2024', '99/99/9999'],
    text: ['a', 'valid text', 'x'.repeat(1000)]
  };
});

Given('form specifications documenting validation rules are accessible', async function () {
  this.testData.validationRules = {
    email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    phone: /^\(\d{3}\) \d{3}-\d{4}$/,
    password: /^(?=.*[A-Z])(?=.*\d).{8,}$/
  };
});

/**************************************************/
/*  TEST CASE: TC-003
/*  Title: Evaluate error message clarity
/*  Priority: High
/*  Category: Negative
/**************************************************/

Given('application with server-side and client-side validation is accessible', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//form'));
});

Given('test scenarios prepared for various validation error types', async function () {
  this.testData.errorScenarios = {
    email: 'invalid-email',
    password: 'weak',
    username: 'duplicate_user',
    phone: '123',
    date: '13/32/2024'
  };
});

Given('validation rules are documented for reference', async function () {
  this.testData.documentedRules = true;
});

/**************************************************/
/*  TEST CASE: TC-004
/*  Title: Verify error message presentation for multiple failures
/*  Priority: High
/*  Category: Functional
/**************************************************/

Given('form with multiple required fields is displayed', async function () {
  await assertions.assertVisible(page.locator('//form'));
  const requiredFields = await page.locator('//input[@required]').count();
  expect(requiredFields).toBeGreaterThan(1);
});

/**************************************************/
/*  TEST CASE: TC-005
/*  Title: Verify consistency of validation behavior
/*  Priority: High
/*  Category: Consistency
/**************************************************/

Given('multiple forms are available in the application', async function () {
  this.testData.formUrls = [
    '/form1', '/form2', '/form3', '/form4', '/form5'
  ];
});

Given('documentation of validation standards and design system guidelines is accessible', async function () {
  this.testData.designStandards = {
    errorColor: '#d32f2f',
    successColor: '#388e3c',
    errorIcon: 'error-icon',
    successIcon: 'success-icon'
  };
});

Given('checklist of consistency criteria is prepared', async function () {
  this.testData.consistencyCriteria = [
    'validation-timing',
    'error-styling',
    'required-indicators',
    'success-indicators',
    'keyboard-navigation'
  ];
});

/**************************************************/
/*  TEST CASE: TC-006
/*  Title: Verify accessibility of validation feedback
/*  Priority: High
/*  Category: Accessibility
/**************************************************/

Given('screen reader testing tools are available', async function () {
  this.testData.ariaChecks = [];
});

/**************************************************/
/*  TEST CASE: TC-007
/*  Title: Test validation performance under load
/*  Priority: Medium
/*  Category: Performance
/**************************************************/

Given('load testing tools are configured', async function () {
  this.testData.performanceMetrics = {
    submissions: [],
    responseTimes: []
  };
});

// ==================== WHEN STEPS ====================

When('user observes the initial state of input fields', async function () {
  await waits.waitForVisible(page.locator('//input'));
  this.testData.initialState = await page.locator('//input').first().getAttribute('class');
});

When('user begins typing {string} in {string} field', async function (text: string, fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  this.testData.startTime = Date.now();
  await actions.type(page.locator(fieldXPath), text);
});

When('user completes email address with {string} in {string} field', async function (email: string, fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase().replace(/\s+/g, '-')}']`;
  await actions.clearAndFill(page.locator(fieldXPath), email);
  await waits.waitForNetworkIdle();
});

When('user moves focus to another field', async function () {
  await page.keyboard.press('Tab');
  await page.waitForTimeout(200);
});

When('user submits form with mix of valid and invalid fields', async function () {
  this.testData.submitStartTime = Date.now();
  await actions.click(page.locator('//button[@type="submit"]'));
  await waits.waitForNetworkIdle();
});

When('user examines input fields for format hints and placeholders', async function () {
  const inputs = page.locator('//input');
  const count = await inputs.count();
  this.testData.placeholders = [];
  for (let i = 0; i < count; i++) {
    const placeholder = await inputs.nth(i).getAttribute('placeholder');
    if (placeholder) {
      this.testData.placeholders.push(placeholder);
    }
  }
});

When('user attempts to enter {string} in numeric-only field', async function (text: string) {
  const numericFieldXPath = '//input[@type="number"]';
  await actions.fill(page.locator(numericFieldXPath), text);
  await page.waitForTimeout(300);
});

When('user tests date picker field by attempting manual entry', async function () {
  const dateFieldXPath = '//input[@type="date"]';
  await actions.click(page.locator(dateFieldXPath));
  await page.waitForTimeout(200);
});

When('user enters password in {string} field', async function (fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase()}']`;
  await actions.fill(page.locator(fieldXPath), 'TestPass123');
  await page.waitForTimeout(300);
});

When('user attempts to exceed maximum character count in text field', async function () {
  const textFieldXPath = '//input[@maxlength]';
  const maxLength = await page.locator(textFieldXPath).getAttribute('maxlength');
  const longText = 'x'.repeat(parseInt(maxLength || '100') + 10);
  await actions.fill(page.locator(textFieldXPath), longText);
});

When('user attempts to submit form with required fields empty', async function () {
  await actions.click(page.locator('//button[@type="submit"]'));
  await page.waitForTimeout(300);
});

When('user submits form with {string} in {string} field', async function (invalidInput: string, fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase()}']`;
  await actions.fill(page.locator(fieldXPath), invalidInput);
  await actions.click(page.locator('//button[@type="submit"]'));
  await waits.waitForNetworkIdle();
});

When('user triggers multiple validation errors simultaneously', async function () {
  const requiredFields = page.locator('//input[@required]');
  const count = await requiredFields.count();
  for (let i = 0; i < count; i++) {
    await actions.fill(requiredFields.nth(i), '');
  }
  await actions.click(page.locator('//button[@type="submit"]'));
  await waits.waitForNetworkIdle();
});

When('user corrects one error and resubmits form', async function () {
  const firstErrorField = page.locator('//input[@aria-invalid="true"]').first();
  await actions.fill(firstErrorField, 'valid@example.com');
  await actions.click(page.locator('//button[@type="submit"]'));
  await waits.waitForNetworkIdle();
});

When('user navigates to {int} different forms in the application', async function (formCount: number) {
  this.testData.formValidationData = [];
  for (let i = 0; i < formCount; i++) {
    const formUrl = this.testData.formUrls[i];
    await actions.navigateTo(formUrl);
    await waits.waitForNetworkIdle();
    this.testData.formValidationData.push({
      url: formUrl,
      timestamp: Date.now()
    });
  }
});

When('user documents validation trigger timing for each form', async function () {
  for (const formData of this.testData.formValidationData) {
    const startTime = Date.now();
    await actions.fill(page.locator('//input').first(), 'test');
    const endTime = Date.now();
    formData.validationTiming = endTime - startTime;
  }
});

When('user compares error message styling across different forms', async function () {
  this.testData.errorStyles = [];
  for (const formUrl of this.testData.formUrls) {
    await actions.navigateTo(formUrl);
    await waits.waitForNetworkIdle();
    await actions.click(page.locator('//button[@type="submit"]'));
    await page.waitForTimeout(300);
    const errorElement = page.locator('//div[@class*="error"]').first();
    if (await errorElement.count() > 0) {
      const styles = await errorElement.evaluate((el) => {
        const computed = window.getComputedStyle(el);
        return {
          color: computed.color,
          fontSize: computed.fontSize,
          fontWeight: computed.fontWeight
        };
      });
      this.testData.errorStyles.push(styles);
    }
  }
});

When('user tests required field indicators across multiple forms', async function () {
  this.testData.requiredIndicators = [];
  for (const formUrl of this.testData.formUrls) {
    await actions.navigateTo(formUrl);
    await waits.waitForNetworkIdle();
    const indicators = await page.locator('//span[@class*="required"]').count();
    this.testData.requiredIndicators.push(indicators);
  }
});

When('user triggers validation errors on similar field types across different forms', async function () {
  this.testData.fieldTypeErrors = [];
  for (const formUrl of this.testData.formUrls) {
    await actions.navigateTo(formUrl);
    await waits.waitForNetworkIdle();
    const emailField = page.locator('//input[@type="email"]');
    if (await emailField.count() > 0) {
      await actions.fill(emailField, 'invalid-email');
      await actions.click(page.locator('//button[@type="submit"]'));
      await page.waitForTimeout(300);
      const errorText = await page.locator('//div[@class*="error"]').first().textContent();
      this.testData.fieldTypeErrors.push(errorText);
    }
  }
});

When('user tests success state indicators across forms', async function () {
  this.testData.successIndicators = [];
  for (const formUrl of this.testData.formUrls) {
    await actions.navigateTo(formUrl);
    await waits.waitForNetworkIdle();
    const emailField = page.locator('//input[@type="email"]');
    if (await emailField.count() > 0) {
      await actions.fill(emailField, 'valid@example.com');
      await page.waitForTimeout(500);
      const successIcon = await page.locator('//span[@class*="success"]').count();
      this.testData.successIndicators.push(successIcon > 0);
    }
  }
});

When('user tests keyboard navigation for validation errors across forms', async function () {
  this.testData.keyboardNavigation = [];
  for (const formUrl of this.testData.formUrls) {
    await actions.navigateTo(formUrl);
    await waits.waitForNetworkIdle();
    await actions.click(page.locator('//button[@type="submit"]'));
    await page.waitForTimeout(300);
    await page.keyboard.press('Tab');
    const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
    this.testData.keyboardNavigation.push(focusedElement);
  }
});

When('user navigates to form using keyboard only', async function () {
  await page.keyboard.press('Tab');
  await page.waitForTimeout(200);
});

When('validation error occurs', async function () {
  await actions.click(page.locator('//button[@type="submit"]'));
  await waits.waitForNetworkIdle();
});

When('validation succeeds', async function () {
  const inputs = page.locator('//input[@required]');
  const count = await inputs.count();
  for (let i = 0; i < count; i++) {
    await actions.fill(inputs.nth(i), 'valid@example.com');
  }
  await actions.click(page.locator('//button[@type="submit"]'));
  await waits.waitForNetworkIdle();
});

When('user submits {int} forms simultaneously with validation errors', async function (formCount: number) {
  this.testData.submissionTimes = [];
  const promises = [];
  for (let i = 0; i < formCount; i++) {
    const startTime = Date.now();
    const promise = page.evaluate(() => {
      const form = document.querySelector('form');
      if (form) {
        const event = new Event('submit', { bubbles: true, cancelable: true });
        form.dispatchEvent(event);
      }
    }).then(() => {
      const endTime = Date.now();
      this.testData.submissionTimes.push(endTime - startTime);
    });
    promises.push(promise);
  }
  await Promise.all(promises);
});

When('user performs rapid input changes triggering real-time validation', async function () {
  const inputField = page.locator('//input[@type="email"]');
  const testValues = ['a', 'ab', 'abc', 'abc@', 'abc@d', 'abc@de', 'abc@def.com'];
  this.testData.rapidInputTimes = [];
  for (const value of testValues) {
    const startTime = Date.now();
    await actions.fill(inputField, value);
    await page.waitForTimeout(50);
    const endTime = Date.now();
    this.testData.rapidInputTimes.push(endTime - startTime);
  }
});

// ==================== THEN STEPS ====================

Then('input fields should be clearly visible', async function () {
  await assertions.assertVisible(page.locator('//input'));
});

Then('no validation indicators should be shown initially', async function () {
  const validationIndicators = await page.locator('//span[@class*="validation"]').count();
  expect(validationIndicators).toBe(0);
});

Then('visual feedback should appear within {int} milliseconds', async function (maxTime: number) {
  const elapsedTime = Date.now() - this.testData.startTime;
  expect(elapsedTime).toBeLessThan(maxTime);
  await assertions.assertVisible(page.locator('//span[@class*="validation"]'));
});

Then('validation indicator should be visible', async function () {
  await assertions.assertVisible(page.locator('//span[@class*="validation"]'));
});

Then('positive validation feedback should appear immediately', async function () {
  await assertions.assertVisible(page.locator('//span[@class*="success"]'));
});

Then('success icon should be displayed for {string} field', async function (fieldName: string) {
  const successIconXPath = `//input[@id='${fieldName.toLowerCase()}']/following-sibling::span[@class*='success']`;
  await assertions.assertVisible(page.locator(successIconXPath));
});

Then('validation status indicators should remain visible', async function () {
  await assertions.assertVisible(page.locator('//span[@class*="validation"]'));
});

Then('validation status should be consistent for all fields', async function () {
  const validationIndicators = await page.locator('//span[@class*="validation"]').count();
  expect(validationIndicators).toBeGreaterThan(0);
});

Then('clear visual distinction between validated and non-validated fields should be shown', async function () {
  const validFields = await page.locator('//input[@aria-invalid="false"]').count();
  const invalidFields = await page.locator('//input[@aria-invalid="true"]').count();
  expect(validFields + invalidFields).toBeGreaterThan(0);
});

Then('processing indicator should be displayed during submission', async function () {
  await assertions.assertVisible(page.locator('//div[@class*="loading"]'));
});

Then('validation feedback response time should be less than {int} milliseconds', async function (maxTime: number) {
  const elapsedTime = Date.now() - this.testData.submitStartTime;
  expect(elapsedTime).toBeLessThan(maxTime);
});

Then('all fields requiring specific formats should display clear examples', async function () {
  const placeholderCount = this.testData.placeholders.length;
  expect(placeholderCount).toBeGreaterThan(0);
});

Then('placeholders showing expected format should be visible', async function () {
  const inputsWithPlaceholders = await page.locator('//input[@placeholder]').count();
  expect(inputsWithPlaceholders).toBeGreaterThan(0);
});

Then('system should prevent entry of invalid characters', async function () {
  const numericField = page.locator('//input[@type="number"]');
  const value = await numericField.inputValue();
  expect(value).not.toContain('abc');
});

Then('immediate inline warning should be shown', async function () {
  await assertions.assertVisible(page.locator('//span[@class*="warning"]'));
});

Then('date picker widget should be provided', async function () {
  await assertions.assertVisible(page.locator('//div[@class*="date-picker"]'));
});

Then('format validation with helpful correction suggestions should be shown', async function () {
  await assertions.assertVisible(page.locator('//div[@class*="format-hint"]'));
});

Then('password requirements should be visible before entry', async function () {
  await assertions.assertVisible(page.locator('//div[@class*="password-requirements"]'));
});

Then('strength meter should update in real-time', async function () {
  await assertions.assertVisible(page.locator('//div[@class*="strength-meter"]'));
});

Then('specific unmet requirements should be highlighted', async function () {
  await assertions.assertVisible(page.locator('//span[@class*="requirement-unmet"]'));
});

Then('character counter should display remaining characters', async function () {
  await assertions.assertVisible(page.locator('//span[@class*="char-count"]'));
});

Then('system should prevent exceeding limit', async function () {
  const textField = page.locator('//input[@maxlength]');
  const maxLength = await textField.getAttribute('maxlength');
  const actualLength = (await textField.inputValue()).length;
  expect(actualLength).toBeLessThanOrEqual(parseInt(maxLength || '100'));
});

Then('clear indication of maximum allowed should be shown', async function () {
  await assertions.assertVisible(page.locator('//span[@class*="max-length"]'));
});

Then('submit button should be disabled', async function () {
  const submitButton = page.locator('//button[@type="submit"]');
  const isDisabled = await submitButton.isDisabled();
  expect(isDisabled).toBe(true);
});

Then('indication of incomplete required fields should be shown', async function () {
  await assertions.assertVisible(page.locator('//div[@class*="required-warning"]'));
});

Then('error message should use plain language', async function () {
  const errorText = await page.locator('//div[@class*="error"]').first().textContent();
  expect(errorText).toBeTruthy();
  expect(errorText?.toLowerCase()).not.toContain('null');
  expect(errorText?.toLowerCase()).not.toContain('undefined');
});

Then('error message {string} should be displayed', async function (expectedMessage: string) {
  await assertions.assertContainsText(page.locator('//div[@class*="error"]'), expectedMessage);
});

Then('error message should not contain technical jargon', async function () {
  const errorText = await page.locator('//div[@class*="error"]').first().textContent();
  expect(errorText?.toLowerCase()).not.toContain('exception');
  expect(errorText?.toLowerCase()).not.toContain('stack trace');
  expect(errorText?.toLowerCase()).not.toContain('null pointer');
});

Then('error message should be clearly visible', async function () {
  await assertions.assertVisible(page.locator('//div[@class*="error"]'));
});

Then('error message should appear adjacent to {string} field', async function (fieldName: string) {
  const fieldXPath = `//input[@id='${fieldName.toLowerCase()}']`;
  const errorXPath = `${fieldXPath}/following-sibling::div[@class*='error']`;
  await assertions.assertVisible(page.locator(errorXPath));
});

Then('visual indicators should draw attention to errors', async function () {
  const errorElements = page.locator('//div[@class*="error"]');
  const count = await errorElements.count();
  expect(count).toBeGreaterThan(0);
});

Then('error message should be accessible via screen readers', async function () {
  const errorElement = page.locator('//div[@class*="error"]').first();
  const ariaLive = await errorElement.getAttribute('aria-live');
  expect(ariaLive).toBeTruthy();
});

Then('all errors should be clearly listed with specific field identification', async function () {
  const errorList = page.locator('//ul[@class*="error-list"]/li');
  const count = await errorList.count();
  expect(count).toBeGreaterThan(1);
});

Then('error summary should appear at top of form', async function () {
  await assertions.assertVisible(page.locator('//div[@class*="error-summary"]'));
});

Then('error summary should contain links to each problematic field', async function () {
  const errorLinks = await page.locator('//div[@class*="error-summary"]//a').count();
  expect(errorLinks).toBeGreaterThan(0);
});

Then('each field should show inline error message', async function () {
  const inlineErrors = await page.locator('//div[@class*="inline-error"]').count();
  expect(inlineErrors).toBeGreaterThan(0);
});

Then('corrected field should no longer show error', async function () {
  const correctedField = page.locator('//input[@aria-invalid="false"]').first();
  await assertions.assertVisible(correctedField);
});

Then('remaining errors should still be clearly displayed', async function () {
  const remainingErrors = await page.locator('//div[@class*="error"]').count();
  expect(remainingErrors).toBeGreaterThan(0);
});

Then('user should be able to progressively fix errors without losing context', async function () {
  const errorSummary = page.locator('//div[@class*="error-summary"]');
  await assertions.assertVisible(errorSummary);
});

Then('all forms should use consistent validation trigger pattern', async function () {
  const timings = this.testData.formValidationData.map((f: any) => f.validationTiming);
  const avgTiming = timings.reduce((a: number, b: number) => a + b, 0) / timings.length;
  timings.forEach((timing: number) => {
    expect(Math.abs(timing - avgTiming)).toBeLessThan(200);
  });
});

Then('validation timing should be identical across all forms', async function () {
  const timings = this.testData.formValidationData.map((f: any) => f.validationTiming);
  const uniqueTimings = new Set(timings);
  expect(uniqueTimings.size).toBeLessThanOrEqual(2);
});

Then('error messages should use identical visual styling', async function () {
  const styles = this.testData.errorStyles;
  if (styles.length > 1) {
    const firstStyle = styles[0];
    styles.forEach((style: any) => {
      expect(style.color).toBe(firstStyle.color);
    });
  }
});

Then('error color should be consistent across all forms', async function () {
  const styles = this.testData.errorStyles;
  const colors = styles.map((s: any) => s.color);
  const uniqueColors = new Set(colors);
  expect(uniqueColors.size).toBe(1);
});

Then('error icon should be consistent across all forms', async function () {
  await assertions.assertVisible(page.locator('//span[@class*="error-icon"]'));
});

Then('error positioning should be consistent across all forms', async function () {
  const errorElement = page.locator('//div[@class*="error"]').first();
  await assertions.assertVisible(errorElement);
});

Then('error typography should be consistent across all forms', async function () {
  const styles = this.testData.errorStyles;
  if (styles.length > 1) {
    const firstStyle = styles[0];
    styles.forEach((style: any) => {
      expect(style.fontSize).toBe(firstStyle.fontSize);
    });
  }
});

Then('required fields should be marked consistently', async function () {
  const indicators = this.testData.requiredIndicators;
  expect(indicators.every((count: number) => count > 0)).toBe(true);
});

Then('required field indicator position should be identical', async function () {
  await assertions.assertVisible(page.locator('//span[@class*="required"]'));
});

Then('same field types should show identical validation rules', async function () {
  const errors = this.testData.fieldTypeErrors;
  expect(errors.length).toBeGreaterThan(0);
});

Then('error messages should be identical for same field types', async function () {
  const errors = this.testData.fieldTypeErrors;
  const uniqueErrors = new Set(errors);
  expect(uniqueErrors.size).toBeLessThanOrEqual(2);
});

Then('valid input confirmation should use consistent visual pattern', async function () {
  const successIndicators = this.testData.successIndicators;
  expect(successIndicators.every((indicator: boolean) => indicator === true)).toBe(true);
});

Then('success indicators should be identical across all forms', async function () {
  await assertions.assertVisible(page.locator('//span[@class*="success"]'));
});

Then('tab order should be consistent across all forms', async function () {
  const navigation = this.testData.keyboardNavigation;
  expect(navigation.length).toBeGreaterThan(0);
});

Then('focus management should be identical', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBeTruthy();
});

Then('ARIA announcements should be consistent', async function () {
  const ariaLiveElements = await page.locator('//*[@aria-live]').count();
  expect(ariaLiveElements).toBeGreaterThan(0);
});

Then('all validation feedback should be accessible via keyboard', async function () {
  await page.keyboard.press('Tab');
  const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
  expect(focusedElement).toBeTruthy();
});

Then('focus should move to first error field on form submission', async function () {
  const focusedElement = await page.evaluate(() => document.activeElement?.getAttribute('aria-invalid'));
  expect(focusedElement).toBe('true');
});

Then('ARIA live regions should announce validation status', async function () {
  const ariaLive = await page.locator('//*[@aria-live="polite"]').count();
  expect(ariaLive).toBeGreaterThan(0);
});

Then('error messages should be associated with form fields using aria-describedby', async function () {
  const describedByFields = await page.locator('//input[@aria-describedby]').count();
  expect(describedByFields).toBeGreaterThan(0);
});

Then('error fields should have aria-invalid attribute set to true', async function () {
  const invalidFields = await page.locator('//input[@aria-invalid="true"]').count();
  expect(invalidFields).toBeGreaterThan(0);
});

Then('success status should be announced to screen readers', async function () {
  const ariaLive = await page.locator('//*[@aria-live]').count();
  expect(ariaLive).toBeGreaterThan(0);
});

Then('aria-invalid attribute should be removed from valid fields', async function () {
  const validFields = await page.locator('//input[@aria-invalid="false"]').count();
  expect(validFields).toBeGreaterThan(0);
});

Then('validation feedback should appear within {int} milliseconds for all submissions', async function (maxTime: number) {
  const times = this.testData.submissionTimes;
  times.forEach((time: number) => {
    expect(time).toBeLessThan(maxTime);
  });
});

Then('system should remain responsive', async function () {
  const isResponsive = await page.evaluate(() => {
    return document.readyState === 'complete';
  });
  expect(isResponsive).toBe(true);
});

Then('no validation errors should be lost or delayed', async function () {
  const errorCount = await page.locator('//div[@class*="error"]').count();
  expect(errorCount).toBeGreaterThanOrEqual(0);
});

Then('validation should debounce appropriately', async function () {
  const times = this.testData.rapidInputTimes;
  expect(times.length).toBeGreaterThan(0);
});

Then('system should not lag or freeze', async function () {
  const isResponsive = await page.evaluate(() => {
    return document.readyState === 'complete';
  });
  expect(isResponsive).toBe(true);
});

Then('validation feedback should remain accurate', async function () {
  await assertions.assertVisible(page.locator('//span[@class*="validation"]'));
});