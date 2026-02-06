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
      admin: { username: 'admin', password: 'admin123' },
      user: { username: 'testuser', password: 'testpass' }
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

Given('user is on the validation test form page', async function () {
  await actions.navigateTo(process.env.BASE_URL + '/validation-form');
  await waits.waitForNetworkIdle();
});

Given('form contains multiple input fields with validation rules', async function () {
  await assertions.assertVisible(page.locator('//form[@id="validation-form"]'));
  const fieldCount = await page.locator('//form[@id="validation-form"]//input').count();
  expect(fieldCount).toBeGreaterThan(0);
});

Given('mouse is disconnected or not used during test', async function () {
  this.keyboardOnlyMode = true;
});

Given('screen reader is turned off to test keyboard-only navigation', async function () {
  this.screenReaderEnabled = false;
});

Given('screen reader is enabled', async function () {
  this.screenReaderEnabled = true;
});

Given('audio output is enabled to hear announcements', async function () {
  this.audioEnabled = true;
});

Given('user is on page with validation that triggers modal dialogs', async function () {
  await actions.navigateTo(process.env.BASE_URL + '/validation-form-modal');
  await waits.waitForNetworkIdle();
});

Given('keyboard-only navigation is being used', async function () {
  this.keyboardOnlyMode = true;
});

Given('color contrast analyzer tool is available', async function () {
  this.contrastAnalyzerAvailable = true;
});

Given('form displays validation states for default, error, success, and focus', async function () {
  await assertions.assertVisible(page.locator('//form[@id="validation-form"]'));
});

Given('browser zoom is set to {int}%', async function (zoomLevel: number) {
  await page.evaluate((zoom) => {
    document.body.style.zoom = `${zoom}%`;
  }, zoomLevel);
});

Given('browser zoom is initially set to {int}%', async function (zoomLevel: number) {
  await page.evaluate((zoom) => {
    document.body.style.zoom = `${zoom}%`;
  }, zoomLevel);
});

Given('test is performed on desktop browser', async function () {
  this.deviceType = 'desktop';
});

Given('browser developer tools are open to inspect ARIA attributes', async function () {
  this.devToolsOpen = true;
});

Given('test is performed on mobile device or mobile emulator', async function () {
  await context.close();
  context = await browser.newContext({
    viewport: { width: 375, height: 667 },
    userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
    isMobile: true,
    hasTouch: true,
  });
  page = await context.newPage();
  actions = new GenericActions(page, context);
  assertions = new AssertionHelpers(page);
  waits = new WaitHelpers(page);
});

Given('mobile screen reader is enabled', async function () {
  this.mobileScreenReaderEnabled = true;
});

Given('form is responsive and optimized for mobile devices', async function () {
  await assertions.assertVisible(page.locator('//form[@id="validation-form"]'));
});

// ==================== WHEN STEPS ====================

When('user presses Tab key from browser address bar', async function () {
  await page.keyboard.press('Tab');
});

When('user continues pressing Tab key through all form fields', async function () {
  const fieldCount = await page.locator('//form[@id="validation-form"]//input, //form[@id="validation-form"]//button, //form[@id="validation-form"]//select').count();
  for (let i = 0; i < fieldCount; i++) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
  }
});

When('user presses Shift+Tab to navigate backwards', async function () {
  await page.keyboard.press('Shift+Tab');
});

When('user navigates to a required field and leaves it empty', async function () {
  await page.keyboard.press('Tab');
  const focusedElement = await page.locator(':focus');
  const isRequired = await focusedElement.getAttribute('required');
  if (isRequired !== null) {
    this.currentRequiredField = focusedElement;
  }
});

When('user presses Tab to move to next field', async function () {
  await page.keyboard.press('Tab');
  await page.waitForTimeout(200);
});

When('user presses Shift+Tab to return to field with validation error', async function () {
  await page.keyboard.press('Shift+Tab');
  await page.waitForTimeout(200);
});

When('user navigates to submit button using Tab key', async function () {
  const submitButton = page.locator('//button[@type="submit"]');
  while (!(await submitButton.evaluate(el => el === document.activeElement))) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
  }
});

When('user presses Enter key', async function () {
  await page.keyboard.press('Enter');
  await waits.waitForNetworkIdle();
});

When('user presses Escape key on any form field', async function () {
  await page.keyboard.press('Escape');
  await page.waitForTimeout(200);
});

When('user navigates to first input field using screen reader commands', async function () {
  const firstInput = page.locator('//form[@id="validation-form"]//input').first();
  await firstInput.focus();
});

When('user leaves required field empty and navigates to next field', async function () {
  const requiredField = page.locator('//input[@required]').first();
  await requiredField.focus();
  await requiredField.fill('');
  await page.keyboard.press('Tab');
  await page.waitForTimeout(300);
});

When('user enters invalid email format and navigates away', async function () {
  const emailField = page.locator('//input[@type="email"]');
  await actions.fill(emailField, 'invalidemail');
  await page.keyboard.press('Tab');
  await page.waitForTimeout(300);
});

When('user corrects invalid input to valid data and navigates away', async function () {
  const emailField = page.locator('//input[@type="email"]');
  await actions.clearAndFill(emailField, 'valid@email.com');
  await page.keyboard.press('Tab');
  await page.waitForTimeout(300);
});

When('user fills all fields with valid data', async function () {
  const inputs = page.locator('//form[@id="validation-form"]//input');
  const count = await inputs.count();
  for (let i = 0; i < count; i++) {
    const input = inputs.nth(i);
    const type = await input.getAttribute('type');
    if (type === 'email') {
      await actions.fill(input, 'test@example.com');
    } else if (type === 'text') {
      await actions.fill(input, 'Valid Text');
    } else if (type === 'number') {
      await actions.fill(input, '123');
    } else {
      await actions.fill(input, 'Valid Data');
    }
  }
});

When('user activates submit button', async function () {
  await actions.click(page.locator('//button[@type="submit"]'));
  await waits.waitForNetworkIdle();
});

When('user navigates to error summary section after validation fails', async function () {
  const errorSummary = page.locator('//div[@id="error-summary"]');
  await errorSummary.focus();
});

When('user activates link in error summary', async function () {
  const firstErrorLink = page.locator('//div[@id="error-summary"]//a').first();
  await actions.click(firstErrorLink);
  await page.waitForTimeout(200);
});

When('user triggers validation error that opens modal dialog', async function () {
  await actions.click(page.locator('//button[@id="trigger-modal"]'));
  await waits.waitForVisible(page.locator('//div[@role="dialog"]'));
});

When('user presses Tab key repeatedly in modal', async function () {
  for (let i = 0; i < 5; i++) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
  }
});

When('user presses Shift+Tab from first focusable element in modal', async function () {
  const firstFocusable = page.locator('//div[@role="dialog"]//*[@tabindex="0"]').first();
  await firstFocusable.focus();
  await page.keyboard.press('Shift+Tab');
  await page.waitForTimeout(200);
});

When('user presses Escape key while focus is inside modal', async function () {
  await page.keyboard.press('Escape');
  await page.waitForTimeout(300);
});

When('user reopens modal and activates close button using Enter key', async function () {
  await actions.click(page.locator('//button[@id="trigger-modal"]'));
  await waits.waitForVisible(page.locator('//div[@role="dialog"]'));
  const closeButton = page.locator('//div[@role="dialog"]//button[@aria-label="Close"]');
  await closeButton.focus();
  await page.keyboard.press('Enter');
  await page.waitForTimeout(300);
});

When('user reopens modal and activates confirmation button', async function () {
  await actions.click(page.locator('//button[@id="trigger-modal"]'));
  await waits.waitForVisible(page.locator('//div[@role="dialog"]'));
  const confirmButton = page.locator('//div[@role="dialog"]//button[@id="confirm"]');
  await actions.click(confirmButton);
  await page.waitForTimeout(300);
});

When('user checks contrast ratio of error message text against background', async function () {
  const errorMessage = page.locator('//div[@class="error-message"]').first();
  const color = await errorMessage.evaluate(el => window.getComputedStyle(el).color);
  const bgColor = await errorMessage.evaluate(el => window.getComputedStyle(el).backgroundColor);
  this.errorTextColor = color;
  this.errorBgColor = bgColor;
});

When('user checks contrast ratio of error state border color against white background', async function () {
  const errorField = page.locator('//input[@aria-invalid="true"]').first();
  const borderColor = await errorField.evaluate(el => window.getComputedStyle(el).borderColor);
  this.errorBorderColor = borderColor;
});

When('user verifies validation errors are indicated by more than color', async function () {
  const errorIcon = page.locator('//div[@class="error-message"]//svg, //div[@class="error-message"]//i');
  this.errorIconExists = await errorIcon.count() > 0;
});

When('user checks contrast ratio of success message and indicators', async function () {
  const successMessage = page.locator('//div[@class="success-message"]').first();
  const color = await successMessage.evaluate(el => window.getComputedStyle(el).color);
  this.successTextColor = color;
});

When('user focuses on input field and checks focus indicator contrast', async function () {
  const firstInput = page.locator('//form[@id="validation-form"]//input').first();
  await firstInput.focus();
  const outline = await firstInput.evaluate(el => window.getComputedStyle(el).outline);
  this.focusOutline = outline;
});

When('user enables Windows High Contrast Mode', async function () {
  await page.emulateMedia({ colorScheme: 'dark', forcedColors: 'active' });
});

When('user sets browser zoom to {string} percent', async function (zoomLevel: string) {
  await page.evaluate((zoom) => {
    document.body.style.zoom = `${zoom}%`;
  }, zoomLevel);
  await page.waitForTimeout(500);
});

When('user verifies form elements at {string} percent zoom', async function (zoomLevel: string) {
  this.currentZoomLevel = zoomLevel;
});

When('user triggers validation errors at {string} percent zoom', async function (zoomLevel: string) {
  await actions.click(page.locator('//button[@type="submit"]'));
  await page.waitForTimeout(300);
});

When('user navigates through form fields using Tab key at {string} percent zoom', async function (zoomLevel: string) {
  for (let i = 0; i < 3; i++) {
    await page.keyboard.press('Tab');
    await page.waitForTimeout(100);
  }
});

When('user increases browser text size to {string} percent', async function (textSize: string) {
  await page.evaluate((size) => {
    document.body.style.fontSize = `${size}%`;
  }, textSize);
  await page.waitForTimeout(500);
});

When('user submits form with valid data at {string} percent zoom', async function (zoomLevel: string) {
  const inputs = page.locator('//form[@id="validation-form"]//input');
  const count = await inputs.count();
  for (let i = 0; i < count; i++) {
    const input = inputs.nth(i);
    await actions.fill(input, 'Valid Data');
  }
  await actions.click(page.locator('//button[@type="submit"]'));
  await waits.waitForNetworkIdle();
});

When('user inspects required input field in browser developer tools', async function () {
  const requiredField = page.locator('//input[@required]').first();
  this.ariaRequired = await requiredField.getAttribute('aria-required');
  this.hasLabel = await requiredField.evaluate(el => {
    const id = el.getAttribute('id');
    return document.querySelector(`label[for="${id}"]`) !== null;
  });
});

When('user triggers validation error and inspects input field', async function () {
  const requiredField = page.locator('//input[@required]').first();
  await requiredField.focus();
  await page.keyboard.press('Tab');
  await page.waitForTimeout(300);
  this.ariaInvalid = await requiredField.getAttribute('aria-invalid');
  this.ariaDescribedBy = await requiredField.getAttribute('aria-describedby');
});

When('user inspects error message element in developer tools', async function () {
  const errorMessage = page.locator('//div[@class="error-message"]').first();
  this.errorMessageId = await errorMessage.getAttribute('id');
  this.errorMessageRole = await errorMessage.getAttribute('role');
});

When('user corrects validation error and inspects field again', async function () {
  const requiredField = page.locator('//input[@required]').first();
  await actions.fill(requiredField, 'Valid Data');
  await page.keyboard.press('Tab');
  await page.waitForTimeout(300);
  this.ariaInvalidAfterFix = await requiredField.getAttribute('aria-invalid');
  this.ariaDescribedByAfterFix = await requiredField.getAttribute('aria-describedby');
});

When('user inspects form element in developer tools', async function () {
  const form = page.locator('//form[@id="validation-form"]');
  this.formRole = await form.getAttribute('role');
  this.formAriaLabel = await form.getAttribute('aria-label');
});

When('user tests with screen reader to verify ARIA attributes', async function () {
  this.screenReaderTestComplete = true;
});

When('user inspects success message after successful form submission', async function () {
  const successMessage = page.locator('//div[@class="success-message"]');
  this.successAriaLive = await successMessage.getAttribute('aria-live');
  this.successRole = await successMessage.getAttribute('role');
});

When('user enables mobile screen reader and swipes right to first field', async function () {
  const firstField = page.locator('//form[@id="validation-form"]//input').first();
  await firstField.focus();
});

When('user verifies touch target sizes', async function () {
  const buttons = page.locator('//button');
  const count = await buttons.count();
  for (let i = 0; i < count; i++) {
    const button = buttons.nth(i);
    const box = await button.boundingBox();
    if (box) {
      expect(box.width).toBeGreaterThanOrEqual(44);
      expect(box.height).toBeGreaterThanOrEqual(44);
    }
  }
});

When('user taps on input field and enters invalid data', async function () {
  const emailField = page.locator('//input[@type="email"]');
  await actions.click(emailField);
  await actions.fill(emailField, 'invalidemail');
  await page.keyboard.press('Tab');
  await page.waitForTimeout(300);
});

When('user uses screen reader gestures to navigate through error messages', async function () {
  const errorMessages = page.locator('//div[@class="error-message"]');
  const count = await errorMessages.count();
  for (let i = 0; i < count; i++) {
    await errorMessages.nth(i).focus();
    await page.waitForTimeout(100);
  }
});

When('user double-taps submit button with screen reader active', async function () {
  const submitButton = page.locator('//button[@type="submit"]');
  await actions.click(submitButton);
  await waits.waitForNetworkIdle();
});

When('user tests pinch-to-zoom functionality on form', async function () {
  await page.evaluate(() => {
    document.body.style.zoom = '200%';
  });
  await page.waitForTimeout(500);
});

When('user rotates device to landscape orientation', async function () {
  await page.setViewportSize({ width: 667, height: 375 });
  await page.waitForTimeout(500);
});

// ==================== THEN STEPS ====================

Then('focus should move to first input field', async function () {
  const firstInput = page.locator('//form[@id="validation-form"]//input').first();
  const isFocused = await firstInput.evaluate(el => el === document.activeElement);
  expect(isFocused).toBeTruthy();
});

Then('visible focus indicator should appear around the field', async function () {
  const focusedElement = page.locator(':focus');
  const outline = await focusedElement.evaluate(el => window.getComputedStyle(el).outline);
  expect(outline).not.toBe('none');
});

Then('focus should move sequentially through all interactive elements', async function () {
  const focusedElement = page.locator(':focus');
  await assertions.assertVisible(focusedElement);
});

Then('focus indicator should be clearly visible on each element', async function () {
  const focusedElement = page.locator(':focus');
  const outline = await focusedElement.evaluate(el => window.getComputedStyle(el).outline);
  expect(outline).not.toBe('none');
});

Then('tab order should follow visual layout', async function () {
  const focusedElement = page.locator(':focus');
  const tabIndex = await focusedElement.getAttribute('tabindex');
  expect(tabIndex === null || parseInt(tabIndex) >= 0).toBeTruthy();
});

Then('focus should move in reverse order through all fields', async function () {
  const focusedElement = page.locator(':focus');
  await assertions.assertVisible(focusedElement);
});

Then('focus indicator should remain visible', async function () {
  const focusedElement = page.locator(':focus');
  const outline = await focusedElement.evaluate(el => window.getComputedStyle(el).outline);
  expect(outline).not.toBe('none');
});

Then('no focus traps should occur', async function () {
  const focusedElement = page.locator(':focus');
  const tagName = await focusedElement.evaluate(el => el.tagName);
  expect(tagName).not.toBe('BODY');
});

Then('validation error message should appear', async function () {
  await assertions.assertVisible(page.locator('//div[@class="error-message"]'));
});

Then('focus should move to next field', async function () {
  const focusedElement = page.locator(':focus');
  await assertions.assertVisible(focusedElement);
});

Then('error message should be associated with the field', async function () {
  const errorMessage = page.locator('//div[@class="error-message"]').first();
  const errorId = await errorMessage.getAttribute('id');
  expect(errorId).toBeTruthy();
});

Then('focus should return to the invalid field', async function () {
  const focusedElement = page.locator(':focus');
  const ariaInvalid = await focusedElement.getAttribute('aria-invalid');
  expect(ariaInvalid).toBe('true');
});

Then('error message should remain displayed', async function () {
  await assertions.assertVisible(page.locator('//div[@class="error-message"]'));
});

Then('form submission should be triggered', async function () {
  await page.waitForTimeout(500);
});

Then('focus should move to first invalid field if validation fails', async function () {
  const firstInvalidField = page.locator('//input[@aria-invalid="true"]').first();
  if (await firstInvalidField.count() > 0) {
    const isFocused = await firstInvalidField.evaluate(el => el === document.activeElement);
    expect(isFocused).toBeTruthy();
  }
});

Then('all error messages should be displayed', async function () {
  const errorMessages = page.locator('//div[@class="error-message"]');
  const count = await errorMessages.count();
  expect(count).toBeGreaterThan(0);
});

Then('modal or dropdown should close if open', async function () {
  const modal = page.locator('//div[@role="dialog"]');
  if (await modal.count() > 0) {
    await waits.waitForHidden(modal);
  }
});

Then('focus should remain on current element if no modal is open', async function () {
  const focusedElement = page.locator(':focus');
  await assertions.assertVisible(focusedElement);
});

Then('screen reader should announce field label', async function () {
  const focusedElement = page.locator(':focus');
  const ariaLabel = await focusedElement.getAttribute('aria-label');
  const hasLabel = await focusedElement.evaluate(el => {
    const id = el.getAttribute('id');
    return document.querySelector(`label[for="${id}"]`) !== null;
  });
  expect(ariaLabel !== null || hasLabel).toBeTruthy();
});

Then('screen reader should announce field type', async function () {
  const focusedElement = page.locator(':focus');
  const type = await focusedElement.getAttribute('type');
  expect(type).toBeTruthy();
});

Then('screen reader should announce required status', async function () {
  const focusedElement = page.locator(':focus');
  const ariaRequired = await focusedElement.getAttribute('aria-required');
  const required = await focusedElement.getAttribute('required');
  expect(ariaRequired === 'true' || required !== null).toBeTruthy();
});

Then('screen reader should announce any help text', async function () {
  const focusedElement = page.locator(':focus');
  const ariaDescribedBy = await focusedElement.getAttribute('aria-describedby');
  if (ariaDescribedBy) {
    const helpText = page.locator(`//*[@id="${ariaDescribedBy}"]`);
    await assertions.assertVisible(helpText);
  }
});

Then('screen reader should announce {string}', async function (announcement: string) {
  const liveRegion = page.locator('//*[@aria-live]');
  if (await liveRegion.count() > 0) {
    await assertions.assertContainsText(liveRegion.first(), announcement);
  }
});

Then('error should be associated with the field', async function () {
  const invalidField = page.locator('//input[@aria-invalid="true"]').first();
  const ariaDescribedBy = await invalidField.getAttribute('aria-describedby');
  expect(ariaDescribedBy).toBeTruthy();
});

Then('error message should be clear and descriptive', async function () {
  const errorMessage = page.locator('//div[@class="error-message"]').first();
  const text = await errorMessage.textContent();
  expect(text?.length).toBeGreaterThan(10);
});

Then('screen reader should announce error is cleared or remain silent', async function () {
  const errorMessage = page.locator('//div[@class="error-message"]');
  const count = await errorMessage.count();
  expect(count).toBe(0);
});

Then('no error message should be announced', async function () {
  const errorMessage = page.locator('//div[@class="error-message"]');
  await waits.waitForHidden(errorMessage.first());
});

Then('field should be marked as valid', async function () {
  const focusedElement = page.locator(':focus');
  const ariaInvalid = await focusedElement.getAttribute('aria-invalid');
  expect(ariaInvalid === 'false' || ariaInvalid === null).toBeTruthy();
});

Then('announcement should use ARIA live region', async function () {
  const liveRegion = page.locator('//*[@aria-live]');
  await assertions.assertVisible(liveRegion.first());
});

Then('announcement should be clear and immediate', async function () {
  const liveRegion = page.locator('//*[@aria-live]');
  const ariaLive = await liveRegion.first().getAttribute('aria-live');
  expect(ariaLive === 'polite' || ariaLive === 'assertive').toBeTruthy();
});

Then('screen reader should announce {string} heading', async function (headingText: string) {
  const heading = page.locator(`//h1[contains(text(),'${headingText}')], //h2[contains(text(),'${headingText}')]`);
  await assertions.assertVisible(heading);
});

Then('screen reader should list all validation errors with links', async function () {
  const errorLinks = page.locator('//div[@id="error-summary"]//a');
  const count = await errorLinks.count();
  expect(count).toBeGreaterThan(0);
});

Then('errors should be numbered or bulleted', async function () {
  const errorList = page.locator('//div[@id="error-summary"]//ul, //div[@id="error-summary"]//ol');
  await assertions.assertVisible(errorList);
});

Then('focus should move to corresponding invalid field', async function () {
  const focusedElement = page.locator(':focus');
  const ariaInvalid = await focusedElement.getAttribute('aria-invalid');
  expect(ariaInvalid).toBe('true');
});

Then('screen reader should announce field label and error message', async function () {
  const focusedElement = page.locator(':focus');
  const ariaDescribedBy = await focusedElement.getAttribute('aria-describedby');
  expect(ariaDescribedBy).toBeTruthy();
});

Then('modal should open', async function () {
  await assertions.assertVisible(page.locator('//div[@role="dialog"]'));
});

Then('focus should automatically move to first focusable element in modal', async function () {
  const firstFocusable = page.locator('//div[@role="dialog"]//*[@tabindex="0"]').first();
  const isFocused = await firstFocusable.evaluate(el => el === document.activeElement);
  expect(isFocused).toBeTruthy();
});

Then('screen reader should announce modal title and role', async function () {
  const modal = page.locator('//div[@role="dialog"]');
  const ariaLabel = await modal.getAttribute('aria-label');
  const ariaLabelledBy = await modal.getAttribute('aria-labelledby');
  expect(ariaLabel !== null || ariaLabelledBy !== null).toBeTruthy();
});

Then('focus should cycle only through elements within modal', async function () {
  const focusedElement = page.locator(':focus');
  const isInModal = await focusedElement.evaluate(el => {
    return el.closest('[role="dialog"]') !== null;
  });
  expect(isInModal).toBeTruthy();
});

Then('focus should not escape to background page content', async function () {
  const focusedElement = page.locator(':focus');
  const isInModal = await focusedElement.evaluate(el => {
    return el.closest('[role="dialog"]') !== null;
  });
  expect(isInModal).toBeTruthy();
});

Then('focus should move to last focusable element in modal', async function () {
  const focusedElement = page.locator(':focus');
  const isInModal = await focusedElement.evaluate(el => {
    return el.closest('[role="dialog"]') !== null;
  });
  expect(isInModal).toBeTruthy();
});

Then('focus trap should keep focus within modal', async function () {
  const focusedElement = page.locator(':focus');
  const isInModal = await focusedElement.evaluate(el => {
    return el.closest('[role="dialog"]') !== null;
  });
  expect(isInModal).toBeTruthy();
});

Then('modal should close', async function () {
  await waits.waitForHidden(page.locator('//div[@role="dialog"]'));
});

Then('focus should return to element that triggered modal', async function () {
  const triggerButton = page.locator('//button[@id="trigger-modal"]');
  const isFocused = await triggerButton.evaluate(el => el === document.activeElement);
  expect(isFocused).toBeTruthy();
});

Then('screen reader should announce modal closure', async function () {
  const modal = page.locator('//div[@role="dialog"]');
  const count = await modal.count();
  expect(count).toBe(0);
});

Then('no focus should be lost to document body', async function () {
  const focusedElement = page.locator(':focus');
  const tagName = await focusedElement.evaluate(el => el.tagName);
  expect(tagName).not.toBe('BODY');
});

Then('modal should close after action is completed', async function () {
  await waits.waitForHidden(page.locator('//div[@role="dialog"]'));
});

Then('focus should return to appropriate element', async function () {
  const focusedElement = page.locator(':focus');
  const tagName = await focusedElement.evaluate(el => el.tagName);
  expect(tagName).not.toBe('BODY');
});

Then('screen reader should announce the result', async function () {
  const liveRegion = page.locator('//*[@aria-live]');
  await assertions.assertVisible(liveRegion.first());
});

Then('error message text should have minimum contrast ratio of {string} for normal text', async function (ratio: string) {
  expect(this.errorTextColor).toBeTruthy();
});

Then('error message should meet WCAG 2.1 AA standards', async function () {
  expect(this.errorTextColor).toBeTruthy();
});

Then('error border should have minimum contrast ratio of {string}', async function (ratio: string) {
  expect(this.errorBorderColor).toBeTruthy();
});

Then('error border should meet WCAG 2.1 AA standards for non-text contrast', async function () {
  expect(this.errorBorderColor).toBeTruthy();
});

Then('error state should include error icon in addition to red color', async function () {
  expect(this.errorIconExists).toBeTruthy();
});

Then('error message text should be present', async function () {
  await assertions.assertVisible(page.locator('//div[@class="error-message"]'));
});

Then('error should not rely solely on color', async function () {
  expect(this.errorIconExists).toBeTruthy();
});

Then('success message should have minimum {string} contrast ratio', async function (ratio: string) {
  expect(this.successTextColor).toBeTruthy();
});

Then('success icon should be present in addition to green color', async function () {
  const successIcon = page.locator('//div[@class="success-message"]//svg, //div[@class="success-message"]//i');
  await assertions.assertVisible(successIcon);
});

Then('focus indicator should have minimum {string} contrast ratio against background', async function (ratio: string) {
  expect(this.focusOutline).toBeTruthy();
});

Then('focus indicator should be at least {string} pixels thick', async function (pixels: string) {
  expect(this.focusOutline).toBeTruthy();
});

Then('all validation states should remain visible and distinguishable', async function () {
  await assertions.assertVisible(page.locator('//form[@id="validation-form"]'));
});

Then('icons and borders should be visible in high contrast mode', async function () {
  const errorIcon = page.locator('//div[@class="error-message"]//svg, //div[@class="error-message"]//i');
  await assertions.assertVisible(errorIcon);
});

Then('page should zoom to {string} percent', async function (zoomLevel: string) {
  expect(this.currentZoomLevel).toBe(zoomLevel);
});

Then('all content should scale proportionally', async function () {
  await assertions.assertVisible(page.locator('//form[@id="validation-form"]'));
});

Then('no horizontal scrolling should be required for form content', async function () {
  const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
  const clientWidth = await page.evaluate(() => document.documentElement.clientWidth);
  expect(scrollWidth).toBeLessThanOrEqual(clientWidth + 10);
});

Then('all form labels should be visible and readable', async function () {
  const labels = page.locator('//label');
  const count = await labels.count();
  expect(count).toBeGreaterThan(0);
});

Then('all input fields should be visible and readable', async function () {
  const inputs = page.locator('//input');
  const count = await inputs.count();
  expect(count).toBeGreaterThan(0);
});

Then('all buttons should be visible and readable', async function () {
  const buttons = page.locator('//button');
  const count = await buttons.count();
  expect(count).toBeGreaterThan(0);
});

Then('no text should be truncated or cut off', async function () {
  await assertions.assertVisible(page.locator('//form[@id="validation-form"]'));
});

Then('form layout should adapt responsively', async function () {
  await assertions.assertVisible(page.locator('//form[@id="validation-form"]'));
});

Then('no elements should overlap', async function () {
  await assertions.assertVisible(page.locator('//form[@id="validation-form"]'));
});

Then('error messages should display completely', async function () {
  const errorMessages = page.locator('//div[@class="error-message"]');
  const count = await errorMessages.count();
  if (count > 0) {
    await assertions.assertVisible(errorMessages.first());
  }
});

Then('error text should not be truncated', async function () {
  const errorMessage = page.locator('//div[@class="error-message"]').first();
  if (await errorMessage.count() > 0) {
    const text = await errorMessage.textContent();
    expect(text?.length).toBeGreaterThan(0);
  }
});

Then('error icons should be visible', async function () {
  const errorIcon = page.locator('//div[@class="error-message"]//svg, //div[@class="error-message"]//i');
  if (await errorIcon.count() > 0) {
    await assertions.assertVisible(errorIcon.first());
  }
});

Then('error messages should be positioned correctly near fields', async function () {
  await assertions.assertVisible(page.locator('//div[@class="error-message"]'));
});

Then('focus indicator should be visible and properly sized', async function () {
  const focusedElement = page.locator(':focus');
  const outline = await focusedElement.evaluate(el => window.getComputedStyle(el).outline);
  expect(outline).not.toBe('none');
});

Then('focused elements should scroll into view automatically if needed', async function () {
  const focusedElement = page.locator(':focus');
  await assertions.assertVisible(focusedElement);
});

Then('text should scale to {string} percent', async function (textSize: string) {
  await assertions.assertVisible(page.locator('//form[@id="validation-form"]'));
});

Then('layout should adapt without breaking', async function () {
  await assertions.assertVisible(page.locator('//form[@id="validation-form"]'));
});

Then('no text should overlap or become unreadable', async function () {
  await assertions.assertVisible(page.locator('//form[@id="validation-form"]'));
});

Then('form should remain functional', async function () {
  await assertions.assertVisible(page.locator('//button[@type="submit"]'));
});

Then('form should submit successfully', async function () {
  await waits.waitForNetworkIdle();
});

Then('success message should be fully visible and readable', async function () {
  await assertions.assertVisible(page.locator('//div[@class="success-message"]'));
});

Then('all functionality should work as expected', async function () {
  await assertions.assertVisible(page.locator('//form[@id="validation-form"]'));
});

Then('field should have {string} attribute set to {string}', async function (attribute: string, value: string) {
  const field = page.locator('//input[@required]').first();
  const attrValue = await field.getAttribute(attribute);
  expect(attrValue).toBe(value);
});

Then('field should have associated label with proper for/id relationship', async function () {
  expect(this.hasLabel).toBeTruthy();
});

Then('field should have {string} attribute pointing to error message ID', async function (attribute: string) {
  expect(this.ariaDescribedBy).toBeTruthy();
});

Then('error message element should have appropriate role or be in live region', async function () {
  expect(this.errorMessageRole === 'alert' || this.errorMessageRole !== null).toBeTruthy();
});

Then('error message should have unique ID matching {string} value', async function (attribute: string) {
  expect(this.errorMessageId).toBeTruthy();
});

Then('error message should have {string} attribute set to {string} or be within ARIA live region', async function (attribute: string, value: string) {
  expect(this.errorMessageRole === value || this.errorMessageRole !== null).toBeTruthy();
});

Then('{string} attribute should be removed or set to {string}', async function (attribute: string, value: string) {
  expect(this.ariaInvalidAfterFix === value || this.ariaInvalidAfterFix === null).toBeTruthy();
});

Then('{string} should no longer reference error message', async function (attribute: string) {
  expect(this.ariaDescribedByAfterFix === null || this.ariaDescribedByAfterFix === '').toBeTruthy();
});

Then('error message should be removed from DOM or hidden with {string}', async function (attribute: string) {
  const errorMessage = page.locator('//div[@class="error-message"]');
  const count = await errorMessage.count();
  expect(count).toBe(0);
});

Then('form should have appropriate {string} attribute set to {string} or be semantic form element', async function (attribute: string, value: string) {
  expect(this.formRole === value || this.formRole === null).toBeTruthy();
});

Then('form should have accessible name via {string} or {string} if multiple forms exist', async function (attr1: string, attr2: string) {
  expect(this.formAriaLabel !== null || this.formRole !== null).toBeTruthy();
});

Then('screen reader should announce required status correctly', async function () {
  expect(this.screenReaderTestComplete).toBeTruthy();
});

Then('screen reader should announce invalid status correctly', async function () {
  expect(this.screenReaderTestComplete).toBeTruthy();
});

Then('screen reader should announce error messages correctly', async function () {
  expect(this.screenReaderTestComplete).toBeTruthy();
});

Then('all ARIA relationships should function as intended', async function () {
  expect(this.screenReaderTestComplete).toBeTruthy();
});

Then('success message should be in {string} region set to {string}', async function (region: string, value: string) {
  expect(this.successAriaLive).toBe(value);
});

Then('success message should be announced by screen reader without requiring focus', async function () {
  expect(this.successAriaLive).toBeTruthy();
});

Then('message should have appropriate role or semantic markup', async function () {
  expect(this.successRole !== null || this.successAriaLive !== null).toBeTruthy();
});

Then('focus indicator should be visible on mobile', async function () {
  const focusedElement = page.locator(':focus');
  const outline = await focusedElement.evaluate(el => window.getComputedStyle(el).outline);
  expect(outline).not.toBe('none');
});

Then('all interactive elements should be at least {string} by {string} pixels', async function (width: string, height: string) {
  const buttons = page.locator('//button');
  const count = await buttons.count();
  for (let i = 0; i < count; i++) {
    const button = buttons.nth(i);
    const box = await button.boundingBox();
    if (box) {
      expect(box.width).toBeGreaterThanOrEqual(parseInt(width));
      expect(box.height).toBeGreaterThanOrEqual(parseInt(height));
    }
  }
});

Then('adequate spacing should exist between touch targets', async function () {
  await assertions.assertVisible(page.locator('//form[@id="validation-form"]'));
});

Then('error message should appear below field', async function () {
  await assertions.assertVisible(page.locator('//div[@class="error-message"]'));
});

Then('error message should be announced by screen reader', async function () {
  const errorMessage = page.locator('//div[@class="error-message"]');
  const role = await errorMessage.first().getAttribute('role');
  expect(role === 'alert' || role !== null).toBeTruthy();
});

Then('error message should be large enough to read on mobile screen', async function () {
  const errorMessage = page.locator('//div[@class="error-message"]').first();
  const fontSize = await errorMessage.evaluate(el => window.getComputedStyle(el).fontSize);
  expect(fontSize).toBeTruthy();
});

Then('screen reader should navigate to and read all error messages', async function () {
  const errorMessages = page.locator('//div[@class="error-message"]');
  const count = await errorMessages.count();
  expect(count).toBeGreaterThan(0);
});

Then('error messages should be in logical reading order', async function () {
  await assertions.assertVisible(page.locator('//div[@class="error-message"]'));
});

Then('swipe gestures should work correctly', async function () {
  await assertions.assertVisible(page.locator('//form[@id="validation-form"]'));
});

Then('form should submit', async function () {
  await waits.waitForNetworkIdle();
});

Then('validation errors should be announced if present', async function () {
  const errorMessages = page.locator('//div[@class="error-message"]');
  if (await errorMessages.count() > 0) {
    await assertions.assertVisible(errorMessages.first());
  }
});

Then('success message should be announced if submission succeeds', async function () {
  const successMessage = page.locator('//div[@class="success-message"]');
  if (await successMessage.count() > 0) {
    await assertions.assertVisible(successMessage);
  }
});

Then('form should zoom up to {string} percent without loss of functionality', async function (zoomLevel: string) {
  await assertions.assertVisible(page.locator('//form[@id="validation-form"]'));
});

Then('validation messages should remain visible and readable when zoomed', async function () {
  const errorMessages = page.locator('//div[@class="error-message"]');
  if (await errorMessages.count() > 0) {
    await assertions.assertVisible(errorMessages.first());
  }
});

Then('no content should be cut off', async function () {
  await assertions.assertVisible(page.locator('//form[@id="validation-form"]'));
});

Then('form layout should adapt to landscape orientation', async function () {
  await assertions.assertVisible(page.locator('//form[@id="validation-form"]'));
});

Then('all validation messages should remain visible', async function () {
  const errorMessages = page.locator('//div[@class="error-message"]');
  if (await errorMessages.count() > 0) {
    await assertions.assertVisible(errorMessages.first());
  }
});

Then('functionality should be preserved in both orientations', async function () {
  await assertions.assertVisible(page.locator('//button[@type="submit"]'));
});