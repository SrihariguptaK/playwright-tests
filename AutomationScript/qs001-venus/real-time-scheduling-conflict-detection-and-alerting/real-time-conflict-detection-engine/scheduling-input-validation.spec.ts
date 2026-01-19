import { test, expect } from '@playwright/test';

test.describe('Story-9: Scheduling Input Validation', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling input form
    await page.goto('/scheduling/new');
    await expect(page.locator('[data-testid="scheduling-form"]')).toBeVisible();
  });

  test('Verify validation of scheduling inputs - invalid date format', async ({ page }) => {
    // Enter an invalid date format in the date field
    const dateField = page.locator('[data-testid="schedule-date-input"]');
    await dateField.fill('32/13/2024');
    
    // Measure the time taken for the validation error to appear
    const startTime = Date.now();
    const errorMessage = page.locator('[data-testid="date-error-message"]');
    await expect(errorMessage).toBeVisible({ timeout: 5000 });
    const validationTime = Date.now() - startTime;
    
    // Verify the error message content and clarity
    await expect(errorMessage).toContainText(/invalid date format|please enter a valid date/i);
    
    // Verify validation feedback is within 500ms
    expect(validationTime).toBeLessThan(500);
    
    // Attempt to submit the form with the invalid date
    const submitButton = page.locator('[data-testid="submit-schedule-button"]');
    await submitButton.click();
    
    // Verify submission is prevented
    await expect(errorMessage).toBeVisible();
    await expect(page.locator('[data-testid="scheduling-form"]')).toBeVisible();
  });

  test('Verify validation of scheduling inputs - invalid date format with alphabetic characters', async ({ page }) => {
    // Enter an invalid date format with alphabetic characters
    const dateField = page.locator('[data-testid="schedule-date-input"]');
    await dateField.fill('abc123');
    
    // Measure the time taken for the validation error to appear
    const startTime = Date.now();
    const errorMessage = page.locator('[data-testid="date-error-message"]');
    await expect(errorMessage).toBeVisible({ timeout: 5000 });
    const validationTime = Date.now() - startTime;
    
    // Verify inline error message displayed immediately
    await expect(errorMessage).toBeVisible();
    expect(validationTime).toBeLessThan(500);
  });

  test('Verify validation of scheduling inputs - start time after end time', async ({ page }) => {
    // Correct the date field with a valid date format
    const dateField = page.locator('[data-testid="schedule-date-input"]');
    await dateField.fill('12/15/2024');
    
    // Wait for date validation to pass
    await expect(page.locator('[data-testid="date-error-message"]')).not.toBeVisible();
    
    // Enter a start time that is after the end time
    const startTimeField = page.locator('[data-testid="start-time-input"]');
    const endTimeField = page.locator('[data-testid="end-time-input"]');
    
    await startTimeField.fill('15:00');
    await endTimeField.fill('14:00');
    
    // Measure the time taken for the validation error to appear
    const startTime = Date.now();
    const timeErrorMessage = page.locator('[data-testid="time-error-message"]');
    await expect(timeErrorMessage).toBeVisible({ timeout: 5000 });
    const validationTime = Date.now() - startTime;
    
    // Verify the error message provides clear guidance
    await expect(timeErrorMessage).toContainText(/start time must be before end time|invalid time range/i);
    
    // Verify validation feedback is within 500ms
    expect(validationTime).toBeLessThan(500);
    
    // Attempt to submit the form with start time after end time
    const submitButton = page.locator('[data-testid="submit-schedule-button"]');
    await submitButton.click();
    
    // Validation error prevents submission
    await expect(timeErrorMessage).toBeVisible();
    await expect(page.locator('[data-testid="scheduling-form"]')).toBeVisible();
  });

  test('Verify validation of scheduling inputs - all valid inputs', async ({ page }) => {
    // Enter all valid inputs in the scheduling form
    const dateField = page.locator('[data-testid="schedule-date-input"]');
    const startTimeField = page.locator('[data-testid="start-time-input"]');
    const endTimeField = page.locator('[data-testid="end-time-input"]');
    const resourceField = page.locator('[data-testid="resource-identifier-input"]');
    
    // Valid date format
    await dateField.fill('12/15/2024');
    
    // Start time before end time
    await startTimeField.fill('14:00');
    await endTimeField.fill('15:00');
    
    // Valid resource identifiers
    await resourceField.fill('RESOURCE-001');
    
    // Verify no validation errors are displayed
    await expect(page.locator('[data-testid="date-error-message"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="time-error-message"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="resource-error-message"]')).not.toBeVisible();
    
    // Submit the form with all valid inputs
    const submitButton = page.locator('[data-testid="submit-schedule-button"]');
    await expect(submitButton).toBeEnabled();
    await submitButton.click();
    
    // Verify the submitted data is processed correctly (no validation errors, submission allowed)
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/schedule created successfully|submission successful/i);
  });

  test('Verify validation of scheduling inputs - complete error correction flow', async ({ page }) => {
    // Navigate to the scheduling input form (already done in beforeEach)
    
    // Enter an invalid date format
    const dateField = page.locator('[data-testid="schedule-date-input"]');
    await dateField.fill('32/13/2024');
    
    // Measure the time taken for the validation error to appear
    let startTime = Date.now();
    const dateErrorMessage = page.locator('[data-testid="date-error-message"]');
    await expect(dateErrorMessage).toBeVisible({ timeout: 5000 });
    let validationTime = Date.now() - startTime;
    
    // Verify the error message content and clarity
    await expect(dateErrorMessage).toContainText(/invalid date format|please enter a valid date/i);
    expect(validationTime).toBeLessThan(500);
    
    // Attempt to submit the form with the invalid date
    const submitButton = page.locator('[data-testid="submit-schedule-button"]');
    await submitButton.click();
    await expect(dateErrorMessage).toBeVisible();
    
    // Correct the date field with a valid date format
    await dateField.clear();
    await dateField.fill('12/15/2024');
    await expect(dateErrorMessage).not.toBeVisible();
    
    // Enter a start time that is after the end time
    const startTimeField = page.locator('[data-testid="start-time-input"]');
    const endTimeField = page.locator('[data-testid="end-time-input"]');
    await startTimeField.fill('15:00');
    await endTimeField.fill('14:00');
    
    // Measure the time taken for the validation error to appear
    startTime = Date.now();
    const timeErrorMessage = page.locator('[data-testid="time-error-message"]');
    await expect(timeErrorMessage).toBeVisible({ timeout: 5000 });
    validationTime = Date.now() - startTime;
    expect(validationTime).toBeLessThan(500);
    
    // Attempt to submit the form with start time after end time
    await submitButton.click();
    
    // Verify the error message provides clear guidance
    await expect(timeErrorMessage).toContainText(/start time must be before end time|invalid time range/i);
    
    // Correct the time fields so start time is before end time
    await startTimeField.clear();
    await startTimeField.fill('14:00');
    await endTimeField.clear();
    await endTimeField.fill('15:00');
    await expect(timeErrorMessage).not.toBeVisible();
    
    // Enter all valid inputs in the scheduling form
    const resourceField = page.locator('[data-testid="resource-identifier-input"]');
    await resourceField.fill('RESOURCE-001');
    
    // Submit the form with all valid inputs
    await expect(submitButton).toBeEnabled();
    await submitButton.click();
    
    // Verify the submitted data is processed correctly
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });
  });
});