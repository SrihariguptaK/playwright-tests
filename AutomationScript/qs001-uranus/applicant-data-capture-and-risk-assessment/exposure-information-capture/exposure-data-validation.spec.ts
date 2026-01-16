import { test, expect } from '@playwright/test';

test.describe('Exposure Data Validation', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const exposureFormURL = `${baseURL}/exposure-data-entry`;

  test.beforeEach(async ({ page }) => {
    await page.goto(exposureFormURL);
    await expect(page).toHaveURL(exposureFormURL);
  });

  test('Validate acceptance of correct exposure data inputs', async ({ page }) => {
    // Navigate to the exposure data entry form
    await expect(page.locator('[data-testid="exposure-form"]')).toBeVisible();

    // Enter valid exposure type from the dropdown list
    await page.locator('[data-testid="exposure-type-dropdown"]').click();
    await page.locator('[data-testid="exposure-type-option-property"]').click();

    // Enter valid numeric value in the exposure amount field
    await page.locator('[data-testid="exposure-amount-input"]').fill('50000');

    // Enter valid date in the exposure date field
    await page.locator('[data-testid="exposure-date-input"]').fill('2024-01-15');

    // Fill in all remaining mandatory exposure fields with valid data
    await page.locator('[data-testid="exposure-location-input"]').fill('123 Main Street');
    await page.locator('[data-testid="exposure-description-input"]').fill('Commercial property exposure');
    await page.locator('[data-testid="exposure-coverage-input"]').fill('1000000');

    // Verify no validation errors displayed
    await expect(page.locator('[data-testid="validation-error"]')).toHaveCount(0);
    await expect(page.locator('.error-message')).toHaveCount(0);

    // Click the Submit button
    await page.locator('[data-testid="submit-exposure-button"]').click();

    // Verify the exposure data is saved in the system
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Data saved successfully');
  });

  test('Verify rejection of invalid exposure data inputs', async ({ page }) => {
    // Navigate to the exposure data entry form
    await expect(page.locator('[data-testid="exposure-form"]')).toBeVisible();

    // Leave the mandatory exposure type field empty and move to next field
    await page.locator('[data-testid="exposure-amount-input"]').click();

    // Verify validation error for empty exposure type
    await expect(page.locator('[data-testid="exposure-type-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="exposure-type-error"]')).toContainText(/required|mandatory/i);

    // Enter alphabetic characters in the numeric exposure amount field
    await page.locator('[data-testid="exposure-amount-input"]').fill('ABC');
    await page.locator('[data-testid="exposure-date-input"]').click();

    // Verify validation error for invalid numeric input
    await expect(page.locator('[data-testid="exposure-amount-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="exposure-amount-error"]')).toContainText(/numeric|number|invalid/i);

    // Enter a numeric value outside the acceptable range
    await page.locator('[data-testid="exposure-amount-input"]').clear();
    await page.locator('[data-testid="exposure-amount-input"]').fill('-1000');
    await page.locator('[data-testid="exposure-date-input"]').click();

    // Verify validation error for out of range value
    await expect(page.locator('[data-testid="exposure-amount-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="exposure-amount-error"]')).toContainText(/range|minimum|invalid/i);

    // Leave other mandatory fields empty
    await page.locator('[data-testid="exposure-date-input"]').clear();

    // Attempt to click the Submit button with validation errors present
    const submitButton = page.locator('[data-testid="submit-exposure-button"]');
    await expect(submitButton).toBeDisabled();

    // Correct all validation errors by entering valid data in all fields
    await page.locator('[data-testid="exposure-type-dropdown"]').click();
    await page.locator('[data-testid="exposure-type-option-property"]').click();
    await page.locator('[data-testid="exposure-amount-input"]').clear();
    await page.locator('[data-testid="exposure-amount-input"]').fill('75000');
    await page.locator('[data-testid="exposure-date-input"]').fill('2024-02-20');
    await page.locator('[data-testid="exposure-location-input"]').fill('456 Oak Avenue');
    await page.locator('[data-testid="exposure-description-input"]').fill('Valid property exposure');
    await page.locator('[data-testid="exposure-coverage-input"]').fill('500000');

    // Verify no validation errors remain
    await expect(page.locator('[data-testid="validation-error"]')).toHaveCount(0);

    // Click the Submit button after correcting all errors
    await expect(submitButton).toBeEnabled();
    await submitButton.click();

    // Verify successful submission
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Data saved successfully');
  });

  test('Test validation for multiple exposure types', async ({ page }) => {
    // Navigate to the exposure data entry form
    await expect(page.locator('[data-testid="exposure-form"]')).toBeVisible();

    // Select 'Property' exposure type from the dropdown
    await page.locator('[data-testid="exposure-type-dropdown"]').click();
    await page.locator('[data-testid="exposure-type-option-property"]').click();

    // Enter valid data for all mandatory property exposure fields
    await page.locator('[data-testid="exposure-amount-input"]').fill('100000');
    await page.locator('[data-testid="exposure-date-input"]').fill('2024-03-01');
    await page.locator('[data-testid="exposure-location-input"]').fill('789 Property Lane');
    await page.locator('[data-testid="exposure-description-input"]').fill('Property exposure data');
    await page.locator('[data-testid="exposure-coverage-input"]').fill('800000');

    // Verify no validation errors
    await expect(page.locator('[data-testid="validation-error"]')).toHaveCount(0);

    // Click Submit button
    await page.locator('[data-testid="submit-exposure-button"]').click();
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Navigate back to exposure data entry form and select 'Liability' exposure type
    await page.goto(exposureFormURL);
    await expect(page.locator('[data-testid="exposure-form"]')).toBeVisible();
    await page.locator('[data-testid="exposure-type-dropdown"]').click();
    await page.locator('[data-testid="exposure-type-option-liability"]').click();

    // Enter valid data for all mandatory liability exposure fields
    await page.locator('[data-testid="exposure-amount-input"]').fill('250000');
    await page.locator('[data-testid="exposure-date-input"]').fill('2024-03-15');
    await page.locator('[data-testid="exposure-location-input"]').fill('321 Liability Street');
    await page.locator('[data-testid="exposure-description-input"]').fill('Liability exposure data');
    await page.locator('[data-testid="exposure-coverage-input"]').fill('1500000');

    // Verify no validation errors
    await expect(page.locator('[data-testid="validation-error"]')).toHaveCount(0);

    // Click Submit button
    await page.locator('[data-testid="submit-exposure-button"]').click();
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Navigate back to exposure data entry form and select 'Auto' exposure type
    await page.goto(exposureFormURL);
    await expect(page.locator('[data-testid="exposure-form"]')).toBeVisible();
    await page.locator('[data-testid="exposure-type-dropdown"]').click();
    await page.locator('[data-testid="exposure-type-option-auto"]').click();

    // Enter valid data for all mandatory auto exposure fields
    await page.locator('[data-testid="exposure-amount-input"]').fill('35000');
    await page.locator('[data-testid="exposure-date-input"]').fill('2024-04-01');
    await page.locator('[data-testid="exposure-location-input"]').fill('654 Auto Boulevard');
    await page.locator('[data-testid="exposure-description-input"]').fill('Auto exposure data');
    await page.locator('[data-testid="exposure-coverage-input"]').fill('300000');

    // Verify no validation errors
    await expect(page.locator('[data-testid="validation-error"]')).toHaveCount(0);

    // Click Submit button
    await page.locator('[data-testid="submit-exposure-button"]').click();
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Verify all submitted exposure records are stored in the system
    await page.goto(`${baseURL}/exposure-data-list`);
    await expect(page.locator('[data-testid="exposure-record"]').filter({ hasText: 'Property' })).toBeVisible();
    await expect(page.locator('[data-testid="exposure-record"]').filter({ hasText: 'Liability' })).toBeVisible();
    await expect(page.locator('[data-testid="exposure-record"]').filter({ hasText: 'Auto' })).toBeVisible();
  });
});