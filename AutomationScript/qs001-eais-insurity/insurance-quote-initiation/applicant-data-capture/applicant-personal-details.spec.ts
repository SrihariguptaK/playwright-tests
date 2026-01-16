import { test, expect } from '@playwright/test';

test.describe('Applicant Personal Details Entry', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to applicant data entry page before each test
    await page.goto('/applicant-data-entry');
    // Wait for form to be fully loaded
    await page.waitForLoadState('networkidle');
  });

  test('Validate successful applicant data entry with valid inputs', async ({ page }) => {
    // Step 1: Verify applicant form is displayed with all mandatory fields
    await expect(page.locator('[data-testid="applicant-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="first-name-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="last-name-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="dob-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="gender-select"]')).toBeVisible();
    await expect(page.locator('[data-testid="phone-input"]')).toBeVisible();

    // Step 2: Enter valid personal details in all mandatory fields
    await page.locator('[data-testid="first-name-input"]').fill('John');
    await page.locator('[data-testid="last-name-input"]').fill('Smith');
    await page.locator('[data-testid="dob-input"]').fill('01/15/1985');
    await page.locator('[data-testid="gender-select"]').selectOption('Male');
    await page.locator('[data-testid="phone-input"]').fill('5551234567');

    // Verify no validation errors are shown
    await expect(page.locator('[data-testid="validation-error"]')).toHaveCount(0);
    await expect(page.locator('.error-message')).toHaveCount(0);

    // Step 3: Submit the form
    await page.locator('[data-testid="submit-button"]').click();

    // Verify applicant data is saved and confirmation is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Applicant data saved successfully');
  });

  test('Verify rejection of form submission with missing mandatory fields', async ({ page }) => {
    // Step 1: Verify applicant form is displayed
    await expect(page.locator('[data-testid="applicant-form"]')).toBeVisible();

    // Step 2: Enter valid first name
    await page.locator('[data-testid="first-name-input"]').fill('Jane');

    // Leave the Last Name field empty and move focus to the next field
    await page.locator('[data-testid="last-name-input"]').click();
    await page.locator('[data-testid="dob-input"]').click();

    // Enter valid date of birth
    await page.locator('[data-testid="dob-input"]').fill('03/20/1990');

    // Leave the Gender field unselected and move to phone
    await page.locator('[data-testid="phone-input"]').click();

    // Enter valid phone number
    await page.locator('[data-testid="phone-input"]').fill('5559876543');

    // Real-time validation should highlight missing fields
    await expect(page.locator('[data-testid="last-name-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="gender-error"]')).toBeVisible();

    // Step 3: Attempt to submit the form
    await page.locator('[data-testid="submit-button"]').click();

    // Verify submission is blocked and error messages are displayed
    await expect(page.locator('[data-testid="last-name-error"]')).toContainText('Last Name is required');
    await expect(page.locator('[data-testid="gender-error"]')).toContainText('Gender is required');

    // Verify form is still on the same page (not submitted)
    await expect(page.locator('[data-testid="applicant-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
  });

  test('Ensure draft save and resume functionality works correctly', async ({ page }) => {
    // Step 1: Enter partial applicant data
    await page.locator('[data-testid="first-name-input"]').fill('Robert');
    await page.locator('[data-testid="last-name-input"]').fill('Johnson');
    await page.locator('[data-testid="dob-input"]').fill('05/10/1988');

    // Leave Gender and Phone Number fields empty
    // Save as draft
    await page.locator('[data-testid="save-draft-button"]').click();

    // Verify draft is saved with a confirmation message
    await expect(page.locator('[data-testid="draft-saved-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="draft-saved-message"]')).toContainText('Draft saved successfully');

    // Capture draft ID if displayed
    const draftId = await page.locator('[data-testid="draft-id"]').textContent();

    // Step 2: Close and reopen the form
    await page.goto('/dashboard');
    await page.goto('/applicant-data-entry');

    // Access the saved draft from drafts list or load directly
    if (draftId) {
      await page.locator(`[data-testid="draft-${draftId}"]`).click();
    } else {
      await page.locator('[data-testid="load-draft-button"]').click();
    }

    // Verify previously saved draft data is loaded correctly
    await expect(page.locator('[data-testid="first-name-input"]')).toHaveValue('Robert');
    await expect(page.locator('[data-testid="last-name-input"]')).toHaveValue('Johnson');
    await expect(page.locator('[data-testid="dob-input"]')).toHaveValue('05/10/1988');

    // Step 3: Complete the form and submit
    await page.locator('[data-testid="gender-select"]').selectOption('Male');
    await page.locator('[data-testid="phone-input"]').fill('5551112222');

    // Submit the completed form
    await page.locator('[data-testid="submit-button"]').click();

    // Verify applicant data is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Applicant data saved successfully');

    // Verify the applicant record is retrievable
    const applicantId = await page.locator('[data-testid="applicant-id"]').textContent();
    expect(applicantId).toBeTruthy();
  });
});