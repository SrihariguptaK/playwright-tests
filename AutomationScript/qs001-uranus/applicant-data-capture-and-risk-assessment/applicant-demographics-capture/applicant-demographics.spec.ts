import { test, expect } from '@playwright/test';

test.describe('Applicant Demographics Data Entry', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const DEMOGRAPHICS_FORM_URL = `${BASE_URL}/applicants/demographics`;

  test.beforeEach(async ({ page }) => {
    // Navigate to demographic data entry form before each test
    await page.goto(DEMOGRAPHICS_FORM_URL);
  });

  test('Validate successful demographic data submission with valid input', async ({ page }) => {
    // Step 1: Verify form is displayed with all mandatory fields
    await expect(page.locator('[data-testid="demographics-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="first-name-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="last-name-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="dob-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="gender-select"]')).toBeVisible();
    await expect(page.locator('[data-testid="email-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="phone-input"]')).toBeVisible();

    // Step 2: Enter valid personal details in all required fields
    await page.locator('[data-testid="first-name-input"]').fill('John');
    await page.locator('[data-testid="last-name-input"]').fill('Smith');
    await page.locator('[data-testid="dob-input"]').fill('01/15/1985');
    await page.locator('[data-testid="gender-select"]').selectOption('Male');
    await page.locator('[data-testid="email-input"]').fill('john.smith@email.com');
    await page.locator('[data-testid="phone-input"]').fill('555-123-4567');

    // Verify all inputs accept data without validation errors
    await expect(page.locator('[data-testid="first-name-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="last-name-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="dob-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="gender-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="email-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="phone-error"]')).not.toBeVisible();

    // Step 3: Submit the form
    await page.locator('[data-testid="submit-button"]').click();

    // Verify data is saved successfully and confirmation is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/successfully|saved|submitted/i);
  });

  test('Verify rejection of submission with missing mandatory fields', async ({ page }) => {
    // Step 1: Verify form is displayed with all mandatory fields
    await expect(page.locator('[data-testid="demographics-form"]')).toBeVisible();

    // Step 2: Enter partial data - leave mandatory fields empty
    await page.locator('[data-testid="first-name-input"]').fill('Jane');
    // Leave Last Name field empty
    await page.locator('[data-testid="dob-input"]').fill('03/20/1990');
    // Leave Gender field unselected
    // Leave Email field empty
    await page.locator('[data-testid="phone-input"]').fill('555-987-6543');

    // Real-time validation should highlight missing fields
    await page.locator('[data-testid="last-name-input"]').blur();
    await page.locator('[data-testid="email-input"]').blur();

    // Step 3: Attempt to submit the form
    await page.locator('[data-testid="submit-button"]').click();

    // Verify submission is blocked and error messages are displayed
    await expect(page.locator('[data-testid="last-name-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="last-name-error"]')).toContainText(/required|mandatory/i);
    await expect(page.locator('[data-testid="gender-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="gender-error"]')).toContainText(/required|mandatory/i);
    await expect(page.locator('[data-testid="email-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="email-error"]')).toContainText(/required|mandatory/i);

    // Verify that focus is set to the first invalid field
    const focusedElement = await page.evaluate(() => document.activeElement?.getAttribute('data-testid'));
    expect(['last-name-input', 'gender-select', 'email-input']).toContain(focusedElement);

    // Verify form is not submitted (still on the same page)
    await expect(page.locator('[data-testid="demographics-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
  });

  test('Test saving draft with incomplete demographic data', async ({ page }) => {
    // Step 1: Verify form is displayed
    await expect(page.locator('[data-testid="demographics-form"]')).toBeVisible();

    // Step 2: Enter partial demographic data
    await page.locator('[data-testid="first-name-input"]').fill('Michael');
    await page.locator('[data-testid="last-name-input"]').fill('Johnson');
    // Leave Date of Birth field empty
    // Leave Gender field unselected
    await page.locator('[data-testid="email-input"]').fill('michael.johnson');

    // Verify partial data is accepted without validation errors for draft
    await expect(page.locator('[data-testid="first-name-input"]')).toHaveValue('Michael');
    await expect(page.locator('[data-testid="last-name-input"]')).toHaveValue('Johnson');
    await expect(page.locator('[data-testid="email-input"]')).toHaveValue('michael.johnson');

    // Step 3: Save the form as draft
    await page.locator('[data-testid="save-draft-button"]').click();

    // Verify draft is saved and notification 'Draft saved' is displayed
    await expect(page.locator('[data-testid="draft-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="draft-notification"]')).toContainText(/draft saved/i);

    // Verify the draft record is retrievable
    await page.reload();
    await expect(page.locator('[data-testid="first-name-input"]')).toHaveValue('Michael');
    await expect(page.locator('[data-testid="last-name-input"]')).toHaveValue('Johnson');
    await expect(page.locator('[data-testid="email-input"]')).toHaveValue('michael.johnson');
  });
});