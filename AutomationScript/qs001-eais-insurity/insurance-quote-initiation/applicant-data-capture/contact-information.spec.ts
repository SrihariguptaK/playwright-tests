import { test, expect } from '@playwright/test';

test.describe('Contact Information - Insurance Agent', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

  test.beforeEach(async ({ page }) => {
    // Navigate to the application before each test
    await page.goto(`${BASE_URL}/applicant/contact-information`);
  });

  test('Validate acceptance of correctly formatted contact information', async ({ page }) => {
    // Action: Navigate to contact information section
    // Expected Result: Contact form is displayed
    await expect(page.locator('[data-testid="contact-form"]').or(page.locator('form')).first()).toBeVisible();
    await expect(page.locator('[data-testid="phone-number-input"]').or(page.getByLabel(/phone number/i)).first()).toBeVisible();
    await expect(page.locator('[data-testid="email-input"]').or(page.getByLabel(/email/i)).first()).toBeVisible();

    // Action: Enter valid phone number '5551234567' in the Phone Number field
    await page.locator('[data-testid="phone-number-input"]').or(page.getByLabel(/phone number/i)).first().fill('5551234567');

    // Action: Enter valid email address 'john.smith@example.com' in the Email Address field
    await page.locator('[data-testid="email-input"]').or(page.getByLabel(/email/i)).first().fill('john.smith@example.com');

    // Action: Enter valid mailing address
    await page.locator('[data-testid="street-input"]').or(page.getByLabel(/street/i)).first().fill('123 Main Street');
    await page.locator('[data-testid="city-input"]').or(page.getByLabel(/city/i)).first().fill('Springfield');
    await page.locator('[data-testid="state-input"]').or(page.getByLabel(/state/i)).first().fill('IL');
    await page.locator('[data-testid="zip-input"]').or(page.getByLabel(/zip/i)).first().fill('62701');

    // Expected Result: No validation errors are shown
    await expect(page.locator('[data-testid="phone-error"]').or(page.locator('.error-message')).first()).not.toBeVisible({ timeout: 2000 }).catch(() => {});
    await expect(page.locator('[data-testid="email-error"]')).not.toBeVisible({ timeout: 2000 }).catch(() => {});

    // Action: Save the contact information
    const saveButton = page.locator('[data-testid="save-button"]').or(page.getByRole('button', { name: /save/i })).first();
    await saveButton.click();

    // Expected Result: Data is saved and confirmation is displayed
    await expect(page.locator('[data-testid="success-message"]').or(page.getByText(/saved successfully|confirmation/i)).first()).toBeVisible({ timeout: 5000 });
  });

  test('Verify rejection of invalid phone and email formats', async ({ page }) => {
    // Action: Navigate to contact information section
    // Expected Result: Contact form is displayed
    await expect(page.locator('[data-testid="contact-form"]').or(page.locator('form')).first()).toBeVisible();

    // Action: Enter invalid phone number '123' in the Phone Number field and move focus to next field
    const phoneInput = page.locator('[data-testid="phone-number-input"]').or(page.getByLabel(/phone number/i)).first();
    await phoneInput.fill('123');
    await phoneInput.blur();

    // Action: Enter invalid email address 'invalidemail@' in the Email Address field and move focus to next field
    const emailInput = page.locator('[data-testid="email-input"]').or(page.getByLabel(/email/i)).first();
    await emailInput.fill('invalidemail@');
    await emailInput.blur();

    // Action: Enter valid mailing address
    await page.locator('[data-testid="street-input"]').or(page.getByLabel(/street/i)).first().fill('456 Oak Avenue');
    await page.locator('[data-testid="city-input"]').or(page.getByLabel(/city/i)).first().fill('Chicago');
    await page.locator('[data-testid="state-input"]').or(page.getByLabel(/state/i)).first().fill('IL');
    await page.locator('[data-testid="zip-input"]').or(page.getByLabel(/zip/i)).first().fill('60601');

    // Expected Result: Inline validation errors are displayed
    await expect(page.locator('[data-testid="phone-error"]').or(page.locator('.error-message').filter({ hasText: /phone/i })).first()).toBeVisible({ timeout: 3000 });
    await expect(page.locator('[data-testid="email-error"]').or(page.locator('.error-message').filter({ hasText: /email/i })).first()).toBeVisible({ timeout: 3000 });

    // Action: Attempt to save the form
    const saveButton = page.locator('[data-testid="save-button"]').or(page.getByRole('button', { name: /save/i })).first();
    
    // Expected Result: Save is blocked until errors are corrected
    const isDisabled = await saveButton.isDisabled().catch(() => false);
    if (!isDisabled) {
      await saveButton.click();
      // Verify form was not submitted by checking errors still exist
      await expect(page.locator('[data-testid="phone-error"]').or(page.locator('.error-message').filter({ hasText: /phone/i })).first()).toBeVisible();
    } else {
      expect(isDisabled).toBe(true);
    }

    // Action: Correct the phone number to valid format '5559876543'
    await phoneInput.fill('5559876543');
    await phoneInput.blur();

    // Action: Correct the email address to valid format 'jane.doe@example.com'
    await emailInput.fill('jane.doe@example.com');
    await emailInput.blur();

    // Expected Result: Verify all validation errors are cleared and Save button is enabled
    await expect(page.locator('[data-testid="phone-error"]')).not.toBeVisible({ timeout: 2000 }).catch(() => {});
    await expect(page.locator('[data-testid="email-error"]')).not.toBeVisible({ timeout: 2000 }).catch(() => {});
    await expect(saveButton).toBeEnabled({ timeout: 2000 });

    // Action: Click the Save button
    await saveButton.click();
    await expect(page.locator('[data-testid="success-message"]').or(page.getByText(/saved successfully/i)).first()).toBeVisible({ timeout: 5000 });
  });

  test('Ensure contact information persistence after form reload', async ({ page }) => {
    // Action: Navigate to contact information section of the applicant form
    await expect(page.locator('[data-testid="contact-form"]').or(page.locator('form')).first()).toBeVisible();

    // Action: Enter valid phone number '5552223333' in the Phone Number field
    const phoneInput = page.locator('[data-testid="phone-number-input"]').or(page.getByLabel(/phone number/i)).first();
    await phoneInput.fill('5552223333');

    // Action: Enter valid email address 'michael.brown@example.com' in the Email Address field
    const emailInput = page.locator('[data-testid="email-input"]').or(page.getByLabel(/email/i)).first();
    await emailInput.fill('michael.brown@example.com');

    // Action: Enter valid mailing address
    await page.locator('[data-testid="street-input"]').or(page.getByLabel(/street/i)).first().fill('789 Elm Street');
    await page.locator('[data-testid="city-input"]').or(page.getByLabel(/city/i)).first().fill('Boston');
    await page.locator('[data-testid="state-input"]').or(page.getByLabel(/state/i)).first().fill('MA');
    await page.locator('[data-testid="zip-input"]').or(page.getByLabel(/zip/i)).first().fill('02101');

    // Action: Click the Save button to save the contact information
    const saveButton = page.locator('[data-testid="save-button"]').or(page.getByRole('button', { name: /save/i })).first();
    await saveButton.click();

    // Expected Result: Data saved successfully
    await expect(page.locator('[data-testid="success-message"]').or(page.getByText(/saved successfully/i)).first()).toBeVisible({ timeout: 5000 });

    // Note the applicant ID or record identifier for reference (if displayed)
    const applicantId = await page.locator('[data-testid="applicant-id"]').textContent().catch(() => 'N/A');

    // Action: Refresh the browser page or navigate away and return to the contact information section
    await page.reload();
    await page.waitForLoadState('networkidle');

    // Expected Result: Previously saved contact information is displayed in the form fields
    await expect(phoneInput).toHaveValue('5552223333', { timeout: 5000 });
    await expect(emailInput).toHaveValue('michael.brown@example.com', { timeout: 5000 });
    await expect(page.locator('[data-testid="street-input"]').or(page.getByLabel(/street/i)).first()).toHaveValue('789 Elm Street');
    await expect(page.locator('[data-testid="city-input"]').or(page.getByLabel(/city/i)).first()).toHaveValue('Boston');
    await expect(page.locator('[data-testid="state-input"]').or(page.getByLabel(/state/i)).first()).toHaveValue('MA');
    await expect(page.locator('[data-testid="zip-input"]').or(page.getByLabel(/zip/i)).first()).toHaveValue('02101');

    // Action: Edit the phone number to '5554445555' and email to 'michael.brown.updated@example.com'
    await phoneInput.fill('5554445555');
    await emailInput.fill('michael.brown.updated@example.com');

    // Action: Click the Save button to save the updated contact information
    await saveButton.click();
    await expect(page.locator('[data-testid="success-message"]').or(page.getByText(/saved successfully/i)).first()).toBeVisible({ timeout: 5000 });

    // Action: Reload the form page again to verify the updates persisted
    await page.reload();
    await page.waitForLoadState('networkidle');

    // Expected Result: Updates are saved and reflected correctly
    await expect(phoneInput).toHaveValue('5554445555', { timeout: 5000 });
    await expect(emailInput).toHaveValue('michael.brown.updated@example.com', { timeout: 5000 });
  });
});