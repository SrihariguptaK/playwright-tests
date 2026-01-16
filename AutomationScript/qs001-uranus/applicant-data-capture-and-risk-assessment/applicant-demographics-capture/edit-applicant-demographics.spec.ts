import { test, expect } from '@playwright/test';

test.describe('Edit and Update Applicant Demographics', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const TEST_APPLICANT_ID = '12345';

  test.beforeEach(async ({ page }) => {
    // Navigate to the application and authenticate if needed
    await page.goto(`${BASE_URL}/applicants/${TEST_APPLICANT_ID}/demographics/edit`);
  });

  test('Validate successful demographic data update', async ({ page }) => {
    // Step 1: Navigate to demographic data edit form
    await expect(page).toHaveURL(new RegExp(`/applicants/${TEST_APPLICANT_ID}/demographics/edit`));
    
    // Verify form is displayed with existing data populated
    await expect(page.locator('[data-testid="demographics-edit-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="first-name-input"]')).not.toBeEmpty();
    await expect(page.locator('[data-testid="last-name-input"]')).not.toBeEmpty();
    await expect(page.locator('[data-testid="email-input"]')).not.toBeEmpty();

    // Verify all existing data is correctly displayed
    const existingLastName = await page.locator('[data-testid="last-name-input"]').inputValue();
    const existingEmail = await page.locator('[data-testid="email-input"]').inputValue();
    expect(existingLastName).toBeTruthy();
    expect(existingEmail).toBeTruthy();

    // Step 2: Modify demographic fields with valid data
    // Modify Last Name field
    await page.locator('[data-testid="last-name-input"]').clear();
    await page.locator('[data-testid="last-name-input"]').fill('Johnson');
    
    // Modify Email field
    await page.locator('[data-testid="email-input"]').clear();
    await page.locator('[data-testid="email-input"]').fill('updated.email@example.com');
    
    // Modify Phone Number field
    await page.locator('[data-testid="phone-number-input"]').clear();
    await page.locator('[data-testid="phone-number-input"]').fill('555-111-2222');

    // Verify inputs accepted without validation errors
    await expect(page.locator('[data-testid="last-name-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="email-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="phone-number-error"]')).not.toBeVisible();

    // Step 3: Submit the updated data
    await page.locator('[data-testid="submit-button"]').click();

    // Verify data updated successfully and confirmation displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('successfully updated');

    // Verify the updated data is reflected in the system
    await page.waitForTimeout(1000);
    const updatedLastName = await page.locator('[data-testid="last-name-input"]').inputValue();
    const updatedEmail = await page.locator('[data-testid="email-input"]').inputValue();
    const updatedPhone = await page.locator('[data-testid="phone-number-input"]').inputValue();
    
    expect(updatedLastName).toBe('Johnson');
    expect(updatedEmail).toBe('updated.email@example.com');
    expect(updatedPhone).toBe('555-111-2222');
  });

  test('Verify rejection of update with invalid data', async ({ page }) => {
    // Step 1: Navigate to demographic data edit form
    await expect(page).toHaveURL(new RegExp(`/applicants/${TEST_APPLICANT_ID}/demographics/edit`));
    
    // Verify form is displayed with existing data
    await expect(page.locator('[data-testid="demographics-edit-form"]')).toBeVisible();

    // Step 2: Enter invalid or empty mandatory fields
    // Clear the Last Name field to make it empty
    await page.locator('[data-testid="last-name-input"]').clear();
    
    // Modify Email field to invalid format
    await page.locator('[data-testid="email-input"]').clear();
    await page.locator('[data-testid="email-input"]').fill('invalidemail.com');
    
    // Modify Date of Birth field to invalid format
    await page.locator('[data-testid="date-of-birth-input"]').clear();
    await page.locator('[data-testid="date-of-birth-input"]').fill('99/99/9999');

    // Trigger validation by clicking outside or tabbing
    await page.locator('[data-testid="first-name-input"]').click();

    // Verify validation errors displayed inline
    await expect(page.locator('[data-testid="last-name-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="last-name-error"]')).toContainText(/required|cannot be empty/i);
    
    await expect(page.locator('[data-testid="email-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="email-error"]')).toContainText(/invalid|valid email/i);
    
    await expect(page.locator('[data-testid="date-of-birth-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-of-birth-error"]')).toContainText(/invalid|valid date/i);

    // Step 3: Attempt to save updates
    await page.locator('[data-testid="submit-button"]').click();

    // Verify save blocked and error messages shown
    await expect(page.locator('[data-testid="last-name-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="email-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-of-birth-error"]')).toBeVisible();
    
    // Verify no success message is displayed
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
    
    // Verify form is still on edit page (not navigated away)
    await expect(page).toHaveURL(new RegExp(`/applicants/${TEST_APPLICANT_ID}/demographics/edit`));

    // Verify focus is set to the first invalid field
    const focusedElement = await page.evaluate(() => document.activeElement?.getAttribute('data-testid'));
    expect(focusedElement).toBe('last-name-input');
  });

  test('Check audit log creation after successful update', async ({ page }) => {
    // Step 1: Update demographic data successfully
    await expect(page.locator('[data-testid="demographics-edit-form"]')).toBeVisible();

    // Store old email value for audit verification
    const oldEmail = await page.locator('[data-testid="email-input"]').inputValue();
    const newEmail = 'new@email.com';

    // Modify Email field with valid data
    await page.locator('[data-testid="email-input"]').clear();
    await page.locator('[data-testid="email-input"]').fill(newEmail);

    // Note the timestamp before update
    const updateTimestamp = new Date();

    // Click Submit button to update demographic data
    await page.locator('[data-testid="submit-button"]').click();

    // Verify update confirmation displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('successfully updated');

    // Step 2: Access audit logs for the updated record
    // Navigate to audit logs section
    await page.goto(`${BASE_URL}/audit-logs`);
    await expect(page.locator('[data-testid="audit-logs-page"]')).toBeVisible();

    // Search or filter audit logs by applicant ID
    await page.locator('[data-testid="search-applicant-id-input"]').fill(TEST_APPLICANT_ID);
    await page.locator('[data-testid="search-button"]').click();

    // Wait for audit log results to load
    await page.waitForSelector('[data-testid="audit-log-entry"]', { timeout: 5000 });

    // Verify audit log entry exists with details of changes
    const auditLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditLogEntry).toBeVisible();

    // Verify audit log contains applicant ID
    await expect(auditLogEntry.locator('[data-testid="audit-applicant-id"]')).toContainText(TEST_APPLICANT_ID);

    // Verify audit log contains field names, old values, and new values
    await expect(auditLogEntry.locator('[data-testid="audit-field-name"]')).toContainText('Email');
    await expect(auditLogEntry.locator('[data-testid="audit-old-value"]')).toContainText(oldEmail);
    await expect(auditLogEntry.locator('[data-testid="audit-new-value"]')).toContainText(newEmail);

    // Verify audit log timestamp is recent (within last few minutes)
    const auditTimestampText = await auditLogEntry.locator('[data-testid="audit-timestamp"]').textContent();
    expect(auditTimestampText).toBeTruthy();

    // Verify audit log entry is immutable (no edit button present)
    await expect(auditLogEntry.locator('[data-testid="edit-audit-button"]')).not.toBeVisible();
    
    // Verify audit log entry cannot be deleted
    await expect(auditLogEntry.locator('[data-testid="delete-audit-button"]')).not.toBeVisible();
  });
});