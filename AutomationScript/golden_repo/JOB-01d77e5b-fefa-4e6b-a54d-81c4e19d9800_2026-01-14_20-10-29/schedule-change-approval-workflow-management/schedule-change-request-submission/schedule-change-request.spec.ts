import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Submission', () => {
  test.beforeEach(async ({ page }) => {
    // Employee logs into the scheduling system
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful schedule change request submission with valid data', async ({ page }) => {
    // Navigate to schedule change request submission page
    await page.goto('/schedule-change-request');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-id-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-schedule-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="requested-schedule-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="effective-date-field"]')).toBeVisible();

    // Enter valid employee ID in the employee ID field
    await page.fill('[data-testid="employee-id-field"]', 'EMP12345');

    // Enter valid current schedule details (date and time)
    await page.fill('[data-testid="current-schedule-date"]', '2024-02-15');
    await page.fill('[data-testid="current-schedule-time"]', '09:00');

    // Enter valid requested schedule details (date and time)
    await page.fill('[data-testid="requested-schedule-date"]', '2024-02-15');
    await page.fill('[data-testid="requested-schedule-time"]', '14:00');

    // Enter a valid reason for the schedule change request
    await page.fill('[data-testid="reason-field"]', 'Medical appointment that cannot be rescheduled');

    // Select a valid effective date for the schedule change
    await page.fill('[data-testid="effective-date-field"]', '2024-02-15');

    // Upload a supporting document using the file upload option
    const fileInput = page.locator('[data-testid="file-upload-input"]');
    await fileInput.setInputFiles({
      name: 'medical-certificate.pdf',
      mimeType: 'application/pdf',
      buffer: Buffer.from('Mock PDF content')
    });
    await expect(page.locator('[data-testid="uploaded-file-name"]')).toContainText('medical-certificate.pdf');

    // Click the Submit button to submit the schedule change request
    await page.click('[data-testid="submit-button"]');

    // Request is saved, confirmation message displayed, and request logged
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule change request submitted successfully');

    // Verify the request appears in the submitted requests list
    await page.goto('/schedule-change-requests/submitted');
    await expect(page.locator('[data-testid="submitted-requests-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-item"]').first()).toContainText('EMP12345');
    await expect(page.locator('[data-testid="request-item"]').first()).toContainText('Medical appointment');
  });

  test('Verify validation errors on incomplete schedule change request submission', async ({ page }) => {
    // Navigate to schedule change request submission page
    await page.goto('/schedule-change-request');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Leave the employee ID field empty
    // Leave the current schedule field empty
    // Leave the requested schedule field empty
    // Leave the reason field empty
    // Leave the effective date field empty

    // Click the Submit button to attempt submission with empty mandatory fields
    await page.click('[data-testid="submit-button"]');

    // Inline validation errors displayed for each missing mandatory field
    await expect(page.locator('[data-testid="employee-id-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-id-error"]')).toContainText('Employee ID is required');
    await expect(page.locator('[data-testid="current-schedule-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-schedule-error"]')).toContainText('Current schedule is required');
    await expect(page.locator('[data-testid="requested-schedule-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="requested-schedule-error"]')).toContainText('Requested schedule is required');
    await expect(page.locator('[data-testid="reason-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-error"]')).toContainText('Reason is required');
    await expect(page.locator('[data-testid="effective-date-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="effective-date-error"]')).toContainText('Effective date is required');

    // Fill in the employee ID field with valid data
    await page.fill('[data-testid="employee-id-field"]', 'EMP67890');
    await expect(page.locator('[data-testid="employee-id-error"]')).not.toBeVisible();

    // Fill in the current schedule field with valid date and time
    await page.fill('[data-testid="current-schedule-date"]', '2024-02-20');
    await page.fill('[data-testid="current-schedule-time"]', '08:00');
    await expect(page.locator('[data-testid="current-schedule-error"]')).not.toBeVisible();

    // Fill in the requested schedule field with valid date and time
    await page.fill('[data-testid="requested-schedule-date"]', '2024-02-20');
    await page.fill('[data-testid="requested-schedule-time"]', '13:00');
    await expect(page.locator('[data-testid="requested-schedule-error"]')).not.toBeVisible();

    // Fill in the reason field with valid text
    await page.fill('[data-testid="reason-field"]', 'Personal family emergency requiring schedule adjustment');
    await expect(page.locator('[data-testid="reason-error"]')).not.toBeVisible();

    // Fill in the effective date field with valid date
    await page.fill('[data-testid="effective-date-field"]', '2024-02-20');
    await expect(page.locator('[data-testid="effective-date-error"]')).not.toBeVisible();

    // Click the Submit button to resubmit with all corrected data
    await page.click('[data-testid="submit-button"]');

    // Submission succeeds with confirmation message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule change request submitted successfully');
  });

  test('Ensure draft saving and editing functionality works correctly', async ({ page }) => {
    // Navigate to schedule change request submission page
    await page.goto('/schedule-change-request');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Enter valid employee ID in the employee ID field
    await page.fill('[data-testid="employee-id-field"]', 'EMP11111');

    // Enter valid current schedule details (date and time)
    await page.fill('[data-testid="current-schedule-date"]', '2024-03-01');
    await page.fill('[data-testid="current-schedule-time"]', '10:00');

    // Leave the requested schedule field empty
    // Leave the reason field empty
    // Leave the effective date field empty

    // Click the Save as Draft button
    await page.click('[data-testid="save-draft-button"]');

    // Draft is saved and confirmation displayed
    await expect(page.locator('[data-testid="draft-saved-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="draft-saved-message"]')).toContainText('Draft saved successfully');

    // Navigate away from the schedule change request submission page
    await page.goto('/dashboard');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the list of draft schedule change requests
    await page.goto('/schedule-change-requests/drafts');
    await expect(page.locator('[data-testid="drafts-list"]')).toBeVisible();

    // Select the saved draft to edit
    await page.click('[data-testid="draft-item"]', { hasText: 'EMP11111' });

    // Draft loads correctly and allows editing
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-id-field"]')).toHaveValue('EMP11111');
    await expect(page.locator('[data-testid="current-schedule-date"]')).toHaveValue('2024-03-01');
    await expect(page.locator('[data-testid="current-schedule-time"]')).toHaveValue('10:00');

    // Enter valid requested schedule details in the previously empty field
    await page.fill('[data-testid="requested-schedule-date"]', '2024-03-01');
    await page.fill('[data-testid="requested-schedule-time"]', '15:00');

    // Enter valid reason in the previously empty field
    await page.fill('[data-testid="reason-field"]', 'Childcare responsibilities require afternoon shift');

    // Enter valid effective date in the previously empty field
    await page.fill('[data-testid="effective-date-field"]', '2024-03-01');

    // Click the Submit button to submit the completed request
    await page.click('[data-testid="submit-button"]');

    // Submission succeeds with confirmation message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule change request submitted successfully');
  });
});