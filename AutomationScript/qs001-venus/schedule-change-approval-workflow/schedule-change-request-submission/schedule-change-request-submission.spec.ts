import { test, expect } from '@playwright/test';
import path from 'path';

test.describe('Schedule Change Request Submission', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the schedule change request submission page
    await page.goto('/schedule-change-request');
    // Wait for the form to be fully loaded
    await page.waitForLoadState('networkidle');
  });

  test('Validate successful schedule change request submission with valid data', async ({ page }) => {
    // Step 1: Verify submission form is displayed with all mandatory fields
    await expect(page.locator('[data-testid="employee-name-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-schedule-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="requested-schedule-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="effective-date-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="attachment-upload"]')).toBeVisible();
    await expect(page.locator('[data-testid="submit-button"]')).toBeVisible();

    // Step 2: Enter valid employee name
    await page.fill('[data-testid="employee-name-field"]', 'John Smith');

    // Enter current schedule details
    await page.fill('[data-testid="current-schedule-field"]', 'Monday-Friday, 9:00 AM - 5:00 PM');

    // Enter requested schedule details
    await page.fill('[data-testid="requested-schedule-field"]', 'Tuesday-Saturday, 10:00 AM - 6:00 PM');

    // Enter a valid reason for the schedule change
    await page.fill('[data-testid="reason-field"]', 'Personal commitment requiring schedule adjustment');

    // Select a valid effective date (future date)
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 14);
    const formattedDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="effective-date-field"]', formattedDate);

    // Upload a valid document (2MB PDF)
    const fileInput = page.locator('[data-testid="attachment-upload"]');
    const filePath = path.join(__dirname, 'test-files', 'valid-document-2mb.pdf');
    await fileInput.setInputFiles(filePath);

    // Verify no validation errors are displayed
    await expect(page.locator('[data-testid="validation-error"]')).toHaveCount(0);

    // Step 3: Submit the form
    await page.click('[data-testid="submit-button"]');

    // Wait for submission to complete
    await page.waitForResponse(response => 
      response.url().includes('/api/schedule-change-requests') && response.status() === 200
    );

    // Verify confirmation message is displayed
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('successfully submitted');

    // Verify request ID is displayed
    const requestIdElement = page.locator('[data-testid="request-id"]');
    await expect(requestIdElement).toBeVisible();
    const requestIdText = await requestIdElement.textContent();
    expect(requestIdText).toMatch(/[A-Z0-9-]+/);

    // Verify approval workflow initiated message
    await expect(page.locator('[data-testid="workflow-status"]')).toContainText('approval workflow initiated');
  });

  test('Verify rejection of submission with missing mandatory fields', async ({ page }) => {
    // Step 1: Verify form is displayed
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Step 2: Leave employee name field empty
    await page.fill('[data-testid="employee-name-field"]', '');

    // Enter valid data in current schedule field
    await page.fill('[data-testid="current-schedule-field"]', 'Monday-Friday, 9:00 AM - 5:00 PM');

    // Leave the requested schedule field empty
    await page.fill('[data-testid="requested-schedule-field"]', '');

    // Enter valid reason for change
    await page.fill('[data-testid="reason-field"]', 'Personal reasons');

    // Leave the effective date field empty
    await page.fill('[data-testid="effective-date-field"]', '');

    // Click outside the empty mandatory fields to trigger validation
    await page.click('[data-testid="reason-field"]');
    await page.waitForTimeout(500);

    // Verify real-time validation highlights missing fields
    await expect(page.locator('[data-testid="employee-name-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-name-error"]')).toContainText('required');
    await expect(page.locator('[data-testid="requested-schedule-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="requested-schedule-error"]')).toContainText('required');
    await expect(page.locator('[data-testid="effective-date-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="effective-date-error"]')).toContainText('required');

    // Step 3: Attempt to submit the form
    await page.click('[data-testid="submit-button"]');

    // Verify submission is blocked
    await expect(page.locator('[data-testid="confirmation-message"]')).not.toBeVisible();

    // Verify error messages are displayed
    await expect(page.locator('[data-testid="form-error-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="form-error-summary"]')).toContainText('Please correct the errors');

    // Verify all empty mandatory fields are highlighted
    await expect(page.locator('[data-testid="employee-name-field"]')).toHaveClass(/error|invalid/);
    await expect(page.locator('[data-testid="requested-schedule-field"]')).toHaveClass(/error|invalid/);
    await expect(page.locator('[data-testid="effective-date-field"]')).toHaveClass(/error|invalid/);
  });

  test('Test attachment upload size limit enforcement', async ({ page }) => {
    // Step 1: Verify form is displayed
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Step 2: Attempt to upload a document larger than 10MB
    const largeFileInput = page.locator('[data-testid="attachment-upload"]');
    const largeFilePath = path.join(__dirname, 'test-files', 'large-document-12mb.pdf');
    await largeFileInput.setInputFiles(largeFilePath);

    // Wait for upload validation
    await page.waitForTimeout(1000);

    // Verify upload is rejected with an error message
    await expect(page.locator('[data-testid="attachment-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="attachment-error"]')).toContainText('10MB');
    await expect(page.locator('[data-testid="attachment-error"]')).toContainText('exceeds maximum');

    // Verify file was not attached
    await expect(page.locator('[data-testid="attached-file-name"]')).not.toBeVisible();

    // Step 3: Upload a valid size document
    const validFileInput = page.locator('[data-testid="attachment-upload"]');
    const validFilePath = path.join(__dirname, 'test-files', 'valid-document-5mb.pdf');
    await validFileInput.setInputFiles(validFilePath);

    // Wait for upload to complete
    await page.waitForTimeout(1000);

    // Verify no error message is displayed
    await expect(page.locator('[data-testid="attachment-error"]')).not.toBeVisible();

    // Verify file is attached successfully
    await expect(page.locator('[data-testid="attached-file-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="attached-file-name"]')).toContainText('valid-document-5mb.pdf');

    // Complete all other mandatory fields with valid data
    await page.fill('[data-testid="employee-name-field"]', 'Jane Doe');
    await page.fill('[data-testid="current-schedule-field"]', 'Monday-Friday, 8:00 AM - 4:00 PM');
    await page.fill('[data-testid="requested-schedule-field"]', 'Monday-Friday, 9:00 AM - 5:00 PM');
    await page.fill('[data-testid="reason-field"]', 'Childcare scheduling requirements');
    
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    const formattedDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="effective-date-field"]', formattedDate);

    // Submit the form
    await page.click('[data-testid="submit-button"]');

    // Wait for submission to complete
    await page.waitForResponse(response => 
      response.url().includes('/api/schedule-change-requests') && response.status() === 200
    );

    // Verify submission succeeds
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('successfully submitted');

    // Verify attachment was saved with the request
    await expect(page.locator('[data-testid="request-id"]')).toBeVisible();
  });
});