import { test, expect } from '@playwright/test';
import path from 'path';

test.describe('Schedule Change Request Submission', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const SUBMISSION_PAGE = '/schedule-change/submit';

  test.beforeEach(async ({ page }) => {
    // Navigate to schedule change submission page before each test
    await page.goto(`${BASE_URL}${SUBMISSION_PAGE}`);
    // Wait for page to be fully loaded
    await page.waitForLoadState('networkidle');
  });

  test('Validate successful schedule change submission with valid data', async ({ page }) => {
    // Step 1: Verify submission form is displayed with all mandatory fields
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="time-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="attachment-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="submit-button"]')).toBeVisible();

    // Step 2: Enter valid data in all required fields
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    const formattedDate = futureDate.toISOString().split('T')[0];
    
    await page.locator('[data-testid="date-field"]').fill(formattedDate);
    await page.locator('[data-testid="time-field"]').fill('14:30');
    await page.locator('[data-testid="reason-field"]').fill('Resource unavailability');

    // Attach a valid document (less than 10MB)
    const validFilePath = path.join(__dirname, 'fixtures', 'test-document.pdf');
    const fileInput = page.locator('[data-testid="attachment-input"]');
    await fileInput.setInputFiles(validFilePath);

    // Verify all inputs accept data without validation errors
    await expect(page.locator('[data-testid="date-field"]')).toHaveValue(formattedDate);
    await expect(page.locator('[data-testid="time-field"]')).toHaveValue('14:30');
    await expect(page.locator('[data-testid="reason-field"]')).toHaveValue('Resource unavailability');
    await expect(page.locator('.error-message')).toHaveCount(0);

    // Step 3: Submit the schedule change request
    await page.locator('[data-testid="submit-button"]').click();

    // Wait for submission to complete
    await page.waitForResponse(response => 
      response.url().includes('/api/schedule-changes') && response.status() === 200
    );

    // Verify request is accepted with status 'Pending Approval'
    await expect(page.locator('[data-testid="status-display"]')).toContainText('Pending Approval');
    
    // Verify confirmation message is displayed
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Schedule change request submitted successfully');
  });

  test('Reject submission with missing mandatory fields', async ({ page }) => {
    // Step 1: Verify submission form is displayed
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Step 2: Enter valid data in date field only, leaving time and reason fields empty
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    const formattedDate = futureDate.toISOString().split('T')[0];
    
    await page.locator('[data-testid="date-field"]').fill(formattedDate);
    
    // Tab out or click outside the empty mandatory fields to trigger validation
    await page.locator('[data-testid="time-field"]').click();
    await page.locator('[data-testid="date-field"]').click();
    await page.locator('[data-testid="reason-field"]').click();
    await page.locator('[data-testid="date-field"]').click();

    // Verify real-time validation highlights missing fields
    await expect(page.locator('[data-testid="time-field-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-field-error"]')).toBeVisible();

    // Step 3: Attempt to submit the incomplete form
    await page.locator('[data-testid="submit-button"]').click();

    // Verify submission is blocked and error messages are displayed
    await expect(page.locator('[data-testid="time-field-error"]')).toContainText('Time is required');
    await expect(page.locator('[data-testid="reason-field-error"]')).toContainText('Reason is required');
    
    // Verify form remains on the submission page
    await expect(page).toHaveURL(new RegExp(SUBMISSION_PAGE));
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    
    // Verify no confirmation message is shown
    await expect(page.locator('[data-testid="confirmation-message"]')).not.toBeVisible();
  });

  test('Reject attachment exceeding size limit', async ({ page }) => {
    // Step 1: Verify submission form is displayed
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Step 2: Enter valid data in all mandatory fields
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    const formattedDate = futureDate.toISOString().split('T')[0];
    
    await page.locator('[data-testid="date-field"]').fill(formattedDate);
    await page.locator('[data-testid="time-field"]').fill('14:30');
    await page.locator('[data-testid="reason-field"]').fill('Resource unavailability');

    // Step 3: Attach a file larger than 10MB
    const oversizedFilePath = path.join(__dirname, 'fixtures', 'large-file-11mb.pdf');
    const fileInput = page.locator('[data-testid="attachment-input"]');
    await fileInput.setInputFiles(oversizedFilePath);

    // Verify attachment is rejected with an error message
    await expect(page.locator('[data-testid="attachment-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="attachment-error"]')).toContainText('File size exceeds 10MB limit');
    
    // Verify that the oversized file is not attached to the form
    await expect(page.locator('[data-testid="attached-file-name"]')).not.toBeVisible();

    // Step 4: Attempt to submit the form without valid attachment
    await page.locator('[data-testid="submit-button"]').click();

    // Verify submission is blocked until attachment size is within limit
    await expect(page.locator('[data-testid="attachment-error"]')).toBeVisible();
    await expect(page).toHaveURL(new RegExp(SUBMISSION_PAGE));

    // Step 5: Remove the oversized file and attach a valid file
    await fileInput.setInputFiles([]);
    await expect(page.locator('[data-testid="attachment-error"]')).not.toBeVisible();
    
    const validFilePath = path.join(__dirname, 'fixtures', 'test-document.pdf');
    await fileInput.setInputFiles(validFilePath);
    
    // Verify valid file is attached
    await expect(page.locator('[data-testid="attached-file-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="attachment-error"]')).not.toBeVisible();

    // Step 6: Submit the form with valid attachment
    await page.locator('[data-testid="submit-button"]').click();

    // Wait for submission to complete
    await page.waitForResponse(response => 
      response.url().includes('/api/schedule-changes') && response.status() === 200
    );

    // Verify successful submission
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="status-display"]')).toContainText('Pending Approval');
  });
});