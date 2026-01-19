import { test, expect } from '@playwright/test';
import path from 'path';

test.describe('Schedule Change Request Submission', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_CREDENTIALS = {
    username: 'employee@company.com',
    password: 'ValidPassword123!'
  };

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate successful schedule change request submission with valid data', async ({ page }) => {
    // Step 1: Employee logs into the scheduling portal
    await page.fill('[data-testid="username-input"]', VALID_CREDENTIALS.username);
    await page.fill('[data-testid="password-input"]', VALID_CREDENTIALS.password);
    await page.click('[data-testid="login-button"]');
    
    // Verify successful authentication and navigation
    await expect(page).toHaveURL(/.*dashboard|portal/);
    await expect(page.locator('[data-testid="user-profile"]')).toBeVisible();

    // Step 2: Click on the 'Schedule Change Request' menu option
    await page.click('[data-testid="schedule-change-request-menu"]');
    await expect(page).toHaveURL(/.*schedule-change-request/);
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Step 3: Fill in the 'Date' field with a current or future date
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    const formattedDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="date-field"]', formattedDate);

    // Step 4: Fill in the 'Time' field with the desired schedule time
    await page.fill('[data-testid="time-field"]', '09:00');

    // Step 5: Fill in the 'Reason' field with a valid explanation
    await page.fill('[data-testid="reason-field"]', 'Medical appointment scheduled for this date');

    // Step 6: Click on 'Attach Document' and select a valid document file under 10MB
    const validFilePath = path.join(__dirname, 'fixtures', 'valid-document.pdf');
    const fileInput = page.locator('[data-testid="attachment-input"]');
    await fileInput.setInputFiles(validFilePath);
    
    // Verify attachment is uploaded
    await expect(page.locator('[data-testid="attachment-indicator"]')).toContainText('valid-document.pdf');

    // Step 7: Click the 'Submit' button
    await page.click('[data-testid="submit-button"]');

    // Step 8: Verify confirmation message with request details and timestamp
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('successfully submitted');
    await expect(page.locator('[data-testid="request-timestamp"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-details"]')).toContainText(formattedDate);
    await expect(page.locator('[data-testid="request-details"]')).toContainText('09:00');
  });

  test('Reject submission with missing mandatory fields', async ({ page }) => {
    // Step 1: Navigate to login and authenticate
    await page.fill('[data-testid="username-input"]', VALID_CREDENTIALS.username);
    await page.fill('[data-testid="password-input"]', VALID_CREDENTIALS.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard|portal/);

    // Step 2: Navigate to schedule change request form
    await page.click('[data-testid="schedule-change-request-menu"]');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Step 3: Leave the 'Date' field empty
    // Step 4: Leave the 'Reason' field empty
    // Fields are already empty by default

    // Step 5: Click the 'Submit' button without filling mandatory fields
    await page.click('[data-testid="submit-button"]');

    // Step 6: Verify inline error messages are displayed
    await expect(page.locator('[data-testid="date-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-error"]')).toContainText(/required|mandatory/);
    await expect(page.locator('[data-testid="reason-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-error"]')).toContainText(/required|mandatory/);

    // Step 7: Verify submission is blocked (still on same page)
    await expect(page).toHaveURL(/.*schedule-change-request/);
    await expect(page.locator('[data-testid="confirmation-message"]')).not.toBeVisible();

    // Step 8: Fill in the 'Date' field with a valid current or future date
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 5);
    const formattedDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="date-field"]', formattedDate);

    // Step 9: Fill in the 'Reason' field with a valid explanation
    await page.fill('[data-testid="reason-field"]', 'Personal emergency requiring schedule adjustment');

    // Step 10: Fill in the 'Time' field with a valid time
    await page.fill('[data-testid="time-field"]', '14:30');

    // Step 11: Click the 'Submit' button with all mandatory fields completed
    await page.click('[data-testid="submit-button"]');

    // Step 12: Verify submission succeeds with confirmation
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('successfully submitted');
  });

  test('Handle attachment size limit enforcement', async ({ page }) => {
    // Step 1: Navigate to login and authenticate
    await page.fill('[data-testid="username-input"]', VALID_CREDENTIALS.username);
    await page.fill('[data-testid="password-input"]', VALID_CREDENTIALS.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard|portal/);

    // Step 2: Navigate to schedule change request form
    await page.click('[data-testid="schedule-change-request-menu"]');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Step 3: Fill in all mandatory fields with valid data
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 3);
    const formattedDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="date-field"]', formattedDate);
    await page.fill('[data-testid="time-field"]', '10:00');
    await page.fill('[data-testid="reason-field"]', 'Testing attachment size validation');

    // Step 4: Click on the 'Attach Document' or 'Browse' button
    // Step 5: Select a file larger than 10MB from the file system
    const oversizedFilePath = path.join(__dirname, 'fixtures', 'oversized-file.pdf');
    const fileInput = page.locator('[data-testid="attachment-input"]');
    await fileInput.setInputFiles(oversizedFilePath);

    // Step 6: Verify error message is displayed for oversized file
    await expect(page.locator('[data-testid="attachment-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="attachment-error"]')).toContainText(/10MB|size limit|too large/);

    // Step 7: Verify that the oversized file is not attached to the form
    await expect(page.locator('[data-testid="attachment-indicator"]')).not.toContainText('oversized-file.pdf');

    // Step 8: Click on the 'Attach Document' button again
    // Step 9: Select a valid file that is within the 10MB size limit
    const validFilePath = path.join(__dirname, 'fixtures', 'valid-document-5mb.pdf');
    await fileInput.setInputFiles(validFilePath);

    // Step 10: Verify the attachment indicator shows the uploaded file name and size
    await expect(page.locator('[data-testid="attachment-indicator"]')).toBeVisible();
    await expect(page.locator('[data-testid="attachment-indicator"]')).toContainText('valid-document-5mb.pdf');
    await expect(page.locator('[data-testid="attachment-error"]')).not.toBeVisible();

    // Step 11: Click the 'Submit' button to submit the request with the valid attachment
    await page.click('[data-testid="submit-button"]');

    // Step 12: Verify the confirmation message includes details about the attached document
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('successfully submitted');
    await expect(page.locator('[data-testid="request-details"]')).toContainText('valid-document-5mb.pdf');
    await expect(page.locator('[data-testid="request-timestamp"]')).toBeVisible();
  });
});