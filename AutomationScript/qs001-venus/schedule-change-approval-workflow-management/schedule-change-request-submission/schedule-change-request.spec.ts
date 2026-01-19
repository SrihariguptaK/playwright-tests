import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Submission', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and authenticate as employee
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful schedule change request submission with valid data', async ({ page }) => {
    // Step 1: Navigate to schedule change request page
    await page.click('[data-testid="schedule-change-menu"]');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-name-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-schedule-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="requested-schedule-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="effective-date-input"]')).toBeVisible();

    // Step 2: Enter valid schedule change details and upload a valid attachment
    await page.fill('[data-testid="employee-name-input"]', 'John Smith');
    await page.fill('[data-testid="current-schedule-input"]', 'Monday-Friday, 9:00 AM - 5:00 PM');
    await page.fill('[data-testid="requested-schedule-input"]', 'Monday-Friday, 10:00 AM - 6:00 PM');
    await page.fill('[data-testid="reason-input"]', 'Need to accommodate childcare schedule');
    
    // Set effective date to 7 days in the future
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    const formattedDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="effective-date-input"]', formattedDate);
    
    // Upload valid attachment
    const fileInput = page.locator('[data-testid="attachment-upload-input"]');
    await fileInput.setInputFiles({
      name: 'schedule_justification.pdf',
      mimeType: 'application/pdf',
      buffer: Buffer.from('Mock PDF content for testing')
    });
    
    // Verify no validation errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();

    // Step 3: Submit the form
    await page.click('[data-testid="submit-button"]');
    
    // Verify confirmation message
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('successfully submitted');
    
    // Verify status is set to Pending Approval
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Pending Approval');
    
    // Verify request appears in history
    await page.click('[data-testid="request-history-link"]');
    await expect(page.locator('[data-testid="request-list"]')).toContainText('John Smith');
  });

  test('Verify rejection of submission with missing mandatory fields', async ({ page }) => {
    // Step 1: Navigate to schedule change request page
    await page.click('[data-testid="schedule-change-menu"]');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Step 2: Leave mandatory fields empty and attempt to submit
    await page.click('[data-testid="submit-button"]');
    
    // Verify inline validation highlights missing fields
    await expect(page.locator('[data-testid="employee-name-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-name-error"]')).toContainText('required');
    await expect(page.locator('[data-testid="current-schedule-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="requested-schedule-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="effective-date-error"]')).toBeVisible();

    // Step 3: Fill in only Employee Name and attempt to submit again
    await page.fill('[data-testid="employee-name-input"]', 'Jane Doe');
    await page.click('[data-testid="submit-button"]');
    
    // Verify Employee Name error is cleared but others remain
    await expect(page.locator('[data-testid="employee-name-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="current-schedule-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="requested-schedule-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="effective-date-error"]')).toBeVisible();
    
    // Progressively fill in each mandatory field
    await page.fill('[data-testid="current-schedule-input"]', 'Monday-Friday, 9:00 AM - 5:00 PM');
    await expect(page.locator('[data-testid="current-schedule-error"]')).not.toBeVisible();
    
    await page.fill('[data-testid="requested-schedule-input"]', 'Monday-Friday, 10:00 AM - 6:00 PM');
    await expect(page.locator('[data-testid="requested-schedule-error"]')).not.toBeVisible();
    
    await page.fill('[data-testid="reason-input"]', 'Personal reasons');
    await expect(page.locator('[data-testid="reason-error"]')).not.toBeVisible();
    
    // Verify submit button is disabled or submission blocked until all fields are filled
    const submitButton = page.locator('[data-testid="submit-button"]');
    const isDisabled = await submitButton.isDisabled();
    if (!isDisabled) {
      await submitButton.click();
      await expect(page.locator('[data-testid="effective-date-error"]')).toBeVisible();
    }
    
    // Fill in the last mandatory field
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    const formattedDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="effective-date-input"]', formattedDate);
    await expect(page.locator('[data-testid="effective-date-error"]')).not.toBeVisible();
    
    // Verify submission is now allowed
    await expect(submitButton).toBeEnabled();
  });

  test('Test attachment upload validation', async ({ page }) => {
    // Step 1: Navigate to schedule change request page
    await page.click('[data-testid="schedule-change-menu"]');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Step 2: Upload a file that exceeds the 10MB size limit
    const fileInput = page.locator('[data-testid="attachment-upload-input"]');
    const largeFileBuffer = Buffer.alloc(12 * 1024 * 1024); // 12MB file
    await fileInput.setInputFiles({
      name: 'large_file.pdf',
      mimeType: 'application/pdf',
      buffer: largeFileBuffer
    });
    
    // Verify validation error for file size
    await expect(page.locator('[data-testid="attachment-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="attachment-error"]')).toContainText('10MB');
    
    // Step 3: Upload a file with invalid file type
    await fileInput.setInputFiles({
      name: 'malicious.exe',
      mimeType: 'application/x-msdownload',
      buffer: Buffer.from('Mock executable content')
    });
    
    // Verify validation error for file type
    await expect(page.locator('[data-testid="attachment-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="attachment-error"]')).toContainText('file type');
    
    // Step 4: Upload a valid file
    const validFileBuffer = Buffer.alloc(5 * 1024 * 1024); // 5MB file
    await fileInput.setInputFiles({
      name: 'schedule_justification.pdf',
      mimeType: 'application/pdf',
      buffer: validFileBuffer
    });
    
    // Verify attachment accepted without errors
    await expect(page.locator('[data-testid="attachment-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="uploaded-file-name"]')).toContainText('schedule_justification.pdf');
    
    // Verify file can be previewed or downloaded if functionality exists
    const previewLink = page.locator('[data-testid="file-preview-link"]');
    if (await previewLink.isVisible()) {
      await expect(previewLink).toBeVisible();
    }
    
    // Step 5: Remove the uploaded file
    await page.click('[data-testid="remove-attachment-button"]');
    await expect(page.locator('[data-testid="uploaded-file-name"]')).not.toBeVisible();
    
    // Step 6: Upload valid file again and submit complete form
    await fileInput.setInputFiles({
      name: 'schedule_justification.pdf',
      mimeType: 'application/pdf',
      buffer: validFileBuffer
    });
    
    await page.fill('[data-testid="employee-name-input"]', 'John Smith');
    await page.fill('[data-testid="current-schedule-input"]', 'Monday-Friday, 9:00 AM - 5:00 PM');
    await page.fill('[data-testid="requested-schedule-input"]', 'Monday-Friday, 10:00 AM - 6:00 PM');
    await page.fill('[data-testid="reason-input"]', 'Need to accommodate childcare schedule');
    
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    const formattedDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="effective-date-input"]', formattedDate);
    
    await page.click('[data-testid="submit-button"]');
    
    // Verify successful submission
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Pending Approval');
  });
});