import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Submission', () => {
  test.beforeEach(async ({ page }) => {
    // Manager logs into the system
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'ManagerPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Submit schedule change request with valid data', async ({ page }) => {
    // Manager navigates to schedule change request page from the main dashboard or menu
    await page.click('[data-testid="schedule-changes-menu"]');
    await page.click('[data-testid="new-request-button"]');
    
    // Submission form is displayed
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Schedule Change Request');

    // Manager enters employee name in the designated field
    await page.fill('[data-testid="employee-name-input"]', 'John Smith');
    
    // Manager enters current schedule details (days and times)
    await page.fill('[data-testid="current-schedule-input"]', 'Monday-Friday, 9:00 AM - 5:00 PM');
    
    // Manager enters proposed schedule details (days and times)
    await page.fill('[data-testid="proposed-schedule-input"]', 'Tuesday-Saturday, 10:00 AM - 6:00 PM');
    
    // Manager selects effective date using the date picker
    await page.click('[data-testid="effective-date-picker"]');
    await page.click('[data-testid="date-option-next-month"]');
    
    // Manager enters reason for schedule change in the text area
    await page.fill('[data-testid="reason-textarea"]', 'Employee requested schedule change to accommodate childcare needs');
    
    // Manager clicks on the attachment button and selects valid document files (PDF format, 2MB size)
    const fileInput = page.locator('[data-testid="file-upload-input"]');
    await fileInput.setInputFiles({
      name: 'schedule-request.pdf',
      mimeType: 'application/pdf',
      buffer: Buffer.alloc(2 * 1024 * 1024)
    });
    
    // Form accepts data without validation errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="file-upload-success"]')).toBeVisible();
    
    // Manager reviews all entered information for accuracy
    await expect(page.locator('[data-testid="employee-name-input"]')).toHaveValue('John Smith');
    await expect(page.locator('[data-testid="current-schedule-input"]')).toHaveValue('Monday-Friday, 9:00 AM - 5:00 PM');
    await expect(page.locator('[data-testid="proposed-schedule-input"]')).toHaveValue('Tuesday-Saturday, 10:00 AM - 6:00 PM');
    
    // Manager clicks the Submit button
    await page.click('[data-testid="submit-request-button"]');
    
    // System confirms successful submission and routes request
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule change request submitted successfully');
    await expect(page.locator('[data-testid="confirmation-number"]')).toBeVisible();
    
    // Manager navigates to the request tracking page
    await page.click('[data-testid="view-requests-link"]');
    await expect(page).toHaveURL(/.*requests/);
    await expect(page.locator('[data-testid="request-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-status"]').first()).toContainText('Pending Approval');
  });

  test('Reject submission with missing mandatory fields', async ({ page }) => {
    // Manager navigates to schedule change request page
    await page.click('[data-testid="schedule-changes-menu"]');
    await page.click('[data-testid="new-request-button"]');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Manager leaves the employee name field empty and moves to the next field
    await page.click('[data-testid="employee-name-input"]');
    await page.click('[data-testid="current-schedule-input"]');
    
    // Real-time validation highlights missing fields
    await expect(page.locator('[data-testid="employee-name-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-name-error"]')).toContainText('Employee name is required');
    
    // Manager leaves the current schedule field empty and moves to the next field
    await page.click('[data-testid="proposed-schedule-input"]');
    await expect(page.locator('[data-testid="current-schedule-error"]')).toBeVisible();
    
    // Manager leaves the proposed schedule field empty and moves to the next field
    await page.click('[data-testid="effective-date-picker"]');
    await expect(page.locator('[data-testid="proposed-schedule-error"]')).toBeVisible();
    
    // Manager leaves the effective date field empty and moves to the next field
    await page.click('[data-testid="reason-textarea"]');
    await expect(page.locator('[data-testid="effective-date-error"]')).toBeVisible();
    
    // Manager leaves the reason for change field empty
    await page.click('[data-testid="submit-request-button"]');
    await expect(page.locator('[data-testid="reason-error"]')).toBeVisible();
    
    // Manager attempts to click the Submit button with all mandatory fields still empty
    await page.click('[data-testid="submit-request-button"]');
    
    // Submission is blocked with error messages
    await expect(page.locator('[data-testid="form-error-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="form-error-summary"]')).toContainText('Please complete all required fields');
    await expect(page).toHaveURL(/.*new-request/);
    
    // Manager fills in only the employee name field and attempts to submit again
    await page.fill('[data-testid="employee-name-input"]', 'Jane Doe');
    await page.click('[data-testid="submit-request-button"]');
    
    // Submission is still blocked
    await expect(page.locator('[data-testid="form-error-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-schedule-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="proposed-schedule-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="effective-date-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-error"]')).toBeVisible();
    
    // Manager scrolls through the form to view all validation errors
    await page.locator('[data-testid="employee-name-error"]').scrollIntoViewIfNeeded();
    await page.locator('[data-testid="current-schedule-error"]').scrollIntoViewIfNeeded();
    await page.locator('[data-testid="proposed-schedule-error"]').scrollIntoViewIfNeeded();
    await page.locator('[data-testid="effective-date-error"]').scrollIntoViewIfNeeded();
    await page.locator('[data-testid="reason-error"]').scrollIntoViewIfNeeded();
    
    const errorCount = await page.locator('[class*="error"][class*="message"]').count();
    expect(errorCount).toBeGreaterThanOrEqual(4);
  });

  test('Validate attachment file types and sizes', async ({ page }) => {
    // Manager navigates to schedule change request page
    await page.click('[data-testid="schedule-changes-menu"]');
    await page.click('[data-testid="new-request-button"]');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Manager fills in all mandatory fields with valid data
    await page.fill('[data-testid="employee-name-input"]', 'Michael Johnson');
    await page.fill('[data-testid="current-schedule-input"]', 'Monday-Friday, 8:00 AM - 4:00 PM');
    await page.fill('[data-testid="proposed-schedule-input"]', 'Monday-Friday, 7:00 AM - 3:00 PM');
    await page.click('[data-testid="effective-date-picker"]');
    await page.click('[data-testid="date-option-next-month"]');
    await page.fill('[data-testid="reason-textarea"]', 'Employee needs earlier schedule for personal commitments');

    // Manager clicks on the attachment button and attempts to select an unsupported file type (e.g., .exe file)
    const fileInputUnsupported = page.locator('[data-testid="file-upload-input"]');
    await fileInputUnsupported.setInputFiles({
      name: 'malicious.exe',
      mimeType: 'application/x-msdownload',
      buffer: Buffer.from('fake exe content')
    });
    
    // System displays validation error
    await expect(page.locator('[data-testid="file-type-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="file-type-error"]')).toContainText('File type not supported');
    
    // Manager clicks on the attachment button and attempts to select an oversized file (e.g., 15MB PDF file)
    await page.locator('[data-testid="file-upload-input"]').setInputFiles({
      name: 'oversized-document.pdf',
      mimeType: 'application/pdf',
      buffer: Buffer.alloc(15 * 1024 * 1024)
    });
    
    // System displays validation error
    await expect(page.locator('[data-testid="file-size-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="file-size-error"]')).toContainText('File size exceeds maximum allowed');
    
    // Manager attempts to submit the form without any valid attachments
    await page.click('[data-testid="submit-request-button"]');
    await expect(page.locator('[data-testid="attachment-required-error"]')).toBeVisible();
    
    // Manager clicks on the attachment button and selects a valid file (e.g., 2MB PDF file)
    await page.locator('[data-testid="file-upload-input"]').setInputFiles({
      name: 'schedule-justification.pdf',
      mimeType: 'application/pdf',
      buffer: Buffer.alloc(2 * 1024 * 1024)
    });
    
    await expect(page.locator('[data-testid="file-upload-success"]')).toBeVisible();
    await expect(page.locator('[data-testid="uploaded-file-name"]')).toContainText('schedule-justification.pdf');
    
    // Manager adds another valid file (e.g., 3MB DOCX file)
    await page.locator('[data-testid="add-another-file-button"]').click();
    await page.locator('[data-testid="file-upload-input-2"]').setInputFiles({
      name: 'supporting-document.docx',
      mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      buffer: Buffer.alloc(3 * 1024 * 1024)
    });
    
    await expect(page.locator('[data-testid="uploaded-file-name-2"]')).toContainText('supporting-document.docx');
    
    // Manager reviews the form to ensure all data is correct and valid files are attached
    await expect(page.locator('[data-testid="employee-name-input"]')).toHaveValue('Michael Johnson');
    await expect(page.locator('[data-testid="uploaded-files-list"]')).toBeVisible();
    const uploadedFilesCount = await page.locator('[data-testid^="uploaded-file-name"]').count();
    expect(uploadedFilesCount).toBe(2);
    
    // Manager clicks the Submit button
    await page.click('[data-testid="submit-request-button"]');
    
    // Submission succeeds
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule change request submitted successfully');
    
    // Manager navigates to the request tracking page and opens the submitted request
    await page.click('[data-testid="view-requests-link"]');
    await expect(page).toHaveURL(/.*requests/);
    await page.click('[data-testid="request-row"]').first();
    
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-employee-name"]')).toContainText('Michael Johnson');
    await expect(page.locator('[data-testid="request-attachments"]')).toBeVisible();
    await expect(page.locator('[data-testid="attachment-link"]')).toHaveCount(2);
  });
});