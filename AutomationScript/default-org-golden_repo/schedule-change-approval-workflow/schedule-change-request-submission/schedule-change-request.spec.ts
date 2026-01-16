import { test, expect } from '@playwright/test';
import path from 'path';

test.describe('Schedule Change Request Submission', () => {
  test.beforeEach(async ({ page }) => {
    // Employee logs into the scheduling system
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful schedule change request submission with valid data', async ({ page }) => {
    // Employee navigates to schedule change request form
    await page.click('[data-testid="schedule-change-menu"]');
    await page.click('[data-testid="new-schedule-change-request"]');
    
    // Verify form is displayed with all mandatory fields
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="from-date-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="to-date-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="change-type-dropdown"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-textarea"]')).toBeVisible();
    
    // Employee enters valid start date
    await page.fill('[data-testid="from-date-field"]', '2024-02-01');
    
    // Employee enters valid end date
    await page.fill('[data-testid="to-date-field"]', '2024-02-05');
    
    // Employee selects a change type
    await page.click('[data-testid="change-type-dropdown"]');
    await page.click('[data-testid="change-type-option-shift-change"]');
    
    // Employee enters a detailed reason
    await page.fill('[data-testid="reason-textarea"]', 'Need to adjust schedule due to personal appointment that cannot be rescheduled');
    
    // Employee uploads a valid document (PDF, 3MB)
    const validFilePath = path.join(__dirname, 'test-files', 'valid-document.pdf');
    await page.setInputFiles('[data-testid="upload-document-input"]', validFilePath);
    
    // Verify all inputs accept data without validation errors
    await expect(page.locator('[data-testid="from-date-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="to-date-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="change-type-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="reason-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="file-upload-success"]')).toBeVisible();
    
    // Employee reviews all entered information
    await expect(page.locator('[data-testid="from-date-field"]')).toHaveValue('2024-02-01');
    await expect(page.locator('[data-testid="to-date-field"]')).toHaveValue('2024-02-05');
    
    // Employee submits the form
    await page.click('[data-testid="submit-button"]');
    
    // Verify request is saved, approval workflow is initiated, and confirmation message is displayed
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Schedule change request submitted successfully');
    await expect(page.locator('[data-testid="request-reference-number"]')).toBeVisible();
    
    // Verify confirmation message contains request reference number
    const referenceNumber = await page.locator('[data-testid="request-reference-number"]').textContent();
    expect(referenceNumber).toMatch(/REF-\d+/);
  });

  test('Verify rejection of submission with missing mandatory fields', async ({ page }) => {
    // Employee navigates to schedule change request form
    await page.click('[data-testid="schedule-change-menu"]');
    await page.click('[data-testid="new-schedule-change-request"]');
    
    // Verify form is displayed
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    
    // Employee leaves the 'From Date' field empty and attempts to move to the next field
    await page.click('[data-testid="to-date-field"]');
    
    // Verify real-time validation highlights missing From Date field
    await expect(page.locator('[data-testid="from-date-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="from-date-error"]')).toContainText('From Date is required');
    
    // Employee enters a valid 'From Date' but leaves the 'To Date' field empty
    await page.fill('[data-testid="from-date-field"]', '2024-02-01');
    await page.click('[data-testid="change-type-dropdown"]');
    
    // Verify To Date validation error
    await expect(page.locator('[data-testid="to-date-error"]')).toBeVisible();
    
    // Employee enters both dates but leaves the 'Change Type' dropdown unselected
    await page.fill('[data-testid="to-date-field"]', '2024-02-05');
    await page.click('[data-testid="reason-textarea"]');
    
    // Verify Change Type validation error
    await expect(page.locator('[data-testid="change-type-error"]')).toBeVisible();
    
    // Employee selects a change type but leaves the 'Reason' text area empty
    await page.click('[data-testid="change-type-dropdown"]');
    await page.click('[data-testid="change-type-option-time-off"]');
    
    // Employee attempts to submit with empty reason
    await page.click('[data-testid="submit-button"]');
    
    // Verify submission is blocked and inline error messages are displayed
    await expect(page.locator('[data-testid="reason-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-error"]')).toContainText('Reason is required');
    await expect(page.locator('[data-testid="confirmation-message"]')).not.toBeVisible();
    
    // Verify all empty mandatory fields are highlighted simultaneously
    await page.reload();
    await page.click('[data-testid="schedule-change-menu"]');
    await page.click('[data-testid="new-schedule-change-request"]');
    await page.click('[data-testid="submit-button"]');
    
    await expect(page.locator('[data-testid="from-date-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="to-date-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="change-type-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-error"]')).toBeVisible();
    
    // Employee fills in all mandatory fields except the 'Reason' field with only 5 characters
    await page.fill('[data-testid="from-date-field"]', '2024-02-01');
    await page.fill('[data-testid="to-date-field"]', '2024-02-05');
    await page.click('[data-testid="change-type-dropdown"]');
    await page.click('[data-testid="change-type-option-shift-change"]');
    await page.fill('[data-testid="reason-textarea"]', 'Short');
    
    // Attempt to submit with insufficient reason length
    await page.click('[data-testid="submit-button"]');
    
    // Verify validation error for minimum character requirement
    await expect(page.locator('[data-testid="reason-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-error"]')).toContainText('Reason must be at least 10 characters');
  });

  test('Test file upload validation for invalid file types and sizes', async ({ page }) => {
    // Employee navigates to schedule change request form
    await page.click('[data-testid="schedule-change-menu"]');
    await page.click('[data-testid="new-schedule-change-request"]');
    
    // Employee attempts to upload a file exceeding size limit (6MB PDF)
    const oversizedFilePath = path.join(__dirname, 'test-files', 'oversized-document.pdf');
    await page.setInputFiles('[data-testid="upload-document-input"]', oversizedFilePath);
    
    // Verify system displays validation error and prevents upload
    await expect(page.locator('[data-testid="file-upload-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="file-upload-error"]')).toContainText('File size exceeds 5MB limit');
    
    // Verify that no file name appears in the upload field after the size validation error
    await expect(page.locator('[data-testid="uploaded-file-name"]')).not.toBeVisible();
    
    // Employee dismisses the error and attempts to upload unsupported file type
    await page.click('[data-testid="dismiss-error-button"]');
    const invalidFileTypePath = path.join(__dirname, 'test-files', 'invalid-file.exe');
    await page.setInputFiles('[data-testid="upload-document-input"]', invalidFileTypePath);
    
    // Verify file type validation error
    await expect(page.locator('[data-testid="file-upload-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="file-upload-error"]')).toContainText('Invalid file type. Only PDF files are allowed');
    
    // Verify the upload field status after file type validation error
    await expect(page.locator('[data-testid="uploaded-file-name"]')).not.toBeVisible();
    
    // Employee attempts to submit the form without any file uploaded (file upload is optional)
    await page.fill('[data-testid="from-date-field"]', '2024-02-01');
    await page.fill('[data-testid="to-date-field"]', '2024-02-05');
    await page.click('[data-testid="change-type-dropdown"]');
    await page.click('[data-testid="change-type-option-shift-change"]');
    await page.fill('[data-testid="reason-textarea"]', 'Valid reason for schedule change request');
    
    await page.click('[data-testid="submit-button"]');
    
    // Verify submission succeeds without file
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    
    // Navigate back to form for valid file upload test
    await page.click('[data-testid="schedule-change-menu"]');
    await page.click('[data-testid="new-schedule-change-request"]');
    
    // Employee uploads a valid file within size and type limits (3MB PDF)
    const validFilePath = path.join(__dirname, 'test-files', 'valid-document.pdf');
    await page.setInputFiles('[data-testid="upload-document-input"]', validFilePath);
    
    // Verify file is accepted without errors
    await expect(page.locator('[data-testid="file-upload-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="file-upload-success"]')).toBeVisible();
    
    // Verify the uploaded file details are correctly displayed
    await expect(page.locator('[data-testid="uploaded-file-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="uploaded-file-name"]')).toContainText('valid-document.pdf');
    await expect(page.locator('[data-testid="uploaded-file-size"]')).toBeVisible();
    
    // Employee fills in all other mandatory fields with valid data
    await page.fill('[data-testid="from-date-field"]', '2024-02-01');
    await page.fill('[data-testid="to-date-field"]', '2024-02-05');
    await page.click('[data-testid="change-type-dropdown"]');
    await page.click('[data-testid="change-type-option-shift-change"]');
    await page.fill('[data-testid="reason-textarea"]', 'Valid reason for schedule change with supporting document');
    
    // Employee submits the form with the valid uploaded file
    await page.click('[data-testid="submit-button"]');
    
    // Verify submission succeeds and confirmation is displayed
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Schedule change request submitted successfully');
    await expect(page.locator('[data-testid="request-reference-number"]')).toBeVisible();
    
    // Test file upload at exactly 5MB boundary (edge case)
    await page.click('[data-testid="schedule-change-menu"]');
    await page.click('[data-testid="new-schedule-change-request"]');
    
    const exactLimitFilePath = path.join(__dirname, 'test-files', 'exactly-5mb-document.pdf');
    await page.setInputFiles('[data-testid="upload-document-input"]', exactLimitFilePath);
    
    // Verify 5MB file is accepted
    await expect(page.locator('[data-testid="file-upload-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="file-upload-success"]')).toBeVisible();
    
    // Test file upload with 5.1MB file (just over the limit)
    await page.click('[data-testid="remove-file-button"]');
    const slightlyOverLimitFilePath = path.join(__dirname, 'test-files', 'slightly-over-5mb-document.pdf');
    await page.setInputFiles('[data-testid="upload-document-input"]', slightlyOverLimitFilePath);
    
    // Verify file over limit is rejected
    await expect(page.locator('[data-testid="file-upload-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="file-upload-error"]')).toContainText('File size exceeds 5MB limit');
  });
});