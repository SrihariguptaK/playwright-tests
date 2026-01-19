import { test, expect } from '@playwright/test';
import path from 'path';

test.describe('Schedule Change Request Submission', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Schedule Manager
    await page.goto(baseURL);
    await page.fill('[data-testid="username-input"]', 'schedule.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
  });

  test('Validate successful schedule change request submission (happy-path)', async ({ page }) => {
    // Step 1: Navigate to schedule change submission page
    await page.click('[data-testid="schedule-changes-menu"]');
    await page.click('[data-testid="submit-change-request-link"]');
    
    // Expected Result: Submission form is displayed
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="form-title"]')).toContainText('Schedule Change Request');
    
    // Step 2: Fill all mandatory fields with valid data
    await page.fill('[data-testid="schedule-id-input"]', 'SCH-2024-001');
    await page.selectOption('[data-testid="change-type-select"]', 'Time Modification');
    await page.fill('[data-testid="effective-date-input"]', '2024-06-15');
    await page.fill('[data-testid="reason-input"]', 'Resource availability conflict requiring schedule adjustment');
    await page.fill('[data-testid="impact-description-textarea"]', 'This change will affect 3 teams and require coordination with external vendors. Estimated impact duration is 2 weeks.');
    
    // Attach allowed files
    const supportingDocPath = path.join(__dirname, 'fixtures', 'supporting-document.pdf');
    const impactAnalysisPath = path.join(__dirname, 'fixtures', 'impact-analysis.docx');
    
    await page.setInputFiles('[data-testid="attachment-input"]', [supportingDocPath, impactAnalysisPath]);
    
    // Expected Result: No validation errors are shown
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    await expect(page.locator('.error-message')).toHaveCount(0);
    
    // Verify attachments are displayed
    await expect(page.locator('[data-testid="attached-file"]').first()).toContainText('supporting-document.pdf');
    await expect(page.locator('[data-testid="attached-file"]').nth(1)).toContainText('impact-analysis.docx');
    
    // Step 3: Submit the schedule change request
    await page.click('[data-testid="submit-button"]');
    
    // Expected Result: Request is accepted, workflow initiated, and confirmation displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule change request submitted successfully');
    
    // Verify tracking ID is displayed
    const trackingIdElement = page.locator('[data-testid="tracking-id"]');
    await expect(trackingIdElement).toBeVisible();
    const trackingId = await trackingIdElement.textContent();
    expect(trackingId).toMatch(/^SCR-\d{4}-\d+$/);
    
    // Verify workflow initiation message
    await expect(page.locator('[data-testid="workflow-status"]')).toContainText('Approval workflow initiated');
    
    // Verify tracking ID can be used for future reference
    await page.click('[data-testid="view-submission-history"]');
    await expect(page.locator(`[data-testid="request-${trackingId}"]`)).toBeVisible();
  });

  test('Verify rejection of submission with missing mandatory fields (error-case)', async ({ page }) => {
    // Step 1: Navigate to submission page
    await page.click('[data-testid="schedule-changes-menu"]');
    await page.click('[data-testid="submit-change-request-link"]');
    
    // Expected Result: Form is displayed
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    
    // Step 2: Fill in only some mandatory fields, leaving 'Reason for Change' blank
    await page.fill('[data-testid="schedule-id-input"]', 'SCH-2024-002');
    await page.selectOption('[data-testid="change-type-select"]', 'Resource Change');
    await page.fill('[data-testid="effective-date-input"]', '2024-07-01');
    // Intentionally leave 'reason-input' empty
    await page.fill('[data-testid="impact-description-textarea"]', 'Minor impact expected');
    
    // Step 3: Attempt to submit the form
    await page.click('[data-testid="submit-button"]');
    
    // Expected Result: Validation errors highlight missing fields
    await expect(page.locator('[data-testid="reason-input-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-input-error"]')).toContainText('Reason for Change is required');
    
    // Expected Result: Submission is blocked with error messages
    await expect(page.locator('[data-testid="form-error-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="form-error-summary"]')).toContainText('Please correct the errors before submitting');
    
    // Verify the form is still displayed and not submitted
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
    
    // Verify field highlighting
    await expect(page.locator('[data-testid="reason-input"]')).toHaveClass(/error|invalid/);
    
    // Attempt to navigate away and verify warning
    page.on('dialog', async dialog => {
      expect(dialog.message()).toContain('unsaved changes');
      await dialog.dismiss();
    });
    
    // Fill in the previously missing mandatory field
    await page.fill('[data-testid="reason-input"]', 'Updated resource allocation requirements');
    
    // Verify error is cleared
    await expect(page.locator('[data-testid="reason-input-error"]')).not.toBeVisible();
    
    // Submit after all mandatory fields are completed
    await page.click('[data-testid="submit-button"]');
    
    // Verify successful submission
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 10000 });
  });

  test('Test attachment validation for unsupported file types (error-case)', async ({ page }) => {
    // Navigate to schedule change submission page
    await page.click('[data-testid="schedule-changes-menu"]');
    await page.click('[data-testid="submit-change-request-link"]');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    
    // Step 1: Attempt to attach file with unsupported format
    const unsupportedFilePath = path.join(__dirname, 'fixtures', 'malicious-file.exe');
    await page.setInputFiles('[data-testid="attachment-input"]', unsupportedFilePath);
    
    // Expected Result: Validation error messages are displayed
    await expect(page.locator('[data-testid="attachment-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="attachment-error"]')).toContainText('File type not supported');
    await expect(page.locator('[data-testid="attachment-error"]')).toContainText('Allowed types: PDF, DOC, DOCX, XLS, XLSX');
    
    // Verify unsupported file is not added to attachment list
    await expect(page.locator('[data-testid="attached-file"]')).toHaveCount(0);
    
    // Attempt to attach multiple unsupported file types simultaneously
    const unsupportedBatFile = path.join(__dirname, 'fixtures', 'script.bat');
    const unsupportedZipFile = path.join(__dirname, 'fixtures', 'archive.zip');
    await page.setInputFiles('[data-testid="attachment-input"]', [unsupportedBatFile, unsupportedZipFile]);
    
    // Verify multiple error messages
    await expect(page.locator('[data-testid="attachment-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="attachment-error"]')).toContainText('2 files rejected');
    
    // Step 2: Remove unsupported file attempts and attach supported formats
    // Clear any previous file selections
    await page.setInputFiles('[data-testid="attachment-input"]', []);
    
    // Select and attach files with supported formats
    const supportedPdfPath = path.join(__dirname, 'fixtures', 'schedule-analysis.pdf');
    const supportedDocxPath = path.join(__dirname, 'fixtures', 'change-justification.docx');
    const supportedXlsxPath = path.join(__dirname, 'fixtures', 'impact-data.xlsx');
    
    await page.setInputFiles('[data-testid="attachment-input"]', [supportedPdfPath, supportedDocxPath, supportedXlsxPath]);
    
    // Expected Result: Attachments accepted without errors
    await expect(page.locator('[data-testid="attachment-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="attached-file"]')).toHaveCount(3);
    await expect(page.locator('[data-testid="attached-file"]').first()).toContainText('schedule-analysis.pdf');
    await expect(page.locator('[data-testid="attached-file"]').nth(1)).toContainText('change-justification.docx');
    await expect(page.locator('[data-testid="attached-file"]').nth(2)).toContainText('impact-data.xlsx');
    
    // Verify file size indicators are shown
    await expect(page.locator('[data-testid="file-size"]').first()).toBeVisible();
    
    // Complete all mandatory fields
    await page.fill('[data-testid="schedule-id-input"]', 'SCH-2024-003');
    await page.selectOption('[data-testid="change-type-select"]', 'Scope Change');
    await page.fill('[data-testid="effective-date-input"]', '2024-08-01');
    await page.fill('[data-testid="reason-input"]', 'Client requested scope modification');
    await page.fill('[data-testid="impact-description-textarea"]', 'Scope change requires timeline extension and additional resources');
    
    // Submit the form with valid attachments
    await page.click('[data-testid="submit-button"]');
    
    // Verify successful submission
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="tracking-id"]')).toBeVisible();
  });

  test('Test attachment validation for file size limits', async ({ page }) => {
    // Navigate to schedule change submission page
    await page.click('[data-testid="schedule-changes-menu"]');
    await page.click('[data-testid="submit-change-request-link"]');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();
    
    // Attempt to attach file exceeding size limit
    const oversizedFilePath = path.join(__dirname, 'fixtures', 'large-document.pdf');
    await page.setInputFiles('[data-testid="attachment-input"]', oversizedFilePath);
    
    // Verify size limit error
    await expect(page.locator('[data-testid="attachment-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="attachment-error"]')).toContainText('File size exceeds maximum limit');
    
    // Verify file is not added
    await expect(page.locator('[data-testid="attached-file"]')).toHaveCount(0);
    
    // Attach file within size limit
    const validSizeFilePath = path.join(__dirname, 'fixtures', 'normal-document.pdf');
    await page.setInputFiles('[data-testid="attachment-input"]', validSizeFilePath);
    
    // Verify attachment is accepted
    await expect(page.locator('[data-testid="attachment-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="attached-file"]')).toHaveCount(1);
  });
});