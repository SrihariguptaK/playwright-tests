import { test, expect } from '@playwright/test';
import * as path from 'path';
import * as fs from 'fs';

test.describe('Manual Attendance Aggregation - Story 12', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const managerCredentials = {
    username: 'attendance.manager@company.com',
    password: 'Manager@123'
  };

  test.beforeEach(async ({ page }) => {
    // Login as Attendance Manager
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', managerCredentials.username);
    await page.fill('[data-testid="password-input"]', managerCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible({ timeout: 10000 });
  });

  test('Validate successful manual attendance upload and reconciliation', async ({ page }) => {
    // Navigate to the manual attendance upload interface
    await page.goto(`${baseURL}/attendance/manual-upload`);
    await expect(page.locator('[data-testid="manual-upload-page"]')).toBeVisible();

    // Select and upload the valid CSV file containing manual attendance entries
    const validCSVPath = path.join(__dirname, 'test-data', 'valid-manual-attendance.csv');
    const fileInput = page.locator('[data-testid="file-upload-input"]');
    await fileInput.setInputFiles(validCSVPath);

    // Upload the manual attendance CSV file to the system
    await page.click('[data-testid="upload-button"]');
    
    // Verify that the system accepts file and validates data
    await expect(page.locator('[data-testid="upload-success-message"]')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('[data-testid="upload-success-message"]')).toContainText('File uploaded successfully');

    // Verify that the system parses and validates the CSV file data
    await expect(page.locator('[data-testid="validation-status"]')).toContainText('Validation completed');
    await expect(page.locator('[data-testid="records-validated"]')).toBeVisible();

    // Allow the system to automatically reconcile manual entries with existing automated attendance data
    await page.waitForSelector('[data-testid="reconciliation-status"]', { timeout: 30000 });
    await expect(page.locator('[data-testid="reconciliation-status"]')).toContainText('Reconciliation completed');

    // Review the reconciliation results to verify that conflicts are flagged accurately
    const conflictsSection = page.locator('[data-testid="conflicts-section"]');
    await expect(conflictsSection).toBeVisible();
    
    const conflictCount = await page.locator('[data-testid="conflict-count"]').textContent();
    if (conflictCount && parseInt(conflictCount) > 0) {
      await expect(page.locator('[data-testid="conflict-details"]')).toBeVisible();
      await expect(page.locator('[data-testid="conflict-item"]').first()).toBeVisible();
    }

    // Verify that non-conflicting manual entries are automatically integrated
    await expect(page.locator('[data-testid="integrated-records-count"]')).toBeVisible();
    const integratedCount = await page.locator('[data-testid="integrated-records-count"]').textContent();
    expect(parseInt(integratedCount || '0')).toBeGreaterThan(0);

    // Query the audit trail to verify entries for the manual upload operation
    await page.click('[data-testid="view-audit-trail-button"]');
    await expect(page.locator('[data-testid="audit-trail-modal"]')).toBeVisible();

    // Verify audit trail entries include details of all manual attendance changes made
    const auditEntries = page.locator('[data-testid="audit-entry"]');
    await expect(auditEntries.first()).toBeVisible();
    
    // Verify audit records created with user and timestamp
    await expect(page.locator('[data-testid="audit-user"]').first()).toContainText(managerCredentials.username);
    await expect(page.locator('[data-testid="audit-timestamp"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="audit-action"]').first()).toContainText('Manual Upload');

    // Check that the audit trail is complete and accessible for compliance review
    const auditCount = await auditEntries.count();
    expect(auditCount).toBeGreaterThan(0);
    await expect(page.locator('[data-testid="audit-export-button"]')).toBeVisible();
  });

  test('Verify rejection of invalid manual attendance files', async ({ page }) => {
    // Navigate to the manual attendance upload interface
    await page.goto(`${baseURL}/attendance/manual-upload`);
    await expect(page.locator('[data-testid="manual-upload-page"]')).toBeVisible();

    // Select and upload a manual attendance file with invalid format
    const invalidFilePath = path.join(__dirname, 'test-data', 'invalid-manual-attendance.csv');
    const fileInput = page.locator('[data-testid="file-upload-input"]');
    await fileInput.setInputFiles(invalidFilePath);

    // Upload the invalid file
    await page.click('[data-testid="upload-button"]');

    // Wait for system to complete file validation
    await page.waitForSelector('[data-testid="validation-error"]', { timeout: 10000 });

    // Verify that the system displays a clear error message
    const errorMessage = page.locator('[data-testid="validation-error"]');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText(/invalid format|incorrect column|validation failed/i);

    // Verify that the system rejects file and displays error message
    await expect(page.locator('[data-testid="upload-status"]')).toContainText(/rejected|failed/i);

    // Check that no records from the invalid file are stored in the database
    await expect(page.locator('[data-testid="records-processed"]')).toContainText('0');

    // Verify that the rejection is logged in the system logs
    await page.click('[data-testid="view-logs-button"]');
    await expect(page.locator('[data-testid="system-logs-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-entry"]').first()).toContainText(/error|validation failed/i);
    await page.click('[data-testid="close-logs-modal"]');

    // Confirm that the user can retry the upload with a corrected file
    await expect(page.locator('[data-testid="file-upload-input"]')).toBeEnabled();
    await expect(page.locator('[data-testid="upload-button"]')).toBeEnabled();
    await expect(page.locator('[data-testid="retry-message"]')).toContainText(/please correct|try again/i);
  });

  test('Test batch processing performance for manual uploads', async ({ page }) => {
    // Note the current system time before starting the upload process
    const startTime = Date.now();

    // Navigate to manual attendance upload interface
    await page.goto(`${baseURL}/attendance/manual-upload`);
    await expect(page.locator('[data-testid="manual-upload-page"]')).toBeVisible();

    // Select the file containing 500 manual attendance records
    const batchFilePath = path.join(__dirname, 'test-data', 'batch-500-records.csv');
    const fileInput = page.locator('[data-testid="file-upload-input"]');
    await fileInput.setInputFiles(batchFilePath);

    // Upload the batch file containing 500 manual attendance records
    await page.click('[data-testid="upload-button"]');

    // Monitor the system processing status and progress indicators
    await expect(page.locator('[data-testid="processing-status"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="progress-bar"]')).toBeVisible();

    // Wait for the system to complete validation, reconciliation, and storage
    await page.waitForSelector('[data-testid="processing-complete"]', { timeout: 150000 });
    
    // Note the system time when processing completes and calculate total processing time
    const endTime = Date.now();
    const processingTimeSeconds = (endTime - startTime) / 1000;

    // Verify that the batch processing completed within 2 minutes (120 seconds)
    expect(processingTimeSeconds).toBeLessThanOrEqual(120);
    console.log(`Batch processing completed in ${processingTimeSeconds} seconds`);

    // Verify processing completion message
    await expect(page.locator('[data-testid="processing-complete"]')).toContainText('Processing completed successfully');

    // Query the database to verify all 500 records were successfully stored
    const processedCount = await page.locator('[data-testid="records-processed"]').textContent();
    expect(parseInt(processedCount || '0')).toBe(500);

    // Verify data integrity by checking summary statistics
    await page.click('[data-testid="view-summary-button"]');
    await expect(page.locator('[data-testid="summary-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="total-records"]')).toContainText('500');
    await expect(page.locator('[data-testid="successful-records"]')).toBeVisible();

    // Sample random records from the batch to ensure accuracy
    await page.click('[data-testid="view-records-button"]');
    await expect(page.locator('[data-testid="records-table"]')).toBeVisible();
    
    const recordRows = page.locator('[data-testid="record-row"]');
    const rowCount = await recordRows.count();
    expect(rowCount).toBeGreaterThan(0);

    // Verify sample record has required fields
    await expect(recordRows.first().locator('[data-testid="employee-id"]')).toBeVisible();
    await expect(recordRows.first().locator('[data-testid="attendance-date"]')).toBeVisible();
    await expect(recordRows.first().locator('[data-testid="attendance-time"]')).toBeVisible();

    // Check system logs for any errors or warnings during batch processing
    await page.click('[data-testid="view-logs-button"]');
    await expect(page.locator('[data-testid="system-logs-modal"]')).toBeVisible();
    
    const errorLogs = page.locator('[data-testid="log-entry"][data-level="error"]');
    const errorCount = await errorLogs.count();
    expect(errorCount).toBe(0);

    // Verify performance metrics are logged
    await expect(page.locator('[data-testid="performance-metrics"]')).toBeVisible();
    await expect(page.locator('[data-testid="processing-time"]')).toContainText(/\d+\s*(seconds|sec)/i);
  });
});