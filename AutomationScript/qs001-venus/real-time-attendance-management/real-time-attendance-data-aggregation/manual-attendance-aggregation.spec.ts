import { test, expect } from '@playwright/test';
import path from 'path';

test.describe('Manual Attendance Data Aggregation', () => {
  const adminCredentials = {
    username: 'admin@company.com',
    password: 'Admin@123'
  };

  test.beforeEach(async ({ page }) => {
    // Navigate to admin dashboard login page
    await page.goto('/admin/login');
    
    // Login with administrator credentials
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Wait for dashboard to load
    await expect(page.locator('[data-testid="admin-dashboard"]')).toBeVisible();
  });

  test('Validate ingestion of manual attendance data (happy-path)', async ({ page }) => {
    // Navigate to the manual attendance data upload section
    await page.click('[data-testid="manual-attendance-menu"]');
    await page.click('[data-testid="data-upload-section"]');
    await expect(page.locator('[data-testid="upload-section-header"]')).toBeVisible();

    // Click 'Browse' or 'Choose File' button and select the prepared sample manual attendance CSV file
    const sampleCSVPath = path.join(__dirname, 'test-data', 'sample-manual-attendance.csv');
    const fileInput = page.locator('[data-testid="file-upload-input"]');
    await fileInput.setInputFiles(sampleCSVPath);

    // Verify file is selected
    await expect(page.locator('[data-testid="selected-file-name"]')).toContainText('sample-manual-attendance.csv');

    // Click 'Upload' or 'Import' button to initiate the manual attendance data ingestion
    await page.click('[data-testid="upload-button"]');

    // Wait for the system to process and ingest the uploaded CSV file
    await expect(page.locator('[data-testid="upload-progress"]')).toBeVisible();
    await expect(page.locator('[data-testid="upload-success-message"]')).toBeVisible({ timeout: 30000 });

    // Verify that system normalizes the manual attendance records
    await expect(page.locator('[data-testid="normalization-status"]')).toContainText('Normalized');

    // Navigate to attendance records view to verify data merged with biometric data
    await page.click('[data-testid="attendance-records-menu"]');
    await page.click('[data-testid="view-all-records"]');

    // Apply filter for the uploaded data time period
    await page.click('[data-testid="filter-button"]');
    await page.fill('[data-testid="date-from-input"]', '2024-01-01');
    await page.fill('[data-testid="date-to-input"]', '2024-01-31');
    await page.click('[data-testid="apply-filter-button"]');

    // Verify that manual entries are merged with biometric data without creating duplicate records
    const recordsTable = page.locator('[data-testid="attendance-records-table"]');
    await expect(recordsTable).toBeVisible();
    
    // Check for duplicate indicator - should not exist
    const duplicateWarning = page.locator('[data-testid="duplicate-warning"]');
    await expect(duplicateWarning).not.toBeVisible();

    // Verify attendance records count matches expected
    const recordCount = page.locator('[data-testid="total-records-count"]');
    await expect(recordCount).toBeVisible();
    const countText = await recordCount.textContent();
    expect(parseInt(countText || '0')).toBeGreaterThan(0);

    // Navigate to the admin monitoring interface for manual data ingestion
    await page.click('[data-testid="monitoring-menu"]');
    await page.click('[data-testid="ingestion-monitoring"]');

    // Review the ingestion status for the recently uploaded CSV file
    await expect(page.locator('[data-testid="ingestion-status-table"]')).toBeVisible();
    
    // Find the most recent upload entry
    const latestIngestion = page.locator('[data-testid="ingestion-row"]').first();
    await expect(latestIngestion).toBeVisible();
    
    // Verify ingestion status shows success
    const statusCell = latestIngestion.locator('[data-testid="status-cell"]');
    await expect(statusCell).toContainText('Success');

    // Verify that any errors or validation warnings are clearly displayed
    const errorColumn = latestIngestion.locator('[data-testid="error-count-cell"]');
    await expect(errorColumn).toContainText('0');
    
    // Check monitoring interface displays correctly
    await expect(page.locator('[data-testid="ingestion-details-panel"]')).toBeVisible();
  });

  test('Verify conflict detection for duplicate entries (error-case)', async ({ page }) => {
    // Navigate to the manual attendance data upload section
    await page.click('[data-testid="manual-attendance-menu"]');
    await page.click('[data-testid="data-upload-section"]');
    await expect(page.locator('[data-testid="upload-section-header"]')).toBeVisible();

    // Select and upload the test CSV file containing duplicate attendance records
    const duplicateCSVPath = path.join(__dirname, 'test-data', 'duplicate-attendance-records.csv');
    const fileInput = page.locator('[data-testid="file-upload-input"]');
    await fileInput.setInputFiles(duplicateCSVPath);

    // Verify file is selected
    await expect(page.locator('[data-testid="selected-file-name"]')).toContainText('duplicate-attendance-records.csv');

    // Click upload button
    await page.click('[data-testid="upload-button"]');

    // Wait for system to complete validation and ingestion process
    await expect(page.locator('[data-testid="upload-progress"]')).toBeVisible();
    await page.waitForSelector('[data-testid="upload-complete-message"]', { timeout: 30000 });

    // Verify that system identifies and flags duplicate records during ingestion
    await expect(page.locator('[data-testid="duplicate-detection-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="duplicate-detection-alert"]')).toContainText('duplicate');

    // Check system logs for conflict detection entries
    await page.click('[data-testid="view-logs-button"]');
    await expect(page.locator('[data-testid="system-logs-modal"]')).toBeVisible();
    
    const conflictLogEntry = page.locator('[data-testid="log-entry"]').filter({ hasText: 'Conflict detected' });
    await expect(conflictLogEntry).toBeVisible();
    
    // Close logs modal
    await page.click('[data-testid="close-logs-modal"]');

    // Navigate to the admin monitoring interface to view flagged conflicts
    await page.click('[data-testid="monitoring-menu"]');
    await page.click('[data-testid="conflict-monitoring"]');

    // Review the conflict details displayed in the monitoring interface
    await expect(page.locator('[data-testid="conflicts-table"]')).toBeVisible();
    
    const conflictRow = page.locator('[data-testid="conflict-row"]').first();
    await expect(conflictRow).toBeVisible();

    // Verify that conflicts are presented in a user-friendly format
    await expect(conflictRow.locator('[data-testid="employee-id"]')).toBeVisible();
    await expect(conflictRow.locator('[data-testid="conflict-date"]')).toBeVisible();
    await expect(conflictRow.locator('[data-testid="conflict-type"]')).toContainText('Duplicate');

    // Click on conflict row to view details
    await conflictRow.click();
    
    // Verify conflict details panel opens
    await expect(page.locator('[data-testid="conflict-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="existing-record-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="new-record-details"]')).toBeVisible();

    // Select a flagged conflict and choose resolution option
    await page.click('[data-testid="resolution-dropdown"]');
    await page.click('[data-testid="resolution-option-keep-existing"]');

    // Verify resolution option is selected
    await expect(page.locator('[data-testid="selected-resolution"]')).toContainText('Keep Existing');

    // Apply the selected resolution to resolve the conflict
    await page.click('[data-testid="apply-resolution-button"]');
    
    // Wait for confirmation message
    await expect(page.locator('[data-testid="resolution-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="resolution-success-message"]')).toContainText('Resolution applied successfully');

    // Trigger reprocessing of the resolved conflicts
    await page.click('[data-testid="reprocess-button"]');
    
    // Wait for reprocessing to complete
    await expect(page.locator('[data-testid="reprocessing-progress"]')).toBeVisible();
    await expect(page.locator('[data-testid="reprocessing-complete-message"]')).toBeVisible({ timeout: 30000 });

    // Verify that attendance records are updated in the database
    await page.click('[data-testid="attendance-records-menu"]');
    await page.click('[data-testid="view-all-records"]');
    
    // Search for the resolved record
    const searchInput = page.locator('[data-testid="search-records-input"]');
    await searchInput.fill('EMP001'); // Example employee ID from test data
    await page.click('[data-testid="search-button"]');
    
    // Verify record exists and is not duplicated
    const searchResults = page.locator('[data-testid="attendance-records-table"] [data-testid="record-row"]');
    const resultCount = await searchResults.count();
    expect(resultCount).toBe(1); // Should only have one record after resolution

    // Navigate back to conflict monitoring
    await page.click('[data-testid="monitoring-menu"]');
    await page.click('[data-testid="conflict-monitoring"]');

    // Check that resolved conflicts are marked as completed
    const resolvedConflict = page.locator('[data-testid="conflict-row"]').filter({ hasText: 'EMP001' });
    const statusBadge = resolvedConflict.locator('[data-testid="conflict-status-badge"]');
    await expect(statusBadge).toContainText('Resolved');
    
    // Verify resolved timestamp is displayed
    await expect(resolvedConflict.locator('[data-testid="resolved-timestamp"]')).toBeVisible();
  });
});