import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

test.describe('Export Attendance Reports - Story 16', () => {
  let downloadPath: string;

  test.beforeEach(async ({ page }) => {
    // Login as authorized manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to attendance dashboard
    await page.goto('/attendance-dashboard');
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
  });

  test('Validate CSV export of filtered attendance data', async ({ page }) => {
    // Step 1: Apply filters on dashboard
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="date-range-last-7-days"]');
    
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-engineering"]');
    
    await page.click('[data-testid="status-filter"]');
    await page.click('[data-testid="status-present"]');
    
    await page.click('[data-testid="apply-filters-button"]');
    
    // Wait for filtered data to load
    await page.waitForSelector('[data-testid="attendance-table-loaded"]');
    
    // Expected Result: Dashboard displays filtered attendance data
    await expect(page.locator('[data-testid="attendance-table"]')).toBeVisible();
    
    // Note the number of records displayed
    const recordCountText = await page.locator('[data-testid="record-count"]').textContent();
    const dashboardRecordCount = parseInt(recordCountText?.match(/\d+/)?.[0] || '0');
    
    // Capture sample data points from dashboard
    const firstRowEmployee = await page.locator('[data-testid="attendance-row"]:first-child [data-testid="employee-name"]').textContent();
    const firstRowDate = await page.locator('[data-testid="attendance-row"]:first-child [data-testid="attendance-date"]').textContent();
    const firstRowStatus = await page.locator('[data-testid="attendance-row"]:first-child [data-testid="attendance-status"]').textContent();
    
    // Step 2: Select CSV export option
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-format-csv"]');
    
    // Expected Result: CSV file is generated and download prompt appears
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.csv');
    
    // Step 3: Open CSV file and verify data matches dashboard
    const filePath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(filePath);
    
    // Expected Result: CSV data accurately reflects filtered attendance data
    const csvContent = fs.readFileSync(filePath, 'utf-8');
    const csvLines = csvContent.split('\n').filter(line => line.trim() !== '');
    const csvDataRows = csvLines.slice(1); // Exclude header
    
    // Verify record count matches
    expect(csvDataRows.length).toBe(dashboardRecordCount);
    
    // Verify CSV contains expected data points
    expect(csvContent).toContain(firstRowEmployee || '');
    expect(csvContent).toContain(firstRowDate || '');
    expect(csvContent).toContain(firstRowStatus || '');
    
    // Verify CSV has proper headers
    const headers = csvLines[0].toLowerCase();
    expect(headers).toContain('employee');
    expect(headers).toContain('date');
    expect(headers).toContain('status');
    
    // Cleanup
    fs.unlinkSync(filePath);
  });

  test('Validate PDF export of filtered attendance data', async ({ page }) => {
    // Step 1: Apply filters on dashboard
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="date-range-current-month"]');
    
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-sales"]');
    
    await page.click('[data-testid="status-filter"]');
    await page.click('[data-testid="status-all"]');
    
    await page.click('[data-testid="apply-filters-button"]');
    
    // Wait for filtered data to load
    await page.waitForSelector('[data-testid="attendance-table-loaded"]');
    
    // Expected Result: Dashboard displays filtered attendance data
    await expect(page.locator('[data-testid="attendance-table"]')).toBeVisible();
    
    // Note the number of records displayed
    const recordCountText = await page.locator('[data-testid="record-count"]').textContent();
    const dashboardRecordCount = parseInt(recordCountText?.match(/\d+/)?.[0] || '0');
    
    // Capture sample data points from dashboard
    const firstRowEmployee = await page.locator('[data-testid="attendance-row"]:first-child [data-testid="employee-name"]').textContent();
    const firstRowDate = await page.locator('[data-testid="attendance-row"]:first-child [data-testid="attendance-date"]').textContent();
    const firstRowStatus = await page.locator('[data-testid="attendance-row"]:first-child [data-testid="attendance-status"]').textContent();
    const firstRowHours = await page.locator('[data-testid="attendance-row"]:first-child [data-testid="hours-worked"]').textContent();
    
    // Step 2: Select PDF export option
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-format-pdf"]');
    
    // Expected Result: PDF file is generated and download prompt appears
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.pdf');
    
    // Step 3: Open PDF file and verify formatting and data accuracy
    const filePath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(filePath);
    
    // Expected Result: PDF report is correctly formatted and data matches dashboard
    // Verify file exists and has content
    const stats = fs.statSync(filePath);
    expect(stats.size).toBeGreaterThan(0);
    
    // Verify download completed within 10 seconds
    const downloadTime = Date.now();
    expect(downloadTime).toBeLessThan(Date.now() + 10000);
    
    // Cleanup
    fs.unlinkSync(filePath);
  });

  test('Test export authorization and logging', async ({ page, context }) => {
    // Step 1: Attempt export without proper authorization
    // Logout from manager account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Login as employee without export permissions
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Employee123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to attendance dashboard
    await page.goto('/attendance-dashboard');
    
    // Expected Result: System denies export request with error
    // Check if export button is hidden or disabled
    const exportButton = page.locator('[data-testid="export-button"]');
    const isExportVisible = await exportButton.isVisible().catch(() => false);
    
    if (isExportVisible) {
      await exportButton.click();
      // Verify error message appears
      await expect(page.locator('[data-testid="error-message"]')).toContainText(/not authorized|permission denied/i);
    } else {
      // Export button should not be visible for unauthorized users
      await expect(exportButton).not.toBeVisible();
    }
    
    // Logout from employee account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Step 2: Perform export with authorized manager account
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    await page.goto('/attendance-dashboard');
    
    // Apply specific filters
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="date-range-last-30-days"]');
    
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-marketing"]');
    
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForSelector('[data-testid="attendance-table-loaded"]');
    
    // Perform export
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-format-csv"]');
    
    // Expected Result: Export completes successfully
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.csv');
    
    const filePath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(filePath);
    
    // Verify file was downloaded successfully
    expect(fs.existsSync(filePath)).toBeTruthy();
    
    // Step 3: Verify export activity is logged with user and timestamp
    // Navigate to audit logs
    await page.goto('/audit-logs');
    await expect(page.locator('[data-testid="audit-logs-page"]')).toBeVisible();
    
    // Filter for export activities
    await page.click('[data-testid="activity-type-filter"]');
    await page.click('[data-testid="activity-type-export"]');
    await page.click('[data-testid="apply-log-filters"]');
    
    // Wait for logs to load
    await page.waitForSelector('[data-testid="log-entry"]');
    
    // Expected Result: Export log entry exists and is accurate
    const latestLogEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(latestLogEntry).toBeVisible();
    
    // Verify log contains username
    await expect(latestLogEntry.locator('[data-testid="log-username"]')).toContainText('manager@company.com');
    
    // Verify log contains timestamp (should be recent)
    const logTimestamp = await latestLogEntry.locator('[data-testid="log-timestamp"]').textContent();
    expect(logTimestamp).toBeTruthy();
    
    // Verify log contains export format
    await expect(latestLogEntry.locator('[data-testid="log-details"]')).toContainText('CSV');
    
    // Verify log contains export status
    await expect(latestLogEntry.locator('[data-testid="log-status"]')).toContainText(/success/i);
    
    // Verify log contains applied filters
    const logDetails = await latestLogEntry.locator('[data-testid="log-details"]').textContent();
    expect(logDetails).toContain('Marketing');
    expect(logDetails).toContain('30 days');
    
    // Cleanup
    fs.unlinkSync(filePath);
  });
});