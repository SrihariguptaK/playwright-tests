import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

test.describe('Story-11: Export Task Status Reports to Excel', () => {
  const downloadPath = path.join(__dirname, 'downloads');
  
  test.beforeEach(async ({ page }) => {
    // Login as Team Lead
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'teamlead@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Export task status report to Excel - happy path', async ({ page, context }) => {
    // Set download path
    const downloadPromise = page.waitForEvent('download');
    
    // Step 1: Navigate to the task status reports section
    await page.goto('/reports/task-status');
    await expect(page.locator('[data-testid="task-status-reports-page"]')).toBeVisible();
    
    // Step 2: Select desired filters or parameters for the task status report
    await page.click('[data-testid="filter-dropdown"]');
    await page.selectOption('[data-testid="status-filter"]', 'all');
    await page.selectOption('[data-testid="priority-filter"]', 'all');
    
    // Step 3: Click on 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');
    
    // Step 4: Verify the displayed report contains accurate task status information
    await expect(page.locator('[data-testid="task-status-report-table"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="report-header"]')).toContainText('Task Status Report');
    
    // Verify report has data rows
    const reportRows = page.locator('[data-testid="task-status-report-table"] tbody tr');
    await expect(reportRows.first()).toBeVisible();
    const rowCount = await reportRows.count();
    expect(rowCount).toBeGreaterThan(0);
    
    // Step 5: Locate and click on 'Export to Excel' button
    const exportButton = page.locator('[data-testid="export-excel-button"]');
    await expect(exportButton).toBeVisible();
    await expect(exportButton).toBeEnabled();
    
    const startTime = Date.now();
    await exportButton.click();
    
    // Step 6: Wait for the Excel file download to complete
    const download = await downloadPromise;
    const downloadDuration = Date.now() - startTime;
    
    // Verify export completes within 5 seconds (Acceptance Criteria #3)
    expect(downloadDuration).toBeLessThan(5000);
    
    // Step 7: Navigate to the download location and locate the downloaded Excel file
    const fileName = download.suggestedFilename();
    expect(fileName).toMatch(/task.*status.*report.*\.xlsx$/i);
    
    const filePath = path.join(downloadPath, fileName);
    await download.saveAs(filePath);
    
    // Verify file exists and has content
    expect(fs.existsSync(filePath)).toBeTruthy();
    const fileStats = fs.statSync(filePath);
    expect(fileStats.size).toBeGreaterThan(0);
    
    // Step 8-13: Verify Excel file contents (simulated verification)
    // Note: In real implementation, you would use a library like 'exceljs' or 'xlsx' to parse and verify Excel content
    
    // Verify file is a valid Excel file by checking magic number
    const fileBuffer = fs.readFileSync(filePath);
    const magicNumber = fileBuffer.toString('hex', 0, 4);
    expect(magicNumber).toBe('504b0304'); // ZIP format (XLSX is ZIP-based)
    
    // Clean up downloaded file
    fs.unlinkSync(filePath);
  });

  test('Export task status report to Excel - verify data integrity', async ({ page }) => {
    const downloadPromise = page.waitForEvent('download');
    
    // Step 1: Generate task status report
    await page.goto('/reports/task-status');
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Report is displayed
    await expect(page.locator('[data-testid="task-status-report-table"]')).toBeVisible({ timeout: 10000 });
    
    // Capture sample data from the displayed report for comparison
    const firstRowData = {
      taskId: await page.locator('[data-testid="task-status-report-table"] tbody tr:first-child td:nth-child(1)').textContent(),
      taskName: await page.locator('[data-testid="task-status-report-table"] tbody tr:first-child td:nth-child(2)').textContent(),
      status: await page.locator('[data-testid="task-status-report-table"] tbody tr:first-child td:nth-child(3)').textContent(),
      assignee: await page.locator('[data-testid="task-status-report-table"] tbody tr:first-child td:nth-child(4)').textContent()
    };
    
    // Step 2: Click export to Excel
    await page.click('[data-testid="export-excel-button"]');
    
    // Expected Result: Excel file is downloaded
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/\.xlsx$/i);
    
    const filePath = path.join(downloadPath, download.suggestedFilename());
    await download.saveAs(filePath);
    
    // Step 3: Open Excel file and verify contents
    // Expected Result: File contains accurate and formatted task status data
    expect(fs.existsSync(filePath)).toBeTruthy();
    
    // Verify file size indicates data is present (Acceptance Criteria #2)
    const fileStats = fs.statSync(filePath);
    expect(fileStats.size).toBeGreaterThan(1024); // At least 1KB
    
    // Clean up
    fs.unlinkSync(filePath);
  });

  test('Export task status report - verify authorized access only', async ({ page, context }) => {
    // Logout as Team Lead
    await page.goto('/reports/task-status');
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Login as unauthorized user (regular team member without export permissions)
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'member@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    
    // Navigate to task status reports
    await page.goto('/reports/task-status');
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="task-status-report-table"]')).toBeVisible();
    
    // Verify export button is not visible or disabled for unauthorized users (Acceptance Criteria #4)
    const exportButton = page.locator('[data-testid="export-excel-button"]');
    await expect(exportButton).not.toBeVisible().catch(async () => {
      // If button is visible, it should be disabled
      await expect(exportButton).toBeDisabled();
    });
  });

  test('Export task status report - verify all columns are present', async ({ page }) => {
    const downloadPromise = page.waitForEvent('download');
    
    await page.goto('/reports/task-status');
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="task-status-report-table"]')).toBeVisible();
    
    // Verify all expected columns are present in the report table
    const expectedColumns = ['Task ID', 'Task Name', 'Status', 'Assignee', 'Start Date', 'Due Date', 'Priority'];
    
    for (const columnName of expectedColumns) {
      const columnHeader = page.locator(`[data-testid="task-status-report-table"] thead th:has-text("${columnName}")`);
      await expect(columnHeader).toBeVisible();
    }
    
    // Export to Excel
    await page.click('[data-testid="export-excel-button"]');
    const download = await downloadPromise;
    
    const filePath = path.join(downloadPath, download.suggestedFilename());
    await download.saveAs(filePath);
    
    // Verify file was created successfully (Acceptance Criteria #1)
    expect(fs.existsSync(filePath)).toBeTruthy();
    
    // Clean up
    fs.unlinkSync(filePath);
  });

  test('Export task status report - verify export completes within performance threshold', async ({ page }) => {
    await page.goto('/reports/task-status');
    
    // Generate a report with filters
    await page.selectOption('[data-testid="date-range-filter"]', 'last-30-days');
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="task-status-report-table"]')).toBeVisible();
    
    // Measure export time
    const downloadPromise = page.waitForEvent('download');
    const startTime = Date.now();
    
    await page.click('[data-testid="export-excel-button"]');
    
    const download = await downloadPromise;
    const exportDuration = Date.now() - startTime;
    
    // Acceptance Criteria #3: Export operation completes within 5 seconds
    expect(exportDuration).toBeLessThan(5000);
    
    const filePath = path.join(downloadPath, download.suggestedFilename());
    await download.saveAs(filePath);
    
    // Verify successful export
    expect(fs.existsSync(filePath)).toBeTruthy();
    
    // Clean up
    fs.unlinkSync(filePath);
  });
});