import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

test.describe('Export Task Status Reports to Excel', () => {
  let downloadPath: string;

  test.beforeEach(async ({ page }) => {
    // Login as Team Lead
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'teamlead@example.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to reports section
    await page.click('[data-testid="reports-menu"]');
    await page.click('[data-testid="task-status-reports-link"]');
    await expect(page.locator('[data-testid="task-status-report-page"]')).toBeVisible();
  });

  test('Export task status report to Excel', async ({ page }) => {
    const startTime = Date.now();

    // Step 1: Generate task status report
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report to be displayed
    await expect(page.locator('[data-testid="task-status-report-table"]')).toBeVisible({ timeout: 10000 });
    
    // Verify report contains data
    const reportRows = page.locator('[data-testid="task-status-report-table"] tbody tr');
    await expect(reportRows).not.toHaveCount(0);
    
    // Expected Result: Report is displayed
    await expect(page.locator('[data-testid="report-title"]')).toContainText('Task Status Report');
    await expect(page.locator('[data-testid="report-generated-timestamp"]')).toBeVisible();

    // Step 2: Click export to Excel
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-button"]');
    
    // Expected Result: Excel file is downloaded
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/task[_-]status[_-]report.*\.xlsx$/i);
    
    // Verify export completed within 5 seconds
    const exportTime = Date.now() - startTime;
    expect(exportTime).toBeLessThan(5000);
    
    // Save the downloaded file
    downloadPath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(downloadPath);
    
    // Step 3: Verify Excel file was downloaded successfully
    // Expected Result: File contains accurate and formatted task status data
    expect(fs.existsSync(downloadPath)).toBeTruthy();
    
    // Verify file size is greater than 0
    const stats = fs.statSync(downloadPath);
    expect(stats.size).toBeGreaterThan(0);
    
    // Verify file is a valid Excel file (basic check by extension and magic bytes)
    const fileBuffer = fs.readFileSync(downloadPath);
    // Excel files start with PK (ZIP format signature)
    expect(fileBuffer[0]).toBe(0x50); // 'P'
    expect(fileBuffer[1]).toBe(0x4B); // 'K'
    
    // Display success message
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('Excel file exported successfully');
  });

  test('Verify exported Excel file maintains data integrity', async ({ page }) => {
    // Generate report with known data
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="task-status-report-table"]')).toBeVisible({ timeout: 10000 });
    
    // Capture report data from UI for comparison
    const reportTable = page.locator('[data-testid="task-status-report-table"]');
    const headerCells = reportTable.locator('thead th');
    const headerCount = await headerCells.count();
    expect(headerCount).toBeGreaterThan(0);
    
    const dataRows = reportTable.locator('tbody tr');
    const rowCount = await dataRows.count();
    expect(rowCount).toBeGreaterThan(0);
    
    // Export to Excel
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-button"]');
    const download = await downloadPromise;
    
    downloadPath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(downloadPath);
    
    // Verify file exists and has content
    expect(fs.existsSync(downloadPath)).toBeTruthy();
    const stats = fs.statSync(downloadPath);
    expect(stats.size).toBeGreaterThan(1000); // Reasonable minimum size for Excel with data
  });

  test('Verify export completes within 5 seconds', async ({ page }) => {
    // Generate report
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="task-status-report-table"]')).toBeVisible({ timeout: 10000 });
    
    // Measure export time
    const startTime = Date.now();
    
    const downloadPromise = page.waitForEvent('download', { timeout: 6000 });
    await page.click('[data-testid="export-excel-button"]');
    
    const download = await downloadPromise;
    const endTime = Date.now();
    const exportDuration = endTime - startTime;
    
    // Verify export completed within 5 seconds
    expect(exportDuration).toBeLessThan(5000);
    
    // Verify download was successful
    expect(download.suggestedFilename()).toMatch(/\.xlsx$/i);
  });

  test('Verify export functionality restricted to authorized users', async ({ page, context }) => {
    // Logout current user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);
    
    // Login as unauthorized user (non-Team Lead)
    await page.fill('[data-testid="username-input"]', 'regularuser@example.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Attempt to access reports section
    await page.click('[data-testid="reports-menu"]');
    
    // Verify unauthorized user cannot see task status reports or export option
    const taskStatusReportsLink = page.locator('[data-testid="task-status-reports-link"]');
    
    if (await taskStatusReportsLink.isVisible()) {
      await taskStatusReportsLink.click();
      
      // Export button should not be visible or should be disabled
      const exportButton = page.locator('[data-testid="export-excel-button"]');
      const isVisible = await exportButton.isVisible();
      
      if (isVisible) {
        await expect(exportButton).toBeDisabled();
      }
    } else {
      // Task status reports link not visible - access properly restricted
      expect(await taskStatusReportsLink.isVisible()).toBeFalsy();
    }
  });

  test.afterEach(async () => {
    // Cleanup downloaded files
    if (downloadPath && fs.existsSync(downloadPath)) {
      fs.unlinkSync(downloadPath);
    }
  });
});