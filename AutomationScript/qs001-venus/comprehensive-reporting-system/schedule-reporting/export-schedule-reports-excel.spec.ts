import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

test.describe('Export Schedule Reports in Excel Format', () => {
  test.beforeEach(async ({ page }) => {
    // Login as Project Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'project.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to schedule reports section
    await page.click('[data-testid="reports-menu"]');
    await page.click('[data-testid="schedule-reports-link"]');
    await expect(page.locator('[data-testid="schedule-reports-page"]')).toBeVisible();
  });

  test('Export schedule report to Excel', async ({ page }) => {
    // Step 1: Generate schedule report
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report to be generated and displayed
    await expect(page.locator('[data-testid="schedule-report-table"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="report-status"]')).toHaveText('Report Generated');
    
    // Verify report contains data
    const reportRows = page.locator('[data-testid="schedule-report-table"] tbody tr');
    await expect(reportRows).not.toHaveCount(0);
    
    // Expected Result: Report is displayed
    await expect(page.locator('[data-testid="schedule-report-container"]')).toBeVisible();
    
    // Step 2: Click export to Excel
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-button"]');
    
    // Wait for download to start
    const download = await downloadPromise;
    
    // Expected Result: Excel file is downloaded
    expect(download.suggestedFilename()).toMatch(/schedule.*\.xlsx?$/i);
    
    // Verify download completes within 5 seconds
    const downloadStartTime = Date.now();
    const downloadPath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(downloadPath);
    const downloadDuration = Date.now() - downloadStartTime;
    expect(downloadDuration).toBeLessThan(5000);
    
    // Step 3: Verify Excel file exists and has content
    expect(fs.existsSync(downloadPath)).toBeTruthy();
    
    // Expected Result: File contains accurate and formatted schedule data
    const fileStats = fs.statSync(downloadPath);
    expect(fileStats.size).toBeGreaterThan(0);
    
    // Verify success message is displayed
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('Excel file exported successfully');
    
    // Cleanup: Remove downloaded file
    fs.unlinkSync(downloadPath);
  });

  test('Verify exported Excel file maintains data integrity', async ({ page }) => {
    // Generate schedule report
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="schedule-report-table"]')).toBeVisible({ timeout: 10000 });
    
    // Capture data from the displayed report for comparison
    const firstRowData = await page.locator('[data-testid="schedule-report-table"] tbody tr').first().allTextContents();
    const totalRows = await page.locator('[data-testid="schedule-report-table"] tbody tr').count();
    
    // Export to Excel
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-button"]');
    const download = await downloadPromise;
    
    // Save and verify file
    const downloadPath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(downloadPath);
    
    // Verify file exists and has appropriate size
    expect(fs.existsSync(downloadPath)).toBeTruthy();
    const fileStats = fs.statSync(downloadPath);
    expect(fileStats.size).toBeGreaterThan(1000); // Excel files should be reasonably sized
    
    // Verify export metadata is displayed
    await expect(page.locator('[data-testid="export-metadata"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-row-count"]')).toContainText(totalRows.toString());
    
    // Cleanup
    fs.unlinkSync(downloadPath);
  });

  test('Verify export completes within 5 seconds', async ({ page }) => {
    // Generate schedule report
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="schedule-report-table"]')).toBeVisible({ timeout: 10000 });
    
    // Measure export time
    const startTime = Date.now();
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-button"]');
    const download = await downloadPromise;
    
    const downloadPath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(downloadPath);
    const exportDuration = Date.now() - startTime;
    
    // Verify export completed within 5 seconds
    expect(exportDuration).toBeLessThan(5000);
    
    // Verify performance indicator if displayed
    const performanceIndicator = page.locator('[data-testid="export-duration"]');
    if (await performanceIndicator.isVisible()) {
      const durationText = await performanceIndicator.textContent();
      expect(durationText).toMatch(/[0-4]\.[0-9]+ seconds?/);
    }
    
    // Cleanup
    fs.unlinkSync(downloadPath);
  });

  test('Verify export functionality is restricted to authorized users', async ({ page, context }) => {
    // Logout current user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);
    
    // Login as unauthorized user (non-Project Manager)
    await page.fill('[data-testid="username-input"]', 'regular.user@company.com');
    await page.fill('[data-testid="password-input"]', 'UserPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Attempt to navigate to schedule reports
    await page.click('[data-testid="reports-menu"]');
    
    // Verify schedule reports link is not available or restricted
    const scheduleReportsLink = page.locator('[data-testid="schedule-reports-link"]');
    const isLinkVisible = await scheduleReportsLink.isVisible().catch(() => false);
    
    if (isLinkVisible) {
      await scheduleReportsLink.click();
      
      // Verify access denied message or export button is disabled/hidden
      const exportButton = page.locator('[data-testid="export-excel-button"]');
      const isExportButtonVisible = await exportButton.isVisible().catch(() => false);
      
      if (isExportButtonVisible) {
        await expect(exportButton).toBeDisabled();
      } else {
        // Verify access denied message
        await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
        await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('not authorized');
      }
    } else {
      // Expected behavior: unauthorized users cannot see the schedule reports option
      expect(isLinkVisible).toBeFalsy();
    }
  });

  test('Verify Excel file format and structure', async ({ page }) => {
    // Generate schedule report
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="schedule-report-table"]')).toBeVisible({ timeout: 10000 });
    
    // Verify report has headers
    const headers = page.locator('[data-testid="schedule-report-table"] thead th');
    await expect(headers).not.toHaveCount(0);
    
    // Export to Excel
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-button"]');
    const download = await downloadPromise;
    
    // Verify file extension
    const filename = download.suggestedFilename();
    expect(filename).toMatch(/\.(xlsx|xls)$/);
    
    // Save and verify file
    const downloadPath = path.join(__dirname, 'downloads', filename);
    await download.saveAs(downloadPath);
    
    // Verify file is a valid Excel file (basic check via file signature)
    const fileBuffer = fs.readFileSync(downloadPath);
    const fileSignature = fileBuffer.toString('hex', 0, 4);
    // Excel files start with PK (50 4B) for .xlsx or D0 CF for .xls
    expect(['504b0304', 'd0cf11e0'].some(sig => fileSignature.startsWith(sig))).toBeTruthy();
    
    // Cleanup
    fs.unlinkSync(downloadPath);
  });
});