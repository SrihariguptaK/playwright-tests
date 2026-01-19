import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

test.describe('Performance Report PDF Export', () => {
  let downloadPath: string;

  test.beforeEach(async ({ page }) => {
    // Login as Department Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'department.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Export performance report to PDF', async ({ page }) => {
    // Step 1: Generate performance report
    await page.click('[data-testid="performance-reports-link"]');
    await expect(page.locator('[data-testid="performance-report-page"]')).toBeVisible();
    
    // Select date range and filters
    await page.click('[data-testid="date-range-selector"]');
    await page.click('[data-testid="last-30-days-option"]');
    
    // Click Generate Report button
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Report is displayed
    await expect(page.locator('[data-testid="performance-report-container"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="report-metrics"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-charts"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-data-table"]')).toBeVisible();
    
    // Step 2: Click export to PDF
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-to-pdf-button"]');
    
    // Expected Result: PDF file is downloaded
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.pdf');
    
    // Save the downloaded file
    downloadPath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(downloadPath);
    
    // Verify download completed within 5 seconds
    const downloadStartTime = Date.now();
    await download.path();
    const downloadDuration = Date.now() - downloadStartTime;
    expect(downloadDuration).toBeLessThan(5000);
    
    // Step 3: Verify PDF file exists and has content
    expect(fs.existsSync(downloadPath)).toBeTruthy();
    const fileStats = fs.statSync(downloadPath);
    expect(fileStats.size).toBeGreaterThan(0);
  });

  test('Export performance report to PDF - happy path with full verification', async ({ page }) => {
    // Navigate to the performance reports section from the main dashboard
    await page.click('[data-testid="performance-reports-link"]');
    await expect(page).toHaveURL(/.*performance-reports/);
    
    // Select the desired date range and filters for the performance report
    await page.click('[data-testid="date-range-selector"]');
    await page.click('text=Last 30 Days');
    
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-sales-option"]');
    
    // Click the 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');
    
    // Verify that the report contains expected data including metrics, graphs, and tables
    await expect(page.locator('[data-testid="performance-report-container"]')).toBeVisible({ timeout: 10000 });
    
    // Verify metrics are present
    await expect(page.locator('[data-testid="metric-total-revenue"]')).toBeVisible();
    await expect(page.locator('[data-testid="metric-total-sales"]')).toBeVisible();
    await expect(page.locator('[data-testid="metric-average-performance"]')).toBeVisible();
    
    // Verify graphs/charts are rendered
    await expect(page.locator('[data-testid="performance-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="trend-chart"]')).toBeVisible();
    
    // Verify data table is present
    await expect(page.locator('[data-testid="report-data-table"]')).toBeVisible();
    const tableRows = page.locator('[data-testid="report-data-table"] tbody tr');
    await expect(tableRows).toHaveCount(await tableRows.count());
    expect(await tableRows.count()).toBeGreaterThan(0);
    
    // Locate and click the 'Export to PDF' button
    const exportButton = page.locator('[data-testid="export-to-pdf-button"]');
    await expect(exportButton).toBeVisible();
    await expect(exportButton).toBeEnabled();
    
    // Wait for the PDF export to complete
    const downloadPromise = page.waitForEvent('download');
    const exportStartTime = Date.now();
    await exportButton.click();
    
    // Verify export initiated notification
    await expect(page.locator('[data-testid="export-notification"]')).toBeVisible({ timeout: 2000 });
    
    const download = await downloadPromise;
    const exportDuration = Date.now() - exportStartTime;
    
    // Verify export completes within 5 seconds
    expect(exportDuration).toBeLessThan(5000);
    
    // Navigate to the download location and locate the downloaded PDF file
    const fileName = download.suggestedFilename();
    expect(fileName).toMatch(/performance.*report.*\.pdf/i);
    
    downloadPath = path.join(__dirname, 'downloads', fileName);
    await download.saveAs(downloadPath);
    
    // Verify the file was downloaded successfully
    expect(fs.existsSync(downloadPath)).toBeTruthy();
    
    // Verify file size is reasonable (greater than 10KB)
    const fileStats = fs.statSync(downloadPath);
    expect(fileStats.size).toBeGreaterThan(10240);
    
    // Verify PDF file signature (PDF files start with %PDF)
    const fileBuffer = fs.readFileSync(downloadPath);
    const pdfSignature = fileBuffer.toString('utf-8', 0, 4);
    expect(pdfSignature).toBe('%PDF');
    
    // Verify success notification
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('PDF exported successfully');
  });

  test('Verify PDF export restricted to authorized users', async ({ page }) => {
    // Logout current user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Login as unauthorized user (non-department manager)
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'regular.user@company.com');
    await page.fill('[data-testid="password-input"]', 'UserPass123');
    await page.click('[data-testid="login-button"]');
    
    // Attempt to navigate to performance reports
    await page.goto('/performance-reports');
    
    // Verify access is denied or export button is not available
    const accessDenied = page.locator('[data-testid="access-denied-message"]');
    const exportButton = page.locator('[data-testid="export-to-pdf-button"]');
    
    // Either access denied message is shown or export button is hidden/disabled
    const isAccessDenied = await accessDenied.isVisible().catch(() => false);
    const isExportButtonVisible = await exportButton.isVisible().catch(() => false);
    
    if (isAccessDenied) {
      await expect(accessDenied).toContainText(/unauthorized|access denied|permission/i);
    } else if (isExportButtonVisible) {
      await expect(exportButton).toBeDisabled();
    } else {
      // Export button should not be visible for unauthorized users
      await expect(exportButton).not.toBeVisible();
    }
  });

  test('Verify exported PDF maintains formatting and visualizations', async ({ page }) => {
    // Navigate to performance reports
    await page.click('[data-testid="performance-reports-link"]');
    
    // Generate report with specific data
    await page.click('[data-testid="date-range-selector"]');
    await page.click('[data-testid="last-quarter-option"]');
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report to load
    await expect(page.locator('[data-testid="performance-report-container"]')).toBeVisible({ timeout: 10000 });
    
    // Capture report title for verification
    const reportTitle = await page.locator('[data-testid="report-title"]').textContent();
    
    // Verify charts are rendered before export
    await expect(page.locator('[data-testid="performance-chart"]')).toBeVisible();
    const chartCount = await page.locator('[data-testid="report-charts"] canvas').count();
    expect(chartCount).toBeGreaterThan(0);
    
    // Export to PDF
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-to-pdf-button"]');
    const download = await downloadPromise;
    
    // Save and verify PDF
    downloadPath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(downloadPath);
    
    // Verify PDF file properties
    expect(fs.existsSync(downloadPath)).toBeTruthy();
    const fileStats = fs.statSync(downloadPath);
    
    // PDF with charts and formatting should be substantial in size
    expect(fileStats.size).toBeGreaterThan(50000);
    
    // Verify PDF header
    const fileBuffer = fs.readFileSync(downloadPath);
    expect(fileBuffer.toString('utf-8', 0, 4)).toBe('%PDF');
  });

  test.afterEach(async ({}, testInfo) => {
    // Cleanup downloaded files after each test
    if (downloadPath && fs.existsSync(downloadPath)) {
      try {
        fs.unlinkSync(downloadPath);
      } catch (error) {
        console.log(`Failed to cleanup file: ${downloadPath}`);
      }
    }
  });
});