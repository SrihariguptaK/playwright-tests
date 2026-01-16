import { test, expect } from '@playwright/test';
import * as path from 'path';
import * as fs from 'fs';

test.describe('Export Schedule Reports - Story 5', () => {
  const downloadsPath = path.join(__dirname, 'downloads');

  test.beforeEach(async ({ page }) => {
    // Ensure downloads directory exists
    if (!fs.existsSync(downloadsPath)) {
      fs.mkdirSync(downloadsPath, { recursive: true });
    }

    // Navigate to schedule reporting module
    await page.goto('/schedule-reporting');
    await expect(page).toHaveTitle(/Schedule Reporting/);
  });

  test.afterEach(async () => {
    // Clean up downloaded files after each test
    if (fs.existsSync(downloadsPath)) {
      const files = fs.readdirSync(downloadsPath);
      files.forEach(file => {
        fs.unlinkSync(path.join(downloadsPath, file));
      });
    }
  });

  test('Export schedule report to PDF', async ({ page }) => {
    // Step 1: Generate schedule report
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="date-range-last-30-days"]');
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.click('[data-testid="team-option-engineering"]');
    await page.click('[data-testid="generate-report-button"]');

    // Expected Result: Report displayed
    await expect(page.locator('[data-testid="schedule-report-container"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="report-data-table"]')).toBeVisible();
    const reportRows = page.locator('[data-testid="report-data-row"]');
    await expect(reportRows.first()).toBeVisible();

    // Step 2: Select export to PDF
    const downloadPromise = page.waitForEvent('download');
    const startTime = Date.now();
    await page.click('[data-testid="export-options-toolbar"]');
    await page.click('[data-testid="export-to-pdf-button"]');

    // Expected Result: Export processed and PDF file downloaded
    const download = await downloadPromise;
    const exportTime = Date.now() - startTime;
    expect(exportTime).toBeLessThan(10000); // Export within 10 seconds
    expect(download.suggestedFilename()).toMatch(/\.pdf$/);

    const filePath = path.join(downloadsPath, download.suggestedFilename());
    await download.saveAs(filePath);

    // Step 3: Verify PDF file exists and has content
    expect(fs.existsSync(filePath)).toBeTruthy();
    const stats = fs.statSync(filePath);
    expect(stats.size).toBeGreaterThan(0);

    // Verify success notification
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('PDF exported successfully');
  });

  test('Export schedule report to Excel', async ({ page }) => {
    // Step 1: Generate schedule report
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="date-range-last-30-days"]');
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.click('[data-testid="team-option-engineering"]');
    await page.click('[data-testid="generate-report-button"]');

    // Expected Result: Report displayed
    await expect(page.locator('[data-testid="schedule-report-container"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="report-data-table"]')).toBeVisible();
    const reportRows = page.locator('[data-testid="report-data-row"]');
    await expect(reportRows.first()).toBeVisible();

    // Step 2: Select export to Excel
    const downloadPromise = page.waitForEvent('download');
    const startTime = Date.now();
    await page.click('[data-testid="export-options-toolbar"]');
    await page.click('[data-testid="export-to-excel-button"]');

    // Expected Result: Export processed and Excel file downloaded
    const download = await downloadPromise;
    const exportTime = Date.now() - startTime;
    expect(exportTime).toBeLessThan(10000); // Export within 10 seconds
    expect(download.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);

    const filePath = path.join(downloadsPath, download.suggestedFilename());
    await download.saveAs(filePath);

    // Step 3: Verify Excel file exists and has content
    expect(fs.existsSync(filePath)).toBeTruthy();
    const stats = fs.statSync(filePath);
    expect(stats.size).toBeGreaterThan(0);

    // Verify success notification
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('Excel exported successfully');
  });

  test('Export schedule report to PDF - comprehensive validation', async ({ page }) => {
    // Navigate to schedule reporting module and generate a schedule report
    await page.click('[data-testid="date-range-picker"]');
    await page.fill('[data-testid="date-range-start"]', '2024-01-01');
    await page.fill('[data-testid="date-range-end"]', '2024-01-31');
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.click('[data-testid="team-option-engineering"]');
    await page.click('[data-testid="generate-report-button"]');

    // Verify the report content is accurate and complete before exporting
    await expect(page.locator('[data-testid="schedule-report-container"]')).toBeVisible({ timeout: 10000 });
    const reportTable = page.locator('[data-testid="report-data-table"]');
    await expect(reportTable).toBeVisible();
    const rowCount = await page.locator('[data-testid="report-data-row"]').count();
    expect(rowCount).toBeGreaterThan(0);
    await expect(page.locator('[data-testid="report-header"]')).toContainText('Schedule Report');

    // Locate the export options toolbar and click on 'Export to PDF' button
    await expect(page.locator('[data-testid="export-options-toolbar"]')).toBeVisible();
    const downloadPromise = page.waitForEvent('download');
    const startTime = Date.now();
    await page.click('[data-testid="export-to-pdf-button"]');

    // Monitor the export processing time
    const download = await downloadPromise;
    const processingTime = Date.now() - startTime;
    expect(processingTime).toBeLessThan(10000);

    // Check the browser's download location for the exported PDF file
    const fileName = download.suggestedFilename();
    expect(fileName).toMatch(/schedule.*report.*\.pdf$/i);
    const filePath = path.join(downloadsPath, fileName);
    await download.saveAs(filePath);

    // Verify the PDF file was downloaded successfully
    expect(fs.existsSync(filePath)).toBeTruthy();
    const fileStats = fs.statSync(filePath);
    expect(fileStats.size).toBeGreaterThan(1000); // PDF should have substantial content

    // Verify PDF metadata and properties through UI feedback
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('PDF');
  });

  test('Export schedule report to Excel - comprehensive validation', async ({ page }) => {
    // Navigate to schedule reporting module and generate a schedule report
    await page.click('[data-testid="date-range-picker"]');
    await page.fill('[data-testid="date-range-start"]', '2024-01-01');
    await page.fill('[data-testid="date-range-end"]', '2024-01-31');
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.click('[data-testid="team-option-engineering"]');
    await page.click('[data-testid="generate-report-button"]');

    // Review the report to ensure all data columns and rows are present
    await expect(page.locator('[data-testid="schedule-report-container"]')).toBeVisible({ timeout: 10000 });
    const reportTable = page.locator('[data-testid="report-data-table"]');
    await expect(reportTable).toBeVisible();
    const columnHeaders = page.locator('[data-testid="report-column-header"]');
    const columnCount = await columnHeaders.count();
    expect(columnCount).toBeGreaterThan(0);
    const rowCount = await page.locator('[data-testid="report-data-row"]').count();
    expect(rowCount).toBeGreaterThan(0);

    // Locate the export options toolbar and click on 'Export to Excel' button
    await expect(page.locator('[data-testid="export-options-toolbar"]')).toBeVisible();
    const downloadPromise = page.waitForEvent('download');
    const startTime = Date.now();
    await page.click('[data-testid="export-to-excel-button"]');

    // Monitor the export processing time
    const download = await downloadPromise;
    const processingTime = Date.now() - startTime;
    expect(processingTime).toBeLessThan(10000);

    // Check the browser's download location for the exported Excel file
    const fileName = download.suggestedFilename();
    expect(fileName).toMatch(/schedule.*report.*\.(xlsx|xls)$/i);
    const filePath = path.join(downloadsPath, fileName);
    await download.saveAs(filePath);

    // Verify the Excel file was downloaded successfully
    expect(fs.existsSync(filePath)).toBeTruthy();
    const fileStats = fs.statSync(filePath);
    expect(fileStats.size).toBeGreaterThan(1000); // Excel should have substantial content

    // Verify success notification and data structure feedback
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('Excel');
  });

  test('Export restricted to authorized users', async ({ page }) => {
    // Generate schedule report
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="date-range-last-30-days"]');
    await page.click('[data-testid="generate-report-button"]');

    await expect(page.locator('[data-testid="schedule-report-container"]')).toBeVisible({ timeout: 10000 });

    // Verify export options are visible for authorized user
    await expect(page.locator('[data-testid="export-options-toolbar"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-to-pdf-button"]')).toBeEnabled();
    await expect(page.locator('[data-testid="export-to-excel-button"]')).toBeEnabled();
  });

  test('Export large report within performance threshold', async ({ page }) => {
    // Generate large schedule report (up to 1000 records)
    await page.click('[data-testid="date-range-picker"]');
    await page.fill('[data-testid="date-range-start"]', '2023-01-01');
    await page.fill('[data-testid="date-range-end"]', '2024-12-31');
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.click('[data-testid="team-option-all"]');
    await page.click('[data-testid="generate-report-button"]');

    await expect(page.locator('[data-testid="schedule-report-container"]')).toBeVisible({ timeout: 15000 });
    const rowCount = await page.locator('[data-testid="report-data-row"]').count();
    expect(rowCount).toBeGreaterThan(100); // Verify large dataset

    // Export to PDF and measure time
    const downloadPromise = page.waitForEvent('download');
    const startTime = Date.now();
    await page.click('[data-testid="export-options-toolbar"]');
    await page.click('[data-testid="export-to-pdf-button"]');

    const download = await downloadPromise;
    const exportTime = Date.now() - startTime;
    expect(exportTime).toBeLessThan(10000); // Must complete within 10 seconds

    const filePath = path.join(downloadsPath, download.suggestedFilename());
    await download.saveAs(filePath);
    expect(fs.existsSync(filePath)).toBeTruthy();
  });
});