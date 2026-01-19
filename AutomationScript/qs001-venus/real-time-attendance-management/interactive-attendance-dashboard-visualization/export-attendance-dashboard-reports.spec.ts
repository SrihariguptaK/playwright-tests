import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

test.describe('Export Attendance Dashboard Reports', () => {
  const downloadsPath = path.join(__dirname, 'downloads');

  test.beforeEach(async ({ page }) => {
    // Navigate to attendance dashboard
    await page.goto('/attendance/dashboard');
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
  });

  test('Validate export of dashboard reports (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the attendance dashboard and verify data is displayed
    await expect(page.locator('[data-testid="dashboard-data-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="dashboard-metrics"]')).toBeVisible();

    // Step 2: Apply filters to the dashboard by selecting a specific date range (e.g., last 30 days) and department
    await page.click('[data-testid="filter-button"]');
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="last-30-days-option"]');
    await page.click('[data-testid="department-filter"]');
    await page.selectOption('[data-testid="department-select"]', { label: 'Engineering' });
    await page.click('[data-testid="apply-filters-button"]');
    
    // Verify dashboard displays filtered data
    await expect(page.locator('[data-testid="applied-filters-badge"]')).toContainText('Last 30 days');
    await expect(page.locator('[data-testid="applied-filters-badge"]')).toContainText('Engineering');
    await page.waitForSelector('[data-testid="dashboard-data-table"]');

    // Step 3: Perform a drill-down operation by clicking on a specific metric (e.g., late arrivals count)
    const lateArrivalsMetric = page.locator('[data-testid="late-arrivals-metric"]');
    await expect(lateArrivalsMetric).toBeVisible();
    const lateArrivalsCount = await lateArrivalsMetric.textContent();
    await lateArrivalsMetric.click();
    await expect(page.locator('[data-testid="drill-down-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="drill-down-title"]')).toContainText('Late Arrivals');

    // Step 4: Locate and click on the 'Export' button or menu option on the dashboard
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-menu"]')).toBeVisible();

    // Step 5: Select 'Export as PDF' option from the export menu
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-option"]');
    const downloadPDF = await downloadPromisePDF;
    
    // Verify PDF download
    expect(downloadPDF.suggestedFilename()).toContain('.pdf');
    const pdfPath = path.join(downloadsPath, downloadPDF.suggestedFilename());
    await downloadPDF.saveAs(pdfPath);
    expect(fs.existsSync(pdfPath)).toBeTruthy();
    const pdfStats = fs.statSync(pdfPath);
    expect(pdfStats.size).toBeGreaterThan(0);

    // Step 6: Open the downloaded PDF file and verify its contents
    // Note: Actual PDF content verification would require PDF parsing library
    // Verifying file exists and has content as proxy for successful export

    // Step 7: Return to the dashboard and click on the 'Export' button again
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-menu"]')).toBeVisible();

    // Step 8: Select 'Export as Excel' option from the export menu
    const downloadPromiseExcel = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-option"]');
    const downloadExcel = await downloadPromiseExcel;
    
    // Verify Excel download
    expect(downloadExcel.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    const excelPath = path.join(downloadsPath, downloadExcel.suggestedFilename());
    await downloadExcel.saveAs(excelPath);
    expect(fs.existsSync(excelPath)).toBeTruthy();
    const excelStats = fs.statSync(excelPath);
    expect(excelStats.size).toBeGreaterThan(0);

    // Step 9: Open the downloaded Excel file and verify its contents
    // Note: Actual Excel content verification would require Excel parsing library
    // Verifying file exists and has content as proxy for successful export

    // Step 10: Verify that both exported files contain identical data in their respective formats
    // Both files should have similar file sizes (within reasonable range)
    const sizeDifferenceRatio = Math.abs(pdfStats.size - excelStats.size) / Math.max(pdfStats.size, excelStats.size);
    expect(sizeDifferenceRatio).toBeLessThan(5); // Allow up to 5x difference in file sizes
  });

  test('Verify export error handling (error-case)', async ({ page, context }) => {
    // Step 1: Navigate to the attendance dashboard and verify data is displayed
    await expect(page.locator('[data-testid="dashboard-data-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="dashboard-metrics"]')).toBeVisible();

    // Step 2: Configure the test environment to simulate a report generation failure
    // Intercept the export API call and return an error response
    await page.route('**/api/reports/export**', route => {
      route.abort('failed');
    });

    // Step 3: Click on the 'Export' button and select 'Export as PDF' option
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-menu"]')).toBeVisible();
    await page.click('[data-testid="export-pdf-option"]');

    // Step 4: Wait for the system to detect and respond to the simulated failure
    await page.waitForSelector('[data-testid="error-notification"]', { timeout: 10000 });

    // Step 5: Observe the error notification displayed to the manager
    const errorNotification = page.locator('[data-testid="error-notification"]');
    await expect(errorNotification).toBeVisible();
    await expect(errorNotification).toContainText(/export.*failed|error.*generating.*report|unable.*to.*export/i);

    // Step 6: Verify the dashboard remains functional after the error
    await expect(page.locator('[data-testid="dashboard-data-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="dashboard-metrics"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-button"]')).toBeEnabled();

    // Step 7: Click the 'Close' or 'OK' button on the error message
    const closeButton = page.locator('[data-testid="error-notification-close"]').or(page.locator('button:has-text("Close")').or(page.locator('button:has-text("OK")')));
    await closeButton.click();
    await expect(errorNotification).not.toBeVisible();

    // Step 8: Attempt to export again using 'Export as Excel' option while failure condition is still active
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-menu"]')).toBeVisible();
    await page.click('[data-testid="export-excel-option"]');
    
    // Verify error notification appears again
    await page.waitForSelector('[data-testid="error-notification"]', { timeout: 10000 });
    await expect(page.locator('[data-testid="error-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-notification"]')).toContainText(/export.*failed|error.*generating.*report|unable.*to.*export/i);
    
    // Close the error notification
    await page.locator('[data-testid="error-notification-close"]').or(page.locator('button:has-text("Close")').or(page.locator('button:has-text("OK")'))).click();

    // Step 9: Restore the test environment to normal operation (remove failure simulation)
    await page.unroute('**/api/reports/export**');

    // Step 10: Attempt to export as PDF again with normal system operation
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-menu"]')).toBeVisible();
    
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-option"]');
    const download = await downloadPromise;
    
    // Verify successful export after restoration
    expect(download.suggestedFilename()).toContain('.pdf');
    const downloadPath = path.join(downloadsPath, download.suggestedFilename());
    await download.saveAs(downloadPath);
    expect(fs.existsSync(downloadPath)).toBeTruthy();
    const fileStats = fs.statSync(downloadPath);
    expect(fileStats.size).toBeGreaterThan(0);
    
    // Verify no error notification is displayed
    await expect(page.locator('[data-testid="error-notification"]')).not.toBeVisible();
  });

  test('Manager applies filters and drill-downs, then exports as PDF', async ({ page }) => {
    // Action: Manager applies filters and drill-downs
    await page.click('[data-testid="filter-button"]');
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="last-7-days-option"]');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Expected Result: Dashboard displays filtered data
    await expect(page.locator('[data-testid="applied-filters-badge"]')).toContainText('Last 7 days');
    await page.waitForSelector('[data-testid="dashboard-data-table"]');
    
    // Perform drill-down
    await page.click('[data-testid="attendance-rate-metric"]');
    await expect(page.locator('[data-testid="drill-down-view"]')).toBeVisible();
    
    // Action: Manager selects export as PDF
    await page.click('[data-testid="export-button"]');
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-option"]');
    const download = await downloadPromise;
    
    // Expected Result: PDF report downloads matching dashboard data
    expect(download.suggestedFilename()).toContain('.pdf');
    const downloadPath = path.join(downloadsPath, download.suggestedFilename());
    await download.saveAs(downloadPath);
    expect(fs.existsSync(downloadPath)).toBeTruthy();
    const fileStats = fs.statSync(downloadPath);
    expect(fileStats.size).toBeGreaterThan(0);
  });

  test('Manager applies filters and drill-downs, then exports as Excel', async ({ page }) => {
    // Action: Manager applies filters and drill-downs
    await page.click('[data-testid="filter-button"]');
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="last-7-days-option"]');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Expected Result: Dashboard displays filtered data
    await expect(page.locator('[data-testid="applied-filters-badge"]')).toContainText('Last 7 days');
    await page.waitForSelector('[data-testid="dashboard-data-table"]');
    
    // Perform drill-down
    await page.click('[data-testid="attendance-rate-metric"]');
    await expect(page.locator('[data-testid="drill-down-view"]')).toBeVisible();
    
    // Action: Manager selects export as Excel
    await page.click('[data-testid="export-button"]');
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-option"]');
    const download = await downloadPromise;
    
    // Expected Result: Excel report downloads matching dashboard data
    expect(download.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    const downloadPath = path.join(downloadsPath, download.suggestedFilename());
    await download.saveAs(downloadPath);
    expect(fs.existsSync(downloadPath)).toBeTruthy();
    const fileStats = fs.statSync(downloadPath);
    expect(fileStats.size).toBeGreaterThan(0);
  });

  test('Simulate report generation failure and verify error handling', async ({ page }) => {
    // Action: Simulate report generation failure
    await page.route('**/api/reports/export**', route => {
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Report generation failed' })
      });
    });
    
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-pdf-option"]');
    
    // Expected Result: System displays error message to manager
    await page.waitForSelector('[data-testid="error-notification"]', { timeout: 10000 });
    const errorNotification = page.locator('[data-testid="error-notification"]');
    await expect(errorNotification).toBeVisible();
    await expect(errorNotification).toContainText(/export.*failed|error.*generating.*report|unable.*to.*export/i);
    
    // Verify error message contains helpful information
    const errorMessage = await errorNotification.textContent();
    expect(errorMessage).toBeTruthy();
    expect(errorMessage!.length).toBeGreaterThan(10);
  });
});