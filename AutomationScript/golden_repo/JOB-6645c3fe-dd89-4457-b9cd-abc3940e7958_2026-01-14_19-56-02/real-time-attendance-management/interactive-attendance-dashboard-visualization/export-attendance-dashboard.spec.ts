import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

test.describe('Export Attendance Dashboard Reports', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to attendance dashboard and login as manager
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager@123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to attendance dashboard
    await page.goto('/attendance/dashboard');
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
  });

  test('Validate export of filtered dashboard data to PDF and Excel', async ({ page }) => {
    // Apply date range filter by selecting start date and end date from the filter panel
    await page.click('[data-testid="filter-panel-toggle"]');
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-01-31');
    
    // Apply department filter by selecting a specific department from the dropdown
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.click('[data-testid="department-option-engineering"]');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Verify that charts and tabular data reflect the applied filters
    await expect(page.locator('[data-testid="dashboard-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="filter-summary"]')).toContainText('Engineering');
    await expect(page.locator('[data-testid="filter-summary"]')).toContainText('2024-01-01');
    
    // Click on the Export button located on the dashboard toolbar
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-modal"]')).toBeVisible();
    
    // Select PDF format from the export options
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-format-pdf"]');
    await page.click('[data-testid="confirm-export-button"]');
    
    // Wait for the PDF file to be generated and downloaded
    const downloadPDF = await downloadPromisePDF;
    expect(downloadPDF.suggestedFilename()).toContain('.pdf');
    const pdfPath = path.join('downloads', downloadPDF.suggestedFilename());
    await downloadPDF.saveAs(pdfPath);
    
    // Verify PDF file exists
    expect(fs.existsSync(pdfPath)).toBeTruthy();
    const pdfStats = fs.statSync(pdfPath);
    expect(pdfStats.size).toBeGreaterThan(0);
    
    // Return to the dashboard and click the Export button again
    await page.waitForTimeout(1000);
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-modal"]')).toBeVisible();
    
    // Select Excel format from the export options
    const downloadPromiseExcel = page.waitForEvent('download');
    await page.click('[data-testid="export-format-excel"]');
    await page.click('[data-testid="confirm-export-button"]');
    
    // Wait for the Excel file to be generated and downloaded
    const downloadExcel = await downloadPromiseExcel;
    expect(downloadExcel.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    const excelPath = path.join('downloads', downloadExcel.suggestedFilename());
    await downloadExcel.saveAs(excelPath);
    
    // Verify Excel file exists and has content
    expect(fs.existsSync(excelPath)).toBeTruthy();
    const excelStats = fs.statSync(excelPath);
    expect(excelStats.size).toBeGreaterThan(0);
  });

  test('Verify export generation time and confirmation', async ({ page }) => {
    // Apply any filter to the dashboard (e.g., select a date range)
    await page.click('[data-testid="filter-panel-toggle"]');
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-01-31');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Wait for dashboard to update
    await expect(page.locator('[data-testid="attendance-table"]')).toBeVisible();
    
    // Click on the Export button and note the current time
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-modal"]')).toBeVisible();
    
    // Select PDF format and start timing the export process
    const startTime = Date.now();
    const downloadPromisePDF = page.waitForEvent('download', { timeout: 15000 });
    await page.click('[data-testid="export-format-pdf"]');
    await page.click('[data-testid="confirm-export-button"]');
    
    // Monitor the export generation process and measure the time taken
    const downloadPDF = await downloadPromisePDF;
    const pdfExportTime = Date.now() - startTime;
    
    // Verify export completes within 10 seconds
    expect(pdfExportTime).toBeLessThan(10000);
    
    // Observe the system response after export completion
    await expect(page.locator('[data-testid="export-confirmation-message"]')).toBeVisible({ timeout: 5000 });
    
    // Verify the confirmation message contains relevant information
    const confirmationText = await page.locator('[data-testid="export-confirmation-message"]').textContent();
    expect(confirmationText).toContain('successfully');
    expect(confirmationText?.toLowerCase()).toMatch(/export|download/);
    
    // Check the download folder for the exported file
    expect(downloadPDF.suggestedFilename()).toContain('.pdf');
    const pdfPath = path.join('downloads', downloadPDF.suggestedFilename());
    await downloadPDF.saveAs(pdfPath);
    expect(fs.existsSync(pdfPath)).toBeTruthy();
    
    // Close confirmation message if present
    const closeButton = page.locator('[data-testid="close-confirmation-button"]');
    if (await closeButton.isVisible()) {
      await closeButton.click();
    }
    
    // Wait a moment before next export
    await page.waitForTimeout(1000);
    
    // Repeat the export process with Excel format and measure the time
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-modal"]')).toBeVisible();
    
    const startTimeExcel = Date.now();
    const downloadPromiseExcel = page.waitForEvent('download', { timeout: 15000 });
    await page.click('[data-testid="export-format-excel"]');
    await page.click('[data-testid="confirm-export-button"]');
    
    // Verify the Excel file is downloaded successfully
    const downloadExcel = await downloadPromiseExcel;
    const excelExportTime = Date.now() - startTimeExcel;
    
    // Verify Excel export completes within 10 seconds
    expect(excelExportTime).toBeLessThan(10000);
    
    // Verify confirmation message displays
    await expect(page.locator('[data-testid="export-confirmation-message"]')).toBeVisible({ timeout: 5000 });
    
    // Verify Excel file download
    expect(downloadExcel.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    const excelPath = path.join('downloads', downloadExcel.suggestedFilename());
    await downloadExcel.saveAs(excelPath);
    expect(fs.existsSync(excelPath)).toBeTruthy();
  });

  test('Verify export functionality is accessible only to authorized manager roles', async ({ page }) => {
    // Verify export button is visible for manager role
    await expect(page.locator('[data-testid="export-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-button"]')).toBeEnabled();
    
    // Click export button to verify access
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-modal"]')).toBeVisible();
    
    // Verify export format options are available
    await expect(page.locator('[data-testid="export-format-pdf"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-format-excel"]')).toBeVisible();
  });

  test('Verify export files include all visible charts and tabular data', async ({ page }) => {
    // Apply filters to dashboard
    await page.click('[data-testid="filter-panel-toggle"]');
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-01-31');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Verify charts and tables are visible before export
    await expect(page.locator('[data-testid="dashboard-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-table"]')).toBeVisible();
    
    // Get count of visible data rows
    const tableRows = await page.locator('[data-testid="attendance-table"] tbody tr').count();
    expect(tableRows).toBeGreaterThan(0);
    
    // Export to PDF
    await page.click('[data-testid="export-button"]');
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-format-pdf"]');
    await page.click('[data-testid="confirm-export-button"]');
    
    // Verify PDF download
    const download = await downloadPromise;
    const filePath = path.join('downloads', download.suggestedFilename());
    await download.saveAs(filePath);
    
    // Verify file size indicates content is included
    const fileStats = fs.statSync(filePath);
    expect(fileStats.size).toBeGreaterThan(5000); // Reasonable size for charts and data
  });
});