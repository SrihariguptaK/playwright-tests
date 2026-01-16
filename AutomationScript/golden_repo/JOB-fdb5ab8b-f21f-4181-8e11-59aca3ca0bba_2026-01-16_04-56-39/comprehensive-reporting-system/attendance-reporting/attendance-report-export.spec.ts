import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

test.describe('Attendance Report Export - Story 10', () => {
  const downloadsPath = path.join(__dirname, 'downloads');

  test.beforeEach(async ({ page }) => {
    // Login as HR Specialist
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'hr.specialist@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate export of attendance reports in CSV format', async ({ page }) => {
    // Navigate to the attendance reports section from the main dashboard
    await page.click('[data-testid="attendance-reports-link"]');
    await expect(page.locator('[data-testid="attendance-reports-header"]')).toBeVisible();

    // Select date range for the attendance report (e.g., last 30 days)
    await page.click('[data-testid="date-range-selector"]');
    await page.click('[data-testid="last-30-days-option"]');

    // Select department or employee filters if applicable
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-engineering"]');

    // Click on 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Report displayed
    await expect(page.locator('[data-testid="attendance-report-table"]')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('[data-testid="report-data-row"]').first()).toBeVisible();

    // Locate and click on the 'Export' button or dropdown menu
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-dropdown"]')).toBeVisible();

    // Select 'CSV' format from the export options
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-option"]');
    
    // Expected Result: CSV file downloaded with correct data
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.csv');
    
    const filePath = path.join(downloadsPath, download.suggestedFilename());
    await download.saveAs(filePath);
    
    // Verify file exists and has content
    expect(fs.existsSync(filePath)).toBeTruthy();
    const fileStats = fs.statSync(filePath);
    expect(fileStats.size).toBeGreaterThan(0);
    
    // Verify CSV content structure
    const csvContent = fs.readFileSync(filePath, 'utf-8');
    expect(csvContent).toContain('Employee');
    expect(csvContent).toContain('Date');
    expect(csvContent).toContain('Status');
    
    // Cleanup
    fs.unlinkSync(filePath);
  });

  test('Validate export of attendance reports in PDF format', async ({ page }) => {
    // Navigate to the attendance reports section from the main dashboard
    await page.click('[data-testid="attendance-reports-link"]');
    await expect(page.locator('[data-testid="attendance-reports-header"]')).toBeVisible();

    // Select date range for the attendance report (e.g., current month)
    await page.click('[data-testid="date-range-selector"]');
    await page.click('[data-testid="current-month-option"]');

    // Apply any necessary filters such as department, team, or specific employees
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-sales"]');
    await page.click('[data-testid="team-filter"]');
    await page.click('[data-testid="team-north-region"]');

    // Click on 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Report displayed
    await expect(page.locator('[data-testid="attendance-report-table"]')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('[data-testid="report-summary-section"]')).toBeVisible();

    // Locate and click on the 'Export' button or dropdown menu
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-dropdown"]')).toBeVisible();

    // Select 'PDF' format from the export options
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-option"]');
    
    // Expected Result: PDF file downloaded with correct formatting
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.pdf');
    
    const filePath = path.join(downloadsPath, download.suggestedFilename());
    await download.saveAs(filePath);
    
    // Verify file exists and has content
    expect(fs.existsSync(filePath)).toBeTruthy();
    const fileStats = fs.statSync(filePath);
    expect(fileStats.size).toBeGreaterThan(1000); // PDF files are typically larger
    
    // Verify PDF file signature (PDF files start with %PDF)
    const pdfBuffer = fs.readFileSync(filePath);
    const pdfSignature = pdfBuffer.toString('utf-8', 0, 4);
    expect(pdfSignature).toBe('%PDF');
    
    // Cleanup
    fs.unlinkSync(filePath);
  });

  test('Validate export of attendance reports in Excel format', async ({ page }) => {
    // Navigate to the attendance reports section from the main dashboard
    await page.click('[data-testid="attendance-reports-link"]');
    await expect(page.locator('[data-testid="attendance-reports-header"]')).toBeVisible();

    // Select date range for the attendance report (e.g., quarterly report)
    await page.click('[data-testid="date-range-selector"]');
    await page.click('[data-testid="custom-range-option"]');
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-03-31');
    await page.click('[data-testid="apply-date-range"]');

    // Configure any additional filters such as department, location, or employee status
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-all"]');
    await page.click('[data-testid="location-filter"]');
    await page.click('[data-testid="location-headquarters"]');
    await page.click('[data-testid="employee-status-filter"]');
    await page.click('[data-testid="status-active"]');

    // Click on 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Report displayed
    await expect(page.locator('[data-testid="attendance-report-table"]')).toBeVisible({ timeout: 15000 });
    const reportRows = page.locator('[data-testid="report-data-row"]');
    await expect(reportRows.first()).toBeVisible();
    const rowCount = await reportRows.count();
    expect(rowCount).toBeGreaterThan(0);

    // Locate and click on the 'Export' button or dropdown menu
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-dropdown"]')).toBeVisible();

    // Select 'Excel' format from the export options
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-option"]');
    
    // Expected Result: Excel file downloaded with accurate data
    const download = await downloadPromise;
    const filename = download.suggestedFilename();
    expect(filename).toMatch(/\.(xlsx|xls)$/);
    
    const filePath = path.join(downloadsPath, filename);
    await download.saveAs(filePath);
    
    // Verify file exists and has content
    expect(fs.existsSync(filePath)).toBeTruthy();
    const fileStats = fs.statSync(filePath);
    expect(fileStats.size).toBeGreaterThan(0);
    
    // Verify Excel file signature (Excel files start with PK for .xlsx)
    const excelBuffer = fs.readFileSync(filePath);
    const excelSignature = excelBuffer.toString('utf-8', 0, 2);
    expect(excelSignature).toBe('PK');
    
    // Verify export completion notification
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('Excel');
    
    // Cleanup
    fs.unlinkSync(filePath);
  });

  test('Verify export operations complete within 10 seconds', async ({ page }) => {
    // Navigate to attendance reports
    await page.click('[data-testid="attendance-reports-link"]');
    await expect(page.locator('[data-testid="attendance-reports-header"]')).toBeVisible();

    // Generate report
    await page.click('[data-testid="date-range-selector"]');
    await page.click('[data-testid="last-7-days-option"]');
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="attendance-report-table"]')).toBeVisible();

    // Measure CSV export time
    await page.click('[data-testid="export-button"]');
    const startTime = Date.now();
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-option"]');
    await downloadPromise;
    const exportDuration = Date.now() - startTime;
    
    // Verify export completes within 10 seconds
    expect(exportDuration).toBeLessThan(10000);
  });

  test('Verify export options are easily accessible in the UI', async ({ page }) => {
    // Navigate to attendance reports
    await page.click('[data-testid="attendance-reports-link"]');
    await expect(page.locator('[data-testid="attendance-reports-header"]')).toBeVisible();

    // Generate report
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="attendance-report-table"]')).toBeVisible();

    // Verify export button is visible and accessible
    const exportButton = page.locator('[data-testid="export-button"]');
    await expect(exportButton).toBeVisible();
    await expect(exportButton).toBeEnabled();

    // Click export button and verify all format options are available
    await exportButton.click();
    const exportDropdown = page.locator('[data-testid="export-dropdown"]');
    await expect(exportDropdown).toBeVisible();

    // Verify all three export format options are present
    await expect(page.locator('[data-testid="export-csv-option"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-pdf-option"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-excel-option"]')).toBeVisible();

    // Verify options have clear labels
    await expect(page.locator('[data-testid="export-csv-option"]')).toContainText('CSV');
    await expect(page.locator('[data-testid="export-pdf-option"]')).toContainText('PDF');
    await expect(page.locator('[data-testid="export-excel-option"]')).toContainText('Excel');
  });
});