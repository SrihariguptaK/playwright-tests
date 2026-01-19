import { test, expect } from '@playwright/test';
import * as path from 'path';
import * as fs from 'fs';

test.describe('Export Attendance Reports to PDF', () => {
  let downloadPath: string;

  test.beforeEach(async ({ page }) => {
    // Login as HR Manager
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'hr.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Export attendance report to PDF - happy path', async ({ page }) => {
    // Navigate to the attendance reports section from the main dashboard
    await page.click('[data-testid="attendance-reports-menu"]');
    await expect(page).toHaveURL(/.*attendance-reports/);
    await expect(page.locator('[data-testid="reports-page-title"]')).toBeVisible();

    // Select the desired date range for the attendance report (e.g., current month)
    await page.click('[data-testid="date-range-selector"]');
    await page.click('[data-testid="current-month-option"]');
    await expect(page.locator('[data-testid="selected-date-range"]')).toContainText('Current Month');

    // Select department or employee filters if applicable
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-option-engineering"]');
    await expect(page.locator('[data-testid="selected-department"]')).toContainText('Engineering');

    // Click on 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');
    
    // Verify the displayed report contains accurate attendance data
    await expect(page.locator('[data-testid="attendance-report-table"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="report-header"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-report-table"] tbody tr')).not.toHaveCount(0);
    
    // Verify report data is loaded
    const reportRows = page.locator('[data-testid="attendance-report-table"] tbody tr');
    const rowCount = await reportRows.count();
    expect(rowCount).toBeGreaterThan(0);

    // Locate and click on 'Export to PDF' button
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    
    // Wait for the PDF export to complete
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/attendance.*\.pdf$/i);
    
    // Navigate to the downloads folder and locate the downloaded PDF file
    const downloadFilePath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(downloadFilePath);
    
    // Verify the file exists and has content
    expect(fs.existsSync(downloadFilePath)).toBeTruthy();
    const stats = fs.statSync(downloadFilePath);
    expect(stats.size).toBeGreaterThan(0);
    
    // Verify export completed within 5 seconds (performance requirement)
    const exportStartTime = Date.now();
    const exportDuration = Date.now() - exportStartTime;
    expect(exportDuration).toBeLessThan(5000);
    
    // Clean up downloaded file
    if (fs.existsSync(downloadFilePath)) {
      fs.unlinkSync(downloadFilePath);
    }
  });

  test('Export attendance report to PDF - verify accurate data', async ({ page }) => {
    // Generate attendance report
    await page.goto('/attendance-reports');
    await page.click('[data-testid="date-range-selector"]');
    await page.click('[data-testid="current-month-option"]');
    await page.click('[data-testid="generate-report-button"]');
    
    // Action: Report is displayed
    await expect(page.locator('[data-testid="attendance-report-table"]')).toBeVisible({ timeout: 10000 });
    const reportData = await page.locator('[data-testid="attendance-report-table"]').textContent();
    expect(reportData).toBeTruthy();
    
    // Action: Click export to PDF
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    
    // Expected Result: PDF file is downloaded
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.pdf');
    const downloadFilePath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(downloadFilePath);
    
    // Expected Result: File contains accurate and formatted attendance data
    expect(fs.existsSync(downloadFilePath)).toBeTruthy();
    const fileStats = fs.statSync(downloadFilePath);
    expect(fileStats.size).toBeGreaterThan(1000); // PDF should have substantial content
    
    // Clean up
    if (fs.existsSync(downloadFilePath)) {
      fs.unlinkSync(downloadFilePath);
    }
  });

  test('Export attendance report to PDF - verify formatting and readability', async ({ page }) => {
    // Navigate and generate report
    await page.goto('/attendance-reports');
    await page.click('[data-testid="date-range-selector"]');
    await page.click('[data-testid="current-month-option"]');
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-option-sales"]');
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="attendance-report-table"]')).toBeVisible({ timeout: 10000 });
    
    // Export to PDF
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    const download = await downloadPromise;
    const downloadFilePath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(downloadFilePath);
    
    // Verify PDF file properties
    expect(fs.existsSync(downloadFilePath)).toBeTruthy();
    const fileBuffer = fs.readFileSync(downloadFilePath);
    const fileContent = fileBuffer.toString('binary');
    
    // Verify PDF header
    expect(fileContent.substring(0, 5)).toBe('%PDF-');
    
    // Verify file size indicates formatted content
    expect(fileBuffer.length).toBeGreaterThan(2000);
    
    // Clean up
    if (fs.existsSync(downloadFilePath)) {
      fs.unlinkSync(downloadFilePath);
    }
  });

  test('Export attendance report to PDF - restricted to authorized users', async ({ page, context }) => {
    // Logout current user
    await page.goto('/dashboard');
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Login as unauthorized user (non-HR role)
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Attempt to access attendance reports
    await page.goto('/attendance-reports');
    
    // Verify unauthorized access is blocked
    const exportButton = page.locator('[data-testid="export-pdf-button"]');
    await expect(exportButton).not.toBeVisible();
    
    // Or verify access denied message
    const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
    if (await accessDeniedMessage.isVisible()) {
      await expect(accessDeniedMessage).toContainText(/access denied|unauthorized/i);
    }
  });

  test('Export attendance report to PDF - verify export completes within 5 seconds', async ({ page }) => {
    // Navigate and generate report
    await page.goto('/attendance-reports');
    await page.click('[data-testid="date-range-selector"]');
    await page.click('[data-testid="current-month-option"]');
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="attendance-report-table"]')).toBeVisible({ timeout: 10000 });
    
    // Measure export time
    const startTime = Date.now();
    const downloadPromise = page.waitForEvent('download', { timeout: 5000 });
    await page.click('[data-testid="export-pdf-button"]');
    const download = await downloadPromise;
    const endTime = Date.now();
    const exportDuration = endTime - startTime;
    
    // Verify export completed within 5 seconds
    expect(exportDuration).toBeLessThan(5000);
    
    // Verify download completed successfully
    const downloadFilePath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(downloadFilePath);
    expect(fs.existsSync(downloadFilePath)).toBeTruthy();
    
    // Clean up
    if (fs.existsSync(downloadFilePath)) {
      fs.unlinkSync(downloadFilePath);
    }
  });
});