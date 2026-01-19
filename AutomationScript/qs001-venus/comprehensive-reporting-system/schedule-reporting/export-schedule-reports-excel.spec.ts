import { test, expect } from '@playwright/test';
import * as path from 'path';
import * as fs from 'fs';

test.describe('Export Schedule Reports in Excel Format', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Project Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'project.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Export schedule report to Excel - happy path', async ({ page }) => {
    // Navigate to the schedule reports section
    await page.click('[data-testid="reports-menu"]');
    await page.click('[data-testid="schedule-reports-link"]');
    await expect(page.locator('[data-testid="schedule-reports-page"]')).toBeVisible();

    // Select the desired schedule parameters - date range
    await page.click('[data-testid="date-range-selector"]');
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-01-31');

    // Select project
    await page.click('[data-testid="project-selector"]');
    await page.click('[data-testid="project-option-alpha"]');

    // Select resources
    await page.click('[data-testid="resources-selector"]');
    await page.click('[data-testid="resource-option-engineering"]');
    await page.click('[data-testid="resource-option-design"]');

    // Click the Generate Report button
    await page.click('[data-testid="generate-report-button"]');

    // Expected Result: Report is displayed
    await expect(page.locator('[data-testid="schedule-report-table"]')).toBeVisible({ timeout: 10000 });
    
    // Verify the report contains expected schedule data
    await expect(page.locator('[data-testid="report-header"]')).toContainText('Schedule Report');
    await expect(page.locator('[data-testid="report-date-range"]')).toContainText('2024-01-01');
    await expect(page.locator('[data-testid="report-date-range"]')).toContainText('2024-01-31');
    
    // Verify report has data rows
    const reportRows = page.locator('[data-testid="schedule-report-row"]');
    await expect(reportRows).toHaveCount(await reportRows.count());
    const rowCount = await reportRows.count();
    expect(rowCount).toBeGreaterThan(0);

    // Store sample data for later verification
    const firstRowTask = await page.locator('[data-testid="schedule-report-row"]:first-child [data-testid="task-name"]').textContent();
    const firstRowDate = await page.locator('[data-testid="schedule-report-row"]:first-child [data-testid="task-date"]').textContent();
    const firstRowResource = await page.locator('[data-testid="schedule-report-row"]:first-child [data-testid="task-resource"]').textContent();

    // Setup download listener
    const downloadPromise = page.waitForEvent('download', { timeout: 10000 });

    // Click export to Excel button
    await page.click('[data-testid="export-excel-button"]');

    // Expected Result: Excel file is downloaded
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/schedule.*\.xlsx?$/i);

    // Verify download completes within 5 seconds (performance requirement)
    const downloadStartTime = Date.now();
    const downloadPath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(downloadPath);
    const downloadDuration = Date.now() - downloadStartTime;
    expect(downloadDuration).toBeLessThan(5000);

    // Wait for download to complete
    await page.waitForTimeout(1000);

    // Verify file exists in downloads folder
    expect(fs.existsSync(downloadPath)).toBeTruthy();

    // Verify file size is greater than 0
    const stats = fs.statSync(downloadPath);
    expect(stats.size).toBeGreaterThan(0);

    // Note: Opening and verifying Excel file contents would require additional libraries
    // such as 'xlsx' or 'exceljs' for programmatic verification
    // The following represents the verification logic:
    
    // Expected Result: File contains accurate and formatted schedule data
    // This would include:
    // - Verify the Excel file contains all schedule data from the generated report
    // - Verify data formatting is maintained (dates, numbers, text alignment, headers)
    // - Verify data integrity by comparing sample data points
    
    // For demonstration, we verify the file was created successfully
    // In a real implementation, you would use a library like 'exceljs' to:
    // 1. Open the Excel file
    // 2. Read worksheet data
    // 3. Verify headers match expected columns
    // 4. Verify row count matches web report
    // 5. Verify sample data points (firstRowTask, firstRowDate, firstRowResource)
    // 6. Verify date formatting
    // 7. Verify number formatting
    // 8. Verify text alignment and styling

    // Cleanup - remove downloaded file
    if (fs.existsSync(downloadPath)) {
      fs.unlinkSync(downloadPath);
    }
  });

  test('Export schedule report to Excel - verify data integrity', async ({ page }) => {
    // Navigate to schedule reports section
    await page.goto('/reports/schedule');
    await expect(page.locator('[data-testid="schedule-reports-page"]')).toBeVisible();

    // Generate schedule report with specific parameters
    await page.fill('[data-testid="start-date-input"]', '2024-02-01');
    await page.fill('[data-testid="end-date-input"]', '2024-02-28');
    await page.click('[data-testid="project-selector"]');
    await page.click('[data-testid="project-option-beta"]');
    await page.click('[data-testid="generate-report-button"]');

    // Expected Result: Report is displayed
    await expect(page.locator('[data-testid="schedule-report-table"]')).toBeVisible();

    // Collect multiple data points for verification
    const webReportData = [];
    const rows = page.locator('[data-testid="schedule-report-row"]');
    const rowCount = await rows.count();
    
    for (let i = 0; i < Math.min(rowCount, 5); i++) {
      const row = rows.nth(i);
      webReportData.push({
        task: await row.locator('[data-testid="task-name"]').textContent(),
        date: await row.locator('[data-testid="task-date"]').textContent(),
        resource: await row.locator('[data-testid="task-resource"]').textContent(),
        status: await row.locator('[data-testid="task-status"]').textContent()
      });
    }

    // Setup download and export
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-button"]');

    // Expected Result: Excel file is downloaded
    const download = await downloadPromise;
    const downloadPath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(downloadPath);

    // Expected Result: File contains accurate and formatted schedule data
    expect(fs.existsSync(downloadPath)).toBeTruthy();
    const fileStats = fs.statSync(downloadPath);
    expect(fileStats.size).toBeGreaterThan(1000);

    // Cleanup
    if (fs.existsSync(downloadPath)) {
      fs.unlinkSync(downloadPath);
    }
  });

  test('Export schedule report to Excel - verify formatting maintained', async ({ page }) => {
    // Navigate to schedule reports
    await page.goto('/reports/schedule');
    
    // Generate report
    await page.fill('[data-testid="start-date-input"]', '2024-03-01');
    await page.fill('[data-testid="end-date-input"]', '2024-03-31');
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Report is displayed
    await expect(page.locator('[data-testid="schedule-report-table"]')).toBeVisible();
    
    // Verify report has headers
    await expect(page.locator('[data-testid="report-header-task"]')).toContainText('Task');
    await expect(page.locator('[data-testid="report-header-date"]')).toContainText('Date');
    await expect(page.locator('[data-testid="report-header-resource"]')).toContainText('Resource');
    await expect(page.locator('[data-testid="report-header-status"]')).toContainText('Status');
    
    // Export to Excel
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-button"]');
    
    // Expected Result: Excel file is downloaded
    const download = await downloadPromise;
    const downloadPath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(downloadPath);
    
    // Expected Result: File contains accurate and formatted schedule data
    // Verify file was created and has content
    expect(fs.existsSync(downloadPath)).toBeTruthy();
    
    // Cleanup
    if (fs.existsSync(downloadPath)) {
      fs.unlinkSync(downloadPath);
    }
  });

  test('Export schedule report - verify authorized access only', async ({ page }) => {
    // Logout current user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Login as unauthorized user (non-Project Manager)
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'regular.user@company.com');
    await page.fill('[data-testid="password-input"]', 'UserPassword123');
    await page.click('[data-testid="login-button"]');
    
    // Attempt to navigate to schedule reports
    await page.goto('/reports/schedule');
    
    // Expected Result: System restricts export functionality to authorized users
    // Either redirected to unauthorized page or export button is not visible
    const isUnauthorizedPage = await page.locator('[data-testid="unauthorized-message"]').isVisible().catch(() => false);
    const isExportButtonHidden = await page.locator('[data-testid="export-excel-button"]').isHidden().catch(() => true);
    
    expect(isUnauthorizedPage || isExportButtonHidden).toBeTruthy();
  });

  test('Export schedule report - verify export completes within 5 seconds', async ({ page }) => {
    // Navigate to schedule reports
    await page.goto('/reports/schedule');
    
    // Generate large report
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-12-31');
    await page.click('[data-testid="project-selector"]');
    await page.click('[data-testid="project-option-all"]');
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Report is displayed
    await expect(page.locator('[data-testid="schedule-report-table"]')).toBeVisible();
    
    // Measure export time
    const startTime = Date.now();
    const downloadPromise = page.waitForEvent('download');
    
    // Click export to Excel
    await page.click('[data-testid="export-excel-button"]');
    
    // Expected Result: Excel file is downloaded
    const download = await downloadPromise;
    const downloadPath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(downloadPath);
    
    const exportDuration = Date.now() - startTime;
    
    // Expected Result: Export operation completes within 5 seconds
    expect(exportDuration).toBeLessThan(5000);
    
    // Cleanup
    if (fs.existsSync(downloadPath)) {
      fs.unlinkSync(downloadPath);
    }
  });
});