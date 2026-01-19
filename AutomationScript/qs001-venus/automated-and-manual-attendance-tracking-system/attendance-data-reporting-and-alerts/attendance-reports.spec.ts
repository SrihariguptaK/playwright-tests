import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

test.describe('Attendance Report Generation and Management', () => {
  const MANAGER_EMAIL = 'manager@company.com';
  const MANAGER_PASSWORD = 'Manager@123';
  const UNAUTHORIZED_EMAIL = 'employee@company.com';
  const UNAUTHORIZED_PASSWORD = 'Employee@123';
  const BASE_URL = 'http://localhost:3000';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('Validate generation of attendance report with combined data (happy-path)', async ({ page }) => {
    // Login as manager
    await page.fill('[data-testid="email-input"]', MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the reporting module from the main dashboard
    await page.click('[data-testid="reports-menu"]');
    await expect(page).toHaveURL(/.*reports/);
    await expect(page.locator('[data-testid="reporting-module"]')).toBeVisible();

    // Select report type as 'Daily Attendance Report' from the dropdown
    await page.click('[data-testid="report-type-dropdown"]');
    await page.click('[data-testid="report-type-daily"]');
    await expect(page.locator('[data-testid="report-type-dropdown"]')).toContainText('Daily Attendance Report');

    // Apply filters: Select specific department, date range (last 7 days), and employee group
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-engineering"]');
    
    await page.fill('[data-testid="date-range-start"]', '2024-01-15');
    await page.fill('[data-testid="date-range-end"]', '2024-01-22');
    
    await page.click('[data-testid="employee-group-filter"]');
    await page.click('[data-testid="employee-group-fulltime"]');
    
    // Verify filters applied successfully
    await expect(page.locator('[data-testid="applied-filters"]')).toContainText('Engineering');
    await expect(page.locator('[data-testid="applied-filters"]')).toContainText('Full Time');

    // Click on 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report generation
    await page.waitForSelector('[data-testid="report-container"]', { timeout: 10000 });
    
    // Report generated with biometric and manual attendance data
    await expect(page.locator('[data-testid="report-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-status"]')).toContainText('Generated Successfully');

    // Review the generated report on screen
    await expect(page.locator('[data-testid="report-title"]')).toContainText('Daily Attendance Report');
    
    // Verify the report summary section
    await expect(page.locator('[data-testid="report-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="total-employees"]')).toBeVisible();
    await expect(page.locator('[data-testid="present-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="absent-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="late-arrivals-count"]')).toBeVisible();

    // Scroll through the detailed attendance records section
    await page.locator('[data-testid="detailed-records-section"]').scrollIntoViewIfNeeded();
    await expect(page.locator('[data-testid="detailed-records-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-record-row"]').first()).toBeVisible();

    // Locate and review highlighted anomalies in the report
    await page.locator('[data-testid="anomalies-section"]').scrollIntoViewIfNeeded();
    await expect(page.locator('[data-testid="anomalies-section"]')).toBeVisible();
    const anomalies = page.locator('[data-testid="anomaly-item"]');
    const anomalyCount = await anomalies.count();
    
    if (anomalyCount > 0) {
      await expect(anomalies.first()).toBeVisible();
      await expect(anomalies.first()).toContainText(/absent|late|early departure/i);
    }

    // Verify data accuracy by cross-checking sample records with source data
    const firstRecord = page.locator('[data-testid="attendance-record-row"]').first();
    await expect(firstRecord.locator('[data-testid="employee-name"]')).toBeVisible();
    await expect(firstRecord.locator('[data-testid="check-in-time"]')).toBeVisible();
    await expect(firstRecord.locator('[data-testid="check-out-time"]')).toBeVisible();
    await expect(firstRecord.locator('[data-testid="attendance-status"]')).toBeVisible();
    await expect(firstRecord.locator('[data-testid="data-source"]')).toContainText(/biometric|manual/i);
  });

  test('Verify report export functionality (happy-path)', async ({ page }) => {
    // Login as manager
    await page.fill('[data-testid="email-input"]', MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the reporting module and select 'Weekly Attendance Report' type
    await page.click('[data-testid="reports-menu"]');
    await page.click('[data-testid="report-type-dropdown"]');
    await page.click('[data-testid="report-type-weekly"]');
    await expect(page.locator('[data-testid="report-type-dropdown"]')).toContainText('Weekly Attendance Report');

    // Apply filters: Select date range for current week and specific department
    await page.fill('[data-testid="date-range-start"]', '2024-01-15');
    await page.fill('[data-testid="date-range-end"]', '2024-01-22');
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-engineering"]');

    // Click 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="report-container"]', { timeout: 10000 });

    // Verify the report is fully loaded and displays complete data
    await expect(page.locator('[data-testid="report-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="detailed-records-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-status"]')).toContainText('Generated Successfully');

    // Click on 'Export' button and select 'CSV' format from the dropdown
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-dropdown"]')).toBeVisible();
    await page.click('[data-testid="export-format-csv"]');

    // Confirm the CSV export by clicking 'Download' button
    const downloadPromiseCSV = page.waitForEvent('download');
    await page.click('[data-testid="confirm-download-button"]');
    const downloadCSV = await downloadPromiseCSV;
    
    // CSV file downloaded with correct data
    expect(downloadCSV.suggestedFilename()).toContain('.csv');
    const csvPath = path.join(__dirname, 'downloads', downloadCSV.suggestedFilename());
    await downloadCSV.saveAs(csvPath);
    expect(fs.existsSync(csvPath)).toBeTruthy();

    // Verify CSV data accuracy by comparing with on-screen report
    const csvContent = fs.readFileSync(csvPath, 'utf-8');
    expect(csvContent).toContain('Employee Name');
    expect(csvContent).toContain('Check In');
    expect(csvContent).toContain('Check Out');
    expect(csvContent).toContain('Status');

    // Return to the report screen and click 'Export' button, then select 'PDF' format
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-format-pdf"]');

    // Confirm the PDF export by clicking 'Download' button
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="confirm-download-button"]');
    const downloadPDF = await downloadPromisePDF;
    
    // PDF file downloaded with correct formatting
    expect(downloadPDF.suggestedFilename()).toContain('.pdf');
    const pdfPath = path.join(__dirname, 'downloads', downloadPDF.suggestedFilename());
    await downloadPDF.saveAs(pdfPath);
    expect(fs.existsSync(pdfPath)).toBeTruthy();
    
    // Verify PDF file size is reasonable (not empty)
    const pdfStats = fs.statSync(pdfPath);
    expect(pdfStats.size).toBeGreaterThan(1000);
  });

  test('Ensure access control for attendance reports (error-case)', async ({ page }) => {
    // Log into the system using unauthorized user credentials (regular employee account)
    await page.fill('[data-testid="email-input"]', UNAUTHORIZED_EMAIL);
    await page.fill('[data-testid="password-input"]', UNAUTHORIZED_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Verify that reporting module link is not visible in the navigation menu for unauthorized user
    const reportsMenuVisible = await page.locator('[data-testid="reports-menu"]').isVisible().catch(() => false);
    expect(reportsMenuVisible).toBeFalsy();

    // Attempt to navigate to the reporting module by entering the URL directly
    await page.goto(`${BASE_URL}/reports`);
    
    // Access denied message displayed
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/access denied|unauthorized|permission denied/i);

    // Attempt to access report generation API endpoint directly
    const apiResponse = await page.request.get(`${BASE_URL}/api/attendance/reports`, {
      params: {
        reportType: 'daily',
        department: 'engineering',
        startDate: '2024-01-15',
        endDate: '2024-01-22'
      }
    });
    expect(apiResponse.status()).toBe(403);

    // Log out from the unauthorized user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Log into the system using authorized Attendance Manager credentials
    await page.fill('[data-testid="email-input"]', MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the reporting module by clicking on the reports menu option
    await page.click('[data-testid="reports-menu"]');
    await expect(page).toHaveURL(/.*reports/);
    await expect(page.locator('[data-testid="reporting-module"]')).toBeVisible();

    // Select 'Monthly Attendance Report' type and apply filters for current month and all departments
    await page.click('[data-testid="report-type-dropdown"]');
    await page.click('[data-testid="report-type-monthly"]');
    await expect(page.locator('[data-testid="report-type-dropdown"]')).toContainText('Monthly Attendance Report');
    
    await page.fill('[data-testid="date-range-start"]', '2024-01-01');
    await page.fill('[data-testid="date-range-end"]', '2024-01-31');
    
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-all"]');

    // Click 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="report-container"]', { timeout: 10000 });
    
    // Reports accessible and functional
    await expect(page.locator('[data-testid="report-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-status"]')).toContainText('Generated Successfully');

    // Click 'Export' button and select CSV format
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-format-csv"]');
    
    const downloadPromiseCSV = page.waitForEvent('download');
    await page.click('[data-testid="confirm-download-button"]');
    const downloadCSV = await downloadPromiseCSV;
    expect(downloadCSV.suggestedFilename()).toContain('.csv');

    // Return to report screen and export the same report as PDF
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-format-pdf"]');
    
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="confirm-download-button"]');
    const downloadPDF = await downloadPromisePDF;
    expect(downloadPDF.suggestedFilename()).toContain('.pdf');

    // Verify all report operations complete without any errors or access restrictions
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="report-container"]')).toBeVisible();
  });
});