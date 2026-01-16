import { test, expect } from '@playwright/test';
import * as path from 'path';
import * as fs from 'fs';

test.describe('Attendance Summary Reports - Story 29', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const managerCredentials = {
    username: 'manager@company.com',
    password: 'Manager123!'
  };
  const unauthorizedCredentials = {
    username: 'employee@company.com',
    password: 'Employee123!'
  };

  test.beforeEach(async ({ page }) => {
    await page.goto(baseURL);
  });

  test('Validate attendance summary report generation (happy-path)', async ({ page }) => {
    // Login as authorized manager
    await page.fill('[data-testid="login-username"]', managerCredentials.username);
    await page.fill('[data-testid="login-password"]', managerCredentials.password);
    await page.click('[data-testid="login-submit"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to the attendance reports module from the main dashboard
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="attendance-reports-link"]');
    
    // Expected Result: Report interface is displayed
    await expect(page.locator('[data-testid="attendance-reports-interface"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-parameters-section"]')).toBeVisible();

    // Select a specific department from the department dropdown
    await page.click('[data-testid="department-dropdown"]');
    await page.click('[data-testid="department-option-engineering"]');
    await expect(page.locator('[data-testid="department-dropdown"]')).toContainText('Engineering');

    // Select a date range using the date picker (e.g., last 30 days)
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="date-range-last-30-days"]');
    await expect(page.locator('[data-testid="date-range-display"]')).toBeVisible();

    // Click the 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report generation (should be under 10 seconds)
    await expect(page.locator('[data-testid="report-loading-indicator"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-loading-indicator"]')).toBeHidden({ timeout: 10000 });

    // Expected Result: Report is generated with accurate data and visualizations
    await expect(page.locator('[data-testid="attendance-report-content"]')).toBeVisible();
    
    // Review the generated report data and verify metrics accuracy
    await expect(page.locator('[data-testid="report-total-hours"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-absences-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-late-arrivals-count"]')).toBeVisible();
    
    const totalHours = await page.locator('[data-testid="report-total-hours"]').textContent();
    expect(totalHours).toMatch(/\d+/);

    // Review the graphical visualizations in the report
    await expect(page.locator('[data-testid="attendance-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-visualization"]')).toBeVisible();

    // Click the 'Export as PDF' button
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    const downloadPDF = await downloadPromisePDF;
    
    // Expected Result: Files download successfully with correct content
    expect(downloadPDF.suggestedFilename()).toContain('.pdf');
    const pdfPath = path.join(__dirname, 'downloads', downloadPDF.suggestedFilename());
    await downloadPDF.saveAs(pdfPath);
    expect(fs.existsSync(pdfPath)).toBeTruthy();
    expect(fs.statSync(pdfPath).size).toBeGreaterThan(0);

    // Return to the report interface and click the 'Export as Excel' button
    await expect(page.locator('[data-testid="attendance-report-content"]')).toBeVisible();
    const downloadPromiseExcel = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-button"]');
    const downloadExcel = await downloadPromiseExcel;
    
    // Expected Result: Excel file downloads successfully with correct content
    expect(downloadExcel.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    const excelPath = path.join(__dirname, 'downloads', downloadExcel.suggestedFilename());
    await downloadExcel.saveAs(excelPath);
    expect(fs.existsSync(excelPath)).toBeTruthy();
    expect(fs.statSync(excelPath).size).toBeGreaterThan(0);
  });

  test('Ensure access control for attendance reports (error-case)', async ({ page }) => {
    // Login to the system using credentials of an unauthorized user
    await page.fill('[data-testid="login-username"]', unauthorizedCredentials.username);
    await page.fill('[data-testid="login-password"]', unauthorizedCredentials.password);
    await page.click('[data-testid="login-submit"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Attempt to navigate to the attendance reports module from the main menu
    await page.click('[data-testid="main-menu"]');
    
    // Expected Result: Access to reports is denied
    const attendanceReportsLink = page.locator('[data-testid="attendance-reports-link"]');
    await expect(attendanceReportsLink).not.toBeVisible();

    // Attempt to access the attendance reports module by entering the direct URL
    await page.goto(`${baseURL}/attendance/reports`);
    
    // Verify that access is denied or redirected
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/access denied|unauthorized|permission/i);
    
    // Verify that no attendance report data or interface elements are displayed
    await expect(page.locator('[data-testid="attendance-reports-interface"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="report-parameters-section"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="generate-report-button"]')).not.toBeVisible();

    // Logout from the unauthorized user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Login to the system using credentials of an authorized manager
    await page.fill('[data-testid="login-username"]', managerCredentials.username);
    await page.fill('[data-testid="login-password"]', managerCredentials.password);
    await page.click('[data-testid="login-submit"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to the attendance reports module from the main menu
    await page.click('[data-testid="main-menu"]');
    
    // Expected Result: Access to reports is granted
    await expect(page.locator('[data-testid="attendance-reports-link"]')).toBeVisible();
    
    // Click on the attendance reports module link
    await page.click('[data-testid="attendance-reports-link"]');
    
    // Verify that all report functionalities are accessible
    await expect(page.locator('[data-testid="attendance-reports-interface"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-parameters-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="department-dropdown"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-range-picker"]')).toBeVisible();
    await expect(page.locator('[data-testid="generate-report-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-pdf-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-excel-button"]')).toBeVisible();
  });
});