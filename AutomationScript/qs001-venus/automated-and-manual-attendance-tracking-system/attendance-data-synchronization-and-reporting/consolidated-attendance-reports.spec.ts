import { test, expect } from '@playwright/test';
import path from 'path';
import fs from 'fs';

test.describe('Consolidated Attendance Reports - Story 7', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const attendanceManagerCredentials = {
    username: 'attendance.manager@company.com',
    password: 'AttendanceManager@123'
  };
  const unauthorizedUserCredentials = {
    username: 'regular.user@company.com',
    password: 'RegularUser@123'
  };

  test.beforeEach(async ({ page }) => {
    await page.goto(baseURL);
  });

  test('Validate generation of consolidated attendance reports (happy-path)', async ({ page }) => {
    // Login as attendance manager
    await page.fill('[data-testid="username-input"]', attendanceManagerCredentials.username);
    await page.fill('[data-testid="password-input"]', attendanceManagerCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Action: Navigate to reporting module
    await page.click('[data-testid="reporting-module-link"]');
    
    // Expected Result: Reporting interface is displayed
    await expect(page.locator('[data-testid="reporting-interface"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-type-selector"]')).toBeVisible();

    // Action: Select filters and generate report
    await page.selectOption('[data-testid="report-type-selector"]', 'consolidated-attendance');
    await page.fill('[data-testid="date-range-start"]', '2024-01-01');
    await page.fill('[data-testid="date-range-end"]', '2024-01-31');
    await page.selectOption('[data-testid="department-filter"]', 'Engineering');
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Consolidated attendance report is displayed
    await expect(page.locator('[data-testid="consolidated-report-container"]')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('[data-testid="report-title"]')).toContainText('Consolidated Attendance Report');
    await expect(page.locator('[data-testid="report-data-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-data-row"]').first()).toBeVisible();

    // Action: Export report in PDF format
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-pdf-option"]');
    
    // Expected Result: PDF file downloads with correct data
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.pdf');
    expect(download.suggestedFilename()).toContain('attendance-report');
    
    const downloadPath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(downloadPath);
    expect(fs.existsSync(downloadPath)).toBeTruthy();
  });

  test('Verify report filtering and export options (happy-path)', async ({ page }) => {
    // Login as attendance manager
    await page.fill('[data-testid="username-input"]', attendanceManagerCredentials.username);
    await page.fill('[data-testid="password-input"]', attendanceManagerCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to reporting module
    await page.click('[data-testid="reporting-module-link"]');
    await expect(page.locator('[data-testid="reporting-interface"]')).toBeVisible();

    // Action: Apply filters for specific employee and date range
    await page.selectOption('[data-testid="report-type-selector"]', 'consolidated-attendance');
    await page.click('[data-testid="employee-filter-dropdown"]');
    await page.fill('[data-testid="employee-search-input"]', 'John Doe');
    await page.click('[data-testid="employee-option-john-doe"]');
    
    await page.fill('[data-testid="date-range-start"]', '2024-01-15');
    await page.fill('[data-testid="date-range-end"]', '2024-01-31');
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Report displays filtered attendance data
    await expect(page.locator('[data-testid="consolidated-report-container"]')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('[data-testid="report-data-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="filtered-employee-name"]')).toContainText('John Doe');
    await expect(page.locator('[data-testid="report-date-range"]')).toContainText('2024-01-15');
    await expect(page.locator('[data-testid="report-date-range"]')).toContainText('2024-01-31');

    // Action: Export report in Excel format
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-excel-option"]');
    
    // Expected Result: Excel file downloads with correct data
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    expect(download.suggestedFilename()).toContain('attendance-report');
    
    const downloadPath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(downloadPath);
    expect(fs.existsSync(downloadPath)).toBeTruthy();
    const stats = fs.statSync(downloadPath);
    expect(stats.size).toBeGreaterThan(0);
  });

  test('Ensure access control for reporting features (error-case)', async ({ page }) => {
    // Action: Login as unauthorized user
    await page.fill('[data-testid="username-input"]', unauthorizedUserCredentials.username);
    await page.fill('[data-testid="password-input"]', unauthorizedUserCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Attempt to navigate to reporting module
    const reportingLink = page.locator('[data-testid="reporting-module-link"]');
    
    // Expected Result: Access to reporting module is denied
    if (await reportingLink.isVisible()) {
      await reportingLink.click();
      await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
      await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    } else {
      // Reporting module link should not be visible for unauthorized users
      await expect(reportingLink).not.toBeVisible();
    }

    // Try direct navigation to reporting URL
    await page.goto(`${baseURL}/reporting`);
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="unauthorized-error"]')).toContainText('unauthorized');

    // Action: Logout from unauthorized user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-button"]')).toBeVisible();

    // Action: Login using attendance manager credentials
    await page.fill('[data-testid="username-input"]', attendanceManagerCredentials.username);
    await page.fill('[data-testid="password-input"]', attendanceManagerCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Expected Result: Access to reporting module is granted
    await expect(page.locator('[data-testid="reporting-module-link"]')).toBeVisible();
    await page.click('[data-testid="reporting-module-link"]');
    await expect(page.locator('[data-testid="reporting-interface"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-type-selector"]')).toBeVisible();
    await expect(page.locator('[data-testid="generate-report-button"]')).toBeVisible();
  });
});