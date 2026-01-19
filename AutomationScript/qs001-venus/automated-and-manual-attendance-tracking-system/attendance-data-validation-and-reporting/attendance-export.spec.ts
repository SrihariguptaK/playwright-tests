import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

test.describe('Attendance Data Export to Payroll Systems', () => {
  const HR_MANAGER_USERNAME = 'hr.manager@company.com';
  const HR_MANAGER_PASSWORD = 'HRManager123!';
  const BASE_URL = 'http://localhost:3000';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate successful attendance data export (happy-path)', async ({ page }) => {
    // Step 1: Login as HR manager
    await page.fill('input[data-testid="username-input"]', HR_MANAGER_USERNAME);
    await page.fill('input[data-testid="password-input"]', HR_MANAGER_PASSWORD);
    await page.click('button[data-testid="login-button"]');
    
    // Expected Result: Access granted to export interface
    await expect(page).toHaveURL(/.*\/dashboard/);
    await expect(page.locator('[data-testid="user-role"]')).toContainText('HR Manager');

    // Step 2: Navigate to attendance export interface
    await page.click('a[data-testid="attendance-menu"]');
    await page.click('a[data-testid="export-attendance-link"]');
    
    // Expected Result: Export interface is accessible
    await expect(page).toHaveURL(/.*\/attendance\/export/);
    await expect(page.locator('h1[data-testid="page-title"]')).toContainText('Export Attendance Data');

    // Step 2: Select pay period and CSV format
    // Select start date for pay period
    await page.click('input[data-testid="pay-period-start-date"]');
    await page.fill('input[data-testid="pay-period-start-date"]', '2024-01-01');
    
    // Select end date for pay period
    await page.click('input[data-testid="pay-period-end-date"]');
    await page.fill('input[data-testid="pay-period-end-date"]', '2024-01-15');
    
    // Select CSV format from dropdown
    await page.click('select[data-testid="export-format-dropdown"]');
    await page.selectOption('select[data-testid="export-format-dropdown"]', 'CSV');
    
    // Expected Result: Filters applied successfully
    await expect(page.locator('input[data-testid="pay-period-start-date"]')).toHaveValue('2024-01-01');
    await expect(page.locator('input[data-testid="pay-period-end-date"]')).toHaveValue('2024-01-15');
    await expect(page.locator('select[data-testid="export-format-dropdown"]')).toHaveValue('CSV');

    // Step 3: Generate and download export file
    await page.click('button[data-testid="generate-export-button"]');
    
    // Wait for file generation to complete
    await expect(page.locator('[data-testid="export-status"]')).toContainText('Export generated successfully', { timeout: 15000 });
    await expect(page.locator('button[data-testid="download-button"]')).toBeVisible();
    await expect(page.locator('button[data-testid="download-button"]')).toBeEnabled();
    
    // Setup download listener
    const downloadPromise = page.waitForEvent('download');
    await page.click('button[data-testid="download-button"]');
    const download = await downloadPromise;
    
    // Expected Result: File generated with correct data and format
    expect(download.suggestedFilename()).toMatch(/attendance_export_.*\.csv/);
    
    // Verify download completed
    const downloadPath = await download.path();
    expect(downloadPath).toBeTruthy();
    
    // Verify export activity is logged
    await expect(page.locator('[data-testid="export-log-entry"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="export-log-entry"]').first()).toContainText('2024-01-01');
    await expect(page.locator('[data-testid="export-log-entry"]').first()).toContainText('2024-01-15');
    await expect(page.locator('[data-testid="export-log-entry"]').first()).toContainText('CSV');
  });

  test('Verify export validation blocks incomplete data (error-case)', async ({ page }) => {
    // Step 1: Login as HR manager
    await page.fill('input[data-testid="username-input"]', HR_MANAGER_USERNAME);
    await page.fill('input[data-testid="password-input"]', HR_MANAGER_PASSWORD);
    await page.click('button[data-testid="login-button"]');
    
    // Navigate to export interface
    await page.click('a[data-testid="attendance-menu"]');
    await page.click('a[data-testid="export-attendance-link"]');
    await expect(page).toHaveURL(/.*\/attendance\/export/);

    // Step 2: Select a pay period with incomplete attendance data
    // This period is known to have incomplete records (missing clock-in/out times)
    await page.click('input[data-testid="pay-period-start-date"]');
    await page.fill('input[data-testid="pay-period-start-date"]', '2024-02-01');
    
    await page.click('input[data-testid="pay-period-end-date"]');
    await page.fill('input[data-testid="pay-period-end-date"]', '2024-02-15');
    
    // Select export format (CSV)
    await page.click('select[data-testid="export-format-dropdown"]');
    await page.selectOption('select[data-testid="export-format-dropdown"]', 'CSV');

    // Step 3: Attempt to generate export
    await page.click('button[data-testid="generate-export-button"]');
    
    // Expected Result: System displays validation error and blocks export
    await expect(page.locator('[data-testid="validation-error-message"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="validation-error-message"]')).toContainText('incomplete attendance data');
    
    // Verify specific validation errors are displayed
    const errorList = page.locator('[data-testid="validation-error-list"]');
    await expect(errorList).toBeVisible();
    await expect(errorList.locator('li')).toContainText(['missing clock-in', 'missing clock-out', 'required fields']);
    
    // Verify download button is not available/enabled
    await expect(page.locator('button[data-testid="download-button"]')).not.toBeVisible();
    
    // Verify export was not generated
    await expect(page.locator('[data-testid="export-status"]')).toContainText('Export failed due to validation errors');
    
    // Verify error is logged in export activity log
    await expect(page.locator('[data-testid="export-log-entry"]').first()).toContainText('Failed');
    await expect(page.locator('[data-testid="export-log-entry"]').first()).toContainText('Validation error');
  });

  test('Verify XML format export with complete data', async ({ page }) => {
    // Login as HR manager
    await page.fill('input[data-testid="username-input"]', HR_MANAGER_USERNAME);
    await page.fill('input[data-testid="password-input"]', HR_MANAGER_PASSWORD);
    await page.click('button[data-testid="login-button"]');
    
    // Navigate to export interface
    await page.click('a[data-testid="attendance-menu"]');
    await page.click('a[data-testid="export-attendance-link"]');

    // Select pay period
    await page.fill('input[data-testid="pay-period-start-date"]', '2024-01-01');
    await page.fill('input[data-testid="pay-period-end-date"]', '2024-01-15');
    
    // Select XML format
    await page.selectOption('select[data-testid="export-format-dropdown"]', 'XML');
    await expect(page.locator('select[data-testid="export-format-dropdown"]')).toHaveValue('XML');

    // Generate export
    await page.click('button[data-testid="generate-export-button"]');
    
    // Wait for successful generation
    await expect(page.locator('[data-testid="export-status"]')).toContainText('Export generated successfully', { timeout: 15000 });
    
    // Download file
    const downloadPromise = page.waitForEvent('download');
    await page.click('button[data-testid="download-button"]');
    const download = await downloadPromise;
    
    // Verify XML file format
    expect(download.suggestedFilename()).toMatch(/attendance_export_.*\.xml/);
  });

  test('Verify export activity logging with user and timestamp', async ({ page }) => {
    // Login as HR manager
    await page.fill('input[data-testid="username-input"]', HR_MANAGER_USERNAME);
    await page.fill('input[data-testid="password-input"]', HR_MANAGER_PASSWORD);
    await page.click('button[data-testid="login-button"]');
    
    // Navigate to export interface
    await page.click('a[data-testid="attendance-menu"]');
    await page.click('a[data-testid="export-attendance-link"]');

    // Perform export
    await page.fill('input[data-testid="pay-period-start-date"]', '2024-01-01');
    await page.fill('input[data-testid="pay-period-end-date"]', '2024-01-15');
    await page.selectOption('select[data-testid="export-format-dropdown"]', 'CSV');
    await page.click('button[data-testid="generate-export-button"]');
    
    // Wait for export completion
    await expect(page.locator('[data-testid="export-status"]')).toContainText('Export generated successfully', { timeout: 15000 });
    
    // Navigate to export logs or verify log entry on same page
    const logEntry = page.locator('[data-testid="export-log-entry"]').first();
    await expect(logEntry).toBeVisible();
    
    // Verify log contains user information
    await expect(logEntry.locator('[data-testid="log-user"]')).toContainText(HR_MANAGER_USERNAME);
    
    // Verify log contains timestamp
    const timestamp = await logEntry.locator('[data-testid="log-timestamp"]').textContent();
    expect(timestamp).toBeTruthy();
    expect(timestamp).toMatch(/\d{4}-\d{2}-\d{2}/);
    
    // Verify log contains export details
    await expect(logEntry).toContainText('2024-01-01');
    await expect(logEntry).toContainText('2024-01-15');
    await expect(logEntry).toContainText('CSV');
    await expect(logEntry.locator('[data-testid="log-status"]')).toContainText('Success');
  });
});