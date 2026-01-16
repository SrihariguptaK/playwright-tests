import { test, expect } from '@playwright/test';
import * as path from 'path';

test.describe('Bulk Upload Manual Attendance Records', () => {
  const HR_OFFICER_EMAIL = 'hr.officer@company.com';
  const HR_OFFICER_PASSWORD = 'HRPassword123';
  const EMPLOYEE_EMAIL = 'employee@company.com';
  const EMPLOYEE_PASSWORD = 'EmployeePassword123';
  const BULK_UPLOAD_URL = '/attendance/bulk-upload';

  test('Validate successful bulk upload with valid CSV', async ({ page }) => {
    // Login as HR Officer
    await page.goto('/login');
    await page.fill('input[name="email"]', HR_OFFICER_EMAIL);
    await page.fill('input[name="password"]', HR_OFFICER_PASSWORD);
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to bulk upload page from the main attendance menu
    await page.click('text=Attendance');
    await page.click('text=Bulk Upload');
    await expect(page).toHaveURL(new RegExp(BULK_UPLOAD_URL));

    // Verify upload form is displayed
    await expect(page.locator('h1, h2').filter({ hasText: /bulk upload/i })).toBeVisible();
    await expect(page.locator('text=CSV format instructions')).toBeVisible();
    await expect(page.locator('text=required columns')).toBeVisible();

    // Review the CSV format instructions and required columns
    await expect(page.locator('[data-testid="csv-format-instructions"]')).toBeVisible();

    // Click 'Choose File' or 'Browse' button to open file selector
    const fileInput = page.locator('input[type="file"]');
    await expect(fileInput).toBeVisible();

    // Select the valid CSV file containing 50 attendance records
    const validCSVPath = path.join(__dirname, 'test-data', 'valid-attendance-50-records.csv');
    await fileInput.setInputFiles(validCSVPath);

    // Click 'Upload' or 'Submit' button to initiate the bulk upload process
    await page.click('button:has-text("Upload"), button:has-text("Submit")');

    // Wait for the system to process the CSV file
    await page.waitForSelector('[data-testid="upload-summary"], .upload-summary', { timeout: 120000 });

    // System processes file and displays success summary
    await expect(page.locator('[data-testid="upload-summary"]')).toBeVisible();
    await expect(page.locator('text=Upload completed successfully')).toBeVisible();
    await expect(page.locator('[data-testid="success-count"]')).toContainText('50');
    await expect(page.locator('[data-testid="failure-count"]')).toContainText('0');

    // Navigate to the manual attendance records list
    await page.click('text=Attendance Records');
    await expect(page).toHaveURL(/.*attendance.*records/);

    // Search for specific records from the uploaded CSV
    await page.fill('input[placeholder*="Search"], input[name="search"]', 'EMP001');
    await page.click('button:has-text("Search")');
    await expect(page.locator('table tbody tr').first()).toBeVisible();

    // Verify a sample of 5 records by comparing CSV data with saved records
    const employeeIds = ['EMP001', 'EMP002', 'EMP003', 'EMP004', 'EMP005'];
    for (const empId of employeeIds) {
      await page.fill('input[placeholder*="Search"], input[name="search"]', empId);
      await page.click('button:has-text("Search")');
      await expect(page.locator(`td:has-text("${empId}")`)).toBeVisible();
    }

    // All valid records are persisted
    await expect(page.locator('[data-testid="total-records"]')).toContainText(/50|more/);
  });

  test('Verify error reporting for invalid CSV records', async ({ page }) => {
    // Login as HR Officer
    await page.goto('/login');
    await page.fill('input[name="email"]', HR_OFFICER_EMAIL);
    await page.fill('input[name="password"]', HR_OFFICER_PASSWORD);
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the bulk upload page
    await page.click('text=Attendance');
    await page.click('text=Bulk Upload');
    await expect(page).toHaveURL(new RegExp(BULK_UPLOAD_URL));

    // Click 'Choose File' button and select the CSV file containing 15 valid and 5 invalid records
    const fileInput = page.locator('input[type="file"]');
    const mixedCSVPath = path.join(__dirname, 'test-data', 'mixed-attendance-15valid-5invalid.csv');
    await fileInput.setInputFiles(mixedCSVPath);

    // Click 'Upload' button to submit the CSV file
    await page.click('button:has-text("Upload"), button:has-text("Submit")');

    // Wait for the system to complete validation and processing
    await page.waitForSelector('[data-testid="upload-summary"]', { timeout: 120000 });

    // System displays detailed error messages for invalid entries
    await expect(page.locator('[data-testid="upload-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-count"]')).toContainText('15');
    await expect(page.locator('[data-testid="failure-count"]')).toContainText('5');

    // Expand or view the detailed error report section
    const errorReportSection = page.locator('[data-testid="error-report"], .error-report');
    await expect(errorReportSection).toBeVisible();
    await expect(page.locator('text=Invalid date format')).toBeVisible();
    await expect(page.locator('text=Missing required field')).toBeVisible();

    // Download or export the error report if option is available
    const downloadButton = page.locator('button:has-text("Download Error Report"), a:has-text("Export Errors")');
    if (await downloadButton.isVisible()) {
      await downloadButton.click();
    }

    // Verify that valid records were saved by navigating to attendance records list
    await page.click('text=Attendance Records');
    await expect(page).toHaveURL(/.*attendance.*records/);
    await expect(page.locator('table tbody tr')).toHaveCount(15, { timeout: 10000 });

    // Return to bulk upload page and upload the corrected CSV file
    await page.click('text=Bulk Upload');
    await expect(page).toHaveURL(new RegExp(BULK_UPLOAD_URL));

    // Select the corrected CSV file and click Upload button
    const correctedCSVPath = path.join(__dirname, 'test-data', 'corrected-attendance-5-records.csv');
    await fileInput.setInputFiles(correctedCSVPath);
    await page.click('button:has-text("Upload"), button:has-text("Submit")');

    // System accepts corrected records and saves them
    await page.waitForSelector('[data-testid="upload-summary"]', { timeout: 120000 });
    await expect(page.locator('[data-testid="success-count"]')).toContainText('5');
    await expect(page.locator('[data-testid="failure-count"]')).toContainText('0');
    await expect(page.locator('text=Upload completed successfully')).toBeVisible();

    // Verify the 5 corrected records are now saved in the system
    await page.click('text=Attendance Records');
    await expect(page.locator('table tbody tr')).toHaveCount(20, { timeout: 10000 });
  });

  test('Ensure access control for bulk upload functionality - unauthorized user', async ({ page }) => {
    // Open the application login page
    await page.goto('/login');
    await expect(page.locator('input[name="email"]')).toBeVisible();

    // Enter username and password for the unauthorized user
    await page.fill('input[name="email"]', EMPLOYEE_EMAIL);
    await page.fill('input[name="password"]', EMPLOYEE_PASSWORD);

    // Click Login button
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Verify that bulk upload menu option is not visible in the navigation menu
    await page.click('text=Attendance');
    const bulkUploadMenu = page.locator('text=Bulk Upload');
    await expect(bulkUploadMenu).not.toBeVisible();

    // Attempt to navigate to the bulk upload page by entering the URL directly
    await page.goto(BULK_UPLOAD_URL);

    // Access to bulk upload page is denied
    await expect(page.locator('text=Access Denied, text=Unauthorized, text=403')).toBeVisible();
    await expect(page).not.toHaveURL(new RegExp(BULK_UPLOAD_URL));
  });

  test('Ensure access control for bulk upload functionality - authorized HR officer', async ({ page }) => {
    // Open the application login page
    await page.goto('/login');

    // Enter username and password for the authorized HR officer
    await page.fill('input[name="email"]', HR_OFFICER_EMAIL);
    await page.fill('input[name="password"]', HR_OFFICER_PASSWORD);

    // Click Login button
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the attendance menu
    await page.click('text=Attendance');

    // Click on the bulk upload menu option
    const bulkUploadMenu = page.locator('text=Bulk Upload');
    await expect(bulkUploadMenu).toBeVisible();
    await bulkUploadMenu.click();

    // Access to bulk upload page is granted
    await expect(page).toHaveURL(new RegExp(BULK_UPLOAD_URL));

    // Verify all bulk upload functionality is available
    await expect(page.locator('input[type="file"]')).toBeVisible();
    await expect(page.locator('button:has-text("Upload"), button:has-text("Submit")')).toBeVisible();
    await expect(page.locator('[data-testid="csv-format-instructions"], text=format instructions')).toBeVisible();
    await expect(page.locator('text=required columns')).toBeVisible();
  });
});