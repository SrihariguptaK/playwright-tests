import { test, expect } from '@playwright/test';
import path from 'path';

test.describe('Bulk Upload Manual Attendance Records', () => {
  const HR_OFFICER_EMAIL = 'hr.officer@company.com';
  const HR_OFFICER_PASSWORD = 'HRPassword123';
  const EMPLOYEE_EMAIL = 'employee@company.com';
  const EMPLOYEE_PASSWORD = 'EmployeePass123';
  const BULK_UPLOAD_URL = '/attendance/bulk-upload';

  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('Validate successful bulk upload with valid CSV', async ({ page }) => {
    // Login as HR Officer
    await page.fill('[data-testid="email-input"]', HR_OFFICER_EMAIL);
    await page.fill('[data-testid="password-input"]', HR_OFFICER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to bulk upload page from main attendance menu
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="bulk-upload-link"]');
    
    // Expected Result: Upload form is displayed
    await expect(page.locator('[data-testid="bulk-upload-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="file-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="upload-button"]')).toBeVisible();

    // Click on 'Download CSV Template' link to verify template format
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="download-template-link"]');
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.csv');

    // Select valid CSV file containing 50 records and submit
    const validCsvPath = path.join(__dirname, 'test-data', 'valid-attendance-50-records.csv');
    await page.setInputFiles('[data-testid="file-input"]', validCsvPath);
    
    // Click Upload button to initiate the bulk upload process
    const startTime = Date.now();
    await page.click('[data-testid="upload-button"]');
    
    // Wait for the upload process to complete
    await expect(page.locator('[data-testid="upload-progress"]')).toBeVisible();
    await expect(page.locator('[data-testid="upload-success-message"]')).toBeVisible({ timeout: 120000 });
    const endTime = Date.now();
    const processingTime = (endTime - startTime) / 1000;
    
    // Expected Result: System processes file and displays success summary
    expect(processingTime).toBeLessThan(120); // Under 2 minutes
    await expect(page.locator('[data-testid="upload-summary"]')).toBeVisible();
    
    // Review the detailed upload summary report
    const successCount = await page.locator('[data-testid="success-count"]').textContent();
    const failureCount = await page.locator('[data-testid="failure-count"]').textContent();
    expect(successCount).toBe('50');
    expect(failureCount).toBe('0');

    // Navigate to manual attendance records list and filter by upload date
    await page.click('[data-testid="view-records-link"]');
    await expect(page).toHaveURL(/.*attendance.*records/);
    
    const today = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="date-filter-input"]', today);
    await page.click('[data-testid="apply-filter-button"]');
    
    // Expected Result: All valid records are persisted
    await expect(page.locator('[data-testid="attendance-record-row"]')).toHaveCount(50);
    
    // Select a few random records and verify their details
    const firstRecord = page.locator('[data-testid="attendance-record-row"]').first();
    await firstRecord.click();
    await expect(page.locator('[data-testid="record-detail-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-name"]')).not.toBeEmpty();
    await expect(page.locator('[data-testid="attendance-date"]')).not.toBeEmpty();
    await page.click('[data-testid="close-modal-button"]');
  });

  test('Verify error reporting for invalid CSV records', async ({ page }) => {
    // Login as HR Officer
    await page.fill('[data-testid="email-input"]', HR_OFFICER_EMAIL);
    await page.fill('[data-testid="password-input"]', HR_OFFICER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the bulk upload page
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="bulk-upload-link"]');
    await expect(page.locator('[data-testid="bulk-upload-form"]')).toBeVisible();

    // Select CSV file containing 20 records (15 valid, 5 invalid) and click Upload
    const mixedCsvPath = path.join(__dirname, 'test-data', 'mixed-attendance-20-records.csv');
    await page.setInputFiles('[data-testid="file-input"]', mixedCsvPath);
    await page.click('[data-testid="upload-button"]');
    
    // Wait for validation and upload process to complete
    await expect(page.locator('[data-testid="upload-complete-message"]')).toBeVisible({ timeout: 120000 });
    
    // Expected Result: System displays detailed error messages for invalid entries
    await expect(page.locator('[data-testid="upload-summary"]')).toBeVisible();
    const successCount = await page.locator('[data-testid="success-count"]').textContent();
    const failureCount = await page.locator('[data-testid="failure-count"]').textContent();
    expect(successCount).toBe('15');
    expect(failureCount).toBe('5');
    
    // Review the error report section of the upload summary
    await expect(page.locator('[data-testid="error-report-section"]')).toBeVisible();
    const errorRows = page.locator('[data-testid="error-row"]');
    await expect(errorRows).toHaveCount(5);
    
    // Verify each error row has detailed error message
    for (let i = 0; i < 5; i++) {
      const errorRow = errorRows.nth(i);
      await expect(errorRow.locator('[data-testid="error-message"]')).not.toBeEmpty();
      await expect(errorRow.locator('[data-testid="row-number"]')).not.toBeEmpty();
    }
    
    // Download or copy the error report
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="download-error-report-button"]');
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('error');
    
    // Verify that valid records were saved by navigating to attendance records list
    await page.click('[data-testid="view-records-link"]');
    await expect(page).toHaveURL(/.*attendance.*records/);
    const today = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="date-filter-input"]', today);
    await page.click('[data-testid="apply-filter-button"]');
    await expect(page.locator('[data-testid="attendance-record-row"]')).toHaveCount(15);
    
    // Navigate back to bulk upload page
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="bulk-upload-link"]');
    
    // Upload corrected CSV file containing only the 5 corrected records
    const correctedCsvPath = path.join(__dirname, 'test-data', 'corrected-attendance-5-records.csv');
    await page.setInputFiles('[data-testid="file-input"]', correctedCsvPath);
    await page.click('[data-testid="upload-button"]');
    
    // Expected Result: System accepts corrected records and saves them
    await expect(page.locator('[data-testid="upload-success-message"]')).toBeVisible({ timeout: 120000 });
    const correctedSuccessCount = await page.locator('[data-testid="success-count"]').textContent();
    const correctedFailureCount = await page.locator('[data-testid="failure-count"]').textContent();
    expect(correctedSuccessCount).toBe('5');
    expect(correctedFailureCount).toBe('0');
    
    // Verify all corrected records are now saved in the system
    await page.click('[data-testid="view-records-link"]');
    await page.fill('[data-testid="date-filter-input"]', today);
    await page.click('[data-testid="apply-filter-button"]');
    await expect(page.locator('[data-testid="attendance-record-row"]')).toHaveCount(20);
  });

  test('Ensure access control for bulk upload functionality', async ({ page }) => {
    // Open the application login page in a browser
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
    
    // Enter credentials for unauthorized user (Employee role) and click Login
    await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Attempt to navigate to bulk upload page by entering URL directly
    await page.goto(BULK_UPLOAD_URL);
    
    // Expected Result: Access to bulk upload page is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('text=Access Denied')).toBeVisible();
    await expect(page.locator('text=You do not have permission')).toBeVisible();
    
    // Check the main navigation menu for bulk upload option
    await page.click('[data-testid="attendance-menu"]');
    await expect(page.locator('[data-testid="bulk-upload-link"]')).not.toBeVisible();
    
    // Log out from the unauthorized user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);
    
    // Enter credentials for authorized HR officer and click Login
    await page.fill('[data-testid="email-input"]', HR_OFFICER_EMAIL);
    await page.fill('[data-testid="password-input"]', HR_OFFICER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Expected Result: Access to bulk upload page is granted
    // Check the main navigation menu for bulk upload option
    await page.click('[data-testid="attendance-menu"]');
    await expect(page.locator('[data-testid="bulk-upload-link"]')).toBeVisible();
    
    // Click on the bulk upload menu item or navigate to URL
    await page.click('[data-testid="bulk-upload-link"]');
    await expect(page).toHaveURL(new RegExp(BULK_UPLOAD_URL));
    
    // Verify all bulk upload features are functional
    await expect(page.locator('[data-testid="bulk-upload-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="file-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="upload-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="download-template-link"]')).toBeVisible();
    
    // Verify file selection is functional
    const testCsvPath = path.join(__dirname, 'test-data', 'valid-attendance-50-records.csv');
    await page.setInputFiles('[data-testid="file-input"]', testCsvPath);
    await expect(page.locator('[data-testid="file-name-display"]')).toContainText('valid-attendance-50-records.csv');
    
    // Verify upload button is enabled
    await expect(page.locator('[data-testid="upload-button"]')).toBeEnabled();
  });
});