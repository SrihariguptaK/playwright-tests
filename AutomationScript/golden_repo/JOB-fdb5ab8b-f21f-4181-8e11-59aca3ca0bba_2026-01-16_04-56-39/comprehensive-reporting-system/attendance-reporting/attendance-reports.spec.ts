import { test, expect } from '@playwright/test';

test.describe('Attendance Report Generation - Story 2', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const HR_USER_EMAIL = 'hr.specialist@company.com';
  const HR_USER_PASSWORD = 'HRPassword123!';
  const NON_HR_USER_EMAIL = 'employee@company.com';
  const NON_HR_USER_PASSWORD = 'EmployeePass123!';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('Validate attendance report generation with valid filters', async ({ page }) => {
    // Login as HR specialist
    await page.fill('[data-testid="email-input"]', HR_USER_EMAIL);
    await page.fill('[data-testid="password-input"]', HR_USER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Action: Navigate to attendance reporting module
    await page.click('[data-testid="attendance-reports-menu"]');
    await page.waitForURL(/.*attendance-reports/);
    
    // Expected Result: Attendance report UI is displayed
    await expect(page.locator('[data-testid="attendance-report-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-range-picker"]')).toBeVisible();
    await expect(page.locator('[data-testid="department-filter"]')).toBeVisible();

    // Action: Select valid date range and filters
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="preset-last-7-days"]');
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-option-engineering"]');
    
    // Expected Result: Filters accepted without errors
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="date-range-display"]')).toContainText('Last 7 days');
    await expect(page.locator('[data-testid="department-filter"]')).toContainText('Engineering');

    // Action: Request report generation
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Attendance report is generated and displayed with correct data
    await expect(page.locator('[data-testid="report-loading-spinner"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-loading-spinner"]')).not.toBeVisible({ timeout: 20000 });
    await expect(page.locator('[data-testid="attendance-report-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-header"]')).toContainText('Attendance Report');
    await expect(page.locator('[data-testid="report-department-label"]')).toContainText('Engineering');
    
    // Verify report contains data rows
    const reportRows = page.locator('[data-testid="report-row"]');
    await expect(reportRows).not.toHaveCount(0);
    
    // Verify report columns are present
    await expect(page.locator('[data-testid="column-employee-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="column-date"]')).toBeVisible();
    await expect(page.locator('[data-testid="column-status"]')).toBeVisible();
  });

  test('Verify export functionality for attendance reports', async ({ page }) => {
    // Login as HR specialist
    await page.fill('[data-testid="email-input"]', HR_USER_EMAIL);
    await page.fill('[data-testid="password-input"]', HR_USER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to attendance reporting module
    await page.click('[data-testid="attendance-reports-menu"]');
    await page.waitForURL(/.*attendance-reports/);

    // Select a date range of last 30 days and a specific department filter
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="preset-last-30-days"]');
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-option-engineering"]');

    // Action: Generate attendance report with filters
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-loading-spinner"]')).not.toBeVisible({ timeout: 20000 });
    
    // Expected Result: Report displayed on screen
    await expect(page.locator('[data-testid="attendance-report-table"]')).toBeVisible();
    const reportRows = page.locator('[data-testid="report-row"]');
    const rowCount = await reportRows.count();
    expect(rowCount).toBeGreaterThan(0);

    // Action: Export report to CSV
    const downloadPromiseCSV = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-button"]');
    const downloadCSV = await downloadPromiseCSV;
    
    // Expected Result: CSV file is downloaded with correct data
    expect(downloadCSV.suggestedFilename()).toContain('.csv');
    expect(downloadCSV.suggestedFilename()).toContain('attendance');
    const csvPath = await downloadCSV.path();
    expect(csvPath).toBeTruthy();

    // Wait for download to complete
    await page.waitForTimeout(1000);

    // Action: Export report to PDF
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    const downloadPDF = await downloadPromisePDF;
    
    // Expected Result: PDF file is downloaded with correct formatting
    expect(downloadPDF.suggestedFilename()).toContain('.pdf');
    expect(downloadPDF.suggestedFilename()).toContain('attendance');
    const pdfPath = await downloadPDF.path();
    expect(pdfPath).toBeTruthy();
    
    // Verify export success message
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
  });

  test('Ensure unauthorized users cannot access attendance reports', async ({ page }) => {
    // Action: Login as non-HR user
    await page.fill('[data-testid="email-input"]', NON_HR_USER_EMAIL);
    await page.fill('[data-testid="password-input"]', NON_HR_USER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Expected Result: Access to attendance reporting module is denied
    // Verify attendance reports menu is not visible for non-HR users
    await expect(page.locator('[data-testid="attendance-reports-menu"]')).not.toBeVisible();

    // Action: Attempt to access attendance reporting module directly by URL
    await page.goto(`${BASE_URL}/attendance-reports`);
    
    // Expected Result: Access denied or redirected
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/access denied|unauthorized|forbidden/i);
    
    // Verify user is redirected away from attendance reports page
    await page.waitForTimeout(500);
    expect(page.url()).not.toContain('attendance-reports');

    // Action: Attempt to access API endpoint directly
    const apiResponse = await page.request.get(`${BASE_URL}/api/reports/attendance`, {
      params: {
        startDate: '2024-01-01',
        endDate: '2024-01-31',
        department: 'Engineering'
      }
    });
    
    // Expected Result: Access forbidden response received
    expect(apiResponse.status()).toBe(403);
    const responseBody = await apiResponse.json();
    expect(responseBody).toHaveProperty('error');
    expect(responseBody.error).toMatch(/forbidden|unauthorized|access denied/i);
  });
});