import { test, expect } from '@playwright/test';

test.describe('Attendance Validation Reports - Story 25', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const AUDITOR_EMAIL = 'auditor@company.com';
  const AUDITOR_PASSWORD = 'AuditorPass123!';
  const UNAUTHORIZED_EMAIL = 'employee@company.com';
  const UNAUTHORIZED_PASSWORD = 'EmployeePass123!';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('Validate generation of attendance validation reports', async ({ page }) => {
    // Login as authorized auditor
    await page.fill('[data-testid="email-input"]', AUDITOR_EMAIL);
    await page.fill('[data-testid="password-input"]', AUDITOR_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Action: Navigate to validation reports module
    await page.click('[data-testid="validation-reports-menu"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Report generation interface is displayed
    await expect(page.locator('[data-testid="validation-reports-header"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-generation-interface"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-range-picker"]')).toBeVisible();
    await expect(page.locator('[data-testid="department-filter"]')).toBeVisible();

    // Action: Select date range and filters
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="last-30-days-option"]');
    
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-option-engineering"]');
    
    await page.click('[data-testid="employee-filter"]');
    await page.fill('[data-testid="employee-search-input"]', 'John Doe');
    await page.click('[data-testid="employee-option-john-doe"]');
    
    // Expected Result: Filters are applied without errors
    await expect(page.locator('[data-testid="selected-date-range"]')).toContainText('Last 30 days');
    await expect(page.locator('[data-testid="selected-department"]')).toContainText('Engineering');
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();

    // Action: Generate report
    const startTime = Date.now();
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report to be generated
    await page.waitForSelector('[data-testid="validation-report-table"]', { timeout: 15000 });
    const endTime = Date.now();
    const generationTime = (endTime - startTime) / 1000;
    
    // Expected Result: Report is generated within 10 seconds displaying anomalies
    expect(generationTime).toBeLessThan(10);
    await expect(page.locator('[data-testid="validation-report-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-anomalies-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-summary"]')).toBeVisible();
    
    // Verify anomalies are displayed
    const anomalyRows = page.locator('[data-testid="anomaly-row"]');
    await expect(anomalyRows.first()).toBeVisible();
  });

  test('Test report export functionality', async ({ page }) => {
    // Login as authorized auditor
    await page.fill('[data-testid="email-input"]', AUDITOR_EMAIL);
    await page.fill('[data-testid="password-input"]', AUDITOR_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to validation reports module
    await page.click('[data-testid="validation-reports-menu"]');
    await page.waitForLoadState('networkidle');

    // Action: Generate validation report
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="last-30-days-option"]');
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="validation-report-table"]', { timeout: 15000 });
    
    // Expected Result: Report is displayed on screen
    await expect(page.locator('[data-testid="validation-report-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-options"]')).toBeVisible();

    // Action: Export report as PDF
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-button"]')
    ]);
    
    // Expected Result: PDF file downloads successfully
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    expect(pdfDownload.suggestedFilename()).toContain('validation-report');
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();

    // Action: Export report as CSV
    const [csvDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-csv-button"]')
    ]);
    
    // Expected Result: CSV file downloads successfully
    expect(csvDownload.suggestedFilename()).toContain('.csv');
    expect(csvDownload.suggestedFilename()).toContain('validation-report');
    const csvPath = await csvDownload.path();
    expect(csvPath).toBeTruthy();
  });

  test('Ensure access control for validation reports - unauthorized user', async ({ page }) => {
    // Action: Login as unauthorized user
    await page.fill('[data-testid="email-input"]', UNAUTHORIZED_EMAIL);
    await page.fill('[data-testid="password-input"]', UNAUTHORIZED_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Expected Result: Access to validation reports is denied
    // Verify validation reports menu is not visible for unauthorized user
    const validationReportsMenu = page.locator('[data-testid="validation-reports-menu"]');
    await expect(validationReportsMenu).not.toBeVisible();

    // Attempt to navigate directly to validation reports URL
    await page.goto(`${BASE_URL}/attendance/validation-reports`);
    
    // Verify access denied message or redirect
    const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
    const unauthorizedMessage = page.locator('text=/Access Denied|Unauthorized|403/');
    
    await expect(
      accessDeniedMessage.or(unauthorizedMessage)
    ).toBeVisible({ timeout: 5000 });
    
    // Verify user is redirected away from validation reports
    await expect(page).not.toHaveURL(/.*validation-reports/);
  });

  test('Ensure access control for validation reports - authorized auditor', async ({ page }) => {
    // Action: Login as authorized auditor
    await page.fill('[data-testid="email-input"]', AUDITOR_EMAIL);
    await page.fill('[data-testid="password-input"]', AUDITOR_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Expected Result: Access to validation reports is granted
    // Verify validation reports menu is visible
    await expect(page.locator('[data-testid="validation-reports-menu"]')).toBeVisible();

    // Navigate to validation reports module
    await page.click('[data-testid="validation-reports-menu"]');
    await page.waitForLoadState('networkidle');
    
    // Verify all report features are accessible
    await expect(page).toHaveURL(/.*validation-reports/);
    await expect(page.locator('[data-testid="validation-reports-header"]')).toBeVisible();
    
    // Verify generation features
    await expect(page.locator('[data-testid="date-range-picker"]')).toBeVisible();
    await expect(page.locator('[data-testid="department-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="generate-report-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="generate-report-button"]')).toBeEnabled();
    
    // Generate a report to verify export options
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="last-7-days-option"]');
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="validation-report-table"]', { timeout: 15000 });
    
    // Verify filtering features
    await expect(page.locator('[data-testid="report-filter-options"]')).toBeVisible();
    
    // Verify export features
    await expect(page.locator('[data-testid="export-pdf-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-pdf-button"]')).toBeEnabled();
    await expect(page.locator('[data-testid="export-csv-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-csv-button"]')).toBeEnabled();
  });
});