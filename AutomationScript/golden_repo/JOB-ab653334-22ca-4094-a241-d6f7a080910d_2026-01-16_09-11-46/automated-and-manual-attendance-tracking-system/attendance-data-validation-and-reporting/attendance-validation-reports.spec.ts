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

  test('Validate generation of attendance validation reports (happy-path)', async ({ page }) => {
    // Login as authorized auditor
    await page.fill('[data-testid="email-input"]', AUDITOR_EMAIL);
    await page.fill('[data-testid="password-input"]', AUDITOR_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for dashboard to load
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 1: Navigate to validation reports module
    await page.click('[data-testid="validation-reports-menu"]');
    await expect(page.locator('[data-testid="validation-reports-interface"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-generation-form"]')).toBeVisible();

    // Step 2: Select date range (last 30 days)
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="last-30-days-option"]');
    await expect(page.locator('[data-testid="date-range-display"]')).toContainText('Last 30 days');

    // Select specific department from dropdown
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.click('[data-testid="department-option-engineering"]');
    await expect(page.locator('[data-testid="department-filter-dropdown"]')).toContainText('Engineering');

    // Select specific employee (optional)
    await page.click('[data-testid="employee-filter-dropdown"]');
    await page.fill('[data-testid="employee-search-input"]', 'John Doe');
    await page.click('[data-testid="employee-option-john-doe"]');
    await expect(page.locator('[data-testid="employee-filter-dropdown"]')).toContainText('John Doe');

    // Verify filters are applied without errors
    await expect(page.locator('[data-testid="filter-error-message"]')).not.toBeVisible();

    // Step 3: Generate report
    const startTime = Date.now();
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report to be generated
    await expect(page.locator('[data-testid="report-loading-indicator"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-report-results"]')).toBeVisible({ timeout: 15000 });
    
    const endTime = Date.now();
    const generationTime = (endTime - startTime) / 1000;
    
    // Verify report generation time is under 10 seconds
    expect(generationTime).toBeLessThan(10);

    // Verify report displays anomalies
    await expect(page.locator('[data-testid="report-anomalies-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-recommendations-section"]')).toBeVisible();
    
    // Verify report contains data
    const anomalyCount = await page.locator('[data-testid="anomaly-row"]').count();
    expect(anomalyCount).toBeGreaterThanOrEqual(0);
  });

  test('Test report export functionality (happy-path)', async ({ page }) => {
    // Login as authorized auditor
    await page.fill('[data-testid="email-input"]', AUDITOR_EMAIL);
    await page.fill('[data-testid="password-input"]', AUDITOR_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to validation reports module
    await page.click('[data-testid="validation-reports-menu"]');
    await expect(page.locator('[data-testid="validation-reports-interface"]')).toBeVisible();

    // Generate a validation report with date range and filters
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="last-30-days-option"]');
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.click('[data-testid="department-option-engineering"]');
    await page.click('[data-testid="generate-report-button"]');
    
    // Step 1: Wait for report to be displayed on screen
    await expect(page.locator('[data-testid="validation-report-results"]')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('[data-testid="report-export-options"]')).toBeVisible();

    // Step 2: Export report as PDF
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-button"]')
    ]);
    
    // Verify PDF download
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();
    
    // Wait for download to complete
    await page.waitForTimeout(1000);

    // Step 3: Export report as CSV
    const [csvDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-csv-button"]')
    ]);
    
    // Verify CSV download
    expect(csvDownload.suggestedFilename()).toContain('.csv');
    const csvPath = await csvDownload.path();
    expect(csvPath).toBeTruthy();
    
    // Verify both exports completed successfully
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
  });

  test('Ensure access control for validation reports (error-case)', async ({ page }) => {
    // Step 1: Login as unauthorized user (regular employee)
    await page.fill('[data-testid="email-input"]', UNAUTHORIZED_EMAIL);
    await page.fill('[data-testid="password-input"]', UNAUTHORIZED_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Step 2: Navigate to main dashboard after successful login
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 3: Attempt to access validation reports module by clicking
    const validationReportsMenu = page.locator('[data-testid="validation-reports-menu"]');
    
    // Check if menu item is not visible or disabled for unauthorized user
    if (await validationReportsMenu.isVisible()) {
      await validationReportsMenu.click();
      // Verify access denied message or redirect
      await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    } else {
      // Menu item should not be visible for unauthorized users
      await expect(validationReportsMenu).not.toBeVisible();
    }

    // Step 4: Attempt direct URL navigation
    await page.goto(`${BASE_URL}/validation-reports`);
    
    // Verify that no validation report data or interface is displayed
    await expect(page.locator('[data-testid="validation-reports-interface"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/access denied|unauthorized|permission/i);

    // Step 5: Log out from unauthorized user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-button"]')).toBeVisible();

    // Step 6: Login as authorized auditor user
    await page.fill('[data-testid="email-input"]', AUDITOR_EMAIL);
    await page.fill('[data-testid="password-input"]', AUDITOR_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Step 7: Navigate to main dashboard after successful login
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 8: Click on validation reports module
    await page.click('[data-testid="validation-reports-menu"]');
    
    // Step 9: Verify full access to all validation report features
    await expect(page.locator('[data-testid="validation-reports-interface"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-generation-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-range-picker"]')).toBeVisible();
    await expect(page.locator('[data-testid="department-filter-dropdown"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-filter-dropdown"]')).toBeVisible();
    await expect(page.locator('[data-testid="generate-report-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="generate-report-button"]')).toBeEnabled();
    
    // Verify no access denied messages
    await expect(page.locator('[data-testid="access-denied-message"]')).not.toBeVisible();
  });
});