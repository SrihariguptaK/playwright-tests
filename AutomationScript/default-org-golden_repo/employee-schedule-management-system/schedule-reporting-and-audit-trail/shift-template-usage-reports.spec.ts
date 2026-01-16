import { test, expect } from '@playwright/test';

test.describe('Shift Template Usage Reports', () => {
  test.beforeEach(async ({ page }) => {
    // Login as HR Manager
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'hrmanager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Generate shift template usage report with filters (happy-path)', async ({ page }) => {
    // Navigate to the reporting module from the main dashboard
    await page.click('[data-testid="reporting-module-link"]');
    await expect(page.locator('[data-testid="reporting-options"]')).toBeVisible();
    
    // Select 'Shift Template Usage Report' from the list of available reports
    await page.click('[data-testid="shift-template-usage-report-option"]');
    await expect(page.locator('[data-testid="report-filters-section"]')).toBeVisible();
    
    // Set the date range filter to the last 30 days using the date picker
    const today = new Date();
    const thirtyDaysAgo = new Date(today.getTime() - 30 * 24 * 60 * 60 * 1000);
    await page.click('[data-testid="date-range-start-picker"]');
    await page.fill('[data-testid="date-range-start-input"]', thirtyDaysAgo.toISOString().split('T')[0]);
    await page.click('[data-testid="date-range-end-picker"]');
    await page.fill('[data-testid="date-range-end-input"]', today.toISOString().split('T')[0]);
    
    // Select a specific department from the department dropdown filter
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.click('[data-testid="department-option-engineering"]');
    await expect(page.locator('[data-testid="department-filter-dropdown"]')).toContainText('Engineering');
    
    // Click the 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-results-table"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="report-results-table"] tbody tr')).not.toHaveCount(0);
    
    // Click the 'Export to PDF' button
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    const download = await downloadPromise;
    
    // Verify PDF file is downloaded with correct data
    expect(download.suggestedFilename()).toContain('shift-template-usage');
    expect(download.suggestedFilename()).toContain('.pdf');
    const path = await download.path();
    expect(path).toBeTruthy();
  });

  test('Restrict report access to authorized users (error-case)', async ({ page, context }) => {
    // Logout current user and login as unauthorized user (non-HR role)
    await page.click('[data-testid="user-menu-button"]');
    await page.click('[data-testid="logout-button"]');
    
    // Login as regular employee without HR permissions
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Attempt to navigate to the reporting module by entering the URL directly
    await page.goto('/reporting/shift-template-usage');
    
    // Verify that the user is redirected to an appropriate page (dashboard or error page)
    await page.waitForURL(/.*dashboard|.*error|.*unauthorized/, { timeout: 5000 });
    const currentUrl = page.url();
    expect(currentUrl).toMatch(/dashboard|error|unauthorized|403/);
    
    // Verify access denied message is displayed
    const errorMessage = page.locator('[data-testid="access-denied-message"], [data-testid="error-message"], text="Access denied"');
    await expect(errorMessage.first()).toBeVisible();
    
    // Attempt to access the report API endpoint directly
    const response = await context.request.get('/api/reports/shifttemplateusage', {
      params: {
        startDate: '2024-01-01',
        endDate: '2024-01-31',
        department: 'Engineering'
      }
    });
    
    // Verify API returns 403 Forbidden or 401 Unauthorized
    expect([401, 403]).toContain(response.status());
  });

  test('Verify report generation performance (boundary)', async ({ page }) => {
    // Navigate to the reporting module
    await page.click('[data-testid="reporting-module-link"]');
    await expect(page.locator('[data-testid="reporting-options"]')).toBeVisible();
    
    // Select 'Shift Template Usage Report' option
    await page.click('[data-testid="shift-template-usage-report-option"]');
    await expect(page.locator('[data-testid="report-filters-section"]')).toBeVisible();
    
    // Set date range filter to maximum range (last 12 months)
    const today = new Date();
    const twelveMonthsAgo = new Date(today.getTime() - 365 * 24 * 60 * 60 * 1000);
    await page.click('[data-testid="date-range-start-picker"]');
    await page.fill('[data-testid="date-range-start-input"]', twelveMonthsAgo.toISOString().split('T')[0]);
    await page.click('[data-testid="date-range-end-picker"]');
    await page.fill('[data-testid="date-range-end-input"]', today.toISOString().split('T')[0]);
    
    // Select 'All Departments' option to include all departments in the report
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.click('[data-testid="department-option-all"]');
    await expect(page.locator('[data-testid="department-filter-dropdown"]')).toContainText('All Departments');
    
    // Start a timer and click 'Generate Report' button
    const startTime = Date.now();
    await page.click('[data-testid="generate-report-button"]');
    
    // Monitor the time taken for the report to fully load and display on screen
    await expect(page.locator('[data-testid="report-results-table"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="report-loading-spinner"]')).not.toBeVisible({ timeout: 10000 });
    
    const endTime = Date.now();
    const loadTime = (endTime - startTime) / 1000;
    
    // Verify report is displayed within 5 seconds
    expect(loadTime).toBeLessThanOrEqual(5);
    
    // Verify that all data is rendered correctly
    await expect(page.locator('[data-testid="report-results-table"] thead')).toBeVisible();
    await expect(page.locator('[data-testid="report-results-table"] tbody tr')).not.toHaveCount(0);
    
    // Verify the report is fully interactive
    const firstRow = page.locator('[data-testid="report-results-table"] tbody tr').first();
    await expect(firstRow).toBeVisible();
    await firstRow.click();
    await expect(page.locator('[data-testid="report-row-details"], [data-testid="report-expanded-view"]')).toBeVisible();
    
    // Verify report contains expected columns
    await expect(page.locator('[data-testid="report-column-template-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-column-department"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-column-usage-count"]')).toBeVisible();
  });
});