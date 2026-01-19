import { test, expect } from '@playwright/test';

test.describe('Schedule Adherence Reports - Story 6', () => {
  test.beforeEach(async ({ page }) => {
    // Login as Manager user before each test
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'ManagerPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate schedule adherence report generation with filters', async ({ page }) => {
    // Step 1: Navigate to reporting page
    await page.click('[data-testid="reports-menu"]');
    await expect(page.locator('[data-testid="reporting-page"]')).toBeVisible();
    await expect(page).toHaveURL(/.*reports/);

    // Step 2: Select schedule adherence report and apply filters
    await page.selectOption('[data-testid="report-type-dropdown"]', 'Schedule Adherence Report');
    
    // Apply date range filter - last 30 days
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="last-30-days-option"]');
    
    // Apply department filter - Sales
    await page.selectOption('[data-testid="department-filter"]', 'Sales');
    
    // Apply employee filter - All
    await page.selectOption('[data-testid="employee-filter"]', 'All');
    
    await expect(page.locator('[data-testid="filters-applied-indicator"]')).toBeVisible();

    // Step 3: Generate report and verify it displays within 5 seconds
    const startTime = Date.now();
    await page.click('[data-testid="generate-report-button"]');
    
    await expect(page.locator('[data-testid="report-results"]')).toBeVisible({ timeout: 5000 });
    const endTime = Date.now();
    const generationTime = endTime - startTime;
    
    expect(generationTime).toBeLessThan(5000);
    await expect(page.locator('[data-testid="report-title"]')).toContainText('Schedule Adherence Report');
    await expect(page.locator('[data-testid="report-data-table"]')).toBeVisible();
  });

  test('Verify report export to PDF and Excel', async ({ page }) => {
    // Step 1: Generate schedule adherence report
    await page.click('[data-testid="reports-menu"]');
    await page.selectOption('[data-testid="report-type-dropdown"]', 'Schedule Adherence Report');
    
    // Apply filters - last 7 days, IT department
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="last-7-days-option"]');
    await page.selectOption('[data-testid="department-filter"]', 'IT');
    
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-results"]')).toBeVisible();

    // Step 2: Export report to PDF
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-button"]')
    ]);
    
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();

    // Step 3: Export report to Excel
    const [excelDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-excel-button"]')
    ]);
    
    expect(excelDownload.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
  });

  test('Ensure unauthorized users cannot access reports', async ({ page }) => {
    // Logout from manager account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 1: Login as non-Manager user (Employee role)
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Attempt to access reporting page directly via URL
    await page.goto('/reports');
    
    // Verify access is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/unauthorized|access denied|permission/i);
    
    // Verify user is redirected or reporting page is not accessible
    const currentUrl = page.url();
    expect(currentUrl).not.toContain('/reports');
    
    // Verify reports menu is not visible for non-manager users
    await expect(page.locator('[data-testid="reports-menu"]')).not.toBeVisible();
  });
});