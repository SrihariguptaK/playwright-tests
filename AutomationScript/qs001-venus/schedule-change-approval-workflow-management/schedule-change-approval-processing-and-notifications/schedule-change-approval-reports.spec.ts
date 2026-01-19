import { test, expect } from '@playwright/test';

test.describe('Schedule Change Approval Reports', () => {
  test.beforeEach(async ({ page }) => {
    // Login as manager before each test
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'ManagerPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('View schedule change approval dashboard with filters', async ({ page }) => {
    // Step 1: Manager navigates to reporting dashboard
    await page.click('[data-testid="reports-menu"]');
    await expect(page.locator('[data-testid="reporting-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="metrics-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="charts-container"]')).toBeVisible();

    // Step 2: Manager selects Schedule Change Approval Reports
    await page.click('[data-testid="schedule-change-approval-reports"]');
    await expect(page.locator('[data-testid="approval-metrics-dashboard"]')).toBeVisible();

    // Step 3: Manager applies date range filter
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="custom-date-range-option"]');
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    await page.fill('[data-testid="start-date-input"]', thirtyDaysAgo.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-input"]', new Date().toISOString().split('T')[0]);

    // Step 4: Manager selects department filter
    await page.click('[data-testid="department-dropdown"]');
    await page.click('[data-testid="department-option-engineering"]');

    // Step 5: Manager applies filters
    await page.click('[data-testid="apply-filters-button"]');
    
    // Verify dashboard updates with filtered data
    await expect(page.locator('[data-testid="filtered-results-indicator"]')).toBeVisible();
    await expect(page.locator('[data-testid="department-filter-tag"]')).toContainText('Engineering');
    await expect(page.locator('[data-testid="date-range-filter-tag"]')).toBeVisible();

    // Step 6: Manager exports report as CSV
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-csv-option"]');
    
    // Wait for download and verify
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="confirm-export-button"]');
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.csv');
    expect(download.suggestedFilename()).toContain('schedule-change-approval');
  });

  test('Verify dashboard load time under normal load', async ({ page }) => {
    // Step 1: Navigate to reporting portal and measure load time
    const startTime = Date.now();
    
    await page.click('[data-testid="reports-menu"]');
    await page.click('[data-testid="schedule-change-approval-reports"]');
    
    // Wait for all dashboard components to be visible
    await expect(page.locator('[data-testid="approval-metrics-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="metrics-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="charts-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-times-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="pending-requests-widget"]')).toBeVisible();
    
    const endTime = Date.now();
    const loadTime = (endTime - startTime) / 1000;
    
    // Verify dashboard loads within 3 seconds
    expect(loadTime).toBeLessThan(3);
    
    // Step 2: Verify all dashboard components are interactive
    await expect(page.locator('[data-testid="date-range-filter"]')).toBeEnabled();
    await expect(page.locator('[data-testid="department-dropdown"]')).toBeEnabled();
    await expect(page.locator('[data-testid="approver-filter"]')).toBeEnabled();
    await expect(page.locator('[data-testid="export-button"]')).toBeEnabled();
    
    // Verify charts are responsive
    await page.click('[data-testid="approval-times-chart"]');
    await expect(page.locator('[data-testid="chart-tooltip"]')).toBeVisible();
  });

  test('Ensure unauthorized users cannot access reports', async ({ page }) => {
    // Logout manager and login as non-manager user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Login as regular employee
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Step 1: Non-manager attempts to access reporting dashboard via menu
    const reportsMenu = page.locator('[data-testid="reports-menu"]');
    
    // Verify Reports menu is either not visible or disabled for non-managers
    if (await reportsMenu.isVisible()) {
      await expect(reportsMenu).toBeDisabled();
    }
    
    // Step 2: Attempt direct URL access
    await page.goto('/reports/schedule-change-approvals');
    
    // Verify access denied message is displayed
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    await expect(page.locator('[data-testid="unauthorized-access-text"]')).toContainText('You do not have permission to view this page');
    
    // Step 3: Verify no report data or dashboard elements are visible
    await expect(page.locator('[data-testid="approval-metrics-dashboard"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="metrics-container"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="charts-container"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="export-button"]')).not.toBeVisible();
    
    // Verify user is redirected or shown error page
    const currentUrl = page.url();
    expect(currentUrl).toMatch(/access-denied|unauthorized|403/);
  });
});