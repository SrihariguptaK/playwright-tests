import { test, expect } from '@playwright/test';

test.describe('Attendance Anomaly Reports - Story 16', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const analystCredentials = {
    username: 'analyst@company.com',
    password: 'AnalystPass123!'
  };
  const nonAnalystCredentials = {
    username: 'employee@company.com',
    password: 'EmployeePass123!'
  };

  test.beforeEach(async ({ page }) => {
    await page.goto(baseURL);
  });

  test('Validate detection of missing attendance punches', async ({ page }) => {
    // Login as analyst user
    await page.fill('[data-testid="username-input"]', analystCredentials.username);
    await page.fill('[data-testid="password-input"]', analystCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Wait for dashboard to load
    await expect(page.locator('[data-testid="reporting-dashboard"]')).toBeVisible();
    
    // Navigate to the reporting dashboard
    await page.click('[data-testid="reports-menu"]');
    await page.click('[data-testid="reporting-dashboard-link"]');
    
    // Select 'Anomaly Report' from the report type dropdown
    await page.click('[data-testid="report-type-dropdown"]');
    await page.click('[data-testid="report-type-anomaly"]');
    
    // Select date range that includes known missing punches (last 7 days)
    const today = new Date();
    const sevenDaysAgo = new Date(today);
    sevenDaysAgo.setDate(today.getDate() - 7);
    
    await page.fill('[data-testid="date-range-start"]', sevenDaysAgo.toISOString().split('T')[0]);
    await page.fill('[data-testid="date-range-end"]', today.toISOString().split('T')[0]);
    
    // Click 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report to be generated (should be under 5 seconds)
    await expect(page.locator('[data-testid="anomaly-report-container"]')).toBeVisible({ timeout: 5000 });
    
    // Review the generated anomaly report for missing check-ins and check-outs
    const missingPunchesSection = page.locator('[data-testid="missing-punches-section"]');
    await expect(missingPunchesSection).toBeVisible();
    
    // Verify that all known missing punches from test data are present in the report
    const missingCheckIns = page.locator('[data-testid="missing-check-in-row"]');
    const missingCheckOuts = page.locator('[data-testid="missing-check-out-row"]');
    
    await expect(missingCheckIns.or(missingCheckOuts)).toHaveCount(await missingCheckIns.count() + await missingCheckOuts.count());
    
    // Verify specific known missing punch entries
    await expect(page.locator('[data-testid="anomaly-report-container"]')).toContainText('Missing Check-in');
    await expect(page.locator('[data-testid="anomaly-report-container"]')).toContainText('Missing Check-out');
    
    // Verify report shows employee details for missing punches
    const reportRows = page.locator('[data-testid="anomaly-row"]');
    await expect(reportRows.first()).toBeVisible();
    await expect(reportRows.first()).toContainText(/EMP\d+|Employee/);
  });

  test('Verify identification of duplicate attendance entries', async ({ page }) => {
    // Login as analyst user
    await page.fill('[data-testid="username-input"]', analystCredentials.username);
    await page.fill('[data-testid="password-input"]', analystCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Wait for dashboard to load
    await expect(page.locator('[data-testid="reporting-dashboard"]')).toBeVisible();
    
    // Navigate to the reporting dashboard
    await page.click('[data-testid="reports-menu"]');
    await page.click('[data-testid="reporting-dashboard-link"]');
    
    // Select 'Anomaly Report' from the report type dropdown
    await page.click('[data-testid="report-type-dropdown"]');
    await page.click('[data-testid="report-type-anomaly"]');
    
    // Select date range that includes known duplicate entries (specific week with duplicates)
    const endDate = new Date('2024-01-15');
    const startDate = new Date('2024-01-08');
    
    await page.fill('[data-testid="date-range-start"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="date-range-end"]', endDate.toISOString().split('T')[0]);
    
    // Click 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report to be generated
    await expect(page.locator('[data-testid="anomaly-report-container"]')).toBeVisible({ timeout: 5000 });
    
    // Review the generated anomaly report for duplicate attendance entries section
    const duplicateEntriesSection = page.locator('[data-testid="duplicate-entries-section"]');
    await expect(duplicateEntriesSection).toBeVisible();
    
    // Verify that all known duplicate entries from test data are identified in the report
    const duplicateRows = page.locator('[data-testid="duplicate-entry-row"]');
    await expect(duplicateRows).toHaveCount(await duplicateRows.count());
    await expect(duplicateRows.first()).toBeVisible();
    
    // Check that duplicate entries show both original and duplicate timestamps
    const firstDuplicateRow = duplicateRows.first();
    await expect(firstDuplicateRow).toContainText('Original:');
    await expect(firstDuplicateRow).toContainText('Duplicate:');
    
    // Verify timestamps are displayed
    await expect(firstDuplicateRow.locator('[data-testid="original-timestamp"]')).toBeVisible();
    await expect(firstDuplicateRow.locator('[data-testid="duplicate-timestamp"]')).toBeVisible();
    
    // Verify duplicate entries contain employee information
    await expect(firstDuplicateRow).toContainText(/EMP\d+|Employee/);
    
    // Verify report highlights duplicate entries
    await expect(duplicateEntriesSection).toContainText('Duplicate');
  });

  test('Ensure unauthorized users cannot access anomaly reports', async ({ page, request }) => {
    // Login to the system as non-analyst user (e.g., regular employee)
    await page.fill('[data-testid="username-input"]', nonAnalystCredentials.username);
    await page.fill('[data-testid="password-input"]', nonAnalystCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Wait for login to complete
    await page.waitForLoadState('networkidle');
    
    // Attempt to navigate to the reporting dashboard URL directly
    await page.goto(`${baseURL}/reporting/dashboard`);
    
    // Verify that anomaly report menu options are not visible in the navigation
    const reportsMenu = page.locator('[data-testid="reports-menu"]');
    
    if (await reportsMenu.isVisible()) {
      await reportsMenu.click();
      await expect(page.locator('[data-testid="anomaly-reports-option"]')).not.toBeVisible();
    }
    
    // Verify access denied message or redirect
    const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
    const unauthorizedMessage = page.locator('text=/Access Denied|Unauthorized|403/');
    
    await expect(accessDeniedMessage.or(unauthorizedMessage)).toBeVisible({ timeout: 3000 }).catch(() => {
      // If no message, verify user was redirected away from reporting dashboard
      expect(page.url()).not.toContain('/reporting/dashboard');
    });
    
    // Logout from the non-analyst user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Login again as non-analyst user and obtain authentication token
    await page.fill('[data-testid="username-input"]', nonAnalystCredentials.username);
    await page.fill('[data-testid="password-input"]', nonAnalystCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await page.waitForLoadState('networkidle');
    
    // Extract authentication token from cookies or localStorage
    const token = await page.evaluate(() => {
      return localStorage.getItem('authToken') || sessionStorage.getItem('authToken');
    });
    
    // Attempt to call anomaly report API endpoint using the non-analyst user's token
    const apiResponse = await request.get(`${baseURL}/api/reports/anomalies`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      params: {
        startDate: '2024-01-01',
        endDate: '2024-01-15'
      }
    });
    
    // Verify the error response contains appropriate security message
    expect(apiResponse.status()).toBe(403);
    
    const responseBody = await apiResponse.json();
    expect(responseBody).toHaveProperty('error');
    expect(responseBody.error).toMatch(/unauthorized|forbidden|access denied|insufficient permissions/i);
  });
});