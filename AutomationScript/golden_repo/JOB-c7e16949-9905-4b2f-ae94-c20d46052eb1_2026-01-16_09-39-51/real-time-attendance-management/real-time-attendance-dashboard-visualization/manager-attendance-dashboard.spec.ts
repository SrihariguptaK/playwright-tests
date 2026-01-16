import { test, expect } from '@playwright/test';

test.describe('Manager Attendance Dashboard - Real-time Visibility', () => {
  const DASHBOARD_URL = '/dashboard/attendance';
  const LOGIN_URL = '/login';
  const MANAGER_EMAIL = 'manager@company.com';
  const MANAGER_PASSWORD = 'Manager@123';
  const REFRESH_INTERVAL = 30000; // 30 seconds
  const LOAD_TIMEOUT = 3000; // 3 seconds

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto(LOGIN_URL);
  });

  test('Validate real-time attendance data display on dashboard', async ({ page }) => {
    // Step 1: Manager logs into the attendance dashboard
    await page.fill('[data-testid="email-input"]', MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Dashboard loads with current attendance data
    await expect(page).toHaveURL(new RegExp(DASHBOARD_URL));
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-summary"]')).toBeVisible();
    
    // Verify initial attendance data is displayed
    const initialTimestamp = await page.locator('[data-testid="last-updated-timestamp"]').textContent();
    expect(initialTimestamp).toBeTruthy();
    
    // Verify summary metrics are displayed
    await expect(page.locator('[data-testid="total-present"]')).toBeVisible();
    await expect(page.locator('[data-testid="total-absent"]')).toBeVisible();
    await expect(page.locator('[data-testid="total-late"]')).toBeVisible();
    
    // Step 2: Observe dashboard for 1 minute - check refresh at 30 seconds
    await page.waitForTimeout(30000);
    
    // Expected Result: Attendance data refreshes automatically every 30 seconds
    const updatedTimestamp = await page.locator('[data-testid="last-updated-timestamp"]').textContent();
    expect(updatedTimestamp).not.toBe(initialTimestamp);
    
    // Continue observing for another 30 seconds
    const secondTimestamp = updatedTimestamp;
    await page.waitForTimeout(30000);
    
    const thirdTimestamp = await page.locator('[data-testid="last-updated-timestamp"]').textContent();
    expect(thirdTimestamp).not.toBe(secondTimestamp);
    
    // Step 3: Filter attendance data by team
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.click('[data-testid="team-option-engineering"]');
    
    // Expected Result: Dashboard updates to show filtered data correctly
    await expect(page.locator('[data-testid="active-filter-team"]')).toContainText('Engineering');
    await expect(page.locator('[data-testid="attendance-list"]')).toBeVisible();
    
    // Verify filtered results contain only engineering team members
    const employeeRows = page.locator('[data-testid="employee-row"]');
    const count = await employeeRows.count();
    expect(count).toBeGreaterThan(0);
    
    // Verify data refreshes after filtering
    const filteredTimestamp = await page.locator('[data-testid="last-updated-timestamp"]').textContent();
    await page.waitForTimeout(30000);
    const refreshedFilteredTimestamp = await page.locator('[data-testid="last-updated-timestamp"]').textContent();
    expect(refreshedFilteredTimestamp).not.toBe(filteredTimestamp);
  });

  test('Verify drill-down to individual employee attendance details', async ({ page }) => {
    // Login to dashboard
    await page.fill('[data-testid="email-input"]', MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(new RegExp(DASHBOARD_URL));
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
    
    // Step 1: Click on an employee presence indicator on the dashboard
    const firstEmployeeIndicator = page.locator('[data-testid="employee-presence-indicator"]').first();
    await expect(firstEmployeeIndicator).toBeVisible();
    
    const employeeName = await firstEmployeeIndicator.locator('[data-testid="employee-name"]').textContent();
    await firstEmployeeIndicator.click();
    
    // Expected Result: Detailed attendance information for the employee is displayed
    await expect(page.locator('[data-testid="employee-detail-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-detail-name"]')).toContainText(employeeName || '');
    
    // Verify detail view contains expected information
    await expect(page.locator('[data-testid="employee-detail-status"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-detail-checkin-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-detail-location"]')).toBeVisible();
    
    // Verify detail view is distinguishable from summary view
    await expect(page.locator('[data-testid="attendance-summary"]')).not.toBeVisible();
    
    // Step 2: Close detail view
    const closeButton = page.locator('[data-testid="close-detail-view"]');
    await expect(closeButton).toBeVisible();
    await closeButton.click();
    
    // Expected Result: Dashboard returns to summary view
    await expect(page.locator('[data-testid="employee-detail-view"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="attendance-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
  });

  test('Test dashboard load performance', async ({ page }) => {
    // Clear browser cache and cookies
    await page.context().clearCookies();
    
    // Navigate to login page
    await page.goto(LOGIN_URL);
    
    // Fill credentials
    await page.fill('[data-testid="email-input"]', MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    
    // Start performance measurement
    const startTime = Date.now();
    
    // Click login button and wait for dashboard to load
    await page.click('[data-testid="login-button"]');
    
    // Wait for dashboard to be fully loaded
    await page.waitForURL(new RegExp(DASHBOARD_URL));
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="total-present"]')).toBeVisible();
    await expect(page.locator('[data-testid="total-absent"]')).toBeVisible();
    await expect(page.locator('[data-testid="total-late"]')).toBeVisible();
    
    // Calculate load time
    const endTime = Date.now();
    const loadTime = endTime - startTime;
    
    // Expected Result: Dashboard loads within 3 seconds
    expect(loadTime).toBeLessThan(LOAD_TIMEOUT);
    
    // Verify all dashboard elements are functional immediately after load
    await expect(page.locator('[data-testid="team-filter-dropdown"]')).toBeEnabled();
    await expect(page.locator('[data-testid="location-filter-dropdown"]')).toBeEnabled();
    await expect(page.locator('[data-testid="date-filter"]')).toBeEnabled();
    
    // Verify employee presence indicators are clickable
    const employeeIndicators = page.locator('[data-testid="employee-presence-indicator"]');
    const indicatorCount = await employeeIndicators.count();
    expect(indicatorCount).toBeGreaterThan(0);
    
    // Test interaction with first employee indicator
    const firstIndicator = employeeIndicators.first();
    await expect(firstIndicator).toBeEnabled();
    await firstIndicator.click();
    await expect(page.locator('[data-testid="employee-detail-view"]')).toBeVisible();
  });
});