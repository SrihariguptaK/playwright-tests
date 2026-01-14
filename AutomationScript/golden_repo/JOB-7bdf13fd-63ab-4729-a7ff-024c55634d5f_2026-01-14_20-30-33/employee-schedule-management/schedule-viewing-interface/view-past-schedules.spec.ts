import { test, expect } from '@playwright/test';

test.describe('View Past Schedules - Story 8', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_USERNAME = 'employee@company.com';
  const VALID_PASSWORD = 'Password123!';
  const EMPLOYEE_ID = '12345';

  test('Validate retrieval of past schedules by date range (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the application login page and enter valid employee credentials
    await page.goto(`${BASE_URL}/login`);
    await expect(page).toHaveURL(/.*login/);
    
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Schedule interface displayed
    await expect(page).toHaveURL(/.*dashboard|schedule/);
    await page.waitForLoadState('networkidle');
    
    // Step 2: Navigate to the schedule section
    await page.click('[data-testid="schedule-menu-item"]');
    await expect(page).toHaveURL(/.*schedule/);
    await expect(page.locator('[data-testid="schedule-interface"]')).toBeVisible();
    
    // Step 3: Locate and click on the date range selector
    await page.click('[data-testid="date-range-selector"]');
    await expect(page.locator('[data-testid="date-range-picker"]')).toBeVisible();
    
    // Step 4: Select a past date range (e.g., last month)
    const lastMonthStart = new Date();
    lastMonthStart.setMonth(lastMonthStart.getMonth() - 1);
    lastMonthStart.setDate(1);
    const lastMonthEnd = new Date();
    lastMonthEnd.setDate(0);
    
    await page.fill('[data-testid="start-date-input"]', lastMonthStart.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-input"]', lastMonthEnd.toISOString().split('T')[0]);
    await page.click('[data-testid="apply-date-range-button"]');
    
    // Expected Result: Schedules for selected range are displayed
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    await expect(page.locator('[data-testid="schedule-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-item"]').first()).toBeVisible();
    
    // Step 5: Verify shift details and data accuracy
    const scheduleItems = page.locator('[data-testid="schedule-item"]');
    const itemCount = await scheduleItems.count();
    expect(itemCount).toBeGreaterThan(0);
    
    // Verify first schedule item contains required details
    const firstItem = scheduleItems.first();
    await expect(firstItem.locator('[data-testid="shift-date"]')).toBeVisible();
    await expect(firstItem.locator('[data-testid="shift-time"]')).toBeVisible();
    await expect(firstItem.locator('[data-testid="shift-location"]')).toBeVisible();
    
    // Expected Result: Displayed data matches historical records
    const shiftDate = await firstItem.locator('[data-testid="shift-date"]').textContent();
    const shiftDateObj = new Date(shiftDate || '');
    expect(shiftDateObj.getTime()).toBeGreaterThanOrEqual(lastMonthStart.getTime());
    expect(shiftDateObj.getTime()).toBeLessThanOrEqual(lastMonthEnd.getTime());
    
    // Step 6: Click Logout button to end the session
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);
  });

  test('Ensure performance under large data loads (boundary)', async ({ page }) => {
    // Login first
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForLoadState('networkidle');
    
    // Step 1: Navigate to the schedule section from the main dashboard
    await page.click('[data-testid="schedule-menu-item"]');
    await expect(page).toHaveURL(/.*schedule/);
    
    // Step 2: Open the date range selector and select a large date range (12 months)
    await page.click('[data-testid="date-range-selector"]');
    
    const twelveMonthsAgo = new Date();
    twelveMonthsAgo.setMonth(twelveMonthsAgo.getMonth() - 12);
    const today = new Date();
    
    await page.fill('[data-testid="start-date-input"]', twelveMonthsAgo.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-input"]', today.toISOString().split('T')[0]);
    
    // Step 3: Start timer and click Apply to request the large dataset
    const startTime = Date.now();
    await page.click('[data-testid="apply-date-range-button"]');
    
    // Expected Result: Data loads within 3 seconds without errors
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200,
      { timeout: 3000 }
    );
    
    await expect(page.locator('[data-testid="schedule-list"]')).toBeVisible({ timeout: 3000 });
    const endTime = Date.now();
    const loadTime = (endTime - startTime) / 1000;
    
    // Step 4: Monitor the loading process and measure time
    expect(loadTime).toBeLessThan(3);
    
    // Step 5: Verify that all data is rendered correctly
    const scheduleItems = page.locator('[data-testid="schedule-item"]');
    const itemCount = await scheduleItems.count();
    expect(itemCount).toBeGreaterThan(0);
    
    // Verify no error messages are displayed
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
    
    // Step 6: Test navigation through the large dataset
    if (await page.locator('[data-testid="pagination-next"]').isVisible()) {
      await page.click('[data-testid="pagination-next"]');
      await expect(page.locator('[data-testid="schedule-list"]')).toBeVisible();
    }
    
    // Step 7: Check browser console for errors
    const consoleErrors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });
    
    expect(consoleErrors.length).toBe(0);
  });

  test('Verify access control for historical schedules (error-case)', async ({ page, context }) => {
    // Step 1: Open a new browser window or incognito session (already isolated by Playwright context)
    // Step 2: Attempt to directly access the past schedules URL without authentication
    const pastScheduleUrl = `${BASE_URL}/schedules?dateRange=past`;
    await page.goto(pastScheduleUrl);
    
    // Expected Result: Access denied and redirected to login
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveURL(/.*login/);
    
    // Step 3: Observe the system response to the unauthorized access attempt
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
    
    // Step 4: Verify that no schedule data is visible or accessible
    await expect(page.locator('[data-testid="schedule-list"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="schedule-item"]')).not.toBeVisible();
    
    // Step 5: Check the URL after redirection
    const currentUrl = page.url();
    expect(currentUrl).toContain('login');
    
    // Step 6: Attempt to access the API endpoint directly without authentication token
    const apiResponse = await page.request.get(`${BASE_URL}/api/schedules?employeeId=${EMPLOYEE_ID}&dateRange=2024-01-01,2024-12-31`);
    
    // Expected Result: API returns 401 Unauthorized or 403 Forbidden
    expect([401, 403]).toContain(apiResponse.status());
    
    // Verify response does not contain schedule data
    const responseBody = await apiResponse.text();
    expect(responseBody).not.toContain('shift');
    expect(responseBody).not.toContain('schedule');
  });
});