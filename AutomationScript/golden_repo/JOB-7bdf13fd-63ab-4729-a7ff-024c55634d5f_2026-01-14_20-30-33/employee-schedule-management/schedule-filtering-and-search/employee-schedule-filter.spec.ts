import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Shift Type Filtering', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_USERNAME = 'employee@company.com';
  const VALID_PASSWORD = 'Password123!';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate shift type filtering functionality', async ({ page }) => {
    // Step 1: Employee logs into the portal and navigates to schedule
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and navigation
    await expect(page).toHaveURL(/.*dashboard|schedule/);
    
    // Navigate to Schedule section
    await page.click('[data-testid="schedule-menu"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Schedule displayed with all shifts
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    const allShiftsCount = await page.locator('[data-testid="shift-item"]').count();
    expect(allShiftsCount).toBeGreaterThan(0);
    
    // Step 2: Select a shift type filter (e.g., 'Morning')
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-morning"]');
    
    // Wait for filter to apply
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Schedule updates to show only morning shifts
    const filteredShifts = await page.locator('[data-testid="shift-item"]').all();
    expect(filteredShifts.length).toBeGreaterThan(0);
    expect(filteredShifts.length).toBeLessThanOrEqual(allShiftsCount);
    
    // Verify each displayed shift has shift type 'Morning'
    for (const shift of filteredShifts) {
      const shiftType = await shift.getAttribute('data-shift-type');
      expect(shiftType?.toLowerCase()).toBe('morning');
    }
    
    // Step 3: Clear the filter
    await page.click('[data-testid="clear-filter-button"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Full schedule is displayed again
    const restoredShiftsCount = await page.locator('[data-testid="shift-item"]').count();
    expect(restoredShiftsCount).toBe(allShiftsCount);
  });

  test('Ensure filter state persistence during navigation', async ({ page }) => {
    // Login to the application with valid employee credentials
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard|schedule/);
    
    // Navigate to the Schedule section
    await page.click('[data-testid="schedule-menu"]');
    await page.waitForLoadState('networkidle');
    
    // Step 1: Apply a shift type filter by selecting 'Evening'
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-evening"]');
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Filtered schedule displayed
    const filteredShifts = await page.locator('[data-testid="shift-item"]').all();
    expect(filteredShifts.length).toBeGreaterThan(0);
    for (const shift of filteredShifts) {
      const shiftType = await shift.getAttribute('data-shift-type');
      expect(shiftType?.toLowerCase()).toBe('evening');
    }
    
    // Step 2: Navigate to a different schedule view (e.g., from weekly to monthly)
    const currentView = await page.locator('[data-testid="schedule-view-selector"]').textContent();
    if (currentView?.toLowerCase().includes('weekly')) {
      await page.click('[data-testid="monthly-view-button"]');
    } else {
      await page.click('[data-testid="weekly-view-button"]');
    }
    await page.waitForLoadState('networkidle');
    
    // Navigate back to the original schedule view
    if (currentView?.toLowerCase().includes('weekly')) {
      await page.click('[data-testid="weekly-view-button"]');
    } else {
      await page.click('[data-testid="monthly-view-button"]');
    }
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Filter remains applied and schedule is filtered
    const persistedShifts = await page.locator('[data-testid="shift-item"]').all();
    expect(persistedShifts.length).toBeGreaterThan(0);
    for (const shift of persistedShifts) {
      const shiftType = await shift.getAttribute('data-shift-type');
      expect(shiftType?.toLowerCase()).toBe('evening');
    }
    
    // Navigate to another section and return to Schedule
    await page.click('[data-testid="dashboard-menu"]');
    await page.waitForLoadState('networkidle');
    await page.click('[data-testid="schedule-menu"]');
    await page.waitForLoadState('networkidle');
    
    // Verify filter still persists
    const stillFilteredShifts = await page.locator('[data-testid="shift-item"]').all();
    expect(stillFilteredShifts.length).toBeGreaterThan(0);
    for (const shift of stillFilteredShifts) {
      const shiftType = await shift.getAttribute('data-shift-type');
      expect(shiftType?.toLowerCase()).toBe('evening');
    }
    
    // Step 3: Logout and login again
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);
    
    // Login again with the same employee credentials
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard|schedule/);
    
    // Navigate to the Schedule section
    await page.click('[data-testid="schedule-menu"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Filters reset to default (no filters applied)
    const allShiftsAfterLogin = await page.locator('[data-testid="shift-item"]').all();
    expect(allShiftsAfterLogin.length).toBeGreaterThan(0);
    
    // Verify filter is not applied by checking for mixed shift types
    const shiftTypes = new Set<string>();
    for (const shift of allShiftsAfterLogin) {
      const shiftType = await shift.getAttribute('data-shift-type');
      if (shiftType) {
        shiftTypes.add(shiftType.toLowerCase());
      }
    }
    expect(shiftTypes.size).toBeGreaterThan(1);
  });

  test('Verify unauthorized access is blocked', async ({ page, context }) => {
    // Step 1: Ensure no user is currently logged in
    await context.clearCookies();
    await page.goto(`${BASE_URL}`);
    
    // Step 2: Attempt to directly access the schedule filtering page
    await page.goto(`${BASE_URL}/schedule`);
    
    // Expected Result: Access denied and redirected to login
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveURL(/.*login/);
    
    // Verify the schedule content is not accessible
    const scheduleContainer = page.locator('[data-testid="schedule-container"]');
    await expect(scheduleContainer).not.toBeVisible();
    
    // Verify login page is displayed
    await expect(page.locator('[data-testid="login-button"]')).toBeVisible();
    
    // Step 3: Attempt to access the schedule API endpoint directly without authentication
    const apiResponse = await page.request.get(`${BASE_URL}/api/schedules?employeeId=123&shiftType=morning`);
    
    // Expected Result: API returns unauthorized status
    expect(apiResponse.status()).toBe(401);
    
    // Verify error response
    const responseBody = await apiResponse.json().catch(() => null);
    if (responseBody) {
      expect(responseBody.error || responseBody.message).toBeTruthy();
    }
  });
});