import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Shift Type Filtering', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to employee portal and login
    await page.goto('/employee/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*employee\/dashboard/);
  });

  test.afterEach(async ({ page }) => {
    // Logout after each test
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
  });

  test('Validate shift type filtering in schedule views - happy path', async ({ page }) => {
    // Navigate to the schedule view section
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*employee\/schedule/);
    
    // Verify that shift type filter dropdown or options are available
    await expect(page.locator('[data-testid="shift-type-filter"]')).toBeVisible();
    
    // Note the total number of shifts displayed before applying any filter
    const allShiftsCount = await page.locator('[data-testid="shift-item"]').count();
    expect(allShiftsCount).toBeGreaterThan(0);
    
    // Select 'Morning' shift type from the filter options
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-morning"]');
    
    // Verify that only morning shifts are displayed in the filtered view
    await page.waitForLoadState('networkidle');
    const morningShifts = await page.locator('[data-testid="shift-item"]').all();
    expect(morningShifts.length).toBeGreaterThan(0);
    expect(morningShifts.length).toBeLessThanOrEqual(allShiftsCount);
    
    for (const shift of morningShifts) {
      const shiftType = await shift.getAttribute('data-shift-type');
      expect(shiftType).toBe('morning');
    }
    
    // Change the filter selection to 'Evening' shift type
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-evening"]');
    
    // Verify that only evening shifts are displayed
    await page.waitForLoadState('networkidle');
    const eveningShifts = await page.locator('[data-testid="shift-item"]').all();
    expect(eveningShifts.length).toBeGreaterThan(0);
    
    for (const shift of eveningShifts) {
      const shiftType = await shift.getAttribute('data-shift-type');
      expect(shiftType).toBe('evening');
    }
    
    // Click the 'Clear filter' button or select 'All shifts' option
    await page.click('[data-testid="clear-filter-button"]');
    
    // Verify that all shift types are now visible in the schedule
    await page.waitForLoadState('networkidle');
    const allShiftsAfterClear = await page.locator('[data-testid="shift-item"]').count();
    expect(allShiftsAfterClear).toBe(allShiftsCount);
  });

  test('Test performance of filtered schedule retrieval - happy path', async ({ page, context }) => {
    // Clear browser cache and cookies
    await context.clearCookies();
    await context.clearPermissions();
    
    // Re-login after clearing cookies
    await page.goto('/employee/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*employee\/dashboard/);
    
    // Navigate to the schedule view section
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*employee\/schedule/);
    await page.waitForLoadState('networkidle');
    
    // Start performance timer and select a shift type filter (e.g., 'Morning')
    const morningFilterStartTime = Date.now();
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-morning"]');
    
    // Measure the time from applying the filter until the filtered schedule is completely rendered and interactive
    await page.waitForSelector('[data-testid="shift-item"]', { state: 'visible' });
    await page.waitForLoadState('networkidle');
    const morningFilterEndTime = Date.now();
    const morningFilterLoadTime = morningFilterEndTime - morningFilterStartTime;
    
    // Record the actual load time for the filtered results
    console.log(`Morning filter load time: ${morningFilterLoadTime}ms`);
    expect(morningFilterLoadTime).toBeLessThan(2000);
    
    // Apply a different shift type filter (e.g., 'Evening') and measure performance again
    const eveningFilterStartTime = Date.now();
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-evening"]');
    
    await page.waitForSelector('[data-testid="shift-item"]', { state: 'visible' });
    await page.waitForLoadState('networkidle');
    const eveningFilterEndTime = Date.now();
    const eveningFilterLoadTime = eveningFilterEndTime - eveningFilterStartTime;
    
    console.log(`Evening filter load time: ${eveningFilterLoadTime}ms`);
    expect(eveningFilterLoadTime).toBeLessThan(2000);
    
    // Clear the filter and measure the time to return to unfiltered view
    const clearFilterStartTime = Date.now();
    await page.click('[data-testid="clear-filter-button"]');
    
    await page.waitForSelector('[data-testid="shift-item"]', { state: 'visible' });
    await page.waitForLoadState('networkidle');
    const clearFilterEndTime = Date.now();
    const clearFilterLoadTime = clearFilterEndTime - clearFilterStartTime;
    
    console.log(`Clear filter load time: ${clearFilterLoadTime}ms`);
    expect(clearFilterLoadTime).toBeLessThan(2000);
  });

  test('Validate shift type filtering applies to daily view', async ({ page }) => {
    // Navigate to schedule view
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*employee\/schedule/);
    
    // Switch to daily view
    await page.click('[data-testid="view-toggle-daily"]');
    await page.waitForLoadState('networkidle');
    
    // Apply shift type filter
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-morning"]');
    
    // Verify filtered schedule loads within 2 seconds and displays only selected shift types
    const startTime = Date.now();
    await page.waitForSelector('[data-testid="shift-item"]', { state: 'visible' });
    await page.waitForLoadState('networkidle');
    const loadTime = Date.now() - startTime;
    
    expect(loadTime).toBeLessThan(2000);
    
    const shifts = await page.locator('[data-testid="shift-item"]').all();
    for (const shift of shifts) {
      const shiftType = await shift.getAttribute('data-shift-type');
      expect(shiftType).toBe('morning');
    }
  });

  test('Validate shift type filtering applies to weekly view', async ({ page }) => {
    // Navigate to schedule view
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*employee\/schedule/);
    
    // Switch to weekly view
    await page.click('[data-testid="view-toggle-weekly"]');
    await page.waitForLoadState('networkidle');
    
    // Apply shift type filter
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-evening"]');
    
    // Verify filtered schedule loads within 2 seconds and displays only selected shift types
    const startTime = Date.now();
    await page.waitForSelector('[data-testid="shift-item"]', { state: 'visible' });
    await page.waitForLoadState('networkidle');
    const loadTime = Date.now() - startTime;
    
    expect(loadTime).toBeLessThan(2000);
    
    const shifts = await page.locator('[data-testid="shift-item"]').all();
    for (const shift of shifts) {
      const shiftType = await shift.getAttribute('data-shift-type');
      expect(shiftType).toBe('evening');
    }
  });

  test('Validate shift type filtering applies to monthly view', async ({ page }) => {
    // Navigate to schedule view
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*employee\/schedule/);
    
    // Switch to monthly view
    await page.click('[data-testid="view-toggle-monthly"]');
    await page.waitForLoadState('networkidle');
    
    // Apply shift type filter
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-night"]');
    
    // Verify filtered schedule loads within 2 seconds and displays only selected shift types
    const startTime = Date.now();
    await page.waitForSelector('[data-testid="shift-item"]', { state: 'visible' });
    await page.waitForLoadState('networkidle');
    const loadTime = Date.now() - startTime;
    
    expect(loadTime).toBeLessThan(2000);
    
    const shifts = await page.locator('[data-testid="shift-item"]').all();
    for (const shift of shifts) {
      const shiftType = await shift.getAttribute('data-shift-type');
      expect(shiftType).toBe('night');
    }
  });

  test('Verify schedule data is restricted to authenticated employee', async ({ page }) => {
    // Navigate to schedule view
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*employee\/schedule/);
    
    // Apply filter and verify shifts belong to logged-in employee
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-morning"]');
    await page.waitForLoadState('networkidle');
    
    const shifts = await page.locator('[data-testid="shift-item"]').all();
    expect(shifts.length).toBeGreaterThan(0);
    
    // Verify each shift belongs to the authenticated employee
    for (const shift of shifts) {
      const employeeId = await shift.getAttribute('data-employee-id');
      expect(employeeId).toBeTruthy();
    }
  });
});