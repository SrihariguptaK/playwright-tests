import { test, expect } from '@playwright/test';

test.describe('Story-14: Filter Schedule by Shift Type', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page and authenticate as employee
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and navigation to dashboard
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to schedule view
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    await page.waitForLoadState('networkidle');
  });

  test('Validate shift type filter application', async ({ page }) => {
    // Verify initial schedule is displayed with all shifts
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    const initialShiftCount = await page.locator('[data-testid="shift-item"]').count();
    expect(initialShiftCount).toBeGreaterThan(0);

    // Step 1: Employee selects 'Morning' shift filter
    await page.click('[data-testid="shift-type-filter-dropdown"]');
    await page.click('[data-testid="filter-option-morning"]');
    
    // Wait for schedule to update
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    await page.waitForTimeout(500);

    // Expected Result: Schedule updates to show only morning shifts
    const morningShifts = await page.locator('[data-testid="shift-item"]').all();
    expect(morningShifts.length).toBeGreaterThan(0);
    
    for (const shift of morningShifts) {
      const shiftType = await shift.getAttribute('data-shift-type');
      expect(shiftType).toBe('morning');
    }
    
    // Verify filter badge or indicator is displayed
    await expect(page.locator('[data-testid="active-filter-morning"]')).toBeVisible();

    // Step 2: Employee selects 'Night' shift filter in addition
    await page.click('[data-testid="shift-type-filter-dropdown"]');
    await page.click('[data-testid="filter-option-night"]');
    
    // Wait for schedule to update with multiple filters
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    await page.waitForTimeout(500);

    // Expected Result: Schedule shows morning and night shifts
    const filteredShifts = await page.locator('[data-testid="shift-item"]').all();
    expect(filteredShifts.length).toBeGreaterThan(0);
    
    let hasMorning = false;
    let hasNight = false;
    
    for (const shift of filteredShifts) {
      const shiftType = await shift.getAttribute('data-shift-type');
      expect(['morning', 'night']).toContain(shiftType);
      if (shiftType === 'morning') hasMorning = true;
      if (shiftType === 'night') hasNight = true;
    }
    
    // Verify both filter badges are displayed
    await expect(page.locator('[data-testid="active-filter-morning"]')).toBeVisible();
    await expect(page.locator('[data-testid="active-filter-night"]')).toBeVisible();

    // Step 3: Employee clears filters
    await page.click('[data-testid="clear-filters-button"]');
    
    // Wait for schedule to reload with all shifts
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    await page.waitForTimeout(500);

    // Expected Result: Full schedule is displayed
    const allShifts = await page.locator('[data-testid="shift-item"]').count();
    expect(allShifts).toBe(initialShiftCount);
    
    // Verify filter badges are removed
    await expect(page.locator('[data-testid="active-filter-morning"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="active-filter-night"]')).not.toBeVisible();
    
    // Verify shifts of all types are present
    const allShiftTypes = await page.locator('[data-testid="shift-item"]').evaluateAll(
      elements => elements.map(el => el.getAttribute('data-shift-type'))
    );
    const uniqueShiftTypes = [...new Set(allShiftTypes)];
    expect(uniqueShiftTypes.length).toBeGreaterThan(1);
  });

  test('Test filter persistence during navigation', async ({ page }) => {
    // Step 1: Employee applies shift type filter
    await page.click('[data-testid="shift-type-filter-dropdown"]');
    await page.click('[data-testid="filter-option-morning"]');
    
    // Wait for filtered schedule to load
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    await page.waitForTimeout(500);

    // Expected Result: Filtered schedule is displayed
    await expect(page.locator('[data-testid="active-filter-morning"]')).toBeVisible();
    
    const filteredShiftsWeek1 = await page.locator('[data-testid="shift-item"]').all();
    expect(filteredShiftsWeek1.length).toBeGreaterThan(0);
    
    for (const shift of filteredShiftsWeek1) {
      const shiftType = await shift.getAttribute('data-shift-type');
      expect(shiftType).toBe('morning');
    }
    
    // Capture current week identifier for comparison
    const currentWeekText = await page.locator('[data-testid="current-week-label"]').textContent();

    // Step 2: Employee navigates to next week
    await page.click('[data-testid="next-week-button"]');
    
    // Wait for next week's schedule to load
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    await page.waitForTimeout(500);

    // Expected Result: Filter remains applied and schedule updates accordingly
    const nextWeekText = await page.locator('[data-testid="current-week-label"]').textContent();
    expect(nextWeekText).not.toBe(currentWeekText);
    
    // Verify filter is still active
    await expect(page.locator('[data-testid="active-filter-morning"]')).toBeVisible();
    
    // Verify only morning shifts are displayed for the new week
    const filteredShiftsWeek2 = await page.locator('[data-testid="shift-item"]').all();
    expect(filteredShiftsWeek2.length).toBeGreaterThan(0);
    
    for (const shift of filteredShiftsWeek2) {
      const shiftType = await shift.getAttribute('data-shift-type');
      expect(shiftType).toBe('morning');
    }
    
    // Verify URL contains filter parameter
    const currentUrl = page.url();
    expect(currentUrl).toContain('shiftType=morning');
    
    // Additional verification: Navigate to previous week and verify filter persists
    await page.click('[data-testid="previous-week-button"]');
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    await page.waitForTimeout(500);
    
    // Verify filter is still active after navigating back
    await expect(page.locator('[data-testid="active-filter-morning"]')).toBeVisible();
    
    const filteredShiftsBack = await page.locator('[data-testid="shift-item"]').all();
    for (const shift of filteredShiftsBack) {
      const shiftType = await shift.getAttribute('data-shift-type');
      expect(shiftType).toBe('morning');
    }
  });
});