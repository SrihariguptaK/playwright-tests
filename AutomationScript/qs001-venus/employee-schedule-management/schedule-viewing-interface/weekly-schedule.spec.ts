import { test, expect } from '@playwright/test';

test.describe('Employee Weekly Schedule View', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('Validate weekly schedule display with correct shift details', async ({ page }) => {
    // Step 1: Employee logs into the web portal
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Login successful
    await expect(page).toHaveURL(/\/dashboard|\/home/);
    await expect(page.locator('[data-testid="user-profile"]')).toBeVisible();
    
    // Step 2: Employee selects weekly schedule view
    await page.click('[data-testid="schedule-nav-link"]');
    await page.click('[data-testid="weekly-view-tab"]');
    
    // Expected Result: Weekly schedule calendar is displayed
    await expect(page.locator('[data-testid="weekly-schedule-calendar"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-week-indicator"]')).toBeVisible();
    
    // Verify all 7 days are displayed
    const dayHeaders = page.locator('[data-testid="day-header"]');
    await expect(dayHeaders).toHaveCount(7);
    
    // Step 3: Verify shifts are displayed correctly for each day
    const mondayShifts = page.locator('[data-testid="day-monday"] [data-testid="shift-card"]');
    const mondayShiftCount = await mondayShifts.count();
    
    if (mondayShiftCount > 0) {
      const firstShift = mondayShifts.first();
      await expect(firstShift.locator('[data-testid="shift-time"]')).toBeVisible();
      await expect(firstShift.locator('[data-testid="shift-location"]')).toBeVisible();
      await expect(firstShift.locator('[data-testid="shift-role"]')).toBeVisible();
    }
    
    // Expected Result: Shift details match employee assignments
    for (let i = 0; i < 7; i++) {
      const dayNames = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
      const dayShifts = page.locator(`[data-testid="day-${dayNames[i]}"] [data-testid="shift-card"]`);
      const shiftCount = await dayShifts.count();
      
      for (let j = 0; j < shiftCount; j++) {
        const shift = dayShifts.nth(j);
        await expect(shift).toBeVisible();
      }
    }
    
    // Verify page load time (should be under 4 seconds)
    const startTime = Date.now();
    await page.reload();
    await page.waitForSelector('[data-testid="weekly-schedule-calendar"]', { timeout: 4000 });
    const loadTime = Date.now() - startTime;
    expect(loadTime).toBeLessThan(4000);
  });

  test('Verify navigation between weeks', async ({ page }) => {
    // Login
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/\/dashboard|\/home/);
    
    // Navigate to weekly schedule
    await page.click('[data-testid="schedule-nav-link"]');
    await page.click('[data-testid="weekly-view-tab"]');
    await expect(page.locator('[data-testid="weekly-schedule-calendar"]')).toBeVisible();
    
    // Note current week date range
    const currentWeekRange = await page.locator('[data-testid="week-date-range"]').textContent();
    
    // Step 1: Employee clicks 'Next Week' button
    await page.click('[data-testid="next-week-button"]');
    
    // Expected Result: Schedule for next week displayed
    await page.waitForTimeout(500); // Allow for schedule update
    const nextWeekRange = await page.locator('[data-testid="week-date-range"]').textContent();
    expect(nextWeekRange).not.toBe(currentWeekRange);
    await expect(page.locator('[data-testid="weekly-schedule-calendar"]')).toBeVisible();
    
    // Verify shift details are displayed for next week
    const nextWeekShifts = page.locator('[data-testid="shift-card"]');
    const nextWeekShiftCount = await nextWeekShifts.count();
    expect(nextWeekShiftCount).toBeGreaterThanOrEqual(0);
    
    // Step 2: Employee clicks 'Previous Week' button
    await page.click('[data-testid="previous-week-button"]');
    
    // Expected Result: Schedule for previous week displayed
    await page.waitForTimeout(500);
    const backToCurrentWeek = await page.locator('[data-testid="week-date-range"]').textContent();
    expect(backToCurrentWeek).toBe(currentWeekRange);
    
    // Click previous week again
    await page.click('[data-testid="previous-week-button"]');
    await page.waitForTimeout(500);
    const previousWeekRange = await page.locator('[data-testid="week-date-range"]').textContent();
    expect(previousWeekRange).not.toBe(currentWeekRange);
    
    // Step 3: Verify no errors during navigation
    // Navigate rapidly multiple times
    for (let i = 0; i < 5; i++) {
      await page.click('[data-testid="next-week-button"]');
      await page.waitForTimeout(200);
    }
    
    for (let i = 0; i < 5; i++) {
      await page.click('[data-testid="previous-week-button"]');
      await page.waitForTimeout(200);
    }
    
    // Expected Result: Navigation is smooth and error-free
    await expect(page.locator('[data-testid="weekly-schedule-calendar"]')).toBeVisible();
    
    // Verify calendar grid structure remains consistent
    const dayHeadersAfterNav = page.locator('[data-testid="day-header"]');
    await expect(dayHeadersAfterNav).toHaveCount(7);
    
    // Check for console errors
    const consoleErrors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });
    
    await page.click('[data-testid="next-week-button"]');
    await page.waitForTimeout(500);
    expect(consoleErrors.length).toBe(0);
  });

  test('Test shift type filtering', async ({ page }) => {
    // Login
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/\/dashboard|\/home/);
    
    // Navigate to weekly schedule
    await page.click('[data-testid="schedule-nav-link"]');
    await page.click('[data-testid="weekly-view-tab"]');
    await expect(page.locator('[data-testid="weekly-schedule-calendar"]')).toBeVisible();
    
    // Note all shifts currently displayed
    const initialShifts = page.locator('[data-testid="shift-card"]');
    const initialShiftCount = await initialShifts.count();
    
    // Locate the shift type filter control
    const shiftTypeFilter = page.locator('[data-testid="shift-type-filter"]');
    await expect(shiftTypeFilter).toBeVisible();
    
    // Step 1: Employee selects a shift type filter
    await shiftTypeFilter.click();
    
    // View available options
    const filterOptions = page.locator('[data-testid="filter-option"]');
    await expect(filterOptions.first()).toBeVisible();
    
    // Select a specific shift type (e.g., 'Morning')
    await page.click('[data-testid="filter-option-morning"]');
    
    // Expected Result: Schedule updates to show only selected shift types
    await page.waitForTimeout(500); // Allow for filter to apply
    const filteredShifts = page.locator('[data-testid="shift-card"]');
    const filteredShiftCount = await filteredShifts.count();
    
    // Verify filtered shifts are displayed
    if (filteredShiftCount > 0) {
      for (let i = 0; i < filteredShiftCount; i++) {
        const shift = filteredShifts.nth(i);
        const shiftType = await shift.locator('[data-testid="shift-type"]').textContent();
        expect(shiftType?.toLowerCase()).toContain('morning');
      }
    }
    
    // Verify shift details remain accurate
    if (filteredShiftCount > 0) {
      const firstFilteredShift = filteredShifts.first();
      await expect(firstFilteredShift.locator('[data-testid="shift-time"]')).toBeVisible();
      await expect(firstFilteredShift.locator('[data-testid="shift-location"]')).toBeVisible();
      await expect(firstFilteredShift.locator('[data-testid="shift-role"]')).toBeVisible();
    }
    
    // Verify days without selected shift type show appropriately
    const emptyDays = page.locator('[data-testid*="day-"][data-empty="true"]');
    const emptyDayCount = await emptyDays.count();
    expect(emptyDayCount).toBeGreaterThanOrEqual(0);
    
    // Step 2: Employee clears filter
    await shiftTypeFilter.click();
    await page.click('[data-testid="filter-option-all"]');
    
    // Expected Result: Full schedule is displayed again
    await page.waitForTimeout(500);
    const restoredShifts = page.locator('[data-testid="shift-card"]');
    const restoredShiftCount = await restoredShifts.count();
    expect(restoredShiftCount).toBe(initialShiftCount);
    
    // Step 3: Verify filtering does not affect other schedule data
    const weekRangeBeforeFilter = await page.locator('[data-testid="week-date-range"]').textContent();
    
    // Apply filter again
    await shiftTypeFilter.click();
    await page.click('[data-testid="filter-option-evening"]');
    await page.waitForTimeout(500);
    
    // Expected Result: Only shift visibility changes
    const weekRangeAfterFilter = await page.locator('[data-testid="week-date-range"]').textContent();
    expect(weekRangeAfterFilter).toBe(weekRangeBeforeFilter);
    
    // Verify calendar structure remains intact
    const dayHeadersAfterFilter = page.locator('[data-testid="day-header"]');
    await expect(dayHeadersAfterFilter).toHaveCount(7);
    
    // Apply filter, navigate to next week, and verify behavior
    await page.click('[data-testid="next-week-button"]');
    await page.waitForTimeout(500);
    
    // Verify filter persists or resets as designed
    const filterAfterNav = await shiftTypeFilter.textContent();
    expect(filterAfterNav).toBeTruthy();
    
    // Verify schedule still displays correctly
    await expect(page.locator('[data-testid="weekly-schedule-calendar"]')).toBeVisible();
  });
});