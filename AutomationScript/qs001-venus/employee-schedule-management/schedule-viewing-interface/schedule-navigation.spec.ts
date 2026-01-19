import { test, expect } from '@playwright/test';

test.describe('Schedule Navigation - Story 18', () => {
  test.beforeEach(async ({ page }) => {
    // Employee logs in
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    
    // Wait for navigation to schedule page
    await page.waitForURL('**/schedule');
    await page.waitForLoadState('networkidle');
  });

  test('Validate schedule navigation between dates', async ({ page }) => {
    // Verify the current date is displayed on the schedule interface
    const currentDateDisplay = page.locator('[data-testid="schedule-current-date"]');
    await expect(currentDateDisplay).toBeVisible();
    const initialDate = await currentDateDisplay.textContent();
    
    // Note the shifts displayed for the current day
    const initialShifts = page.locator('[data-testid="shift-item"]');
    const initialShiftCount = await initialShifts.count();
    expect(initialShiftCount).toBeGreaterThan(0);
    
    // Click the 'Next Day' button
    await page.click('[data-testid="next-day-button"]');
    await page.waitForLoadState('networkidle');
    
    // Verify the schedule content has changed to the next day
    const nextDayDate = await currentDateDisplay.textContent();
    expect(nextDayDate).not.toBe(initialDate);
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    
    // Click the 'Previous Week' button
    await page.click('[data-testid="previous-week-button"]');
    await page.waitForLoadState('networkidle');
    
    // Verify the schedule content has changed to the previous week
    const previousWeekDate = await currentDateDisplay.textContent();
    expect(previousWeekDate).not.toBe(nextDayDate);
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    
    // Click the 'Next Week' button twice to navigate forward
    await page.click('[data-testid="next-week-button"]');
    await page.waitForLoadState('networkidle');
    const afterFirstNextWeek = await currentDateDisplay.textContent();
    
    await page.click('[data-testid="next-week-button"]');
    await page.waitForLoadState('networkidle');
    const afterSecondNextWeek = await currentDateDisplay.textContent();
    expect(afterSecondNextWeek).not.toBe(afterFirstNextWeek);
    
    // Click the 'Previous Day' button
    await page.click('[data-testid="previous-day-button"]');
    await page.waitForLoadState('networkidle');
    
    // Verify schedule updated
    const finalDate = await currentDateDisplay.textContent();
    expect(finalDate).not.toBe(afterSecondNextWeek);
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
  });

  test('Verify filter persistence during navigation', async ({ page }) => {
    // Verify the schedule displays all shift types without any filters applied
    const allShifts = page.locator('[data-testid="shift-item"]');
    const initialShiftCount = await allShifts.count();
    expect(initialShiftCount).toBeGreaterThan(0);
    
    // Locate and click on the shift type filter dropdown or control
    await page.click('[data-testid="shift-type-filter-dropdown"]');
    await expect(page.locator('[data-testid="filter-options"]')).toBeVisible();
    
    // Select 'Morning' shift type from the filter options
    await page.click('[data-testid="filter-option-morning"]');
    await page.waitForLoadState('networkidle');
    
    // Verify only Morning shifts are displayed on the current schedule
    const morningShifts = page.locator('[data-testid="shift-item"]');
    const morningShiftCount = await morningShifts.count();
    
    // Verify all visible shifts are Morning shifts
    for (let i = 0; i < morningShiftCount; i++) {
      const shiftType = await morningShifts.nth(i).locator('[data-testid="shift-type"]').textContent();
      expect(shiftType?.toLowerCase()).toContain('morning');
    }
    
    // Store current date for comparison
    const currentDate = await page.locator('[data-testid="schedule-current-date"]').textContent();
    
    // Click the 'Next Day' button to navigate to the next day
    await page.click('[data-testid="next-day-button"]');
    await page.waitForLoadState('networkidle');
    
    // Verify the filter is still active and only Morning shifts are shown for the new date
    const nextDayDate = await page.locator('[data-testid="schedule-current-date"]').textContent();
    expect(nextDayDate).not.toBe(currentDate);
    
    const nextDayShifts = page.locator('[data-testid="shift-item"]');
    const nextDayShiftCount = await nextDayShifts.count();
    
    if (nextDayShiftCount > 0) {
      for (let i = 0; i < nextDayShiftCount; i++) {
        const shiftType = await nextDayShifts.nth(i).locator('[data-testid="shift-type"]').textContent();
        expect(shiftType?.toLowerCase()).toContain('morning');
      }
    }
    
    // Verify filter indicator is still active
    await expect(page.locator('[data-testid="active-filter-morning"]')).toBeVisible();
    
    // Click the 'Next Week' button to navigate to the next week
    await page.click('[data-testid="next-week-button"]');
    await page.waitForLoadState('networkidle');
    
    // Verify the filter persistence across week navigation
    const nextWeekDate = await page.locator('[data-testid="schedule-current-date"]').textContent();
    expect(nextWeekDate).not.toBe(nextDayDate);
    
    const nextWeekShifts = page.locator('[data-testid="shift-item"]');
    const nextWeekShiftCount = await nextWeekShifts.count();
    
    if (nextWeekShiftCount > 0) {
      for (let i = 0; i < nextWeekShiftCount; i++) {
        const shiftType = await nextWeekShifts.nth(i).locator('[data-testid="shift-type"]').textContent();
        expect(shiftType?.toLowerCase()).toContain('morning');
      }
    }
    
    await expect(page.locator('[data-testid="active-filter-morning"]')).toBeVisible();
    
    // Click the 'Previous Day' button to navigate backward
    await page.click('[data-testid="previous-day-button"]');
    await page.waitForLoadState('networkidle');
    
    // Verify filter still persists after backward navigation
    const previousDayShifts = page.locator('[data-testid="shift-item"]');
    const previousDayShiftCount = await previousDayShifts.count();
    
    if (previousDayShiftCount > 0) {
      for (let i = 0; i < previousDayShiftCount; i++) {
        const shiftType = await previousDayShifts.nth(i).locator('[data-testid="shift-type"]').textContent();
        expect(shiftType?.toLowerCase()).toContain('morning');
      }
    }
    
    // Clear the filter by deselecting 'Morning' or clicking 'Clear Filter'
    await page.click('[data-testid="clear-filter-button"]');
    await page.waitForLoadState('networkidle');
    
    // Verify all shift types are now displayed
    const allShiftsAfterClear = page.locator('[data-testid="shift-item"]');
    const finalShiftCount = await allShiftsAfterClear.count();
    expect(finalShiftCount).toBeGreaterThanOrEqual(morningShiftCount);
    
    // Verify filter indicator is no longer visible
    await expect(page.locator('[data-testid="active-filter-morning"]')).not.toBeVisible();
  });
});