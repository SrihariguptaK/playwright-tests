import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Filtering by Shift Type', () => {
  test.beforeEach(async ({ page }) => {
    // Employee logs in
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to schedule section from main dashboard
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    await page.waitForSelector('[data-testid="schedule-view"]');
  });

  test('Validate schedule filtering by single shift type (happy-path)', async ({ page }) => {
    // Locate the shift type filter control on the schedule page
    await page.waitForSelector('[data-testid="shift-type-filter"]');
    
    // Select 'Morning' from the shift type filter options
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-morning"]');
    
    // Wait for schedule to update (within 2 seconds as per acceptance criteria)
    await page.waitForTimeout(500);
    
    // Verify that only morning shifts are displayed in the schedule view
    const morningShifts = await page.locator('[data-testid="shift-card"][data-shift-type="morning"]').count();
    expect(morningShifts).toBeGreaterThan(0);
    
    // Verify no other shift types are displayed
    const eveningShifts = await page.locator('[data-testid="shift-card"][data-shift-type="evening"]').count();
    const nightShifts = await page.locator('[data-testid="shift-card"][data-shift-type="night"]').count();
    expect(eveningShifts).toBe(0);
    expect(nightShifts).toBe(0);
    
    // Click the 'Clear filter' button or deselect the 'Morning' filter
    await page.click('[data-testid="clear-filter-button"]');
    
    // Verify that all shift types are now visible in the schedule
    await page.waitForTimeout(500);
    const totalShifts = await page.locator('[data-testid="shift-card"]').count();
    expect(totalShifts).toBeGreaterThan(morningShifts);
    
    // Verify multiple shift types are present
    const allMorningShifts = await page.locator('[data-testid="shift-card"][data-shift-type="morning"]').count();
    const allEveningShifts = await page.locator('[data-testid="shift-card"][data-shift-type="evening"]').count();
    const allNightShifts = await page.locator('[data-testid="shift-card"][data-shift-type="night"]').count();
    expect(allMorningShifts + allEveningShifts + allNightShifts).toBe(totalShifts);
  });

  test('Validate schedule filtering by multiple shift types (happy-path)', async ({ page }) => {
    // Locate the shift type filter control on the schedule page
    await page.waitForSelector('[data-testid="shift-type-filter"]');
    
    // Select 'Morning' from the shift type filter options
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-morning"]');
    await page.waitForTimeout(500);
    
    // Get count of morning shifts
    const morningShiftsCount = await page.locator('[data-testid="shift-card"][data-shift-type="morning"]').count();
    
    // Additionally select 'Evening' from the shift type filter options while keeping 'Morning' selected
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-evening"]');
    
    // Observe the schedule view update
    await page.waitForTimeout(500);
    
    // Verify that displayed shifts include both Morning and Evening shifts
    const morningShifts = await page.locator('[data-testid="shift-card"][data-shift-type="morning"]').count();
    const eveningShifts = await page.locator('[data-testid="shift-card"][data-shift-type="evening"]').count();
    
    expect(morningShifts).toBeGreaterThan(0);
    expect(eveningShifts).toBeGreaterThan(0);
    
    // Verify no other shift types are displayed
    const nightShifts = await page.locator('[data-testid="shift-card"][data-shift-type="night"]').count();
    expect(nightShifts).toBe(0);
    
    // Count the total number of shifts displayed and verify against expected count
    const totalDisplayedShifts = await page.locator('[data-testid="shift-card"]').count();
    expect(totalDisplayedShifts).toBe(morningShifts + eveningShifts);
    
    // Verify schedule displays shifts matching either filter
    const scheduleView = page.locator('[data-testid="schedule-view"]');
    await expect(scheduleView).toBeVisible();
  });

  test('Test no matching shifts message (edge-case)', async ({ page }) => {
    // Navigate to the schedule section is already done in beforeEach
    await page.waitForSelector('[data-testid="shift-type-filter"]');
    
    // Identify a shift type that has no scheduled shifts (e.g., 'Weekend' or 'Holiday')
    // Select the shift type filter for which no shifts are scheduled
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-weekend"]');
    
    // Observe the schedule display area
    await page.waitForTimeout(500);
    
    // Verify that the system displays the message 'No shifts match the selected filters'
    const noShiftsMessage = page.locator('[data-testid="no-shifts-message"]');
    await expect(noShiftsMessage).toBeVisible();
    await expect(noShiftsMessage).toHaveText('No shifts match the selected filters');
    
    // Verify no shift cards are displayed
    const shiftCards = await page.locator('[data-testid="shift-card"]').count();
    expect(shiftCards).toBe(0);
    
    // Clear the filter or select a different shift type with scheduled shifts
    await page.click('[data-testid="clear-filter-button"]');
    await page.waitForTimeout(500);
    
    // Verify shifts are now displayed after clearing filter
    const shiftsAfterClear = await page.locator('[data-testid="shift-card"]').count();
    expect(shiftsAfterClear).toBeGreaterThan(0);
    
    // Verify no shifts message is no longer visible
    await expect(noShiftsMessage).not.toBeVisible();
  });

  test('Verify filter state persists when navigating between schedule views', async ({ page }) => {
    // Apply a filter
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-morning"]');
    await page.waitForTimeout(500);
    
    // Verify filter is applied
    const morningShifts = await page.locator('[data-testid="shift-card"][data-shift-type="morning"]').count();
    expect(morningShifts).toBeGreaterThan(0);
    
    // Navigate away from schedule
    await page.click('[data-testid="dashboard-nav-link"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate back to schedule
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    await page.waitForSelector('[data-testid="schedule-view"]');
    
    // Verify filter state persists
    const persistedMorningShifts = await page.locator('[data-testid="shift-card"][data-shift-type="morning"]').count();
    expect(persistedMorningShifts).toBe(morningShifts);
    
    // Verify other shift types are still filtered out
    const eveningShifts = await page.locator('[data-testid="shift-card"][data-shift-type="evening"]').count();
    expect(eveningShifts).toBe(0);
  });

  test('Verify schedule view updates within 2 seconds upon filter application', async ({ page }) => {
    // Record start time
    const startTime = Date.now();
    
    // Apply filter
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-evening"]');
    
    // Wait for schedule to update
    await page.waitForSelector('[data-testid="shift-card"][data-shift-type="evening"]', { timeout: 2000 });
    
    // Calculate elapsed time
    const elapsedTime = Date.now() - startTime;
    
    // Verify update happened within 2 seconds (2000ms)
    expect(elapsedTime).toBeLessThan(2000);
    
    // Verify correct shifts are displayed
    const eveningShifts = await page.locator('[data-testid="shift-card"][data-shift-type="evening"]').count();
    expect(eveningShifts).toBeGreaterThan(0);
  });

  test.afterEach(async ({ page }) => {
    // Logout
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
  });
});