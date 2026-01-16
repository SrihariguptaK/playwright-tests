import { test, expect } from '@playwright/test';

test.describe('Schedule Shift Type Filtering', () => {
  test.beforeEach(async ({ page }) => {
    // Employee logs in
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate schedule filtering by single shift type', async ({ page }) => {
    // Navigate to the schedule section from the main dashboard
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    await page.waitForSelector('[data-testid="schedule-view"]');

    // Locate the shift type filter control on the schedule page
    const filterControl = page.locator('[data-testid="shift-type-filter"]');
    await expect(filterControl).toBeVisible();

    // Get initial count of all shifts
    const allShifts = page.locator('[data-testid="shift-item"]');
    const initialCount = await allShifts.count();
    expect(initialCount).toBeGreaterThan(0);

    // Select 'Morning' from the shift type filter options
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-morning"]');

    // Wait for schedule to update (within 2 seconds as per acceptance criteria)
    await page.waitForResponse(response => 
      response.url().includes('/api/schedule') && response.status() === 200,
      { timeout: 2000 }
    );

    // Verify that only morning shifts are displayed in the schedule view
    const morningShifts = page.locator('[data-testid="shift-item"][data-shift-type="morning"]');
    const morningCount = await morningShifts.count();
    expect(morningCount).toBeGreaterThan(0);

    // Verify no other shift types are visible
    const nonMorningShifts = page.locator('[data-testid="shift-item"]:not([data-shift-type="morning"])');
    await expect(nonMorningShifts).toHaveCount(0);

    // Note the number of shifts displayed after filtering
    const filteredCount = await page.locator('[data-testid="shift-item"]').count();
    expect(filteredCount).toBeLessThanOrEqual(initialCount);

    // Click the 'Clear filter' button or deselect the 'Morning' filter
    await page.click('[data-testid="clear-filter-button"]');

    // Wait for schedule to reload
    await page.waitForResponse(response => 
      response.url().includes('/api/schedule') && response.status() === 200
    );

    // Verify that all shift types are now visible in the schedule
    const allShiftsAfterClear = page.locator('[data-testid="shift-item"]');
    const finalCount = await allShiftsAfterClear.count();
    expect(finalCount).toBe(initialCount);
  });

  test('Validate schedule filtering by multiple shift types', async ({ page }) => {
    // Navigate to the schedule section from the main dashboard
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    await page.waitForSelector('[data-testid="schedule-view"]');

    // Locate the shift type filter control on the schedule page
    const filterControl = page.locator('[data-testid="shift-type-filter"]');
    await expect(filterControl).toBeVisible();

    // Select 'Morning' from the shift type filter options
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-morning"]');

    // Wait for initial filter application
    await page.waitForResponse(response => 
      response.url().includes('/api/schedule') && response.status() === 200,
      { timeout: 2000 }
    );

    // While keeping 'Morning' selected, also select 'Evening' from the shift type filter options
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-evening"]');

    // Observe the schedule view update
    await page.waitForResponse(response => 
      response.url().includes('/api/schedule') && response.status() === 200,
      { timeout: 2000 }
    );

    // Verify that only Morning and Evening shifts are displayed
    const morningShifts = page.locator('[data-testid="shift-item"][data-shift-type="morning"]');
    const eveningShifts = page.locator('[data-testid="shift-item"][data-shift-type="evening"]');
    
    const morningCount = await morningShifts.count();
    const eveningCount = await eveningShifts.count();
    
    expect(morningCount).toBeGreaterThan(0);
    expect(eveningCount).toBeGreaterThan(0);

    // Verify no other shift types are visible
    const otherShifts = page.locator('[data-testid="shift-item"]:not([data-shift-type="morning"]):not([data-shift-type="evening"])');
    await expect(otherShifts).toHaveCount(0);

    // Count the total number of shifts displayed
    const totalFilteredShifts = page.locator('[data-testid="shift-item"]');
    const totalCount = await totalFilteredShifts.count();
    expect(totalCount).toBe(morningCount + eveningCount);
  });

  test('Test no matching shifts message', async ({ page }) => {
    // Navigate to the schedule section from the main dashboard
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    await page.waitForSelector('[data-testid="schedule-view"]');

    // Identify a shift type that has no scheduled shifts (e.g., 'Weekend' or 'Holiday')
    // Select the shift type filter for which no shifts are scheduled
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-weekend"]');

    // Wait for schedule to update
    await page.waitForResponse(response => 
      response.url().includes('/api/schedule') && response.status() === 200,
      { timeout: 2000 }
    );

    // Observe the schedule display area
    const scheduleView = page.locator('[data-testid="schedule-view"]');
    await expect(scheduleView).toBeVisible();

    // Verify that a message is displayed to the user
    const noMatchMessage = page.locator('[data-testid="no-shifts-message"]');
    await expect(noMatchMessage).toBeVisible();

    // Verify the message content
    await expect(noMatchMessage).toContainText('No shifts match the selected filters');

    // Verify that the message is clearly visible and appropriately positioned
    const messageBox = await noMatchMessage.boundingBox();
    expect(messageBox).not.toBeNull();
    expect(messageBox!.width).toBeGreaterThan(0);
    expect(messageBox!.height).toBeGreaterThan(0);

    // Verify no shift items are displayed
    const shiftItems = page.locator('[data-testid="shift-item"]');
    await expect(shiftItems).toHaveCount(0);

    // Clear the filter or select a different shift type with scheduled shifts
    await page.click('[data-testid="clear-filter-button"]');

    // Wait for schedule to reload
    await page.waitForResponse(response => 
      response.url().includes('/api/schedule') && response.status() === 200
    );

    // Verify that shifts are now displayed
    const allShifts = page.locator('[data-testid="shift-item"]');
    const shiftCount = await allShifts.count();
    expect(shiftCount).toBeGreaterThan(0);

    // Verify the no match message is no longer visible
    await expect(noMatchMessage).not.toBeVisible();
  });

  test.afterEach(async ({ page }) => {
    // Logout
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
  });
});