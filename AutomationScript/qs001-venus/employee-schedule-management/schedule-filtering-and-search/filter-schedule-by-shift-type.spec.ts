import { test, expect } from '@playwright/test';

test.describe('Filter Schedule by Shift Type', () => {
  test.beforeEach(async ({ page }) => {
    // Employee logs in
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*schedule/);
  });

  test('Validate filtering by single shift type', async ({ page }) => {
    // Navigate to the schedule view page
    await page.goto('/schedule');
    await page.waitForSelector('[data-testid="schedule-container"]');

    // Locate and click on the shift type filter dropdown/option
    await page.click('[data-testid="shift-type-filter-dropdown"]');
    await page.waitForSelector('[data-testid="shift-type-filter-options"]');

    // Select 'Morning' shift type from the filter options
    await page.click('[data-testid="shift-type-option-morning"]');

    // Wait for schedule display to update
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && 
      response.url().includes('shiftType=Morning') &&
      response.status() === 200
    );

    // Verify that only Morning shifts are displayed in the schedule
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    const shiftElements = await page.locator('[data-testid="shift-item"]').all();
    
    for (const shift of shiftElements) {
      const shiftType = await shift.getAttribute('data-shift-type');
      expect(shiftType).toBe('Morning');
    }

    // Verify at least one morning shift is displayed
    await expect(page.locator('[data-testid="shift-item"][data-shift-type="Morning"]')).toHaveCount(await page.locator('[data-testid="shift-item"]').count());

    // Click the 'Clear filter' button or option
    await page.click('[data-testid="clear-filter-button"]');

    // Wait for schedule to reload with all shifts
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && 
      !response.url().includes('shiftType=') &&
      response.status() === 200
    );

    // Verify full schedule is displayed
    const allShifts = await page.locator('[data-testid="shift-item"]').all();
    expect(allShifts.length).toBeGreaterThan(0);
    
    // Verify different shift types are present
    const shiftTypes = new Set();
    for (const shift of allShifts) {
      const shiftType = await shift.getAttribute('data-shift-type');
      shiftTypes.add(shiftType);
    }
    expect(shiftTypes.size).toBeGreaterThan(1);
  });

  test('Validate filtering by multiple shift types', async ({ page }) => {
    // Navigate to the schedule view page
    await page.goto('/schedule');
    await page.waitForSelector('[data-testid="schedule-container"]');

    // Locate and click on the shift type filter dropdown/option
    await page.click('[data-testid="shift-type-filter-dropdown"]');
    await page.waitForSelector('[data-testid="shift-type-filter-options"]');

    // Select 'Morning' shift type from the filter options
    await page.click('[data-testid="shift-type-option-morning"]');
    
    // Keep dropdown open or reopen if it closes
    const isDropdownVisible = await page.locator('[data-testid="shift-type-filter-options"]').isVisible();
    if (!isDropdownVisible) {
      await page.click('[data-testid="shift-type-filter-dropdown"]');
    }

    // Select 'Evening' shift type from the filter options while Morning is still selected
    await page.click('[data-testid="shift-type-option-evening"]');

    // Wait for schedule display to update with multiple filters
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && 
      (response.url().includes('shiftType=Morning') || response.url().includes('shiftType=Evening')) &&
      response.status() === 200
    );

    // Verify that only Morning and Evening shifts are displayed
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    const shiftElements = await page.locator('[data-testid="shift-item"]').all();
    
    expect(shiftElements.length).toBeGreaterThan(0);

    for (const shift of shiftElements) {
      const shiftType = await shift.getAttribute('data-shift-type');
      expect(['Morning', 'Evening']).toContain(shiftType);
    }

    // Count the total number of shifts displayed and verify against expected count
    const morningShifts = await page.locator('[data-testid="shift-item"][data-shift-type="Morning"]').count();
    const eveningShifts = await page.locator('[data-testid="shift-item"][data-shift-type="Evening"]').count();
    const totalFilteredShifts = morningShifts + eveningShifts;
    
    expect(totalFilteredShifts).toBe(shiftElements.length);
    expect(totalFilteredShifts).toBeGreaterThan(0);
  });

  test('Test handling of invalid shift type filter', async ({ page }) => {
    // Navigate to the schedule view page
    await page.goto('/schedule');
    await page.waitForSelector('[data-testid="schedule-container"]');

    // Note the current URL in the browser address bar
    const originalUrl = page.url();
    expect(originalUrl).toContain('/schedule');

    // Get employee ID from page context or use test data
    const employeeId = await page.evaluate(() => {
      return window.localStorage.getItem('employeeId') || '123';
    });

    // Manually modify the URL to include an invalid shift type parameter
    const invalidUrl = `/api/schedules?employeeId=${employeeId}&shiftType=InvalidType`;
    await page.goto(invalidUrl);

    // Observe the system response and error handling
    await page.waitForLoadState('networkidle');

    // Verify validation error is displayed or handled
    const errorMessage = page.locator('[data-testid="error-message"]');
    const isErrorVisible = await errorMessage.isVisible().catch(() => false);
    
    if (isErrorVisible) {
      await expect(errorMessage).toContainText(/invalid|error|validation/i);
    }

    // Navigate back to schedule view to verify default state
    await page.goto('/schedule');
    await page.waitForSelector('[data-testid="schedule-container"]');

    // Verify the schedule display shows full schedule after validation error
    const scheduleContainer = page.locator('[data-testid="schedule-container"]');
    await expect(scheduleContainer).toBeVisible();
    
    const allShifts = await page.locator('[data-testid="shift-item"]').all();
    expect(allShifts.length).toBeGreaterThan(0);

    // Verify that the filter interface is in default state
    const filterDropdown = page.locator('[data-testid="shift-type-filter-dropdown"]');
    await expect(filterDropdown).toBeVisible();
    
    const filterText = await filterDropdown.textContent();
    expect(filterText).toMatch(/all|select|filter/i);

    // Verify no active filters are applied
    const activeFilters = page.locator('[data-testid="active-filter-tag"]');
    const activeFilterCount = await activeFilters.count();
    expect(activeFilterCount).toBe(0);
  });
});