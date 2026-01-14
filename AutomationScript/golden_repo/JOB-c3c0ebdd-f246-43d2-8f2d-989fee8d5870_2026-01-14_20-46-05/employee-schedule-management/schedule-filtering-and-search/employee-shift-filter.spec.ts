import { test, expect } from '@playwright/test';

test.describe('Employee Shift Type Filtering', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('Validate shift type filtering updates schedule display', async ({ page }) => {
    // Step 1: Log in as employee
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Schedule dashboard is displayed
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible({ timeout: 5000 });
    await expect(page).toHaveURL(/.*\/schedule/);
    
    // Get initial count of all shifts
    const allShifts = page.locator('[data-testid="shift-item"]');
    const initialShiftCount = await allShifts.count();
    expect(initialShiftCount).toBeGreaterThan(0);
    
    // Step 2: Select shift type filter (e.g., morning shifts)
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-morning"]');
    
    // Wait for schedule to update
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    
    // Expected Result: Schedule updates to show only morning shifts
    await expect(page.locator('[data-testid="active-filter-morning"]')).toBeVisible();
    const morningShifts = page.locator('[data-testid="shift-item"][data-shift-type="morning"]');
    const morningShiftCount = await morningShifts.count();
    expect(morningShiftCount).toBeGreaterThan(0);
    
    // Verify only morning shifts are displayed
    const visibleShifts = await page.locator('[data-testid="shift-item"]').all();
    for (const shift of visibleShifts) {
      const shiftType = await shift.getAttribute('data-shift-type');
      expect(shiftType).toBe('morning');
    }
    
    // Step 3: Select additional shift type filter (e.g., evening shifts)
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-evening"]');
    
    // Wait for schedule to update with multiple filters
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    
    // Expected Result: Schedule shows morning and evening shifts
    await expect(page.locator('[data-testid="active-filter-morning"]')).toBeVisible();
    await expect(page.locator('[data-testid="active-filter-evening"]')).toBeVisible();
    
    const combinedShifts = await page.locator('[data-testid="shift-item"]').all();
    expect(combinedShifts.length).toBeGreaterThan(morningShiftCount);
    
    // Verify only morning and evening shifts are displayed
    for (const shift of combinedShifts) {
      const shiftType = await shift.getAttribute('data-shift-type');
      expect(['morning', 'evening']).toContain(shiftType);
    }
  });

  test('Verify filter state persistence during navigation', async ({ page }) => {
    // Step 1: Log in as employee
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    
    // Wait for schedule dashboard to load
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible({ timeout: 5000 });
    
    // Apply shift type filters - select Morning and Night shift types
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-morning"]');
    await page.waitForTimeout(500); // Allow filter to apply
    
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-night"]');
    
    // Wait for filtered schedule to load
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    
    // Expected Result: Filtered schedule is displayed
    await expect(page.locator('[data-testid="active-filter-morning"]')).toBeVisible();
    await expect(page.locator('[data-testid="active-filter-night"]')).toBeVisible();
    
    // Capture filtered shift count before navigation
    const filteredShiftsBeforeNav = await page.locator('[data-testid="shift-item"]').count();
    expect(filteredShiftsBeforeNav).toBeGreaterThan(0);
    
    // Verify only morning and night shifts are displayed
    const shiftsBeforeNav = await page.locator('[data-testid="shift-item"]').all();
    for (const shift of shiftsBeforeNav) {
      const shiftType = await shift.getAttribute('data-shift-type');
      expect(['morning', 'night']).toContain(shiftType);
    }
    
    // Step 2: Navigate to another schedule view
    await page.click('[data-testid="schedule-view-toggle"]');
    await page.click('[data-testid="monthly-view-option"]');
    
    // Wait for monthly view to load
    await expect(page.locator('[data-testid="monthly-view-container"]')).toBeVisible();
    await page.waitForTimeout(1000); // Allow view to fully render
    
    // Navigate back to original schedule view
    await page.click('[data-testid="schedule-view-toggle"]');
    await page.click('[data-testid="weekly-view-option"]');
    
    // Wait for weekly view to load
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    
    // Expected Result: Filters remain applied and schedule is filtered
    await expect(page.locator('[data-testid="active-filter-morning"]')).toBeVisible();
    await expect(page.locator('[data-testid="active-filter-night"]')).toBeVisible();
    
    // Verify shift count matches previous filtered count
    const filteredShiftsAfterNav = await page.locator('[data-testid="shift-item"]').count();
    expect(filteredShiftsAfterNav).toBe(filteredShiftsBeforeNav);
    
    // Verify only morning and night shifts are still displayed
    const shiftsAfterNav = await page.locator('[data-testid="shift-item"]').all();
    for (const shift of shiftsAfterNav) {
      const shiftType = await shift.getAttribute('data-shift-type');
      expect(['morning', 'night']).toContain(shiftType);
    }
    
    // Verify filter state is maintained in URL or session
    const currentUrl = page.url();
    expect(currentUrl).toMatch(/filter.*morning|morning.*filter/);
    expect(currentUrl).toMatch(/filter.*night|night.*filter/);
  });
});