import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Filter by Shift Type', () => {
  test.beforeEach(async ({ page }) => {
    // Employee logs in
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to schedule section
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page.locator('[data-testid="schedule-section"]')).toBeVisible();
  });

  test('Validate filtering by single shift type', async ({ page }) => {
    // Locate and click on the filter panel or filter icon
    await page.click('[data-testid="filter-panel-button"]');
    await expect(page.locator('[data-testid="filter-panel"]')).toBeVisible();
    
    // Select 'Morning' shift type from the available filter options
    await page.click('[data-testid="shift-type-morning"]');
    
    // Click 'Apply' or confirm the filter selection
    await page.click('[data-testid="apply-filter-button"]');
    
    // Wait for API response
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && 
      response.url().includes('shiftType=morning') &&
      response.status() === 200
    );
    
    // Verify the filtered results show only Morning shifts
    const shiftCards = page.locator('[data-testid="shift-card"]');
    await expect(shiftCards).not.toHaveCount(0);
    
    const shiftCount = await shiftCards.count();
    for (let i = 0; i < shiftCount; i++) {
      const shiftType = await shiftCards.nth(i).locator('[data-testid="shift-type"]').textContent();
      expect(shiftType?.toLowerCase()).toContain('morning');
    }
    
    // Click the 'Clear filter' button or option
    await page.click('[data-testid="clear-filter-button"]');
    
    // Wait for unfiltered API response
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && 
      !response.url().includes('shiftType') &&
      response.status() === 200
    );
    
    // Verify all shifts are now visible
    const allShiftCards = page.locator('[data-testid="shift-card"]');
    const allShiftCount = await allShiftCards.count();
    expect(allShiftCount).toBeGreaterThan(shiftCount);
  });

  test('Validate filtering by multiple shift types', async ({ page }) => {
    // Open the filter panel by clicking on the filter icon or button
    await page.click('[data-testid="filter-panel-button"]');
    await expect(page.locator('[data-testid="filter-panel"]')).toBeVisible();
    
    // Select 'Morning' shift type from the filter options
    await page.click('[data-testid="shift-type-morning"]');
    await expect(page.locator('[data-testid="shift-type-morning"]')).toHaveClass(/selected|active/);
    
    // Select 'Night' shift type from the filter options while keeping 'Morning' selected
    await page.click('[data-testid="shift-type-night"]');
    await expect(page.locator('[data-testid="shift-type-night"]')).toHaveClass(/selected|active/);
    await expect(page.locator('[data-testid="shift-type-morning"]')).toHaveClass(/selected|active/);
    
    // Click 'Apply' button to apply the multiple filters
    await page.click('[data-testid="apply-filter-button"]');
    
    // Wait for API response with multiple shift types
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && 
      (response.url().includes('shiftType=morning') || response.url().includes('shiftType=night')) &&
      response.status() === 200
    );
    
    // Verify the filtered results contain only Morning and Night shifts
    const shiftCards = page.locator('[data-testid="shift-card"]');
    await expect(shiftCards).not.toHaveCount(0);
    
    const shiftCount = await shiftCards.count();
    for (let i = 0; i < shiftCount; i++) {
      const shiftType = await shiftCards.nth(i).locator('[data-testid="shift-type"]').textContent();
      const shiftTypeLower = shiftType?.toLowerCase() || '';
      expect(shiftTypeLower === 'morning' || shiftTypeLower === 'night' || 
             shiftTypeLower.includes('morning') || shiftTypeLower.includes('night')).toBeTruthy();
    }
    
    // Scroll through the filtered schedule to confirm consistency
    await page.locator('[data-testid="schedule-section"]').evaluate(el => el.scrollTop = el.scrollHeight / 2);
    await page.waitForTimeout(500);
    
    const visibleShifts = page.locator('[data-testid="shift-card"]:visible');
    const visibleCount = await visibleShifts.count();
    for (let i = 0; i < Math.min(visibleCount, 5); i++) {
      const shiftType = await visibleShifts.nth(i).locator('[data-testid="shift-type"]').textContent();
      const shiftTypeLower = shiftType?.toLowerCase() || '';
      expect(shiftTypeLower === 'morning' || shiftTypeLower === 'night' || 
             shiftTypeLower.includes('morning') || shiftTypeLower.includes('night')).toBeTruthy();
    }
  });

  test('Verify filter performance under 2 seconds', async ({ page }) => {
    // Navigate to schedule section containing large dataset (already done in beforeEach)
    
    // Open the filter panel
    await page.click('[data-testid="filter-panel-button"]');
    await expect(page.locator('[data-testid="filter-panel"]')).toBeVisible();
    
    // Note the current timestamp or start the performance timer
    const startTime = Date.now();
    
    // Select a shift type filter (e.g., 'Morning') and click Apply
    await page.click('[data-testid="shift-type-morning"]');
    
    // Monitor the API call and measure response time
    const responsePromise = page.waitForResponse(response => 
      response.url().includes('/api/schedules') && 
      response.url().includes('shiftType') &&
      response.status() === 200
    );
    
    await page.click('[data-testid="apply-filter-button"]');
    
    const response = await responsePromise;
    
    // Wait for filtered results to be fully displayed on screen
    await expect(page.locator('[data-testid="shift-card"]').first()).toBeVisible();
    await page.waitForLoadState('networkidle');
    
    // Measure the total time from clicking Apply until filtered results are fully displayed
    const endTime = Date.now();
    const totalTime = endTime - startTime;
    
    // Verify the measured response time is under 2 seconds (2000ms)
    expect(totalTime).toBeLessThan(2000);
    
    // Verify filtered results are displayed
    const shiftCards = page.locator('[data-testid="shift-card"]');
    await expect(shiftCards).not.toHaveCount(0);
    
    // Clear filter for next iteration
    await page.click('[data-testid="clear-filter-button"]');
    await page.waitForLoadState('networkidle');
    
    // Repeat the test with different shift type filter (Night)
    await page.click('[data-testid="filter-panel-button"]');
    const startTime2 = Date.now();
    
    await page.click('[data-testid="shift-type-night"]');
    
    const responsePromise2 = page.waitForResponse(response => 
      response.url().includes('/api/schedules') && 
      response.url().includes('shiftType') &&
      response.status() === 200
    );
    
    await page.click('[data-testid="apply-filter-button"]');
    await responsePromise2;
    
    await expect(page.locator('[data-testid="shift-card"]').first()).toBeVisible();
    await page.waitForLoadState('networkidle');
    
    const endTime2 = Date.now();
    const totalTime2 = endTime2 - startTime2;
    
    // Verify consistent performance under 2 seconds
    expect(totalTime2).toBeLessThan(2000);
  });
});