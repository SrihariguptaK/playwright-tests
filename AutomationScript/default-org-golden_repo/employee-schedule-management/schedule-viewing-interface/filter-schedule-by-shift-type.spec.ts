import { test, expect } from '@playwright/test';

test.describe('Story-16: Filter Schedule by Shift Type', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to employee schedule page
    await page.goto('/employee/schedule');
    // Wait for schedule to load
    await page.waitForSelector('[data-testid="schedule-container"]', { timeout: 5000 });
  });

  test('#1 Validate shift type filtering in schedule view', async ({ page }) => {
    // Step 1: Employee opens schedule view - Full schedule is displayed
    const scheduleContainer = page.locator('[data-testid="schedule-container"]');
    await expect(scheduleContainer).toBeVisible();
    
    // Verify all shift types are initially displayed
    const allShifts = page.locator('[data-testid="shift-card"]');
    const initialShiftCount = await allShifts.count();
    expect(initialShiftCount).toBeGreaterThan(0);
    
    // Verify different shift types exist
    const morningShifts = page.locator('[data-testid="shift-card"][data-shift-type="morning"]');
    const eveningShifts = page.locator('[data-testid="shift-card"][data-shift-type="evening"]');
    const nightShifts = page.locator('[data-testid="shift-card"][data-shift-type="night"]');
    
    const initialMorningCount = await morningShifts.count();
    const initialEveningCount = await eveningShifts.count();
    const initialNightCount = await nightShifts.count();
    
    // Step 2: Employee selects 'Morning' shift filter - Schedule updates to show only morning shifts
    const morningFilterCheckbox = page.locator('[data-testid="filter-shift-type-morning"]');
    await morningFilterCheckbox.click();
    
    // Wait for filter to apply
    await page.waitForTimeout(500);
    
    // Verify only morning shifts are displayed
    const visibleShifts = page.locator('[data-testid="shift-card"]:visible');
    const filteredCount = await visibleShifts.count();
    expect(filteredCount).toBe(initialMorningCount);
    
    // Verify all visible shifts are morning shifts
    const visibleShiftTypes = await visibleShifts.evaluateAll(elements => 
      elements.map(el => el.getAttribute('data-shift-type'))
    );
    visibleShiftTypes.forEach(type => {
      expect(type).toBe('morning');
    });
    
    // Verify evening and night shifts are not visible
    await expect(page.locator('[data-testid="shift-card"][data-shift-type="evening"]:visible')).toHaveCount(0);
    await expect(page.locator('[data-testid="shift-card"][data-shift-type="night"]:visible')).toHaveCount(0);
    
    // Step 3: Employee selects additional 'Evening' shift filter - Schedule shows morning and evening shifts
    const eveningFilterCheckbox = page.locator('[data-testid="filter-shift-type-evening"]');
    await eveningFilterCheckbox.click();
    
    // Wait for filter to apply
    await page.waitForTimeout(500);
    
    // Verify morning and evening shifts are displayed
    const multiFilteredShifts = page.locator('[data-testid="shift-card"]:visible');
    const multiFilteredCount = await multiFilteredShifts.count();
    expect(multiFilteredCount).toBe(initialMorningCount + initialEveningCount);
    
    // Verify only morning and evening shifts are visible
    const multiFilteredTypes = await multiFilteredShifts.evaluateAll(elements => 
      elements.map(el => el.getAttribute('data-shift-type'))
    );
    multiFilteredTypes.forEach(type => {
      expect(['morning', 'evening']).toContain(type);
    });
    
    // Verify night shifts are still not visible
    await expect(page.locator('[data-testid="shift-card"][data-shift-type="night"]:visible')).toHaveCount(0);
  });

  test('#2 Verify filter response time', async ({ page }) => {
    // Step 1: Employee applies shift type filter - Schedule updates within 2 seconds
    const morningFilterCheckbox = page.locator('[data-testid="filter-shift-type-morning"]');
    
    // Record start time
    const startTime = Date.now();
    
    // Apply filter
    await morningFilterCheckbox.click();
    
    // Wait for schedule to update (check for filtered results)
    await page.waitForFunction(
      () => {
        const shifts = document.querySelectorAll('[data-testid="shift-card"]:visible');
        const allMorning = Array.from(shifts).every(
          shift => shift.getAttribute('data-shift-type') === 'morning'
        );
        return allMorning && shifts.length > 0;
      },
      { timeout: 2000 }
    );
    
    // Calculate elapsed time
    const elapsedTime = Date.now() - startTime;
    
    // Verify filter applied within 2 seconds (2000ms)
    expect(elapsedTime).toBeLessThan(2000);
    
    // Verify schedule is updated correctly
    const visibleShifts = page.locator('[data-testid="shift-card"]:visible');
    await expect(visibleShifts.first()).toBeVisible();
    
    const shiftTypes = await visibleShifts.evaluateAll(elements => 
      elements.map(el => el.getAttribute('data-shift-type'))
    );
    shiftTypes.forEach(type => {
      expect(type).toBe('morning');
    });
  });

  test('#3 Ensure filter state persistence during navigation', async ({ page }) => {
    // Step 1: Employee applies filter and navigates to another date - Filter remains applied and schedule updates accordingly
    
    // Apply morning shift filter
    const morningFilterCheckbox = page.locator('[data-testid="filter-shift-type-morning"]');
    await morningFilterCheckbox.click();
    await page.waitForTimeout(500);
    
    // Verify filter is applied
    await expect(morningFilterCheckbox).toBeChecked();
    
    // Verify only morning shifts are visible
    const initialVisibleShifts = page.locator('[data-testid="shift-card"]:visible');
    const initialShiftTypes = await initialVisibleShifts.evaluateAll(elements => 
      elements.map(el => el.getAttribute('data-shift-type'))
    );
    initialShiftTypes.forEach(type => {
      expect(type).toBe('morning');
    });
    
    // Navigate to next date/week
    const nextDateButton = page.locator('[data-testid="schedule-next-date"]').or(page.locator('button:has-text("Next")')).first();
    await nextDateButton.click();
    
    // Wait for schedule to reload
    await page.waitForTimeout(1000);
    await page.waitForSelector('[data-testid="schedule-container"]');
    
    // Verify filter checkbox is still checked
    await expect(morningFilterCheckbox).toBeChecked();
    
    // Verify only morning shifts are displayed after navigation
    const navigatedVisibleShifts = page.locator('[data-testid="shift-card"]:visible');
    const navigatedShiftCount = await navigatedVisibleShifts.count();
    
    if (navigatedShiftCount > 0) {
      const navigatedShiftTypes = await navigatedVisibleShifts.evaluateAll(elements => 
        elements.map(el => el.getAttribute('data-shift-type'))
      );
      navigatedShiftTypes.forEach(type => {
        expect(type).toBe('morning');
      });
    }
    
    // Verify evening and night shifts are not visible
    await expect(page.locator('[data-testid="shift-card"][data-shift-type="evening"]:visible')).toHaveCount(0);
    await expect(page.locator('[data-testid="shift-card"][data-shift-type="night"]:visible')).toHaveCount(0);
    
    // Navigate to previous date to verify filter persists in both directions
    const prevDateButton = page.locator('[data-testid="schedule-prev-date"]').or(page.locator('button:has-text("Previous")')).first();
    await prevDateButton.click();
    
    // Wait for schedule to reload
    await page.waitForTimeout(1000);
    
    // Verify filter is still applied
    await expect(morningFilterCheckbox).toBeChecked();
    
    const finalVisibleShifts = page.locator('[data-testid="shift-card"]:visible');
    const finalShiftTypes = await finalVisibleShifts.evaluateAll(elements => 
      elements.map(el => el.getAttribute('data-shift-type'))
    );
    finalShiftTypes.forEach(type => {
      expect(type).toBe('morning');
    });
  });
});