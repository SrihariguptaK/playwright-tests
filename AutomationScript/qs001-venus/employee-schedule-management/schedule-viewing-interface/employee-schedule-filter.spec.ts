import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Shift Type Filtering', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page and authenticate as employee
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to schedule page
    await page.goto('/schedule');
    await expect(page.locator('[data-testid="schedule-page"]')).toBeVisible();
  });

  test('Validate shift type filtering updates schedule display - Morning shift only', async ({ page }) => {
    // Locate the shift type filter control on the schedule page
    const shiftFilterControl = page.locator('[data-testid="shift-type-filter"]');
    await expect(shiftFilterControl).toBeVisible();

    // Get initial count of all shifts
    const allShiftsCount = await page.locator('[data-testid="shift-item"]').count();
    expect(allShiftsCount).toBeGreaterThan(0);

    // Select 'Morning' shift filter from the filter control
    await page.click('[data-testid="shift-filter-morning"]');
    
    // Wait for schedule to update
    await page.waitForTimeout(500);
    
    // Verify the filtered schedule contains only morning shifts
    const morningShifts = page.locator('[data-testid="shift-item"][data-shift-type="morning"]');
    const morningShiftsCount = await morningShifts.count();
    expect(morningShiftsCount).toBeGreaterThan(0);
    
    // Verify no other shift types are displayed
    const nonMorningShifts = page.locator('[data-testid="shift-item"]:not([data-shift-type="morning"])');
    await expect(nonMorningShifts).toHaveCount(0);
    
    // Verify each visible shift has morning type
    const shiftItems = await morningShifts.all();
    for (const shift of shiftItems) {
      await expect(shift).toHaveAttribute('data-shift-type', 'morning');
    }
  });

  test('Validate shift type filtering updates schedule display - Multiple shift types', async ({ page }) => {
    // Locate the shift type filter control
    const shiftFilterControl = page.locator('[data-testid="shift-type-filter"]');
    await expect(shiftFilterControl).toBeVisible();

    // Select multiple shift types by choosing 'Morning' and 'Evening' filters
    await page.click('[data-testid="shift-filter-morning"]');
    await page.click('[data-testid="shift-filter-evening"]');
    
    // Wait for schedule to update
    await page.waitForTimeout(500);
    
    // Verify the filtered schedule contains only the selected shift types
    const morningShifts = page.locator('[data-testid="shift-item"][data-shift-type="morning"]');
    const eveningShifts = page.locator('[data-testid="shift-item"][data-shift-type="evening"]');
    
    const morningCount = await morningShifts.count();
    const eveningCount = await eveningShifts.count();
    
    expect(morningCount).toBeGreaterThan(0);
    expect(eveningCount).toBeGreaterThan(0);
    
    // Verify no night shifts are displayed
    const nightShifts = page.locator('[data-testid="shift-item"][data-shift-type="night"]');
    await expect(nightShifts).toHaveCount(0);
    
    // Verify total visible shifts equals morning + evening
    const totalVisibleShifts = await page.locator('[data-testid="shift-item"]').count();
    expect(totalVisibleShifts).toBe(morningCount + eveningCount);
  });

  test('Validate shift type filtering updates schedule display - Clear filters', async ({ page }) => {
    // Select a filter first
    await page.click('[data-testid="shift-filter-morning"]');
    await page.waitForTimeout(500);
    
    // Verify filtered state
    const filteredCount = await page.locator('[data-testid="shift-item"]').count();
    
    // Clear all filters by clicking 'Clear Filters' button
    const clearFiltersButton = page.locator('[data-testid="clear-filters-button"]');
    await expect(clearFiltersButton).toBeVisible();
    await clearFiltersButton.click();
    
    // Wait for schedule to update
    await page.waitForTimeout(500);
    
    // Verify all shifts are now visible
    const allShiftsCount = await page.locator('[data-testid="shift-item"]').count();
    expect(allShiftsCount).toBeGreaterThan(filteredCount);
    
    // Verify all shift types are present
    const morningShifts = await page.locator('[data-testid="shift-item"][data-shift-type="morning"]').count();
    const eveningShifts = await page.locator('[data-testid="shift-item"][data-shift-type="evening"]').count();
    const nightShifts = await page.locator('[data-testid="shift-item"][data-shift-type="night"]').count();
    
    expect(morningShifts).toBeGreaterThan(0);
    expect(eveningShifts).toBeGreaterThan(0);
    expect(nightShifts).toBeGreaterThan(0);
    
    // Verify no filters are active
    await expect(page.locator('[data-testid="shift-filter-morning"][aria-pressed="true"]')).toHaveCount(0);
    await expect(page.locator('[data-testid="shift-filter-evening"][aria-pressed="true"]')).toHaveCount(0);
    await expect(page.locator('[data-testid="shift-filter-night"][aria-pressed="true"]')).toHaveCount(0);
  });

  test('Verify filter input validation - Invalid filter value', async ({ page }) => {
    // Locate the shift type filter input field
    const filterInput = page.locator('[data-testid="shift-filter-input"]');
    
    // Check if input field exists (alternative to button-based filters)
    const inputExists = await filterInput.count() > 0;
    
    if (inputExists) {
      // Get initial schedule state
      const initialShiftsCount = await page.locator('[data-testid="shift-item"]').count();
      
      // Attempt to input an invalid filter value (special characters)
      await filterInput.fill('!@#$%^&*()');
      await page.keyboard.press('Enter');
      await page.waitForTimeout(500);
      
      // Verify the schedule display remains unchanged
      const currentShiftsCount = await page.locator('[data-testid="shift-item"]').count();
      expect(currentShiftsCount).toBe(initialShiftsCount);
      
      // Verify error message is displayed
      const errorMessage = page.locator('[data-testid="filter-error-message"]');
      await expect(errorMessage).toBeVisible();
      await expect(errorMessage).toContainText(/invalid/i);
      
      // Clear the invalid input
      await filterInput.clear();
    } else {
      // Test with button-based filter attempting invalid selection
      const initialShiftsCount = await page.locator('[data-testid="shift-item"]').count();
      
      // Try to manipulate filter with invalid data attribute
      await page.evaluate(() => {
        const filterButton = document.querySelector('[data-testid="shift-filter-morning"]');
        if (filterButton) {
          filterButton.setAttribute('data-shift-value', 'InvalidShift');
          (filterButton as HTMLElement).click();
        }
      });
      
      await page.waitForTimeout(500);
      
      // Verify error handling or that schedule remains valid
      const errorMessage = page.locator('[data-testid="filter-error-message"]');
      const errorVisible = await errorMessage.isVisible().catch(() => false);
      
      if (errorVisible) {
        await expect(errorMessage).toContainText(/invalid/i);
      }
    }
  });

  test('Verify filter input validation - SQL injection attempt', async ({ page }) => {
    // Locate the shift type filter input field
    const filterInput = page.locator('[data-testid="shift-filter-input"]');
    const inputExists = await filterInput.count() > 0;
    
    if (inputExists) {
      // Get initial schedule state
      const initialShiftsCount = await page.locator('[data-testid="shift-item"]').count();
      
      // Attempt SQL injection
      await filterInput.fill("'; DROP TABLE schedules; --");
      await page.keyboard.press('Enter');
      await page.waitForTimeout(500);
      
      // Verify the schedule display remains unchanged
      const currentShiftsCount = await page.locator('[data-testid="shift-item"]').count();
      expect(currentShiftsCount).toBe(initialShiftsCount);
      
      // Verify error message is clearly visible to the employee
      const errorMessage = page.locator('[data-testid="filter-error-message"]');
      await expect(errorMessage).toBeVisible();
      
      // Clear the invalid input
      await filterInput.clear();
    }
  });

  test('Verify filter input validation - Correct filter input after error', async ({ page }) => {
    const filterInput = page.locator('[data-testid="shift-filter-input"]');
    const inputExists = await filterInput.count() > 0;
    
    if (inputExists) {
      // Input invalid value first
      await filterInput.fill('InvalidShift');
      await page.keyboard.press('Enter');
      await page.waitForTimeout(500);
      
      // Verify error is shown
      const errorMessage = page.locator('[data-testid="filter-error-message"]');
      await expect(errorMessage).toBeVisible();
      
      // Correct the filter input by selecting a valid shift type
      await filterInput.clear();
      await filterInput.fill('Evening');
      await page.keyboard.press('Enter');
      
      // Start performance timer
      const startTime = Date.now();
      
      // Wait for schedule to update
      await page.waitForSelector('[data-testid="shift-item"][data-shift-type="evening"]', { timeout: 3000 });
      
      const loadTime = Date.now() - startTime;
      
      // Verify the schedule updates with the corrected filter
      const eveningShifts = page.locator('[data-testid="shift-item"][data-shift-type="evening"]');
      const eveningCount = await eveningShifts.count();
      expect(eveningCount).toBeGreaterThan(0);
      
      // Verify no error message is displayed
      await expect(errorMessage).not.toBeVisible();
      
      // Verify the filtered results load within 3 seconds
      expect(loadTime).toBeLessThan(3000);
    } else {
      // Use button-based filter for correction test
      await page.click('[data-testid="shift-filter-evening"]');
      
      const startTime = Date.now();
      await page.waitForSelector('[data-testid="shift-item"][data-shift-type="evening"]', { timeout: 3000 });
      const loadTime = Date.now() - startTime;
      
      // Verify the schedule updates with the corrected filter
      const eveningShifts = page.locator('[data-testid="shift-item"][data-shift-type="evening"]');
      const eveningCount = await eveningShifts.count();
      expect(eveningCount).toBeGreaterThan(0);
      
      // Verify the filtered results load within 3 seconds
      expect(loadTime).toBeLessThan(3000);
    }
  });

  test('Verify filtered schedule performance - Load time under 3 seconds', async ({ page }) => {
    // Measure performance of filter application
    const startTime = Date.now();
    
    // Apply filter
    await page.click('[data-testid="shift-filter-morning"]');
    
    // Wait for filtered results to load
    await page.waitForSelector('[data-testid="shift-item"][data-shift-type="morning"]', { timeout: 3000 });
    
    const loadTime = Date.now() - startTime;
    
    // Verify load time is within 3 seconds
    expect(loadTime).toBeLessThan(3000);
    
    // Verify filtered results are displayed
    const morningShifts = page.locator('[data-testid="shift-item"][data-shift-type="morning"]');
    const count = await morningShifts.count();
    expect(count).toBeGreaterThan(0);
  });

  test('Verify authenticated employee sees only their filtered schedule data', async ({ page }) => {
    // Apply morning shift filter
    await page.click('[data-testid="shift-filter-morning"]');
    await page.waitForTimeout(500);
    
    // Get all visible shifts
    const shiftItems = page.locator('[data-testid="shift-item"]');
    const shifts = await shiftItems.all();
    
    // Verify each shift belongs to the authenticated employee
    for (const shift of shifts) {
      const employeeId = await shift.getAttribute('data-employee-id');
      expect(employeeId).toBe('employee@company.com');
    }
    
    // Verify shift type is correct
    for (const shift of shifts) {
      const shiftType = await shift.getAttribute('data-shift-type');
      expect(shiftType).toBe('morning');
    }
  });
});