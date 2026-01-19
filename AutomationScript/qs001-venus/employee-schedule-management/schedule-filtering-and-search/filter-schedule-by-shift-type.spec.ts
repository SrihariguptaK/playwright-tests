import { test, expect } from '@playwright/test';

test.describe('Filter Schedule by Shift Type - Story 14', () => {
  test.beforeEach(async ({ page }) => {
    // Employee logs in
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test.afterEach(async ({ page }) => {
    // Employee logs out
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
  });

  test('Validate filtering by single shift type (happy-path)', async ({ page }) => {
    // Navigate to the schedule page from the main dashboard
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    
    // Wait for schedule to load
    await page.waitForSelector('[data-testid="schedule-container"]');
    
    // Store initial count of all shifts
    const initialShifts = await page.locator('[data-testid="shift-item"]').count();
    expect(initialShifts).toBeGreaterThan(0);
    
    // Locate the shift type filter control on the schedule page
    const filterControl = page.locator('[data-testid="shift-type-filter"]');
    await expect(filterControl).toBeVisible();
    
    // Click on the shift type filter control to view available shift types
    await filterControl.click();
    
    // Wait for filter options to be visible
    await page.waitForSelector('[data-testid="filter-option"]');
    
    // Select a specific shift type from the filter options (e.g., 'Morning')
    await page.click('[data-testid="filter-option-morning"]');
    
    // Wait for schedule to update dynamically (without full page reload)
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    
    // Verify that the URL did not change (no full page reload)
    await expect(page).toHaveURL(/.*schedule/);
    
    // Observe the schedule display update
    await page.waitForTimeout(500); // Allow for dynamic update
    
    // Verify that only shifts of the selected type are displayed
    const filteredShifts = page.locator('[data-testid="shift-item"]');
    const filteredCount = await filteredShifts.count();
    
    // Verify filtered results are shown
    expect(filteredCount).toBeGreaterThan(0);
    expect(filteredCount).toBeLessThanOrEqual(initialShifts);
    
    // Verify all displayed shifts are of the selected type
    for (let i = 0; i < filteredCount; i++) {
      const shiftType = await filteredShifts.nth(i).getAttribute('data-shift-type');
      expect(shiftType?.toLowerCase()).toBe('morning');
    }
    
    // Verify filter indicator is active
    await expect(page.locator('[data-testid="active-filter-badge"]')).toBeVisible();
    await expect(page.locator('[data-testid="active-filter-badge"]')).toContainText('Morning');
    
    // Locate and click the 'Clear filter' button or option
    const clearFilterButton = page.locator('[data-testid="clear-filter-button"]');
    await expect(clearFilterButton).toBeVisible();
    await clearFilterButton.click();
    
    // Wait for schedule to update after clearing filter
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    
    // Observe the schedule display after clearing the filter
    await page.waitForTimeout(500);
    
    // Verify full schedule is displayed again
    const restoredShifts = await page.locator('[data-testid="shift-item"]').count();
    expect(restoredShifts).toBe(initialShifts);
    
    // Verify filter indicator is no longer active
    await expect(page.locator('[data-testid="active-filter-badge"]')).not.toBeVisible();
  });

  test('Verify rejection of invalid shift type filter (error-case)', async ({ page }) => {
    // Navigate to the schedule page
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    
    // Wait for schedule to load
    await page.waitForSelector('[data-testid="schedule-container"]');
    
    // Store initial count of shifts before attempting invalid filter
    const initialShifts = await page.locator('[data-testid="shift-item"]').count();
    
    // Locate the shift type filter input field or control
    const filterControl = page.locator('[data-testid="shift-type-filter"]');
    await expect(filterControl).toBeVisible();
    
    // Click to open filter options
    await filterControl.click();
    
    // Check if there's a custom input option for shift type
    const customInputOption = page.locator('[data-testid="custom-filter-input"]');
    
    if (await customInputOption.isVisible()) {
      // Attempt to input an invalid shift type
      await customInputOption.fill('InvalidType123');
      
      // Submit or apply the invalid shift type filter
      await page.click('[data-testid="apply-filter-button"]');
    } else {
      // Try to manipulate the filter through developer tools or direct API call simulation
      // Simulate invalid filter by attempting to select non-existent option
      await page.evaluate(() => {
        const filterElement = document.querySelector('[data-testid="shift-type-filter"]') as HTMLSelectElement;
        if (filterElement) {
          const option = document.createElement('option');
          option.value = 'InvalidType123';
          option.text = 'InvalidType123';
          filterElement.appendChild(option);
          filterElement.value = 'InvalidType123';
          filterElement.dispatchEvent(new Event('change', { bubbles: true }));
        }
      });
      
      // Attempt to apply the invalid filter
      const applyButton = page.locator('[data-testid="apply-filter-button"]');
      if (await applyButton.isVisible()) {
        await applyButton.click();
      }
    }
    
    // Observe the system response
    // Wait for error message to appear
    const errorMessage = page.locator('[data-testid="filter-error-message"]');
    await expect(errorMessage).toBeVisible({ timeout: 5000 });
    
    // Verify clear error message is displayed
    await expect(errorMessage).toContainText(/invalid.*shift.*type/i);
    
    // Verify that the filter was not applied to the schedule
    const currentShifts = await page.locator('[data-testid="shift-item"]').count();
    expect(currentShifts).toBe(initialShifts);
    
    // Verify no filter badge is shown for invalid filter
    const filterBadge = page.locator('[data-testid="active-filter-badge"]');
    if (await filterBadge.isVisible()) {
      await expect(filterBadge).not.toContainText('InvalidType123');
    }
    
    // Verify the filter control state is reset or shows error state
    const filterControlState = await filterControl.getAttribute('aria-invalid');
    expect(filterControlState).toBe('true');
    
    // Verify schedule remains unchanged with all shift types visible
    const shiftItems = page.locator('[data-testid="shift-item"]');
    const shiftCount = await shiftItems.count();
    expect(shiftCount).toBe(initialShifts);
    
    // Close error message if dismissible
    const closeErrorButton = page.locator('[data-testid="close-error-button"]');
    if (await closeErrorButton.isVisible()) {
      await closeErrorButton.click();
      await expect(errorMessage).not.toBeVisible();
    }
  });

  test('Verify filter results load within 3 seconds (performance)', async ({ page }) => {
    // Navigate to schedule page
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    await page.waitForSelector('[data-testid="schedule-container"]');
    
    // Click on shift type filter
    await page.click('[data-testid="shift-type-filter"]');
    await page.waitForSelector('[data-testid="filter-option"]');
    
    // Measure time for filter application
    const startTime = Date.now();
    
    // Select a shift type filter
    await page.click('[data-testid="filter-option-evening"]');
    
    // Wait for filtered results to load
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    
    await page.waitForSelector('[data-testid="shift-item"]');
    
    const endTime = Date.now();
    const loadTime = endTime - startTime;
    
    // Verify filter results load within 3 seconds (3000ms)
    expect(loadTime).toBeLessThan(3000);
    
    // Verify filtered results are displayed
    const filteredShifts = await page.locator('[data-testid="shift-item"]').count();
    expect(filteredShifts).toBeGreaterThan(0);
  });

  test('Verify multiple filters can be applied simultaneously', async ({ page }) => {
    // Navigate to schedule page
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    await page.waitForSelector('[data-testid="schedule-container"]');
    
    const initialShifts = await page.locator('[data-testid="shift-item"]').count();
    
    // Open filter control
    await page.click('[data-testid="shift-type-filter"]');
    await page.waitForSelector('[data-testid="filter-option"]');
    
    // Select first shift type (Morning)
    await page.click('[data-testid="filter-option-morning"]');
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    
    // Verify first filter is applied
    await expect(page.locator('[data-testid="active-filter-badge"]')).toContainText('Morning');
    
    const firstFilterCount = await page.locator('[data-testid="shift-item"]').count();
    expect(firstFilterCount).toBeLessThanOrEqual(initialShifts);
    
    // Apply second filter (Evening)
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-evening"]');
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    
    // Verify both filters are active
    const filterBadges = page.locator('[data-testid="active-filter-badge"]');
    const badgeCount = await filterBadges.count();
    expect(badgeCount).toBeGreaterThanOrEqual(1);
    
    // Verify schedule shows shifts matching either filter
    const multiFilterCount = await page.locator('[data-testid="shift-item"]').count();
    expect(multiFilterCount).toBeGreaterThan(0);
    
    // Clear all filters
    await page.click('[data-testid="clear-filter-button"]');
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    
    // Verify full schedule is restored
    const restoredCount = await page.locator('[data-testid="shift-item"]').count();
    expect(restoredCount).toBe(initialShifts);
  });
});