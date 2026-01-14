import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Calendar - Story 5', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Scheduling Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduling.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('View schedules in calendar with filters (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the schedule calendar page from the main menu or dashboard
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="calendar-view-link"]');
    
    // Expected Result: Calendar displayed
    await expect(page.locator('[data-testid="schedule-calendar"]')).toBeVisible();
    
    // Step 2: Verify that the calendar displays schedules with employee names, shift times, and shift types
    await expect(page.locator('[data-testid="calendar-shift-item"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="shift-employee-name"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="shift-time"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="shift-type"]').first()).toBeVisible();
    
    // Step 3: Locate and click on the employee filter dropdown
    await page.click('[data-testid="employee-filter-dropdown"]');
    await expect(page.locator('[data-testid="employee-filter-options"]')).toBeVisible();
    
    // Step 4: Select a specific employee from the filter dropdown
    await page.click('[data-testid="employee-option-john-doe"]');
    
    // Step 5: Locate and click on the shift type filter dropdown
    await page.click('[data-testid="shift-type-filter-dropdown"]');
    await expect(page.locator('[data-testid="shift-type-filter-options"]')).toBeVisible();
    
    // Step 6: Select a specific shift type from the filter dropdown
    await page.click('[data-testid="shift-type-option-morning"]');
    
    // Expected Result: Calendar updates to show filtered schedules
    await page.waitForResponse(response => response.url().includes('/api/employeeschedules') && response.status() === 200);
    await expect(page.locator('[data-testid="calendar-shift-item"]')).toBeVisible();
    
    // Step 7: Verify that scheduling conflicts are visually highlighted
    const conflictShifts = page.locator('[data-testid="shift-conflict"]');
    if (await conflictShifts.count() > 0) {
      await expect(conflictShifts.first()).toHaveClass(/conflict|warning|error/);
      await expect(conflictShifts.first()).toHaveCSS('border-color', /red|#ff0000|rgb\(255, 0, 0\)/i);
    }
    
    // Step 8: Verify that unassigned shifts or gaps in coverage are visually indicated
    const unassignedShifts = page.locator('[data-testid="shift-unassigned"]');
    if (await unassignedShifts.count() > 0) {
      await expect(unassignedShifts.first()).toBeVisible();
      await expect(unassignedShifts.first()).toHaveClass(/unassigned|empty|gap/);
    }
    
    // Step 9: Clear all filters or select 'All' options to return to full calendar view
    await page.click('[data-testid="clear-filters-button"]');
    await page.waitForResponse(response => response.url().includes('/api/employeeschedules') && response.status() === 200);
    await expect(page.locator('[data-testid="calendar-shift-item"]')).toHaveCount(await page.locator('[data-testid="calendar-shift-item"]').count());
  });

  test('Edit shift from calendar view (happy-path)', async ({ page }) => {
    // Navigate to schedule calendar page
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="calendar-view-link"]');
    await expect(page.locator('[data-testid="schedule-calendar"]')).toBeVisible();
    
    // Step 1: Locate a specific shift in the calendar view
    const targetShift = page.locator('[data-testid="calendar-shift-item"]').first();
    await expect(targetShift).toBeVisible();
    
    // Store original shift details for verification
    const originalShiftTime = await page.locator('[data-testid="shift-time"]').first().textContent();
    
    // Step 2: Click on the shift block in the calendar
    await targetShift.click();
    
    // Expected Result: Edit form displayed
    await expect(page.locator('[data-testid="shift-edit-form"]')).toBeVisible();
    
    // Step 3: Verify that all shift fields are editable and populated with current values
    await expect(page.locator('[data-testid="shift-start-time-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-template-select"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-date-input"]')).toBeVisible();
    
    // Verify fields are populated
    await expect(page.locator('[data-testid="shift-start-time-input"]')).not.toHaveValue('');
    await expect(page.locator('[data-testid="shift-end-time-input"]')).not.toHaveValue('');
    
    // Step 4: Modify one or more shift details
    await page.fill('[data-testid="shift-start-time-input"]', '09:00');
    await page.fill('[data-testid="shift-end-time-input"]', '17:00');
    await page.selectOption('[data-testid="shift-template-select"]', { label: 'Day Shift' });
    
    // Step 5: Click the Save or Update button in the edit form
    await page.click('[data-testid="shift-save-button"]');
    
    // Expected Result: Shift updated and calendar refreshed
    await page.waitForResponse(response => 
      (response.url().includes('/api/employeeschedules') && 
      (response.request().method() === 'PUT' || response.request().method() === 'PATCH')) &&
      response.status() === 200
    );
    
    // Step 6: Verify that the edit form closes automatically after successful save
    await expect(page.locator('[data-testid="shift-edit-form"]')).not.toBeVisible({ timeout: 5000 });
    
    // Step 7: Verify that the calendar automatically refreshes to display the updated shift information
    await expect(page.locator('[data-testid="schedule-calendar"]')).toBeVisible();
    const updatedShiftTime = await page.locator('[data-testid="shift-time"]').first().textContent();
    expect(updatedShiftTime).not.toBe(originalShiftTime);
    expect(updatedShiftTime).toContain('09:00');
    
    // Step 8: Optionally, click on the same shift again to verify changes were persisted
    await page.locator('[data-testid="calendar-shift-item"]').first().click();
    await expect(page.locator('[data-testid="shift-edit-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-start-time-input"]')).toHaveValue('09:00');
    await expect(page.locator('[data-testid="shift-end-time-input"]')).toHaveValue('17:00');
    await expect(page.locator('[data-testid="shift-template-select"]')).toHaveValue(/day.*shift/i);
    
    // Close the edit form
    await page.click('[data-testid="shift-cancel-button"]');
    await expect(page.locator('[data-testid="shift-edit-form"]')).not.toBeVisible();
  });
});