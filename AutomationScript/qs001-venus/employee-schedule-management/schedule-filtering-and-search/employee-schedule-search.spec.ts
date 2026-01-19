import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Search by Date', () => {
  test.beforeEach(async ({ page }) => {
    // Employee logs in
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to schedule section from the main dashboard
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page.locator('[data-testid="schedule-section"]')).toBeVisible();
  });

  test('Validate search by single date (happy-path)', async ({ page }) => {
    // Locate and click on the search panel or search icon
    await page.click('[data-testid="search-panel-button"]');
    await expect(page.locator('[data-testid="search-panel"]')).toBeVisible();
    
    // Click on the date input field to activate the calendar picker
    await page.click('[data-testid="date-input"]');
    await expect(page.locator('[data-testid="calendar-picker"]')).toBeVisible();
    
    // Select a valid date (e.g., '2024-03-15') from the calendar picker that has scheduled shifts
    await page.fill('[data-testid="date-input"]', '2024-03-15');
    
    // Click 'Search' or 'Submit' button to execute the search
    await page.click('[data-testid="search-submit-button"]');
    
    // Wait for search results to load (within 2 seconds as per requirements)
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200,
      { timeout: 2000 }
    );
    
    // Verify the displayed schedule shows only shifts for the selected date
    const shifts = page.locator('[data-testid="shift-item"]');
    await expect(shifts).toHaveCountGreaterThan(0);
    
    // Check that all displayed shifts match the searched date
    const shiftCount = await shifts.count();
    for (let i = 0; i < shiftCount; i++) {
      const shiftDate = await shifts.nth(i).locator('[data-testid="shift-date"]').textContent();
      expect(shiftDate).toContain('2024-03-15');
    }
    
    // Verify the shift count matches expected number for that date
    await expect(page.locator('[data-testid="shift-count"]')).toBeVisible();
    const displayedCount = await shifts.count();
    const countText = await page.locator('[data-testid="shift-count"]').textContent();
    expect(countText).toContain(displayedCount.toString());
  });

  test('Validate search by date range (happy-path)', async ({ page }) => {
    // Open the search panel by clicking the search icon or button
    await page.click('[data-testid="search-panel-button"]');
    await expect(page.locator('[data-testid="search-panel"]')).toBeVisible();
    
    // Click on the 'Start Date' input field
    await page.click('[data-testid="start-date-input"]');
    
    // Select a valid start date (e.g., '2024-03-01') from the calendar
    await page.fill('[data-testid="start-date-input"]', '2024-03-01');
    
    // Click on the 'End Date' input field
    await page.click('[data-testid="end-date-input"]');
    
    // Select a valid end date (e.g., '2024-03-15') that is after the start date
    await page.fill('[data-testid="end-date-input"]', '2024-03-15');
    
    // Verify both start and end dates are correctly displayed in the search panel
    await expect(page.locator('[data-testid="start-date-input"]')).toHaveValue('2024-03-01');
    await expect(page.locator('[data-testid="end-date-input"]')).toHaveValue('2024-03-15');
    
    // Click 'Search' or 'Submit' button to execute the date range search
    await page.click('[data-testid="search-submit-button"]');
    
    // Wait for search results to load (within 2 seconds as per requirements)
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && 
      response.url().includes('startDate=2024-03-01') &&
      response.url().includes('endDate=2024-03-15') &&
      response.status() === 200,
      { timeout: 2000 }
    );
    
    // Verify the schedule displays only shifts within the specified date range
    const shifts = page.locator('[data-testid="shift-item"]');
    await expect(shifts).toHaveCountGreaterThan(0);
    
    // Scroll through the results and verify date boundaries
    const shiftCount = await shifts.count();
    for (let i = 0; i < shiftCount; i++) {
      const shiftDateText = await shifts.nth(i).locator('[data-testid="shift-date"]').textContent();
      const shiftDate = new Date(shiftDateText || '');
      const startDate = new Date('2024-03-01');
      const endDate = new Date('2024-03-15');
      
      expect(shiftDate.getTime()).toBeGreaterThanOrEqual(startDate.getTime());
      expect(shiftDate.getTime()).toBeLessThanOrEqual(endDate.getTime());
    }
    
    // Verify the total count of shifts matches expected shifts within the date range
    await expect(page.locator('[data-testid="shift-count"]')).toBeVisible();
    const displayedCount = await shifts.count();
    const countText = await page.locator('[data-testid="shift-count"]').textContent();
    expect(countText).toContain(displayedCount.toString());
  });

  test('Verify error handling for invalid date input (error-case)', async ({ page }) => {
    // Open the search panel by clicking the search icon or button
    await page.click('[data-testid="search-panel-button"]');
    await expect(page.locator('[data-testid="search-panel"]')).toBeVisible();
    
    // Click on the date input field to enable manual text entry (bypass calendar picker if possible)
    await page.click('[data-testid="date-input"]');
    
    // Enter an invalid date format such as '32/13/2024' (invalid day and month)
    await page.fill('[data-testid="date-input"]', '32/13/2024');
    
    // Click 'Search' or 'Submit' button to attempt the search
    await page.click('[data-testid="search-submit-button"]');
    
    // Verify that an error message is displayed
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('invalid date format');
    
    // Verify that the search operation is blocked
    await expect(page.locator('[data-testid="shift-item"]')).toHaveCount(0);
    
    // Test with another invalid format such as 'abc123' (non-date characters)
    await page.fill('[data-testid="date-input"]', 'abc123');
    await page.click('[data-testid="search-submit-button"]');
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('invalid date format');
    
    // Test with invalid date value like '2024-02-30' (February 30th does not exist)
    await page.fill('[data-testid="date-input"]', '2024-02-30');
    await page.click('[data-testid="search-submit-button"]');
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('invalid date');
    
    // Clear the invalid input and enter a valid date format
    await page.fill('[data-testid="date-input"]', '');
    await page.fill('[data-testid="date-input"]', '2024-03-15');
    
    // Verify that search can now proceed with valid date
    await page.click('[data-testid="search-submit-button"]');
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200,
      { timeout: 2000 }
    );
    await expect(page.locator('[data-testid="shift-item"]')).toHaveCountGreaterThan(0);
  });

  test('System allows clearing search inputs to reset schedule view', async ({ page }) => {
    // Open the search panel
    await page.click('[data-testid="search-panel-button"]');
    await expect(page.locator('[data-testid="search-panel"]')).toBeVisible();
    
    // Enter a date and perform search
    await page.fill('[data-testid="date-input"]', '2024-03-15');
    await page.click('[data-testid="search-submit-button"]');
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    
    // Verify filtered results are displayed
    const filteredShifts = await page.locator('[data-testid="shift-item"]').count();
    expect(filteredShifts).toBeGreaterThan(0);
    
    // Clear search inputs
    await page.click('[data-testid="clear-search-button"]');
    
    // Verify search inputs are cleared
    await expect(page.locator('[data-testid="date-input"]')).toHaveValue('');
    
    // Verify schedule view is reset to show all shifts
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    const allShifts = await page.locator('[data-testid="shift-item"]').count();
    expect(allShifts).toBeGreaterThanOrEqual(filteredShifts);
  });
});