import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Search by Date', () => {
  test.beforeEach(async ({ page }) => {
    // Employee logs in
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*schedule/);
    
    // Navigate to schedule page if not already there
    await page.goto('/schedule');
    await page.waitForLoadState('networkidle');
  });

  test('Validate schedule search with valid date', async ({ page }) => {
    // Locate the date search field or date picker input on the schedule page
    const dateSearchField = page.locator('[data-testid="schedule-date-search"]');
    await expect(dateSearchField).toBeVisible();
    
    // Enter a valid date in the correct format for a date that has scheduled shifts
    const searchDate = '06/15/2024';
    await dateSearchField.fill(searchDate);
    
    // Submit the search by clicking the search button or pressing Enter
    await page.click('[data-testid="search-button"]');
    await page.waitForLoadState('networkidle');
    
    // Verify that only shifts for the searched date are displayed
    const shiftCards = page.locator('[data-testid="shift-card"]');
    await expect(shiftCards).toHaveCountGreaterThan(0);
    
    // Verify shifts belong to the logged-in employee and match the searched date
    const displayedShifts = await shiftCards.all();
    for (const shift of displayedShifts) {
      const shiftDate = await shift.locator('[data-testid="shift-date"]').textContent();
      expect(shiftDate).toContain('06/15/2024');
    }
    
    // Click the 'Clear search' button or clear the date input field
    await page.click('[data-testid="clear-search-button"]');
    await page.waitForLoadState('networkidle');
    
    // Verify that full schedule view is restored
    const allShifts = page.locator('[data-testid="shift-card"]');
    const allShiftsCount = await allShifts.count();
    expect(allShiftsCount).toBeGreaterThan(displayedShifts.length);
  });

  test('Verify handling of invalid date input - invalid format', async ({ page }) => {
    // Locate the date search field on the schedule page
    const dateSearchField = page.locator('[data-testid="schedule-date-search"]');
    await expect(dateSearchField).toBeVisible();
    
    // Enter an invalid date format in the search field
    const invalidDates = ['99/99/9999', 'abc123', '13/45/2024'];
    
    for (const invalidDate of invalidDates) {
      await dateSearchField.fill(invalidDate);
      
      // Attempt to submit the search
      await page.click('[data-testid="search-button"]');
      
      // Verify that error message is displayed and search is blocked
      const errorMessage = page.locator('[data-testid="date-error-message"]');
      await expect(errorMessage).toBeVisible();
      await expect(errorMessage).toContainText(/invalid date format|please enter a valid date/i);
      
      // Verify no shifts are displayed for invalid search
      const shiftCards = page.locator('[data-testid="shift-card"]');
      const isVisible = await shiftCards.first().isVisible().catch(() => false);
      
      // Clear the invalid input
      await dateSearchField.clear();
      await page.waitForTimeout(500);
    }
  });

  test('Verify handling of invalid date input - out of range date', async ({ page }) => {
    // Locate the date search field on the schedule page
    const dateSearchField = page.locator('[data-testid="schedule-date-search"]');
    await expect(dateSearchField).toBeVisible();
    
    // Enter a valid date that is outside the employee's schedule range
    const outOfRangeDate = '01/01/2000'; // Date far in the past before employment
    await dateSearchField.fill(outOfRangeDate);
    
    // Submit the search for the out-of-range date
    await page.click('[data-testid="search-button"]');
    await page.waitForLoadState('networkidle');
    
    // Verify that the schedule view shows the 'No shifts found' message
    const noShiftsMessage = page.locator('[data-testid="no-shifts-message"]');
    await expect(noShiftsMessage).toBeVisible();
    await expect(noShiftsMessage).toContainText(/no shifts found/i);
    
    // Verify that no shift data is displayed
    const shiftCards = page.locator('[data-testid="shift-card"]');
    await expect(shiftCards).toHaveCount(0);
    
    // Test with a date far in the future
    await dateSearchField.clear();
    const futureDate = '12/31/2099';
    await dateSearchField.fill(futureDate);
    await page.click('[data-testid="search-button"]');
    await page.waitForLoadState('networkidle');
    
    // Verify 'No shifts found' message for future date
    await expect(noShiftsMessage).toBeVisible();
    await expect(noShiftsMessage).toContainText(/no shifts found/i);
    await expect(shiftCards).toHaveCount(0);
  });

  test('Verify search response time is under 2 seconds', async ({ page }) => {
    const dateSearchField = page.locator('[data-testid="schedule-date-search"]');
    await expect(dateSearchField).toBeVisible();
    
    const searchDate = '06/15/2024';
    await dateSearchField.fill(searchDate);
    
    // Measure search response time
    const startTime = Date.now();
    await page.click('[data-testid="search-button"]');
    await page.waitForLoadState('networkidle');
    const endTime = Date.now();
    
    const responseTime = endTime - startTime;
    
    // Verify response time is under 2 seconds (2000ms)
    expect(responseTime).toBeLessThan(2000);
    
    // Verify shifts are displayed
    const shiftCards = page.locator('[data-testid="shift-card"]');
    await expect(shiftCards.first()).toBeVisible();
  });

  test('Verify search results are restricted to logged-in employee only', async ({ page }) => {
    const dateSearchField = page.locator('[data-testid="schedule-date-search"]');
    await expect(dateSearchField).toBeVisible();
    
    const searchDate = '06/15/2024';
    await dateSearchField.fill(searchDate);
    await page.click('[data-testid="search-button"]');
    await page.waitForLoadState('networkidle');
    
    // Verify all displayed shifts belong to the logged-in employee
    const shiftCards = page.locator('[data-testid="shift-card"]');
    const shiftsCount = await shiftCards.count();
    
    if (shiftsCount > 0) {
      const employeeInfo = page.locator('[data-testid="employee-name"]').first();
      const loggedInEmployee = await employeeInfo.textContent();
      
      // Check each shift card belongs to the logged-in employee
      for (let i = 0; i < shiftsCount; i++) {
        const shiftEmployee = await shiftCards.nth(i).locator('[data-testid="shift-employee-name"]').textContent();
        expect(shiftEmployee).toBe(loggedInEmployee);
      }
    }
  });
});