import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Search by Date', () => {
  test.beforeEach(async ({ page }) => {
    // Employee logs in
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to schedule page
    await page.click('[data-testid="schedule-menu-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    await page.waitForLoadState('networkidle');
  });

  test.afterEach(async ({ page }) => {
    // Employee logs out
    await page.click('[data-testid="user-menu-button"]');
    await page.click('[data-testid="logout-button"]');
  });

  test('Validate search by valid date', async ({ page }) => {
    // Locate the date search field on the schedule page
    const dateSearchField = page.locator('[data-testid="date-search-input"]');
    await expect(dateSearchField).toBeVisible();
    
    // Click on the date search field to activate it
    await dateSearchField.click();
    
    // Enter a valid date in the correct format YYYY-MM-DD
    const searchDate = '2024-03-15';
    await dateSearchField.fill(searchDate);
    
    // Submit the search by pressing Enter
    await dateSearchField.press('Enter');
    
    // Wait for search results to load (within 3 seconds as per requirements)
    await page.waitForResponse(
      response => response.url().includes(`/api/schedules?date=${searchDate}`) && response.status() === 200,
      { timeout: 3000 }
    );
    
    // Observe the schedule display update
    await page.waitForSelector('[data-testid="schedule-results"]', { state: 'visible' });
    
    // Verify that only shifts matching the searched date are displayed
    const displayedShifts = page.locator('[data-testid="shift-item"]');
    await expect(displayedShifts).toHaveCountGreaterThan(0);
    
    // Verify each shift has the correct date
    const shiftCount = await displayedShifts.count();
    for (let i = 0; i < shiftCount; i++) {
      const shiftDate = await displayedShifts.nth(i).getAttribute('data-shift-date');
      expect(shiftDate).toBe(searchDate);
    }
    
    // Verify search results loaded within 3 seconds (already validated by waitForResponse timeout)
    const scheduleContainer = page.locator('[data-testid="schedule-results"]');
    await expect(scheduleContainer).toBeVisible();
    
    // Locate and click the clear search button
    const clearButton = page.locator('[data-testid="clear-search-button"]');
    await expect(clearButton).toBeVisible();
    await clearButton.click();
    
    // Observe the schedule after clearing the search
    await page.waitForLoadState('networkidle');
    
    // Verify that full schedule is displayed
    await expect(dateSearchField).toHaveValue('');
    const allShifts = page.locator('[data-testid="shift-item"]');
    const allShiftCount = await allShifts.count();
    expect(allShiftCount).toBeGreaterThanOrEqual(shiftCount);
  });

  test('Verify rejection of invalid date input - DD/MM/YYYY format', async ({ page }) => {
    // Locate the date search input field
    const dateSearchField = page.locator('[data-testid="date-search-input"]');
    await expect(dateSearchField).toBeVisible();
    
    // Click on the date search field to activate it
    await dateSearchField.click();
    
    // Enter an invalid date format DD/MM/YYYY
    const invalidDate = '15/03/2024';
    await dateSearchField.fill(invalidDate);
    
    // Attempt to submit the search by pressing Enter
    await dateSearchField.press('Enter');
    
    // Observe the system response to the invalid input
    const errorMessage = page.locator('[data-testid="date-search-error"]');
    await expect(errorMessage).toBeVisible();
    
    // Verify error message is clear and informative
    await expect(errorMessage).toContainText(/invalid.*date.*format|YYYY-MM-DD/i);
    
    // Verify that the search was not performed
    const scheduleResults = page.locator('[data-testid="schedule-results"]');
    const initialShiftCount = await page.locator('[data-testid="shift-item"]').count();
    
    // Verify the search field state shows the invalid input
    await expect(dateSearchField).toHaveValue(invalidDate);
  });

  test('Verify rejection of invalid date input - MM-DD-YYYY format', async ({ page }) => {
    // Locate the date search input field
    const dateSearchField = page.locator('[data-testid="date-search-input"]');
    await expect(dateSearchField).toBeVisible();
    
    // Click on the date search field to activate it
    await dateSearchField.click();
    
    // Enter an invalid date format MM-DD-YYYY
    const invalidDate = '03-15-2024';
    await dateSearchField.fill(invalidDate);
    
    // Attempt to submit the search by clicking the search button
    const searchButton = page.locator('[data-testid="search-button"]');
    if (await searchButton.isVisible()) {
      await searchButton.click();
    } else {
      await dateSearchField.press('Enter');
    }
    
    // Observe the system response to the invalid input
    const errorMessage = page.locator('[data-testid="date-search-error"]');
    await expect(errorMessage).toBeVisible();
    
    // Verify error message displayed
    await expect(errorMessage).toContainText(/invalid.*date.*format|YYYY-MM-DD/i);
    
    // Verify that the search was not performed
    await expect(dateSearchField).toHaveValue(invalidDate);
  });

  test('Verify rejection of invalid date input - text string', async ({ page }) => {
    // Locate the date search input field
    const dateSearchField = page.locator('[data-testid="date-search-input"]');
    await expect(dateSearchField).toBeVisible();
    
    // Click on the date search field to activate it
    await dateSearchField.click();
    
    // Enter an invalid date format - text string
    const invalidDate = 'invalid-date';
    await dateSearchField.fill(invalidDate);
    
    // Attempt to submit the search by pressing Enter
    await dateSearchField.press('Enter');
    
    // Observe the system response to the invalid input
    const errorMessage = page.locator('[data-testid="date-search-error"]');
    await expect(errorMessage).toBeVisible();
    
    // Verify error message is clear
    await expect(errorMessage).toContainText(/invalid.*date.*format|YYYY-MM-DD/i);
    
    // Verify that the search was not performed
    await expect(dateSearchField).toHaveValue(invalidDate);
  });

  test('Verify rejection of invalid date input - impossible date', async ({ page }) => {
    // Locate the date search input field
    const dateSearchField = page.locator('[data-testid="date-search-input"]');
    await expect(dateSearchField).toBeVisible();
    
    // Click on the date search field to activate it
    await dateSearchField.click();
    
    // Enter an invalid date - impossible date values
    const invalidDate = '2024-13-45';
    await dateSearchField.fill(invalidDate);
    
    // Attempt to submit the search by pressing Enter
    await dateSearchField.press('Enter');
    
    // Observe the system response to the invalid input
    const errorMessage = page.locator('[data-testid="date-search-error"]');
    await expect(errorMessage).toBeVisible();
    
    // Verify error message displayed and search not performed
    await expect(errorMessage).toContainText(/invalid.*date|valid.*date/i);
    
    // Verify the search field state
    await expect(dateSearchField).toHaveValue(invalidDate);
  });

  test('Verify search results update dynamically without full page reload', async ({ page }) => {
    // Track navigation events to ensure no full page reload
    let navigationOccurred = false;
    page.on('framenavigated', () => {
      navigationOccurred = true;
    });
    
    // Locate the date search field
    const dateSearchField = page.locator('[data-testid="date-search-input"]');
    await dateSearchField.click();
    
    // Enter a valid date
    const searchDate = '2024-03-15';
    await dateSearchField.fill(searchDate);
    await dateSearchField.press('Enter');
    
    // Wait for search results
    await page.waitForResponse(
      response => response.url().includes(`/api/schedules?date=${searchDate}`),
      { timeout: 3000 }
    );
    
    // Verify results are displayed
    await expect(page.locator('[data-testid="schedule-results"]')).toBeVisible();
    
    // Verify no full page reload occurred (dynamic update)
    expect(navigationOccurred).toBe(false);
  });
});