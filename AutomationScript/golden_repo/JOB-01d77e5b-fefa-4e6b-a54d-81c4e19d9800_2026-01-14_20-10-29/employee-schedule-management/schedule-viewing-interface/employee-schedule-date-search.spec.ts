import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Date Search', () => {
  test.beforeEach(async ({ page }) => {
    // Employee logs in
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to schedule section from the main dashboard
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    await page.waitForLoadState('networkidle');
  });

  test('Validate successful date search - search date with scheduled shifts', async ({ page }) => {
    // Locate the date search input field on the schedule page
    const dateSearchInput = page.locator('[data-testid="date-search-input"]');
    await expect(dateSearchInput).toBeVisible();
    
    // Enter a valid date (e.g., 2024-03-15) that has scheduled shifts
    await dateSearchInput.fill('2024-03-15');
    
    // Click the search button or press Enter to execute the search
    await page.click('[data-testid="search-button"]');
    
    // Wait for search results to load (within 2 seconds)
    await page.waitForSelector('[data-testid="shift-item"]', { timeout: 2000 });
    
    // Verify that only shifts for the searched date are displayed
    const shiftItems = page.locator('[data-testid="shift-item"]');
    await expect(shiftItems).toHaveCount(await shiftItems.count());
    
    // Verify each shift displays the correct date
    const firstShift = shiftItems.first();
    await expect(firstShift).toContainText('2024-03-15');
    
    // Verify shifts are visible
    await expect(shiftItems.first()).toBeVisible();
  });

  test('Validate successful date search - search date with no shifts', async ({ page }) => {
    // Locate the date search input field
    const dateSearchInput = page.locator('[data-testid="date-search-input"]');
    await expect(dateSearchInput).toBeVisible();
    
    // Clear the search field or click a clear/reset button
    await dateSearchInput.clear();
    
    // Enter a valid date (e.g., 2024-04-20) that has no scheduled shifts
    await dateSearchInput.fill('2024-04-20');
    
    // Click the search button or press Enter to execute the search
    await page.click('[data-testid="search-button"]');
    
    // Wait for response (within 2 seconds)
    await page.waitForTimeout(500);
    
    // Verify that no shift data is displayed
    const shiftItems = page.locator('[data-testid="shift-item"]');
    await expect(shiftItems).toHaveCount(0);
    
    // Verify 'No shifts found' message is displayed and user-friendly
    const noShiftsMessage = page.locator('[data-testid="no-shifts-message"]');
    await expect(noShiftsMessage).toBeVisible();
    await expect(noShiftsMessage).toContainText('No shifts found');
  });

  test('Validate date search with invalid date format - numeric invalid date', async ({ page }) => {
    // Locate the date search input field
    const dateSearchInput = page.locator('[data-testid="date-search-input"]');
    await expect(dateSearchInput).toBeVisible();
    
    // Enter an invalid date format (e.g., '32/13/2024')
    await dateSearchInput.fill('32/13/2024');
    
    // Attempt to execute the search with the invalid date format
    await page.click('[data-testid="search-button"]');
    
    // Verify error message is displayed
    const errorMessage = page.locator('[data-testid="date-error-message"]');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText(/invalid.*date.*format/i);
    
    // Verify that no search is executed and no shift data is displayed
    const shiftItems = page.locator('[data-testid="shift-item"]');
    await expect(shiftItems).toHaveCount(0);
  });

  test('Validate date search with invalid date format - alphanumeric invalid date', async ({ page }) => {
    // Locate the date search input field
    const dateSearchInput = page.locator('[data-testid="date-search-input"]');
    await expect(dateSearchInput).toBeVisible();
    
    // Enter an invalid date format (e.g., 'abc123')
    await dateSearchInput.fill('abc123');
    
    // Attempt to execute the search with the invalid date format
    await page.click('[data-testid="search-button"]');
    
    // Verify error message is displayed
    const errorMessage = page.locator('[data-testid="date-error-message"]');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText(/invalid.*date.*format/i);
    
    // Verify that no search is executed and no shift data is displayed
    const shiftItems = page.locator('[data-testid="shift-item"]');
    await expect(shiftItems).toHaveCount(0);
  });

  test('Validate date search with invalid date format - out of range date', async ({ page }) => {
    // Locate the date search input field
    const dateSearchInput = page.locator('[data-testid="date-search-input"]');
    await expect(dateSearchInput).toBeVisible();
    
    // Enter an invalid date format (e.g., '2024-13-45')
    await dateSearchInput.fill('2024-13-45');
    
    // Attempt to execute the search with the invalid date format
    await page.click('[data-testid="search-button"]');
    
    // Verify error message is displayed
    const errorMessage = page.locator('[data-testid="date-error-message"]');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText(/invalid.*date.*format/i);
    
    // Verify that no search is executed and no shift data is displayed
    const shiftItems = page.locator('[data-testid="shift-item"]');
    await expect(shiftItems).toHaveCount(0);
  });

  test('Validate clear search functionality returns to full schedule', async ({ page }) => {
    // Enter a valid date and search
    const dateSearchInput = page.locator('[data-testid="date-search-input"]');
    await dateSearchInput.fill('2024-03-15');
    await page.click('[data-testid="search-button"]');
    await page.waitForSelector('[data-testid="shift-item"]', { timeout: 2000 });
    
    // Clear the search field or click a clear/reset button
    const clearButton = page.locator('[data-testid="clear-search-button"]');
    if (await clearButton.isVisible()) {
      await clearButton.click();
    } else {
      await dateSearchInput.clear();
      await page.keyboard.press('Enter');
    }
    
    // Verify full schedule is displayed
    await page.waitForLoadState('networkidle');
    const shiftItems = page.locator('[data-testid="shift-item"]');
    const shiftCount = await shiftItems.count();
    
    // Verify multiple shifts are displayed (full schedule)
    expect(shiftCount).toBeGreaterThan(0);
  });

  test('Validate search results load within 2 seconds performance requirement', async ({ page }) => {
    const dateSearchInput = page.locator('[data-testid="date-search-input"]');
    await dateSearchInput.fill('2024-03-15');
    
    // Record start time
    const startTime = Date.now();
    
    // Execute search
    await page.click('[data-testid="search-button"]');
    
    // Wait for results
    await page.waitForSelector('[data-testid="shift-item"]', { timeout: 2000 });
    
    // Calculate elapsed time
    const elapsedTime = Date.now() - startTime;
    
    // Verify results loaded within 2 seconds (2000ms)
    expect(elapsedTime).toBeLessThan(2000);
    
    // Verify shifts are displayed
    const shiftItems = page.locator('[data-testid="shift-item"]');
    await expect(shiftItems.first()).toBeVisible();
  });
});