import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Search Functionality', () => {
  test.beforeEach(async ({ page }) => {
    // Employee logs in
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to schedule section
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    await page.waitForSelector('[data-testid="schedule-container"]');
  });

  test('Validate schedule search with matching keyword - happy path', async ({ page }) => {
    // Locate the search input field on the schedule page
    const searchInput = page.locator('[data-testid="schedule-search-input"]');
    await expect(searchInput).toBeVisible();
    
    // Enter a keyword that exists in shift notes (e.g., 'training')
    const keyword = 'training';
    await searchInput.fill(keyword);
    
    // Wait for schedule to update dynamically (within 2 seconds)
    await page.waitForTimeout(500);
    
    // Verify that schedule updates to show only matching shifts
    const scheduleEntries = page.locator('[data-testid="schedule-entry"]');
    const entryCount = await scheduleEntries.count();
    expect(entryCount).toBeGreaterThan(0);
    
    // Verify all displayed shifts contain the searched keyword in their notes
    for (let i = 0; i < entryCount; i++) {
      const noteText = await scheduleEntries.nth(i).locator('[data-testid="shift-notes"]').textContent();
      expect(noteText?.toLowerCase()).toContain(keyword.toLowerCase());
    }
    
    // Test partial match by entering only part of a word
    await searchInput.clear();
    const partialKeyword = 'train';
    await searchInput.fill(partialKeyword);
    await page.waitForTimeout(500);
    
    const partialMatchEntries = page.locator('[data-testid="schedule-entry"]');
    const partialCount = await partialMatchEntries.count();
    expect(partialCount).toBeGreaterThan(0);
    
    // Verify partial matches work
    for (let i = 0; i < partialCount; i++) {
      const noteText = await partialMatchEntries.nth(i).locator('[data-testid="shift-notes"]').textContent();
      expect(noteText?.toLowerCase()).toContain(partialKeyword.toLowerCase());
    }
    
    // Test case-insensitive search with uppercase
    await searchInput.clear();
    await searchInput.fill('TRAINING');
    await page.waitForTimeout(500);
    
    const uppercaseEntries = page.locator('[data-testid="schedule-entry"]');
    const uppercaseCount = await uppercaseEntries.count();
    expect(uppercaseCount).toBeGreaterThan(0);
    
    // Test case-insensitive search with mixed case
    await searchInput.clear();
    await searchInput.fill('TrAiNiNg');
    await page.waitForTimeout(500);
    
    const mixedCaseEntries = page.locator('[data-testid="schedule-entry"]');
    const mixedCount = await mixedCaseEntries.count();
    expect(mixedCount).toBeGreaterThan(0);
    
    // Clear search input to restore full schedule view
    const clearButton = page.locator('[data-testid="search-clear-button"]');
    if (await clearButton.isVisible()) {
      await clearButton.click();
    } else {
      await searchInput.clear();
    }
    
    // Verify full schedule view is restored
    await page.waitForTimeout(500);
    const allEntries = page.locator('[data-testid="schedule-entry"]');
    const fullCount = await allEntries.count();
    expect(fullCount).toBeGreaterThanOrEqual(partialCount);
    
    // Verify search input is empty
    await expect(searchInput).toHaveValue('');
  });

  test('Validate schedule search with no matching keyword - edge case', async ({ page }) => {
    // Locate the search input field on the schedule page
    const searchInput = page.locator('[data-testid="schedule-search-input"]');
    await expect(searchInput).toBeVisible();
    
    // Enter a keyword that does not exist in any shift notes
    const nonExistentKeyword = 'xyz123nonexistent';
    await searchInput.fill(nonExistentKeyword);
    
    // Press Enter or trigger search functionality
    await searchInput.press('Enter');
    
    // Wait for search to complete (within 2 seconds)
    await page.waitForTimeout(500);
    
    // Verify that system displays 'No matching shifts found' message
    const noResultsMessage = page.locator('[data-testid="no-results-message"]');
    await expect(noResultsMessage).toBeVisible();
    
    // Verify the message text is appropriate and user-friendly
    const messageText = await noResultsMessage.textContent();
    expect(messageText?.toLowerCase()).toMatch(/no matching shifts found|no results|no shifts found/);
    
    // Verify that the message is clearly visible
    await expect(noResultsMessage).toHaveCSS('display', /block|flex|grid/);
    
    // Verify no schedule entries are displayed
    const scheduleEntries = page.locator('[data-testid="schedule-entry"]');
    await expect(scheduleEntries).toHaveCount(0);
    
    // Verify that the search input still contains the entered keyword
    await expect(searchInput).toHaveValue(nonExistentKeyword);
    
    // Clear the search input by clicking clear button or deleting text
    const clearButton = page.locator('[data-testid="search-clear-button"]');
    if (await clearButton.isVisible()) {
      await clearButton.click();
    } else {
      await searchInput.clear();
    }
    
    // Verify that the 'no matching shifts' message disappears
    await page.waitForTimeout(500);
    await expect(noResultsMessage).not.toBeVisible();
    
    // Verify full schedule is restored
    const allEntries = page.locator('[data-testid="schedule-entry"]');
    const entryCount = await allEntries.count();
    expect(entryCount).toBeGreaterThan(0);
    
    // Verify search input is empty
    await expect(searchInput).toHaveValue('');
  });

  test('Validate schedule updates dynamically within 2 seconds', async ({ page }) => {
    const searchInput = page.locator('[data-testid="schedule-search-input"]');
    
    // Record start time
    const startTime = Date.now();
    
    // Enter keyword
    await searchInput.fill('meeting');
    
    // Wait for schedule to update
    await page.waitForSelector('[data-testid="schedule-entry"]', { timeout: 2000 });
    
    // Calculate elapsed time
    const elapsedTime = Date.now() - startTime;
    
    // Verify update occurred within 2 seconds
    expect(elapsedTime).toBeLessThan(2000);
    
    // Verify schedule entries are visible
    const scheduleEntries = page.locator('[data-testid="schedule-entry"]');
    await expect(scheduleEntries.first()).toBeVisible();
  });
});