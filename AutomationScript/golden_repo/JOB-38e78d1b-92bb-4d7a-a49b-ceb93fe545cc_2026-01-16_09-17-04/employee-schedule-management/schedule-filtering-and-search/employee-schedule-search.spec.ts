import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Search - Story 16', () => {
  test.beforeEach(async ({ page }) => {
    // Employee logs in
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
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
    
    // Get initial count of shifts displayed
    const initialShifts = page.locator('[data-testid="shift-entry"]');
    const initialCount = await initialShifts.count();
    expect(initialCount).toBeGreaterThan(0);
    
    // Enter keyword that exists in shift notes (e.g., 'training')
    await searchInput.fill('training');
    
    // Wait for schedule to update dynamically (within 2 seconds)
    await page.waitForTimeout(500);
    
    // Verify schedule updates to show only matching shifts
    const filteredShifts = page.locator('[data-testid="shift-entry"]');
    const filteredCount = await filteredShifts.count();
    expect(filteredCount).toBeGreaterThan(0);
    expect(filteredCount).toBeLessThanOrEqual(initialCount);
    
    // Verify all displayed shifts contain the searched keyword in their notes
    for (let i = 0; i < filteredCount; i++) {
      const shiftNote = filteredShifts.nth(i).locator('[data-testid="shift-note"]');
      const noteText = await shiftNote.textContent();
      expect(noteText?.toLowerCase()).toContain('training');
    }
    
    // Test partial match by entering only part of a word
    await searchInput.clear();
    await searchInput.fill('train');
    await page.waitForTimeout(500);
    
    const partialMatchShifts = page.locator('[data-testid="shift-entry"]');
    const partialMatchCount = await partialMatchShifts.count();
    expect(partialMatchCount).toBeGreaterThan(0);
    
    // Verify partial match works
    for (let i = 0; i < partialMatchCount; i++) {
      const shiftNote = partialMatchShifts.nth(i).locator('[data-testid="shift-note"]');
      const noteText = await shiftNote.textContent();
      expect(noteText?.toLowerCase()).toContain('train');
    }
    
    // Test case-insensitive search
    await searchInput.clear();
    await searchInput.fill('TRAINING');
    await page.waitForTimeout(500);
    
    const caseInsensitiveShifts = page.locator('[data-testid="shift-entry"]');
    const caseInsensitiveCount = await caseInsensitiveShifts.count();
    expect(caseInsensitiveCount).toBeGreaterThan(0);
    
    // Verify case-insensitive search works
    for (let i = 0; i < caseInsensitiveCount; i++) {
      const shiftNote = caseInsensitiveShifts.nth(i).locator('[data-testid="shift-note"]');
      const noteText = await shiftNote.textContent();
      expect(noteText?.toLowerCase()).toContain('training');
    }
    
    // Clear search input to restore full schedule view
    const clearButton = page.locator('[data-testid="search-clear-button"]');
    if (await clearButton.isVisible()) {
      await clearButton.click();
    } else {
      await searchInput.clear();
    }
    
    await page.waitForTimeout(500);
    
    // Verify full schedule view is restored
    const restoredShifts = page.locator('[data-testid="shift-entry"]');
    const restoredCount = await restoredShifts.count();
    expect(restoredCount).toBe(initialCount);
  });

  test('Validate schedule search with no matching keyword - edge case', async ({ page }) => {
    // Locate the search input field on the schedule page
    const searchInput = page.locator('[data-testid="schedule-search-input"]');
    await expect(searchInput).toBeVisible();
    
    // Get initial count of shifts displayed
    const initialShifts = page.locator('[data-testid="shift-entry"]');
    const initialCount = await initialShifts.count();
    expect(initialCount).toBeGreaterThan(0);
    
    // Enter keyword that does not exist in any shift notes
    await searchInput.fill('xyz123nonexistent');
    
    // Wait for schedule to update dynamically (within 2 seconds)
    await page.waitForTimeout(500);
    
    // Verify system displays 'No matching shifts found' message
    const noResultsMessage = page.locator('[data-testid="no-results-message"]');
    await expect(noResultsMessage).toBeVisible();
    await expect(noResultsMessage).toHaveText(/No matching shifts found/i);
    
    // Verify no shift entries are visible in the schedule
    const filteredShifts = page.locator('[data-testid="shift-entry"]');
    const filteredCount = await filteredShifts.count();
    expect(filteredCount).toBe(0);
    
    // Clear the search input
    const clearButton = page.locator('[data-testid="search-clear-button"]');
    if (await clearButton.isVisible()) {
      await clearButton.click();
    } else {
      await searchInput.clear();
    }
    
    await page.waitForTimeout(500);
    
    // Verify full schedule view is restored after clearing
    const restoredShifts = page.locator('[data-testid="shift-entry"]');
    const restoredCount = await restoredShifts.count();
    expect(restoredCount).toBe(initialCount);
    
    // Verify no results message is no longer visible
    await expect(noResultsMessage).not.toBeVisible();
  });

  test('Validate schedule updates dynamically within 2 seconds', async ({ page }) => {
    const searchInput = page.locator('[data-testid="schedule-search-input"]');
    await expect(searchInput).toBeVisible();
    
    // Record start time
    const startTime = Date.now();
    
    // Enter search keyword
    await searchInput.fill('meeting');
    
    // Wait for schedule to update
    await page.waitForSelector('[data-testid="shift-entry"], [data-testid="no-results-message"]', { timeout: 2000 });
    
    // Calculate elapsed time
    const elapsedTime = Date.now() - startTime;
    
    // Verify update happened within 2 seconds
    expect(elapsedTime).toBeLessThan(2000);
  });

  test('Validate search input can be cleared to restore full schedule view', async ({ page }) => {
    const searchInput = page.locator('[data-testid="schedule-search-input"]');
    
    // Get initial shift count
    const initialShifts = page.locator('[data-testid="shift-entry"]');
    const initialCount = await initialShifts.count();
    
    // Perform a search
    await searchInput.fill('urgent');
    await page.waitForTimeout(500);
    
    // Verify filtered results
    const filteredShifts = page.locator('[data-testid="shift-entry"]');
    const filteredCount = await filteredShifts.count();
    
    // Clear search using clear button if available
    const clearButton = page.locator('[data-testid="search-clear-button"]');
    if (await clearButton.isVisible()) {
      await clearButton.click();
    } else {
      // Alternative: clear by deleting text
      await searchInput.clear();
    }
    
    await page.waitForTimeout(500);
    
    // Verify full schedule is restored
    const restoredShifts = page.locator('[data-testid="shift-entry"]');
    const restoredCount = await restoredShifts.count();
    expect(restoredCount).toBe(initialCount);
    
    // Verify search input is empty
    await expect(searchInput).toHaveValue('');
  });
});