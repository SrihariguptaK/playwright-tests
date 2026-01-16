import { test, expect } from '@playwright/test';

test.describe('Shift Template Search and Filter Management', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to shift template list page before each test
    await page.goto('/shift-templates');
    // Wait for the page to load completely
    await page.waitForLoadState('networkidle');
  });

  test('Search shift templates by name', async ({ page }) => {
    // Step 1: Navigate to shift template list page
    // Expected Result: List of shift templates is displayed
    const templateList = page.locator('[data-testid="shift-template-list"]');
    await expect(templateList).toBeVisible();
    
    const templateItems = page.locator('[data-testid="shift-template-item"]');
    const initialCount = await templateItems.count();
    await expect(initialCount).toBeGreaterThan(0);

    // Step 2: Enter a keyword in the search box
    // Expected Result: List updates to show matching templates
    const searchBox = page.locator('[data-testid="shift-template-search"]');
    await expect(searchBox).toBeVisible();
    await searchBox.fill('Morning');
    
    // Wait for search results to update
    await page.waitForTimeout(500);
    
    const filteredItems = page.locator('[data-testid="shift-template-item"]');
    const filteredCount = await filteredItems.count();
    
    // Verify filtered results contain the search keyword
    for (let i = 0; i < await filteredItems.count(); i++) {
      const itemText = await filteredItems.nth(i).textContent();
      expect(itemText?.toLowerCase()).toContain('morning');
    }
    
    // Verify filtered count is less than or equal to initial count
    expect(filteredCount).toBeLessThanOrEqual(initialCount);

    // Step 3: Clear search box
    // Expected Result: Full list of templates is restored
    await searchBox.clear();
    await page.waitForTimeout(500);
    
    const restoredItems = page.locator('[data-testid="shift-template-item"]');
    const restoredCount = await restoredItems.count();
    expect(restoredCount).toBe(initialCount);
  });

  test('Filter shift templates by start time', async ({ page }) => {
    // Step 1: Select a start time filter criterion
    // Expected Result: List updates to show templates matching the filter
    const startTimeFilter = page.locator('[data-testid="start-time-filter"]');
    await expect(startTimeFilter).toBeVisible();
    await startTimeFilter.click();
    
    // Select 09:00 AM from dropdown
    const startTimeOption = page.locator('[data-testid="start-time-option-09:00"]').or(page.getByText('09:00 AM'));
    await startTimeOption.click();
    
    // Wait for filter to apply
    await page.waitForTimeout(500);
    
    const filteredItems = page.locator('[data-testid="shift-template-item"]');
    const filteredCount = await filteredItems.count();
    await expect(filteredCount).toBeGreaterThan(0);
    
    // Verify filtered results show correct start time
    for (let i = 0; i < await filteredItems.count(); i++) {
      const startTime = await filteredItems.nth(i).locator('[data-testid="template-start-time"]').textContent();
      expect(startTime).toContain('09:00');
    }

    // Step 2: Combine with search keywords
    // Expected Result: List shows templates matching both criteria
    const searchBox = page.locator('[data-testid="shift-template-search"]');
    await searchBox.fill('Shift A');
    await page.waitForTimeout(500);
    
    const combinedFilteredItems = page.locator('[data-testid="shift-template-item"]');
    const combinedCount = await combinedFilteredItems.count();
    
    // Verify combined filter results
    expect(combinedCount).toBeLessThanOrEqual(filteredCount);
    
    for (let i = 0; i < await combinedFilteredItems.count(); i++) {
      const itemText = await combinedFilteredItems.nth(i).textContent();
      expect(itemText?.toLowerCase()).toContain('shift a');
      const startTime = await combinedFilteredItems.nth(i).locator('[data-testid="template-start-time"]').textContent();
      expect(startTime).toContain('09:00');
    }

    // Step 3: Remove filters
    // Expected Result: Full list is displayed again
    await searchBox.clear();
    
    const clearFilterButton = page.locator('[data-testid="clear-filters-button"]').or(page.getByRole('button', { name: /clear/i }));
    await clearFilterButton.click();
    
    await page.waitForTimeout(500);
    
    const restoredItems = page.locator('[data-testid="shift-template-item"]');
    const restoredCount = await restoredItems.count();
    await expect(restoredCount).toBeGreaterThan(combinedCount);
  });

  test('Sort shift templates by duration', async ({ page }) => {
    // Step 1: Click on duration column header
    // Expected Result: Templates are sorted ascending by duration
    const durationHeader = page.locator('[data-testid="duration-column-header"]').or(page.getByRole('columnheader', { name: /duration/i }));
    await expect(durationHeader).toBeVisible();
    
    await durationHeader.click();
    await page.waitForTimeout(500);
    
    // Get all duration values after first sort
    const templateItems = page.locator('[data-testid="shift-template-item"]');
    const firstSortDurations: number[] = [];
    
    for (let i = 0; i < await templateItems.count(); i++) {
      const durationText = await templateItems.nth(i).locator('[data-testid="template-duration"]').textContent();
      const durationValue = parseInt(durationText?.replace(/\D/g, '') || '0');
      firstSortDurations.push(durationValue);
    }
    
    // Verify ascending order
    for (let i = 0; i < firstSortDurations.length - 1; i++) {
      expect(firstSortDurations[i]).toBeLessThanOrEqual(firstSortDurations[i + 1]);
    }
    
    // Verify sort indicator shows ascending
    const sortIndicator = durationHeader.locator('[data-testid="sort-indicator"]').or(durationHeader.locator('.sort-asc'));
    await expect(sortIndicator).toBeVisible();

    // Step 2: Click again on duration header
    // Expected Result: Templates are sorted descending by duration
    await durationHeader.click();
    await page.waitForTimeout(500);
    
    // Get all duration values after second sort
    const secondSortDurations: number[] = [];
    
    for (let i = 0; i < await templateItems.count(); i++) {
      const durationText = await templateItems.nth(i).locator('[data-testid="template-duration"]').textContent();
      const durationValue = parseInt(durationText?.replace(/\D/g, '') || '0');
      secondSortDurations.push(durationValue);
    }
    
    // Verify descending order
    for (let i = 0; i < secondSortDurations.length - 1; i++) {
      expect(secondSortDurations[i]).toBeGreaterThanOrEqual(secondSortDurations[i + 1]);
    }
    
    // Verify sort indicator shows descending
    const sortIndicatorDesc = durationHeader.locator('[data-testid="sort-indicator-desc"]').or(durationHeader.locator('.sort-desc'));
    await expect(sortIndicatorDesc).toBeVisible();
  });
});