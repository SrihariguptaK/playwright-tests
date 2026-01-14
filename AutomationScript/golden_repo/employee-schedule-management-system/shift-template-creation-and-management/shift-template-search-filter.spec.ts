import { test, expect } from '@playwright/test';

test.describe('Shift Template Search and Filter', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as HR Manager
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'hrmanager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate search by shift template name', async ({ page }) => {
    // Step 1: Navigate to shift template list
    await page.click('text=Shift Templates');
    await expect(page).toHaveURL(/.*shift-templates/);
    await expect(page.locator('[data-testid="template-list"]')).toBeVisible();
    
    // Verify initial template list is displayed
    const initialTemplateCount = await page.locator('[data-testid="template-item"]').count();
    expect(initialTemplateCount).toBeGreaterThan(0);
    
    // Step 2: Enter search keyword matching template name
    await page.fill('[data-testid="search-input"]', 'Morning');
    await page.waitForTimeout(500); // Wait for debounce/search to trigger
    
    // Verify filtered list shows matching templates
    const filteredTemplates = page.locator('[data-testid="template-item"]');
    const filteredCount = await filteredTemplates.count();
    expect(filteredCount).toBeGreaterThan(0);
    expect(filteredCount).toBeLessThanOrEqual(initialTemplateCount);
    
    // Verify all visible templates contain the search keyword
    for (let i = 0; i < filteredCount; i++) {
      const templateName = await filteredTemplates.nth(i).locator('[data-testid="template-name"]').textContent();
      expect(templateName?.toLowerCase()).toContain('morning');
    }
    
    // Step 3: Clear search and verify full list returns
    await page.click('[data-testid="clear-search-button"]');
    await page.waitForTimeout(500);
    
    // Verify all templates are displayed
    const restoredTemplateCount = await page.locator('[data-testid="template-item"]').count();
    expect(restoredTemplateCount).toBe(initialTemplateCount);
  });

  test('Verify filtering by shift type', async ({ page }) => {
    // Step 1: Navigate to shift template list page
    await page.click('text=Shift Templates');
    await expect(page).toHaveURL(/.*shift-templates/);
    await expect(page.locator('[data-testid="template-list"]')).toBeVisible();
    
    const initialTemplateCount = await page.locator('[data-testid="template-item"]').count();
    
    // Step 2: Select shift type filter
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-day-shift"]');
    await page.waitForTimeout(500);
    
    // Verify list updates to show only selected type
    const filteredByTypeCount = await page.locator('[data-testid="template-item"]').count();
    expect(filteredByTypeCount).toBeGreaterThan(0);
    expect(filteredByTypeCount).toBeLessThanOrEqual(initialTemplateCount);
    
    // Verify all visible templates have the selected shift type
    const filteredTemplates = page.locator('[data-testid="template-item"]');
    for (let i = 0; i < filteredByTypeCount; i++) {
      const shiftType = await filteredTemplates.nth(i).locator('[data-testid="template-shift-type"]').textContent();
      expect(shiftType).toContain('Day Shift');
    }
    
    // Step 3: Combine filter with search keyword
    await page.fill('[data-testid="search-input"]', 'Morning');
    await page.waitForTimeout(500);
    
    // Verify list shows templates matching both criteria
    const combinedFilterCount = await page.locator('[data-testid="template-item"]').count();
    expect(combinedFilterCount).toBeLessThanOrEqual(filteredByTypeCount);
    
    // Verify templates match both search and filter criteria
    for (let i = 0; i < combinedFilterCount; i++) {
      const templateName = await filteredTemplates.nth(i).locator('[data-testid="template-name"]').textContent();
      const shiftType = await filteredTemplates.nth(i).locator('[data-testid="template-shift-type"]').textContent();
      expect(templateName?.toLowerCase()).toContain('morning');
      expect(shiftType).toContain('Day Shift');
    }
    
    // Step 4: Remove filters and verify full list
    await page.click('[data-testid="clear-search-button"]');
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-all-types"]');
    await page.waitForTimeout(500);
    
    // Verify all templates are displayed
    const restoredTemplateCount = await page.locator('[data-testid="template-item"]').count();
    expect(restoredTemplateCount).toBe(initialTemplateCount);
  });

  test('Validate sorting and pagination of templates', async ({ page }) => {
    // Step 1: Navigate to shift template list page
    await page.click('text=Shift Templates');
    await expect(page).toHaveURL(/.*shift-templates/);
    await expect(page.locator('[data-testid="template-list"]')).toBeVisible();
    
    // Step 2: Sort templates by creation date ascending
    await page.click('[data-testid="sort-dropdown"]');
    await page.click('[data-testid="sort-creation-date-asc"]');
    await page.waitForTimeout(500);
    
    // Verify templates are ordered correctly by creation date
    const templatesAfterSort = page.locator('[data-testid="template-item"]');
    const firstTemplateCount = await templatesAfterSort.count();
    expect(firstTemplateCount).toBeGreaterThan(0);
    
    // Get first two template dates and verify ascending order
    if (firstTemplateCount >= 2) {
      const firstDate = await templatesAfterSort.nth(0).locator('[data-testid="template-creation-date"]').getAttribute('data-date');
      const secondDate = await templatesAfterSort.nth(1).locator('[data-testid="template-creation-date"]').getAttribute('data-date');
      expect(new Date(firstDate!).getTime()).toBeLessThanOrEqual(new Date(secondDate!).getTime());
    }
    
    // Step 3: Navigate to next page of results
    const nextButton = page.locator('[data-testid="pagination-next"]');
    if (await nextButton.isEnabled()) {
      await nextButton.click();
      await page.waitForTimeout(500);
      
      // Verify pagination navigation is successful
      await expect(page.locator('[data-testid="pagination-current-page"]')).toContainText('2');
      
      // Verify next set of templates is displayed
      const page2TemplateCount = await page.locator('[data-testid="template-item"]').count();
      expect(page2TemplateCount).toBeGreaterThan(0);
    }
    
    // Step 4: Sort by name descending
    await page.click('[data-testid="sort-dropdown"]');
    await page.click('[data-testid="sort-name-desc"]');
    await page.waitForTimeout(500);
    
    // Verify templates reorder accordingly
    const templatesAfterNameSort = page.locator('[data-testid="template-item"]');
    const namesSortedCount = await templatesAfterNameSort.count();
    
    // Get first two template names and verify descending order
    if (namesSortedCount >= 2) {
      const firstName = await templatesAfterNameSort.nth(0).locator('[data-testid="template-name"]').textContent();
      const secondName = await templatesAfterNameSort.nth(1).locator('[data-testid="template-name"]').textContent();
      expect(firstName!.localeCompare(secondName!)).toBeGreaterThanOrEqual(0);
    }
    
    // Navigate back to page 1 using pagination controls
    const page1Button = page.locator('[data-testid="pagination-page-1"]');
    if (await page1Button.isVisible()) {
      await page1Button.click();
      await page.waitForTimeout(500);
      await expect(page.locator('[data-testid="pagination-current-page"]')).toContainText('1');
    }
  });
});