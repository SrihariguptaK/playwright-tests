import { test, expect } from '@playwright/test';

test.describe('Shift Template Categories Management', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to shift template management section
    await page.goto('/shift-templates');
    await expect(page).toHaveURL(/.*shift-templates/);
  });

  test('Create and assign categories to shift templates', async ({ page }) => {
    // Step 1: Create a new category
    await page.click('[data-testid="manage-categories-button"]');
    await page.waitForSelector('[data-testid="category-dialog"]');
    
    const categoryName = `Sales Department ${Date.now()}`;
    await page.fill('[data-testid="category-name-input"]', categoryName);
    await page.click('[data-testid="save-category-button"]');
    
    // Expected Result: Category is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Category created successfully');
    
    // Close category management dialog if needed
    const closeButton = page.locator('[data-testid="close-category-dialog"]');
    if (await closeButton.isVisible()) {
      await closeButton.click();
    }
    
    // Step 2: Assign category to a shift template
    // Select an existing shift template from the template list
    await page.click('[data-testid="template-list-item"]:first-child');
    await page.waitForSelector('[data-testid="template-form"]');
    
    // Locate the category assignment section
    await page.click('[data-testid="category-assignment-dropdown"]');
    await page.waitForSelector('[data-testid="category-option"]');
    
    // Select the newly created category
    await page.click(`[data-testid="category-option"]:has-text("${categoryName}")`);
    
    // Save the template with assigned category
    await page.click('[data-testid="save-template-button"]');
    
    // Expected Result: Template is saved with assigned category
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="template-category-badge"]')).toContainText(categoryName);
  });

  test('Filter shift templates by category', async ({ page }) => {
    // Step 1: Select a category filter
    // Locate the category filter dropdown
    await page.waitForSelector('[data-testid="category-filter-dropdown"]');
    await page.click('[data-testid="category-filter-dropdown"]');
    
    // Wait for filter options to appear
    await page.waitForSelector('[data-testid="filter-option"]');
    
    // Select 'Sales Department' from the category filter options
    await page.click('[data-testid="filter-option"]:has-text("Sales Department")');
    
    // Expected Result: Template list updates to show only matching templates
    await page.waitForTimeout(500); // Wait for filter to apply
    
    // Verify the filtered results
    const templateItems = page.locator('[data-testid="template-list-item"]');
    const count = await templateItems.count();
    
    // Check each displayed template has the correct category
    for (let i = 0; i < count; i++) {
      const categoryBadge = templateItems.nth(i).locator('[data-testid="template-category-badge"]');
      await expect(categoryBadge).toContainText('Sales Department');
    }
    
    // Clear the filter
    await page.click('[data-testid="category-filter-dropdown"]');
    await page.click('[data-testid="filter-option"]:has-text("All Categories")');
    
    // Verify all templates are shown again
    await page.waitForTimeout(500);
    const allTemplates = page.locator('[data-testid="template-list-item"]');
    const allCount = await allTemplates.count();
    expect(allCount).toBeGreaterThanOrEqual(count);
  });

  test('Prevent duplicate category names', async ({ page }) => {
    // Step 1: Create initial category
    await page.click('[data-testid="manage-categories-button"]');
    await page.waitForSelector('[data-testid="category-dialog"]');
    
    const existingCategoryName = 'Sales Department';
    await page.fill('[data-testid="category-name-input"]', existingCategoryName);
    await page.click('[data-testid="save-category-button"]');
    
    // Wait for success and prepare for duplicate test
    await page.waitForTimeout(500);
    
    // Step 2: Attempt to create a category with existing name
    await page.click('[data-testid="create-new-category-button"]');
    await page.fill('[data-testid="category-name-input"]', existingCategoryName);
    await page.click('[data-testid="save-category-button"]');
    
    // Expected Result: Validation error is displayed and creation blocked
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Category name already exists');
    
    // Verify that the duplicate category was not created
    const categoryList = page.locator('[data-testid="category-list-item"]:has-text("' + existingCategoryName + '")');
    const duplicateCount = await categoryList.count();
    expect(duplicateCount).toBe(1);
    
    // Step 3: Modify the category name to a unique value
    const uniqueCategoryName = 'Sales Department - East Region';
    await page.fill('[data-testid="category-name-input"]', uniqueCategoryName);
    await page.click('[data-testid="save-category-button"]');
    
    // Expected Result: Category is created successfully with unique name
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="category-list-item"]:has-text("' + uniqueCategoryName + '")')).toBeVisible();
  });
});