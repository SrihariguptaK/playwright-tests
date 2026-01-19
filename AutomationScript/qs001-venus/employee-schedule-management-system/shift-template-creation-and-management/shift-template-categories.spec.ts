import { test, expect } from '@playwright/test';

test.describe('Shift Template Categories - Story 9', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Scheduling Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduling.manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Create and assign shift template categories', async ({ page }) => {
    // Step 1: Navigate to category management section and click 'Create New Category' button
    await page.goto('/shift-templates/categories');
    await page.waitForSelector('[data-testid="category-management-page"]');
    await page.click('[data-testid="create-category-button"]');
    
    // Step 2: Enter 'Weekend' as the category name and click Save/Submit button
    await page.waitForSelector('[data-testid="category-name-input"]');
    await page.fill('[data-testid="category-name-input"]', 'Weekend');
    await page.click('[data-testid="save-category-button"]');
    
    // Expected Result: Category is saved and listed
    await expect(page.locator('[data-testid="category-list"]')).toContainText('Weekend');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Category created successfully');
    
    // Step 3: Navigate to shift template list or template details page and select a shift template to edit
    await page.goto('/shift-templates');
    await page.waitForSelector('[data-testid="shift-template-list"]');
    await page.click('[data-testid="shift-template-item"]:first-child');
    await page.waitForSelector('[data-testid="template-details-page"]');
    await page.click('[data-testid="edit-template-button"]');
    
    // Step 4: Select 'Weekend' category from the available categories and save the template assignment
    await page.waitForSelector('[data-testid="category-selector"]');
    await page.click('[data-testid="category-selector"]');
    await page.click('[data-testid="category-option-Weekend"]');
    await page.click('[data-testid="save-template-button"]');
    
    // Expected Result: Template is associated with category
    await expect(page.locator('[data-testid="template-category-badge"]')).toContainText('Weekend');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Template updated successfully');
  });

  test('Filter shift templates by category', async ({ page }) => {
    // Step 1: Navigate to shift template list page
    await page.goto('/shift-templates');
    await page.waitForSelector('[data-testid="shift-template-list"]');
    
    // Get initial count of templates
    const initialTemplateCount = await page.locator('[data-testid="shift-template-item"]').count();
    
    // Step 2: Locate the category filter dropdown/selector and select 'Weekend' category from the available options
    await page.waitForSelector('[data-testid="category-filter"]');
    await page.click('[data-testid="category-filter"]');
    await page.waitForSelector('[data-testid="category-filter-option-Weekend"]');
    await page.click('[data-testid="category-filter-option-Weekend"]');
    
    // Wait for filter to be applied
    await page.waitForTimeout(500);
    
    // Expected Result: Template list shows only 'Weekend' categorized templates
    await expect(page.locator('[data-testid="active-filter-badge"]')).toContainText('Weekend');
    
    // Step 3: Verify the filtered results by checking each displayed template's category assignment
    const filteredTemplates = page.locator('[data-testid="shift-template-item"]');
    const filteredCount = await filteredTemplates.count();
    
    // Verify that filtered count is less than or equal to initial count
    expect(filteredCount).toBeLessThanOrEqual(initialTemplateCount);
    
    // Verify each visible template has the 'Weekend' category
    for (let i = 0; i < filteredCount; i++) {
      const template = filteredTemplates.nth(i);
      const categoryBadge = template.locator('[data-testid="template-category-badge"]');
      await expect(categoryBadge).toContainText('Weekend');
    }
    
    // Verify no templates without 'Weekend' category are displayed
    await expect(page.locator('[data-testid="no-results-message"]').or(page.locator('[data-testid="shift-template-item"]'))).toBeVisible();
  });

  test('System restricts category management to authorized users', async ({ page }) => {
    // Logout as Scheduling Manager
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Login as unauthorized user (regular employee)
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Attempt to navigate to category management
    await page.goto('/shift-templates/categories');
    
    // Expected Result: Access denied or redirected
    await expect(page.locator('[data-testid="access-denied-message"]').or(page.locator('[data-testid="error-message"]'))).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"], [data-testid="error-message"]')).toContainText(/access denied|unauthorized|permission/i);
  });

  test('System enables assignment of templates to multiple categories', async ({ page }) => {
    // Navigate to shift template list
    await page.goto('/shift-templates');
    await page.waitForSelector('[data-testid="shift-template-list"]');
    
    // Select a shift template to edit
    await page.click('[data-testid="shift-template-item"]:first-child');
    await page.waitForSelector('[data-testid="template-details-page"]');
    await page.click('[data-testid="edit-template-button"]');
    
    // Assign multiple categories
    await page.waitForSelector('[data-testid="category-selector"]');
    await page.click('[data-testid="category-selector"]');
    await page.click('[data-testid="category-option-Weekend"]');
    await page.click('[data-testid="category-selector"]');
    await page.click('[data-testid="category-option-Morning"]');
    await page.click('[data-testid="save-template-button"]');
    
    // Expected Result: Template is associated with multiple categories
    await expect(page.locator('[data-testid="template-category-badge"]').filter({ hasText: 'Weekend' })).toBeVisible();
    await expect(page.locator('[data-testid="template-category-badge"]').filter({ hasText: 'Morning' })).toBeVisible();
  });
});