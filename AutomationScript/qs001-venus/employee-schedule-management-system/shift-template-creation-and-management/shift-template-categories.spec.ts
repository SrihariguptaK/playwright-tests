import { test, expect } from '@playwright/test';

test.describe('Shift Template Categories Management', () => {
  test.beforeEach(async ({ page }) => {
    // Login as HR Manager before each test
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'hr.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'HRManager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate creation and editing of shift template categories', async ({ page }) => {
    // Step 1: Navigate to category management page
    await page.click('[data-testid="category-management-menu"]');
    await expect(page).toHaveURL(/.*categories/);
    await expect(page.locator('[data-testid="category-list"]')).toBeVisible();

    // Step 2: Create new category
    await page.click('[data-testid="create-category-button"]');
    await page.fill('[data-testid="category-name-input"]', 'Morning Shifts');
    await page.fill('[data-testid="category-description-input"]', 'Templates for morning shift schedules');
    await page.click('[data-testid="save-category-button"]');
    
    // Verify category is added and displayed
    await expect(page.locator('[data-testid="category-list"]')).toContainText('Morning Shifts');
    const categoryItem = page.locator('[data-testid="category-item"]', { hasText: 'Morning Shifts' });
    await expect(categoryItem).toBeVisible();

    // Step 3: Edit existing category
    await categoryItem.locator('[data-testid="edit-category-button"]').click();
    await page.fill('[data-testid="category-name-input"]', 'Early Morning Shifts');
    await page.fill('[data-testid="category-description-input"]', 'Templates for early morning shift schedules');
    await page.click('[data-testid="save-category-button"]');
    
    // Verify changes are saved and reflected
    await expect(page.locator('[data-testid="category-list"]')).toContainText('Early Morning Shifts');
    await expect(page.locator('[data-testid="category-list"]')).not.toContainText('Morning Shifts');
  });

  test('Verify filtering of shift templates by category', async ({ page }) => {
    // Navigate to shift template management page
    await page.click('[data-testid="shift-templates-menu"]');
    await expect(page).toHaveURL(/.*shift-templates/);
    await expect(page.locator('[data-testid="template-list"]')).toBeVisible();

    // Step 1: Assign categories to shift templates
    // Assign first template to Morning Shifts category
    const firstTemplate = page.locator('[data-testid="template-item"]', { hasText: 'Early Morning 6AM-2PM' });
    await firstTemplate.locator('[data-testid="edit-template-button"]').click();
    await page.click('[data-testid="category-dropdown"]');
    await page.click('[data-testid="category-option"]', { hasText: 'Morning Shifts' });
    await page.click('[data-testid="save-template-button"]');
    
    // Verify template shows assigned category
    await expect(firstTemplate).toContainText('Morning Shifts');

    // Assign second template to Evening Shifts category
    const secondTemplate = page.locator('[data-testid="template-item"]', { hasText: 'Evening 2PM-10PM' });
    await secondTemplate.locator('[data-testid="edit-template-button"]').click();
    await page.click('[data-testid="category-dropdown"]');
    await page.click('[data-testid="category-option"]', { hasText: 'Evening Shifts' });
    await page.click('[data-testid="save-template-button"]');
    
    // Verify template shows assigned category
    await expect(secondTemplate).toContainText('Evening Shifts');

    // Step 2: Apply category filter in template list
    // Filter by Morning Shifts
    await page.click('[data-testid="category-filter-dropdown"]');
    await page.click('[data-testid="filter-option"]', { hasText: 'Morning Shifts' });
    
    // Verify only templates in selected category are displayed
    await expect(page.locator('[data-testid="template-list"]')).toContainText('Early Morning 6AM-2PM');
    await expect(page.locator('[data-testid="template-list"]')).not.toContainText('Evening 2PM-10PM');

    // Filter by Evening Shifts
    await page.click('[data-testid="category-filter-dropdown"]');
    await page.click('[data-testid="filter-option"]', { hasText: 'Evening Shifts' });
    
    // Verify only templates in selected category are displayed
    await expect(page.locator('[data-testid="template-list"]')).toContainText('Evening 2PM-10PM');
    await expect(page.locator('[data-testid="template-list"]')).not.toContainText('Early Morning 6AM-2PM');

    // Clear filter
    await page.click('[data-testid="category-filter-dropdown"]');
    await page.click('[data-testid="filter-option"]', { hasText: 'All Categories' });
    
    // Verify all templates are displayed
    await expect(page.locator('[data-testid="template-list"]')).toContainText('Early Morning 6AM-2PM');
    await expect(page.locator('[data-testid="template-list"]')).toContainText('Evening 2PM-10PM');
  });

  test('Ensure unauthorized users cannot manage categories', async ({ page }) => {
    // Logout from HR Manager account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Step 1: Login as non-HR user
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Employee123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Verify category management menu is not visible
    await expect(page.locator('[data-testid="category-management-menu"]')).not.toBeVisible();

    // Step 3: Attempt to navigate directly to category management page
    await page.goto('/categories');
    
    // Verify access is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    
    // Verify user is redirected or shown error
    const currentUrl = page.url();
    const isAccessDenied = currentUrl.includes('access-denied') || currentUrl.includes('unauthorized') || await page.locator('[data-testid="error-message"]').isVisible();
    expect(isAccessDenied).toBeTruthy();

    // Step 4: Verify API endpoint access is denied
    const response = await page.request.get('/api/categories');
    expect(response.status()).toBe(403);
  });
});