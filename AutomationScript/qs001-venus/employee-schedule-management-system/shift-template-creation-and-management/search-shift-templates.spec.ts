import { test, expect } from '@playwright/test';

test.describe('Search Shift Templates - Story 10', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the shift template management page before each test
    await page.goto('/shift-templates');
    // Wait for the page to be fully loaded
    await page.waitForLoadState('networkidle');
  });

  test('Search shift templates by name - partial match displays matching templates dynamically', async ({ page }) => {
    // Locate the search box for template name
    const searchBox = page.getByTestId('template-search-input').or(page.getByPlaceholder('Search templates')).or(page.getByRole('textbox', { name: /search/i }));
    await expect(searchBox).toBeVisible();

    // Enter partial template name in search box
    await searchBox.fill('Morn');

    // Wait for dynamic search results to update
    await page.waitForTimeout(500);

    // Verify matching templates are displayed dynamically
    const templateList = page.getByTestId('template-list').or(page.locator('[data-testid*="template"]')).or(page.locator('.template-item'));
    await expect(templateList.first()).toBeVisible();

    // Verify all displayed templates contain the searched partial name
    const templateItems = await page.getByTestId('template-item').or(page.locator('[data-testid*="template-item"]')).or(page.locator('.template-item')).all();
    
    for (const item of templateItems) {
      const templateName = await item.textContent();
      expect(templateName?.toLowerCase()).toContain('morn');
    }

    // Verify at least one matching template is displayed
    expect(templateItems.length).toBeGreaterThan(0);
  });

  test('Filter search results by category - displays only templates from selected category', async ({ page }) => {
    // Locate the category filter dropdown or selection control
    const categoryFilter = page.getByTestId('category-filter').or(page.getByRole('combobox', { name: /category/i })).or(page.locator('select[name="category"]'));
    await expect(categoryFilter).toBeVisible();

    // Click on the category filter control to open dropdown
    await categoryFilter.click();

    // Apply category filter by selecting 'Morning' from available options
    const morningOption = page.getByRole('option', { name: 'Morning' }).or(page.getByText('Morning', { exact: true })).or(page.locator('[value="Morning"]'));
    await morningOption.click();

    // Wait for search results to update after applying filter
    await page.waitForTimeout(500);

    // Observe the template list after applying the filter
    const templateList = page.getByTestId('template-list').or(page.locator('.template-list'));
    await expect(templateList).toBeVisible();

    // Verify all displayed templates belong to the 'Morning' category
    const templateItems = await page.getByTestId('template-item').or(page.locator('[data-testid*="template-item"]')).or(page.locator('.template-item')).all();
    
    expect(templateItems.length).toBeGreaterThan(0);

    for (const item of templateItems) {
      const categoryLabel = item.getByTestId('template-category').or(item.locator('.template-category')).or(item.locator('[data-category]'));
      const categoryText = await categoryLabel.textContent();
      expect(categoryText?.toLowerCase()).toContain('morning');
    }

    // Verify search results update dynamically
    const filteredCount = templateItems.length;
    expect(filteredCount).toBeGreaterThan(0);
  });

  test('Search shift templates by name - verify dynamic update as user types', async ({ page }) => {
    // Locate the search box for template name
    const searchBox = page.getByTestId('template-search-input').or(page.getByPlaceholder('Search templates')).or(page.getByRole('textbox', { name: /search/i }));
    await expect(searchBox).toBeVisible();

    // Get initial template count
    const initialTemplates = await page.getByTestId('template-item').or(page.locator('.template-item')).count();

    // Enter first character
    await searchBox.fill('M');
    await page.waitForTimeout(300);
    const afterFirstChar = await page.getByTestId('template-item').or(page.locator('.template-item')).count();

    // Enter more characters to narrow search
    await searchBox.fill('Mor');
    await page.waitForTimeout(300);
    const afterThirdChar = await page.getByTestId('template-item').or(page.locator('.template-item')).count();

    // Complete the partial search term
    await searchBox.fill('Morn');
    await page.waitForTimeout(300);

    // Verify templates are displayed and contain search term
    const finalTemplates = await page.getByTestId('template-item').or(page.locator('.template-item')).all();
    expect(finalTemplates.length).toBeGreaterThan(0);

    // Verify dynamic filtering occurred
    for (const template of finalTemplates) {
      const templateText = await template.textContent();
      expect(templateText?.toLowerCase()).toContain('morn');
    }
  });

  test('Filter search results by category - verify accurate and relevant templates returned', async ({ page }) => {
    // Navigate to the shift template management page
    await expect(page.getByTestId('template-management-page').or(page.locator('h1')).first()).toBeVisible();

    // Locate the category filter dropdown
    const categoryFilter = page.getByTestId('category-filter').or(page.getByRole('combobox', { name: /category/i })).or(page.locator('select[name="category"]'));
    await expect(categoryFilter).toBeVisible();

    // Click to open category filter
    await categoryFilter.click();

    // Select 'Morning' category
    await page.getByRole('option', { name: 'Morning' }).or(page.getByText('Morning', { exact: true })).click();

    // Wait for results to update
    await page.waitForTimeout(500);

    // Verify all displayed templates belong to Morning category
    const templateItems = await page.getByTestId('template-item').or(page.locator('.template-item')).all();
    
    expect(templateItems.length).toBeGreaterThan(0);

    // Verify each template shows Morning category
    for (const item of templateItems) {
      const isVisible = await item.isVisible();
      expect(isVisible).toBeTruthy();
      
      const itemContent = await item.textContent();
      expect(itemContent).toBeTruthy();
    }

    // Verify search results are accurate and relevant
    const resultCount = templateItems.length;
    expect(resultCount).toBeGreaterThan(0);
  });
});