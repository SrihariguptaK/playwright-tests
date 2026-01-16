import { test, expect } from '@playwright/test';

test.describe('Quote Editing - Story 11', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const quoteManagerCredentials = {
    username: 'quotemanager@example.com',
    password: 'QuoteManager123!'
  };
  const viewerCredentials = {
    username: 'viewer@example.com',
    password: 'Viewer123!'
  };
  const testQuoteId = 'Q-12345';
  const testCustomerName = 'Acme Corporation';

  test('Validate successful loading and editing of existing quote', async ({ page }) => {
    // Step 1: Login as Quote Manager and navigate to quote search
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', quoteManagerCredentials.username);
    await page.fill('[data-testid="password-input"]', quoteManagerCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Quote search page is displayed
    await expect(page).toHaveURL(/.*dashboard/);
    await page.click('[data-testid="quotes-menu"]');
    await page.click('[data-testid="quote-search-link"]');
    await expect(page.locator('[data-testid="quote-search-page"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Quote Search');

    // Step 2: Search and select an existing quote
    const startTime = Date.now();
    await page.fill('[data-testid="quote-search-input"]', testQuoteId);
    await page.click('[data-testid="search-button"]');
    await expect(page.locator('[data-testid="search-results"]')).toBeVisible();
    
    await page.click(`[data-testid="quote-row-${testQuoteId}"]`);
    
    // Expected Result: Quote details load into editable form within 2 seconds
    await expect(page.locator('[data-testid="quote-edit-form"]')).toBeVisible();
    const loadTime = Date.now() - startTime;
    expect(loadTime).toBeLessThan(2000);
    
    // Verify all quote fields are displayed
    await expect(page.locator('[data-testid="customer-name-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="quote-amount-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="expiration-date-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="line-items-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="pricing-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="terms-section"]')).toBeVisible();

    // Step 3: Modify quote fields with valid data and submit
    const originalAmount = await page.inputValue('[data-testid="quote-amount-field"]');
    const newAmount = '15000.00';
    await page.fill('[data-testid="quote-amount-field"]', newAmount);
    
    const originalQuantity = await page.inputValue('[data-testid="line-item-quantity-0"]');
    const newQuantity = '50';
    await page.fill('[data-testid="line-item-quantity-0"]', newQuantity);
    
    await page.fill('[data-testid="terms-field"]', 'Updated payment terms: Net 45 days');
    
    await page.click('[data-testid="submit-button"]');
    
    // Review change summary
    await expect(page.locator('[data-testid="change-summary-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="change-summary-modal"]')).toContainText('Quote Amount');
    await expect(page.locator('[data-testid="change-summary-modal"]')).toContainText(originalAmount);
    await expect(page.locator('[data-testid="change-summary-modal"]')).toContainText(newAmount);
    
    await page.click('[data-testid="confirm-changes-button"]');
    
    // Expected Result: Changes are saved, new version created, confirmation displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Quote updated successfully');
    await expect(page.locator('[data-testid="version-number"]')).toBeVisible();
    
    const versionText = await page.textContent('[data-testid="version-number"]');
    expect(versionText).toMatch(/Version \d+/);
  });

  test('Verify validation prevents saving with missing mandatory fields', async ({ page }) => {
    // Step 1: Open existing quote for editing
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', quoteManagerCredentials.username);
    await page.fill('[data-testid="password-input"]', quoteManagerCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await page.click('[data-testid="quotes-menu"]');
    await page.click('[data-testid="quote-search-link"]');
    await page.fill('[data-testid="quote-search-input"]', testQuoteId);
    await page.click('[data-testid="search-button"]');
    await page.click(`[data-testid="quote-row-${testQuoteId}"]`);
    
    // Expected Result: Editable form is displayed
    await expect(page.locator('[data-testid="quote-edit-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="customer-name-field"]')).toBeEditable();
    await expect(page.locator('[data-testid="quote-amount-field"]')).toBeEditable();

    // Step 2: Clear a mandatory field and attempt to save
    const originalCustomerName = await page.inputValue('[data-testid="customer-name-field"]');
    await page.fill('[data-testid="customer-name-field"]', '');
    
    await page.click('[data-testid="submit-button"]');
    
    // Expected Result: Validation error shown, save prevented
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Customer Name is required');
    await expect(page.locator('[data-testid="customer-name-field"]')).toHaveClass(/error|invalid/);
    
    // Verify change summary modal does not appear
    await expect(page.locator('[data-testid="change-summary-modal"]')).not.toBeVisible();

    // Step 3: Fill mandatory field correctly and save
    await page.fill('[data-testid="customer-name-field"]', originalCustomerName);
    
    // Verify validation error is cleared
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    
    await page.click('[data-testid="submit-button"]');
    
    // Expected Result: Save succeeds, confirmation displayed
    await expect(page.locator('[data-testid="change-summary-modal"]')).toBeVisible();
    await page.click('[data-testid="confirm-changes-button"]');
    
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Quote updated successfully');
  });

  test('Ensure unauthorized users cannot access quote editing', async ({ page }) => {
    // Step 1: Login as a user without edit permissions
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', viewerCredentials.username);
    await page.fill('[data-testid="password-input"]', viewerCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access to quote editing interface is denied
    await expect(page).toHaveURL(/.*dashboard/);
    await page.click('[data-testid="quotes-menu"]');
    
    // Verify edit option is not available in UI
    const editButton = page.locator('[data-testid="quote-edit-button"]');
    await expect(editButton).not.toBeVisible();

    // Step 2: Attempt to access editing URL directly
    await page.goto(`${baseURL}/quotes/edit/${testQuoteId}`);
    
    // Expected Result: Access denied error displayed
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    await expect(page.locator('[data-testid="error-message"]')).toContainText('You do not have permission to edit quotes');
    
    // Verify error message does not expose sensitive information
    const errorText = await page.textContent('[data-testid="error-message"]');
    expect(errorText).not.toContain('database');
    expect(errorText).not.toContain('SQL');
    expect(errorText).not.toContain('server error');
    
    // Verify quote edit form is not displayed
    await expect(page.locator('[data-testid="quote-edit-form"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="customer-name-field"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="quote-amount-field"]')).not.toBeVisible();
    
    // Verify user cannot view or modify quote data
    const pageContent = await page.content();
    expect(pageContent).not.toContain(testCustomerName);
  });
});