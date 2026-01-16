import { test, expect } from '@playwright/test';

test.describe('Risk Category Input - Story 4', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the risk data input page
    await page.goto('/underwriter/risk-input');
    // Wait for page to be fully loaded
    await page.waitForLoadState('networkidle');
  });

  test('Validate dynamic display of risk data fields based on category selection', async ({ page }) => {
    // Step 1: Select a risk category from the dropdown
    await page.click('[data-testid="risk-category-dropdown"]');
    await page.click('[data-testid="risk-category-option-property"]');
    
    // Expected Result: Relevant input fields for the selected category are displayed
    await expect(page.locator('[data-testid="property-address-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="property-value-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="property-type-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="construction-year-field"]')).toBeVisible();
    
    // Step 2: Enter valid risk data in displayed fields
    await page.fill('[data-testid="property-address-field"]', '123 Main Street, New York, NY 10001');
    await page.fill('[data-testid="property-value-field"]', '500000');
    await page.click('[data-testid="property-type-field"]');
    await page.click('[data-testid="property-type-residential"]');
    await page.fill('[data-testid="construction-year-field"]', '2010');
    
    // Expected Result: No validation errors are shown
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    await expect(page.locator('.error-message')).toHaveCount(0);
    
    // Step 3: Save the risk data
    await page.click('[data-testid="save-risk-data-button"]');
    
    // Expected Result: Data is saved and confirmation is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Risk data saved successfully');
  });

  test('Verify validation errors for invalid risk data', async ({ page }) => {
    // Step 1: Select a risk category
    await page.click('[data-testid="risk-category-dropdown"]');
    await page.click('[data-testid="risk-category-option-auto"]');
    
    // Expected Result: Relevant fields are displayed
    await expect(page.locator('[data-testid="vehicle-make-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="vehicle-model-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="vehicle-year-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="vehicle-vin-field"]')).toBeVisible();
    
    // Step 2: Enter invalid or incomplete risk data
    await page.fill('[data-testid="vehicle-make-field"]', 'Toyota');
    // Leave model empty (required field)
    await page.fill('[data-testid="vehicle-year-field"]', '1899'); // Invalid year (too old)
    await page.fill('[data-testid="vehicle-vin-field"]', 'ABC123'); // Invalid VIN format
    
    // Trigger validation by clicking outside or tabbing
    await page.click('[data-testid="vehicle-make-field"]');
    await page.click('body');
    
    // Expected Result: Inline validation errors are displayed
    await expect(page.locator('[data-testid="vehicle-model-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="vehicle-model-error"]')).toContainText('Vehicle model is required');
    await expect(page.locator('[data-testid="vehicle-year-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="vehicle-year-error"]')).toContainText('Vehicle year must be between 1900 and');
    await expect(page.locator('[data-testid="vehicle-vin-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="vehicle-vin-error"]')).toContainText('VIN must be 17 characters');
    
    // Step 3: Attempt to save the form
    await page.click('[data-testid="save-risk-data-button"]');
    
    // Expected Result: Save is blocked until errors are corrected
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="vehicle-model-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="save-risk-data-button"]')).toBeDisabled();
  });

  test('Ensure risk data persistence and retrieval', async ({ page }) => {
    // Step 1: Enter and save valid risk data
    await page.click('[data-testid="risk-category-dropdown"]');
    await page.click('[data-testid="risk-category-option-liability"]');
    
    await page.fill('[data-testid="business-name-field"]', 'Acme Corporation');
    await page.fill('[data-testid="business-address-field"]', '456 Business Ave, Chicago, IL 60601');
    await page.fill('[data-testid="employee-count-field"]', '150');
    await page.fill('[data-testid="annual-revenue-field"]', '5000000');
    await page.click('[data-testid="industry-type-field"]');
    await page.click('[data-testid="industry-type-manufacturing"]');
    
    await page.click('[data-testid="save-risk-data-button"]');
    
    // Expected Result: Data saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Risk data saved successfully');
    
    // Store the saved values for comparison
    const savedBusinessName = 'Acme Corporation';
    const savedBusinessAddress = '456 Business Ave, Chicago, IL 60601';
    const savedEmployeeCount = '150';
    const savedAnnualRevenue = '5000000';
    
    // Step 2: Reload the risk data form
    await page.reload();
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Previously saved data is displayed correctly
    await expect(page.locator('[data-testid="risk-category-dropdown"]')).toContainText('Liability');
    await expect(page.locator('[data-testid="business-name-field"]')).toHaveValue(savedBusinessName);
    await expect(page.locator('[data-testid="business-address-field"]')).toHaveValue(savedBusinessAddress);
    await expect(page.locator('[data-testid="employee-count-field"]')).toHaveValue(savedEmployeeCount);
    await expect(page.locator('[data-testid="annual-revenue-field"]')).toHaveValue(savedAnnualRevenue);
    
    // Step 3: Edit and resave risk data
    await page.fill('[data-testid="employee-count-field"]', '175');
    await page.fill('[data-testid="annual-revenue-field"]', '6000000');
    
    await page.click('[data-testid="save-risk-data-button"]');
    
    // Expected Result: Changes are saved and reflected correctly
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Reload again to verify persistence of edited data
    await page.reload();
    await page.waitForLoadState('networkidle');
    
    await expect(page.locator('[data-testid="employee-count-field"]')).toHaveValue('175');
    await expect(page.locator('[data-testid="annual-revenue-field"]')).toHaveValue('6000000');
    await expect(page.locator('[data-testid="business-name-field"]')).toHaveValue(savedBusinessName);
  });
});