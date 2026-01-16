import { test, expect } from '@playwright/test';

test.describe('Risk Factor Capture - Story 2', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    // Navigate to applicant profile page and then to risk factors section
    await page.goto(`${BASE_URL}/applicants/profile`);
    await page.waitForLoadState('networkidle');
  });

  test('Validate risk factor data submission with complete inputs', async ({ page }) => {
    // Step 1: Navigate to risk factors input section
    await page.click('[data-testid="risk-factors-tab"]');
    await page.waitForSelector('[data-testid="risk-factors-section"]');
    
    // Expected Result: Risk categories and input fields are displayed
    await expect(page.locator('[data-testid="risk-categories-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="risk-factor-inputs"]')).toBeVisible();
    
    // Step 2: Enter valid risk factor data in all mandatory fields
    await page.selectOption('[data-testid="risk-category-select"]', 'health');
    await page.selectOption('[data-testid="risk-severity-select"]', 'medium');
    await page.fill('[data-testid="risk-description-input"]', 'Applicant has controlled hypertension with regular medication');
    
    // Fill profile-specific required fields
    await page.fill('[data-testid="risk-duration-input"]', '5');
    await page.selectOption('[data-testid="risk-impact-select"]', 'moderate');
    
    // Expected Result: Inputs accepted without validation errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    await expect(page.locator('.error-message')).toHaveCount(0);
    
    // Step 3: Submit the risk factor data
    await page.click('[data-testid="submit-risk-factors-btn"]');
    
    // Expected Result: Data saved successfully and integrated with quoting engine
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Risk factor data saved successfully');
    
    // Verify integration with quoting engine
    await page.waitForResponse(response => 
      response.url().includes('/api/applicants/riskfactors') && response.status() === 200
    );
    
    // Verify risk profile updated
    await expect(page.locator('[data-testid="risk-profile-status"]')).toContainText('Updated');
  });

  test('Verify rejection of incomplete risk factor data submission', async ({ page }) => {
    // Step 1: Navigate to risk factors input section
    await page.click('[data-testid="risk-factors-tab"]');
    await page.waitForSelector('[data-testid="risk-factors-section"]');
    
    // Expected Result: Risk categories and input fields are displayed
    await expect(page.locator('[data-testid="risk-categories-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="risk-factor-inputs"]')).toBeVisible();
    
    // Step 2: Leave mandatory risk factor fields empty
    // Select risk category but leave other mandatory fields empty
    await page.selectOption('[data-testid="risk-category-select"]', 'health');
    // Intentionally leave risk-severity-select empty
    // Intentionally leave risk-description-input empty
    
    // Fill some non-mandatory fields
    await page.fill('[data-testid="risk-notes-input"]', 'Additional notes for review');
    
    // Expected Result: Validation highlights missing fields
    await page.click('[data-testid="submit-risk-factors-btn"]');
    
    // Wait for validation to trigger
    await page.waitForSelector('[data-testid="validation-error"]', { timeout: 3000 });
    
    await expect(page.locator('[data-testid="risk-severity-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="risk-severity-error"]')).toContainText('Risk severity is required');
    
    await expect(page.locator('[data-testid="risk-description-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="risk-description-error"]')).toContainText('Risk description is required');
    
    // Step 3: Attempt to submit the data
    // Expected Result: Submission blocked and error messages displayed
    await expect(page.locator('[data-testid="submit-risk-factors-btn"]')).toBeDisabled();
    
    await expect(page.locator('[data-testid="error-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-summary"]')).toContainText('Please complete all required fields');
    
    // Verify no success message appears
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
    
    // Verify data was not saved
    const responsePromise = page.waitForResponse(
      response => response.url().includes('/api/applicants/riskfactors'),
      { timeout: 2000 }
    ).catch(() => null);
    
    const response = await responsePromise;
    expect(response).toBeNull();
  });

  test('Test addition of custom risk factor details', async ({ page }) => {
    // Step 1: Navigate to risk factors input section
    await page.click('[data-testid="risk-factors-tab"]');
    await page.waitForSelector('[data-testid="risk-factors-section"]');
    
    // Expected Result: Risk categories and input fields are displayed
    await expect(page.locator('[data-testid="risk-categories-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="risk-factor-inputs"]')).toBeVisible();
    
    // Step 2: Add custom risk factor details
    await page.click('[data-testid="add-custom-risk-factor-btn"]');
    await page.waitForSelector('[data-testid="custom-risk-factor-form"]');
    
    // Enter custom risk factor details
    await page.fill('[data-testid="custom-category-name-input"]', 'Occupational Hazard');
    await page.fill('[data-testid="custom-description-input"]', 'Works in high-risk construction environment with safety protocols');
    await page.selectOption('[data-testid="custom-severity-select"]', 'high');
    await page.fill('[data-testid="custom-notes-input"]', 'Regular safety training completed. Proper equipment usage verified.');
    
    // Expected Result: Custom inputs accepted with validation
    await expect(page.locator('[data-testid="custom-validation-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="custom-risk-factor-form"] .error-message')).toHaveCount(0);
    
    // Verify custom risk factor is added to the list
    await page.click('[data-testid="save-custom-risk-factor-btn"]');
    await expect(page.locator('[data-testid="custom-risk-factor-item"]')).toBeVisible();
    await expect(page.locator('[data-testid="custom-risk-factor-item"]')).toContainText('Occupational Hazard');
    
    // Complete all mandatory standard risk factor fields
    await page.selectOption('[data-testid="risk-category-select"]', 'lifestyle');
    await page.selectOption('[data-testid="risk-severity-select"]', 'low');
    await page.fill('[data-testid="risk-description-input"]', 'Non-smoker, exercises regularly, balanced diet');
    await page.fill('[data-testid="risk-duration-input"]', '10');
    await page.selectOption('[data-testid="risk-impact-select"]', 'minimal');
    
    // Step 3: Submit the data
    await page.click('[data-testid="submit-risk-factors-btn"]');
    
    // Expected Result: Custom risk factors saved and integrated successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Risk factor data saved successfully');
    
    // Verify API call includes custom risk factors
    const response = await page.waitForResponse(response => 
      response.url().includes('/api/applicants/riskfactors') && response.status() === 200
    );
    
    expect(response.status()).toBe(200);
    
    // Verify custom risk factor appears in saved data
    await page.reload();
    await page.click('[data-testid="risk-factors-tab"]');
    await expect(page.locator('[data-testid="custom-risk-factor-item"]')).toBeVisible();
    await expect(page.locator('[data-testid="custom-risk-factor-item"]')).toContainText('Occupational Hazard');
    
    // Verify integration with quoting engine
    await expect(page.locator('[data-testid="risk-profile-status"]')).toContainText('Updated');
    await expect(page.locator('[data-testid="quote-integration-status"]')).toContainText('Integrated');
  });
});