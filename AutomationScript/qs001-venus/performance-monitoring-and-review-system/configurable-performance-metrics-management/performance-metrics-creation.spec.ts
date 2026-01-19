import { test, expect } from '@playwright/test';

test.describe('Performance Metrics Creation - Story 13', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Performance Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'performance.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful metric creation with valid input', async ({ page }) => {
    // Step 1: Navigate to Metrics Management page
    await page.click('[data-testid="metrics-management-link"]');
    await expect(page).toHaveURL(/.*metrics/);
    await expect(page.locator('[data-testid="metrics-list"]')).toBeVisible();
    
    // Step 2: Click 'Add Metric' and fill in valid metric details
    await page.click('[data-testid="add-metric-button"]');
    await expect(page.locator('[data-testid="metric-form"]')).toBeVisible();
    
    await page.fill('[data-testid="metric-name-input"]', 'Sales Target Achievement');
    await page.fill('[data-testid="metric-description-input"]', 'Measures quarterly sales target completion percentage');
    await page.selectOption('[data-testid="metric-type-dropdown"]', 'Percentage');
    await page.fill('[data-testid="metric-target-input"]', '100');
    await page.fill('[data-testid="metric-weight-input"]', '0.3');
    await page.selectOption('[data-testid="role-department-dropdown"]', 'Sales Team');
    
    // Verify all inputs accept data without validation errors
    await expect(page.locator('[data-testid="metric-name-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="metric-target-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="metric-weight-error"]')).not.toBeVisible();
    
    // Step 3: Submit the metric creation form
    await page.click('[data-testid="submit-metric-button"]');
    
    // Verify metric is created successfully and confirmation is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Metric created successfully');
    
    // Verify newly created metric appears in the metrics list
    await expect(page.locator('[data-testid="metrics-list"]')).toContainText('Sales Target Achievement');
    await expect(page.locator('[data-testid="metric-item"]').filter({ hasText: 'Sales Target Achievement' })).toBeVisible();
  });

  test('Reject metric creation with invalid numeric fields', async ({ page }) => {
    // Step 1: Navigate to Add Metric form
    await page.click('[data-testid="metrics-management-link"]');
    await page.click('[data-testid="add-metric-button"]');
    await expect(page.locator('[data-testid="metric-form"]')).toBeVisible();
    
    // Step 2: Enter invalid values in target and weight fields
    await page.fill('[data-testid="metric-name-input"]', 'Customer Satisfaction Score');
    await page.fill('[data-testid="metric-description-input"]', 'Measures customer satisfaction levels');
    await page.selectOption('[data-testid="metric-type-dropdown"]', 'Score');
    await page.fill('[data-testid="metric-target-input"]', '-50');
    await page.fill('[data-testid="metric-weight-input"]', '-0.5');
    
    // Trigger validation by clicking outside or tabbing
    await page.click('[data-testid="metric-name-input"]');
    
    // Verify validation errors are shown inline
    await expect(page.locator('[data-testid="metric-target-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="metric-target-error"]')).toContainText(/negative|invalid|must be positive/i);
    await expect(page.locator('[data-testid="metric-weight-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="metric-weight-error"]')).toContainText(/negative|invalid|must be positive/i);
    
    // Step 3: Attempt to submit the form
    await page.click('[data-testid="submit-metric-button"]');
    
    // Verify submission is blocked until errors are corrected
    await expect(page.locator('[data-testid="metric-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
    
    // Correct the values
    await page.fill('[data-testid="metric-target-input"]', '80');
    await page.fill('[data-testid="metric-weight-input"]', '0.25');
    
    // Verify errors are cleared
    await expect(page.locator('[data-testid="metric-target-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="metric-weight-error"]')).not.toBeVisible();
  });

  test('Prevent duplicate metric names for the same role', async ({ page }) => {
    // Step 1: Create a metric with a specific name for a role
    await page.click('[data-testid="metrics-management-link"]');
    await page.click('[data-testid="add-metric-button"]');
    
    await page.fill('[data-testid="metric-name-input"]', 'Quality Score');
    await page.fill('[data-testid="metric-description-input"]', 'Measures overall quality performance');
    await page.selectOption('[data-testid="metric-type-dropdown"]', 'Score');
    await page.fill('[data-testid="metric-target-input"]', '90');
    await page.fill('[data-testid="metric-weight-input"]', '0.4');
    await page.selectOption('[data-testid="role-department-dropdown"]', 'Engineering Team');
    
    await page.click('[data-testid="submit-metric-button"]');
    
    // Verify metric is created successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="metrics-list"]')).toContainText('Quality Score');
    
    // Step 2: Attempt to create another metric with the same name and role
    await page.click('[data-testid="add-metric-button"]');
    
    await page.fill('[data-testid="metric-name-input"]', 'Quality Score');
    await page.fill('[data-testid="metric-description-input"]', 'Another quality metric');
    await page.selectOption('[data-testid="metric-type-dropdown"]', 'Percentage');
    await page.fill('[data-testid="metric-target-input"]', '85');
    await page.fill('[data-testid="metric-weight-input"]', '0.35');
    await page.selectOption('[data-testid="role-department-dropdown"]', 'Engineering Team');
    
    await page.click('[data-testid="submit-metric-button"]');
    
    // Verify system rejects creation and displays duplicate name error
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/duplicate|already exists/i);
    
    // Verify the duplicate metric was not created in the metrics list
    const qualityScoreMetrics = page.locator('[data-testid="metric-item"]').filter({ hasText: 'Quality Score' });
    await expect(qualityScoreMetrics).toHaveCount(1);
    
    // Step 3: Modify the name to a unique value and submit
    await page.fill('[data-testid="metric-name-input"]', 'Code Quality Score');
    await page.click('[data-testid="submit-metric-button"]');
    
    // Verify metric is created successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="metrics-list"]')).toContainText('Code Quality Score');
    await expect(page.locator('[data-testid="metric-item"]').filter({ hasText: 'Code Quality Score' })).toBeVisible();
  });
});