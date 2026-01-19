import { test, expect } from '@playwright/test';

test.describe('Alert Threshold Customization', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'managerPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate alert threshold customization and application (happy-path)', async ({ page }) => {
    // Navigate to the alert settings page from the main dashboard menu
    await page.click('[data-testid="main-menu-button"]');
    await page.click('[data-testid="alert-settings-menu-item"]');
    
    // Click on 'Alert Threshold Settings' option
    await page.click('[data-testid="alert-threshold-settings-link"]');
    await expect(page).toHaveURL(/.*alert-threshold-settings/);
    
    // Review the current threshold values displayed for each alert type
    await expect(page.locator('[data-testid="late-arrivals-threshold"]')).toBeVisible();
    await expect(page.locator('[data-testid="consecutive-late-arrivals-threshold"]')).toBeVisible();
    await expect(page.locator('[data-testid="early-departures-threshold"]')).toBeVisible();
    
    // Click on the 'Late Arrivals' threshold field to edit
    await page.click('[data-testid="late-arrivals-threshold-input"]');
    
    // Enter a new valid threshold value of '20' minutes for Late Arrivals
    await page.fill('[data-testid="late-arrivals-threshold-input"]', '20');
    await expect(page.locator('[data-testid="late-arrivals-threshold-input"]')).toHaveValue('20');
    
    // Click on the 'Consecutive Late Arrivals' threshold field to edit
    await page.click('[data-testid="consecutive-late-arrivals-threshold-input"]');
    
    // Enter a new valid threshold value of '5' occurrences for Consecutive Late Arrivals
    await page.fill('[data-testid="consecutive-late-arrivals-threshold-input"]', '5');
    await expect(page.locator('[data-testid="consecutive-late-arrivals-threshold-input"]')).toHaveValue('5');
    
    // Click on the 'Early Departures' threshold field to edit
    await page.click('[data-testid="early-departures-threshold-input"]');
    
    // Enter a new valid threshold value of '15' minutes for Early Departures
    await page.fill('[data-testid="early-departures-threshold-input"]', '15');
    await expect(page.locator('[data-testid="early-departures-threshold-input"]')).toHaveValue('15');
    
    // Click 'Save' button to save the modified threshold settings
    await page.click('[data-testid="save-thresholds-button"]');
    
    // Verify success message appears
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Settings saved and applied successfully');
    
    // Verify the saved values by refreshing the alert threshold settings page
    await page.reload();
    await expect(page.locator('[data-testid="late-arrivals-threshold-input"]')).toHaveValue('20');
    await expect(page.locator('[data-testid="consecutive-late-arrivals-threshold-input"]')).toHaveValue('5');
    await expect(page.locator('[data-testid="early-departures-threshold-input"]')).toHaveValue('15');
    
    // Click on 'Preview Alert Impact' button
    await page.click('[data-testid="preview-alert-impact-button"]');
    
    // Select a date range for preview (e.g., last 7 days) and click 'Generate Preview'
    await page.click('[data-testid="date-range-selector"]');
    await page.click('[data-testid="last-7-days-option"]');
    await page.click('[data-testid="generate-preview-button"]');
    
    // Review the preview results to verify new threshold settings impact
    await expect(page.locator('[data-testid="preview-results-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="preview-results-container"]')).toContainText('Preview reflects new threshold settings');
    
    // Simulate a new late arrival event with employee arriving 18 minutes late
    await page.click('[data-testid="simulate-event-button"]');
    await page.fill('[data-testid="employee-id-input"]', 'EMP001');
    await page.fill('[data-testid="late-minutes-input"]', '18');
    await page.click('[data-testid="submit-simulation-button"]');
    
    // Verify no alert is triggered (18 < 20 threshold)
    await expect(page.locator('[data-testid="alert-notification"]')).not.toBeVisible();
    
    // Simulate a new late arrival event with employee arriving 25 minutes late
    await page.click('[data-testid="simulate-event-button"]');
    await page.fill('[data-testid="employee-id-input"]', 'EMP002');
    await page.fill('[data-testid="late-minutes-input"]', '25');
    await page.click('[data-testid="submit-simulation-button"]');
    
    // Verify alert is triggered (25 >= 20 threshold)
    await expect(page.locator('[data-testid="alert-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-notification"]')).toContainText('Late arrival alert');
  });

  test('Verify validation prevents invalid threshold inputs (error-case)', async ({ page }) => {
    // Navigate to the alert threshold settings page
    await page.click('[data-testid="main-menu-button"]');
    await page.click('[data-testid="alert-settings-menu-item"]');
    await page.click('[data-testid="alert-threshold-settings-link"]');
    await expect(page).toHaveURL(/.*alert-threshold-settings/);
    
    // Click on the 'Late Arrivals' threshold field and enter a negative value '-10'
    await page.click('[data-testid="late-arrivals-threshold-input"]');
    await page.fill('[data-testid="late-arrivals-threshold-input"]', '-10');
    
    // Attempt to click 'Save' button with the negative value still in the field
    await page.click('[data-testid="save-thresholds-button"]');
    
    // Verify validation error appears
    await expect(page.locator('[data-testid="validation-error-late-arrivals"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-late-arrivals"]')).toContainText('Value must be positive');
    
    // Clear the negative value and enter zero '0' in the 'Late Arrivals' threshold field
    await page.fill('[data-testid="late-arrivals-threshold-input"]', '0');
    await page.click('[data-testid="save-thresholds-button"]');
    
    // Verify validation error for zero value
    await expect(page.locator('[data-testid="validation-error-late-arrivals"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-late-arrivals"]')).toContainText('Value must be greater than zero');
    
    // Clear the zero value and enter a non-numeric value 'abc' in the 'Late Arrivals' threshold field
    await page.fill('[data-testid="late-arrivals-threshold-input"]', 'abc');
    await page.click('[data-testid="save-thresholds-button"]');
    
    // Verify validation error for non-numeric value
    await expect(page.locator('[data-testid="validation-error-late-arrivals"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-late-arrivals"]')).toContainText('Value must be numeric');
    
    // Clear the non-numeric value and enter a decimal value '15.5' in the 'Late Arrivals' threshold field
    await page.fill('[data-testid="late-arrivals-threshold-input"]', '15.5');
    await page.click('[data-testid="save-thresholds-button"]');
    
    // Verify validation error for decimal value
    await expect(page.locator('[data-testid="validation-error-late-arrivals"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-late-arrivals"]')).toContainText('Value must be a whole number');
    
    // Clear the field and enter an extremely large value '999999' in the 'Late Arrivals' threshold field
    await page.fill('[data-testid="late-arrivals-threshold-input"]', '999999');
    await page.click('[data-testid="save-thresholds-button"]');
    
    // Verify validation error for extremely large value
    await expect(page.locator('[data-testid="validation-error-late-arrivals"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-late-arrivals"]')).toContainText('Value exceeds maximum allowed');
    
    // Click on the 'Consecutive Late Arrivals' threshold field and enter a negative value '-5'
    await page.click('[data-testid="consecutive-late-arrivals-threshold-input"]');
    await page.fill('[data-testid="consecutive-late-arrivals-threshold-input"]', '-5');
    await page.click('[data-testid="save-thresholds-button"]');
    
    // Verify validation error for negative value
    await expect(page.locator('[data-testid="validation-error-consecutive-late-arrivals"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-consecutive-late-arrivals"]')).toContainText('Value must be positive');
    
    // Clear the field and leave the 'Consecutive Late Arrivals' threshold field empty (blank)
    await page.fill('[data-testid="consecutive-late-arrivals-threshold-input"]', '');
    await page.click('[data-testid="save-thresholds-button"]');
    
    // Verify validation error for empty field
    await expect(page.locator('[data-testid="validation-error-consecutive-late-arrivals"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-consecutive-late-arrivals"]')).toContainText('Field is required');
    
    // Enter special characters '!@#$' in the 'Early Departures' threshold field
    await page.click('[data-testid="early-departures-threshold-input"]');
    await page.fill('[data-testid="early-departures-threshold-input"]', '!@#$');
    await page.click('[data-testid="save-thresholds-button"]');
    
    // Verify validation error for special characters
    await expect(page.locator('[data-testid="validation-error-early-departures"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-early-departures"]')).toContainText('Invalid characters');
    
    // Attempt to save the form with multiple validation errors present
    await expect(page.locator('[data-testid="save-thresholds-button"]')).toBeDisabled();
    
    // Correct all invalid inputs by entering valid threshold values: Late Arrivals (20), Consecutive Late Arrivals (5), Early Departures (15)
    await page.fill('[data-testid="late-arrivals-threshold-input"]', '20');
    await page.fill('[data-testid="consecutive-late-arrivals-threshold-input"]', '5');
    await page.fill('[data-testid="early-departures-threshold-input"]', '15');
    
    // Verify validation errors are cleared
    await expect(page.locator('[data-testid="validation-error-late-arrivals"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="validation-error-consecutive-late-arrivals"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="validation-error-early-departures"]')).not.toBeVisible();
    
    // Click 'Save' button with all valid inputs
    await page.click('[data-testid="save-thresholds-button"]');
    
    // Verify success message appears
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Settings saved and applied successfully');
  });
});