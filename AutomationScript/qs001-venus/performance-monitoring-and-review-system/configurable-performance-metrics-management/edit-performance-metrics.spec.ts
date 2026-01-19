import { test, expect } from '@playwright/test';

test.describe('Edit Performance Metrics', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Performance Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'performance.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful metric editing with valid input', async ({ page }) => {
    // Step 1: Navigate to Metrics Management page from the main dashboard
    await page.click('[data-testid="metrics-management-link"]');
    await expect(page).toHaveURL(/.*metrics/);
    
    // Expected Result: Metrics list is displayed
    await expect(page.locator('[data-testid="metrics-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="metric-item"]').first()).toBeVisible();

    // Step 2: Locate an existing metric and click the Edit button
    const salesTargetMetric = page.locator('[data-testid="metric-item"]', { hasText: 'Sales Target Achievement' });
    await expect(salesTargetMetric).toBeVisible();
    await salesTargetMetric.locator('[data-testid="edit-metric-button"]').click();
    
    // Expected Result: Form populated with current metric data
    await expect(page.locator('[data-testid="edit-metric-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="metric-name-input"]')).toHaveValue('Sales Target Achievement');
    const currentDescription = await page.locator('[data-testid="metric-description-input"]').inputValue();
    expect(currentDescription).toBeTruthy();

    // Step 3: Modify the metric description to a new valid value
    await page.fill('[data-testid="metric-description-input"]', 'Updated: Measures monthly sales target completion percentage');
    
    // Step 4: Modify the target value to a new valid number
    await page.fill('[data-testid="metric-target-input"]', '110');
    
    // Step 5: Modify the weight value to a new valid number
    await page.fill('[data-testid="metric-weight-input"]', '0.35');
    
    // Step 6: Click the Submit or Update button
    await page.click('[data-testid="submit-metric-button"]');
    
    // Expected Result: Metric is updated successfully and confirmation is shown
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Metric updated successfully');
    
    // Step 7: Verify the updated metric appears in the metrics list with modified values
    await expect(page.locator('[data-testid="metrics-list"]')).toBeVisible();
    const updatedMetric = page.locator('[data-testid="metric-item"]', { hasText: 'Sales Target Achievement' });
    await expect(updatedMetric).toContainText('Updated: Measures monthly sales target completion percentage');
    await expect(updatedMetric).toContainText('110');
    await expect(updatedMetric).toContainText('0.35');
    
    // Step 8: Check the audit log for the metric update
    await page.click('[data-testid="view-audit-log-button"]');
    await expect(page.locator('[data-testid="audit-log-modal"]')).toBeVisible();
    const latestAuditEntry = page.locator('[data-testid="audit-entry"]').first();
    await expect(latestAuditEntry).toContainText('Metric updated');
    await expect(latestAuditEntry).toContainText('Sales Target Achievement');
  });

  test('Reject editing of metrics linked to active review cycles', async ({ page }) => {
    // Step 1: Navigate to Metrics Management page
    await page.click('[data-testid="metrics-management-link"]');
    await expect(page).toHaveURL(/.*metrics/);
    await expect(page.locator('[data-testid="metrics-list"]')).toBeVisible();
    
    // Step 2: Locate a metric that is linked to an active review cycle
    const activeReviewMetric = page.locator('[data-testid="metric-item"]', { hasText: 'Q4 Performance Rating' });
    await expect(activeReviewMetric).toBeVisible();
    
    // Step 3: Click the Edit button for the metric linked to active review cycle
    await activeReviewMetric.locator('[data-testid="edit-metric-button"]').click();
    
    // Expected Result: Edit option is available and form is displayed
    await expect(page.locator('[data-testid="edit-metric-form"]')).toBeVisible();
    
    // Step 4: Modify any field (e.g., change target value from 90 to 95)
    const originalTarget = await page.locator('[data-testid="metric-target-input"]').inputValue();
    await page.fill('[data-testid="metric-target-input"]', '95');
    
    // Step 5: Click the Submit or Update button
    await page.click('[data-testid="submit-metric-button"]');
    
    // Expected Result: System rejects update and displays error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Cannot edit metric linked to active review cycle');
    
    // Step 6: Close the edit form and verify that the metric values remain unchanged
    await page.click('[data-testid="cancel-button"]');
    await expect(page.locator('[data-testid="metrics-list"]')).toBeVisible();
    const unchangedMetric = page.locator('[data-testid="metric-item"]', { hasText: 'Q4 Performance Rating' });
    await expect(unchangedMetric).toContainText(originalTarget);
    
    // Step 7: Check the audit log to ensure no update was recorded
    await unchangedMetric.locator('[data-testid="view-audit-log-button"]').click();
    await expect(page.locator('[data-testid="audit-log-modal"]')).toBeVisible();
    const latestAuditEntry = page.locator('[data-testid="audit-entry"]').first();
    await expect(latestAuditEntry).not.toContainText('Metric updated');
  });

  test('Reject invalid input during metric editing', async ({ page }) => {
    // Step 1: Navigate to Metrics Management page
    await page.click('[data-testid="metrics-management-link"]');
    await expect(page).toHaveURL(/.*metrics/);
    await expect(page.locator('[data-testid="metrics-list"]')).toBeVisible();
    
    // Step 2: Select an editable metric and click the Edit button
    const editableMetric = page.locator('[data-testid="metric-item"]').first();
    await editableMetric.locator('[data-testid="edit-metric-button"]').click();
    
    // Expected Result: Form is displayed
    await expect(page.locator('[data-testid="edit-metric-form"]')).toBeVisible();
    
    // Step 3: Clear the target field and enter an invalid non-numeric value
    await page.fill('[data-testid="metric-target-input"]', 'abc');
    
    // Expected Result: Inline validation errors are shown
    await expect(page.locator('[data-testid="target-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="target-error"]')).toContainText('Target must be a valid number');
    
    // Step 4: Clear the weight field and enter an invalid value outside the acceptable range
    await page.fill('[data-testid="metric-weight-input"]', '1.5');
    await expect(page.locator('[data-testid="weight-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="weight-error"]')).toContainText('Weight must be between 0 and 1');
    
    // Step 5: Enter a negative number in the target field
    await page.fill('[data-testid="metric-target-input"]', '-20');
    await expect(page.locator('[data-testid="target-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="target-error"]')).toContainText('Target must be a positive number');
    
    // Step 6: Attempt to click the Submit or Update button
    const submitButton = page.locator('[data-testid="submit-metric-button"]');
    
    // Expected Result: Submission blocked until errors are corrected
    await expect(submitButton).toBeDisabled();
    
    // Step 7: Correct the target field to a valid positive number
    await page.fill('[data-testid="metric-target-input"]', '85');
    await expect(page.locator('[data-testid="target-error"]')).not.toBeVisible();
    
    // Step 8: Correct the weight field to a valid value within range
    await page.fill('[data-testid="metric-weight-input"]', '0.4');
    await expect(page.locator('[data-testid="weight-error"]')).not.toBeVisible();
    
    // Step 9: Click the Submit button with corrected values
    await expect(submitButton).toBeEnabled();
    await submitButton.click();
    
    // Expected Result: Metric is updated successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Metric updated successfully');
  });
});