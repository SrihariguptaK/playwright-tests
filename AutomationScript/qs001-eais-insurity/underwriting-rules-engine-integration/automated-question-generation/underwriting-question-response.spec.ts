import { test, expect } from '@playwright/test';

test.describe('Story-29: Underwriting Question Response Submission', () => {
  test.beforeEach(async ({ page }) => {
    // Login as Underwriting Analyst
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'underwriting.analyst@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate question response submission (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the assigned questions section from the analyst dashboard
    await page.click('[data-testid="assigned-questions-menu"]');
    await expect(page).toHaveURL(/.*assigned-questions/);
    
    // Step 2: Select a specific assigned question from the list
    await page.click('[data-testid="question-item-1"]');
    
    // Expected Result: Response submission form is displayed
    await expect(page.locator('[data-testid="response-submission-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="question-title"]')).toBeVisible();
    
    // Step 3: Enter valid response data in all mandatory fields
    await page.fill('[data-testid="response-field-risk-assessment"]', 'Low risk based on financial analysis');
    await page.fill('[data-testid="response-field-coverage-amount"]', '500000');
    await page.selectOption('[data-testid="response-field-recommendation"]', 'approve');
    await page.fill('[data-testid="response-field-notes"]', 'All documentation verified and complete');
    
    // Step 4: Click the submit button to save the response
    const responseTime = Date.now();
    await page.click('[data-testid="submit-response-button"]');
    
    // Expected Result: Response is saved and application status updates
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Response submitted successfully');
    
    // Verify response submission completes within 2 seconds
    const elapsedTime = Date.now() - responseTime;
    expect(elapsedTime).toBeLessThan(2000);
    
    // Step 5: Verify the application status has been updated
    await expect(page.locator('[data-testid="application-status"]')).toContainText('Under Review');
    
    // Step 6: Navigate to the response history section for the application
    await page.click('[data-testid="response-history-tab"]');
    await expect(page).toHaveURL(/.*response-history/);
    
    // Step 7: Locate the recently submitted response in the history
    // Expected Result: Submitted response is listed with timestamp
    const responseHistoryItem = page.locator('[data-testid="response-history-item"]').first();
    await expect(responseHistoryItem).toBeVisible();
    await expect(responseHistoryItem.locator('[data-testid="response-text"]')).toContainText('Low risk based on financial analysis');
    await expect(responseHistoryItem.locator('[data-testid="response-timestamp"]')).toBeVisible();
    await expect(responseHistoryItem.locator('[data-testid="response-analyst"]')).toContainText('underwriting.analyst@company.com');
  });

  test('Verify validation prevents incomplete responses (error-case)', async ({ page }) => {
    // Step 1: Navigate to the assigned questions section
    await page.click('[data-testid="assigned-questions-menu"]');
    await expect(page).toHaveURL(/.*assigned-questions/);
    
    // Step 2: Select a question that has mandatory response fields
    await page.click('[data-testid="question-item-2"]');
    await expect(page.locator('[data-testid="response-submission-form"]')).toBeVisible();
    
    // Step 3: Leave one or more mandatory fields empty
    await page.fill('[data-testid="response-field-risk-assessment"]', 'Moderate risk identified');
    // Intentionally leave coverage-amount field empty
    await page.selectOption('[data-testid="response-field-recommendation"]', 'review');
    // Leave notes field empty
    
    // Step 4: Attempt to submit the response with missing mandatory fields
    await page.click('[data-testid="submit-response-button"]');
    
    // Expected Result: Validation error messages are displayed and submission blocked
    await expect(page.locator('[data-testid="validation-error-coverage-amount"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-coverage-amount"]')).toContainText('Coverage amount is required');
    await expect(page.locator('[data-testid="validation-error-notes"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-notes"]')).toContainText('Notes field is required');
    
    // Verify that no success message appears
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
    
    // Step 5: Verify that no data is saved to the database
    // Check that form still contains the partial data (not cleared/saved)
    await expect(page.locator('[data-testid="response-field-risk-assessment"]')).toHaveValue('Moderate risk identified');
    
    // Step 6: Fill in all mandatory fields with valid data
    await page.fill('[data-testid="response-field-coverage-amount"]', '750000');
    await page.fill('[data-testid="response-field-notes"]', 'Additional review required for high-value policy');
    
    // Step 7: Submit the response with all mandatory fields completed
    await page.click('[data-testid="submit-response-button"]');
    
    // Expected Result: Response is successfully submitted
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Response submitted successfully');
    
    // Verify validation errors are cleared
    await expect(page.locator('[data-testid="validation-error-coverage-amount"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="validation-error-notes"]')).not.toBeVisible();
  });

  test('Access assigned question displays response submission form', async ({ page }) => {
    // Action: Access assigned question
    await page.click('[data-testid="assigned-questions-menu"]');
    await page.click('[data-testid="question-item-1"]');
    
    // Expected Result: Response submission form is displayed
    await expect(page.locator('[data-testid="response-submission-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="response-field-risk-assessment"]')).toBeVisible();
    await expect(page.locator('[data-testid="response-field-coverage-amount"]')).toBeVisible();
    await expect(page.locator('[data-testid="response-field-recommendation"]')).toBeVisible();
    await expect(page.locator('[data-testid="response-field-notes"]')).toBeVisible();
    await expect(page.locator('[data-testid="submit-response-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="submit-response-button"]')).toBeEnabled();
  });

  test('Enter valid response and submit updates application status', async ({ page }) => {
    // Navigate to assigned question
    await page.click('[data-testid="assigned-questions-menu"]');
    await page.click('[data-testid="question-item-3"]');
    
    // Action: Enter valid response and submit
    await page.fill('[data-testid="response-field-risk-assessment"]', 'High risk due to previous claims history');
    await page.fill('[data-testid="response-field-coverage-amount"]', '250000');
    await page.selectOption('[data-testid="response-field-recommendation"]', 'decline');
    await page.fill('[data-testid="response-field-notes"]', 'Multiple claims in past 3 years exceed acceptable threshold');
    
    await page.click('[data-testid="submit-response-button"]');
    
    // Expected Result: Response is saved and application status updates
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="application-status"]')).toContainText('Declined');
  });

  test('View response history shows submitted response with timestamp', async ({ page }) => {
    // Submit a response first
    await page.click('[data-testid="assigned-questions-menu"]');
    await page.click('[data-testid="question-item-4"]');
    
    await page.fill('[data-testid="response-field-risk-assessment"]', 'Standard risk profile');
    await page.fill('[data-testid="response-field-coverage-amount"]', '1000000');
    await page.selectOption('[data-testid="response-field-recommendation"]', 'approve');
    await page.fill('[data-testid="response-field-notes"]', 'Excellent credit history and no prior claims');
    
    await page.click('[data-testid="submit-response-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Action: View response history
    await page.click('[data-testid="response-history-tab"]');
    
    // Expected Result: Submitted response is listed with timestamp
    const latestResponse = page.locator('[data-testid="response-history-item"]').first();
    await expect(latestResponse).toBeVisible();
    await expect(latestResponse.locator('[data-testid="response-text"]')).toContainText('Standard risk profile');
    await expect(latestResponse.locator('[data-testid="response-timestamp"]')).toBeVisible();
    
    // Verify timestamp format and recency
    const timestampText = await latestResponse.locator('[data-testid="response-timestamp"]').textContent();
    expect(timestampText).toMatch(/\d{1,2}\/\d{1,2}\/\d{4}|\d{4}-\d{2}-\d{2}/);
  });
});