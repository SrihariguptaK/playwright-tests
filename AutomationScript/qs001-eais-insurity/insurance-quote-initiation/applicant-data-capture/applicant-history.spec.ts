import { test, expect } from '@playwright/test';

test.describe('Applicant History Management', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login if needed
    await page.goto('/dashboard');
  });

  test('Validate successful entry of multiple applicant history records', async ({ page }) => {
    // Action: Navigate to applicant history section
    await page.click('[data-testid="applicant-history-link"]');
    
    // Expected Result: History entry form is displayed
    await expect(page.locator('[data-testid="history-entry-form"]')).toBeVisible();
    
    // Enter first history record with valid data
    await page.fill('[data-testid="previous-insurer-name"]', 'ABC Insurance');
    await page.fill('[data-testid="coverage-start-date"]', '01/01/2020');
    await page.fill('[data-testid="coverage-end-date"]', '12/31/2020');
    await page.fill('[data-testid="claim-amount"]', '5000');
    await page.fill('[data-testid="claim-date"]', '06/15/2020');
    await page.selectOption('[data-testid="claim-type"]', 'Property Damage');
    
    // Click 'Add Another Record' button to add a second history entry
    await page.click('[data-testid="add-another-record-btn"]');
    
    // Enter second history record with valid data
    await page.fill('[data-testid="previous-insurer-name-1"]', 'XYZ Insurance');
    await page.fill('[data-testid="coverage-start-date-1"]', '01/01/2021');
    await page.fill('[data-testid="coverage-end-date-1"]', '12/31/2021');
    await page.fill('[data-testid="claim-amount-1"]', '3500');
    await page.fill('[data-testid="claim-date-1"]', '09/20/2021');
    await page.selectOption('[data-testid="claim-type-1"]', 'Liability');
    
    // Click 'Add Another Record' button to add a third history entry
    await page.click('[data-testid="add-another-record-btn"]');
    
    // Enter third history record with valid data (no claims filed)
    await page.fill('[data-testid="previous-insurer-name-2"]', 'DEF Insurance');
    await page.fill('[data-testid="coverage-start-date-2"]', '01/01/2022');
    await page.fill('[data-testid="coverage-end-date-2"]', '12/31/2022');
    
    // Expected Result: No validation errors are shown
    await expect(page.locator('[data-testid="validation-error"]')).toHaveCount(0);
    
    // Action: Save the history data
    await page.click('[data-testid="save-history-btn"]');
    
    // Expected Result: Data is saved and confirmation is displayed
    await expect(page.locator('[data-testid="save-confirmation"]')).toBeVisible();
    await expect(page.locator('[data-testid="save-confirmation"]')).toContainText('successfully saved');
    
    // Verify the saved data by refreshing the page
    await page.reload();
    await page.click('[data-testid="applicant-history-link"]');
    
    // Verify all three records are displayed
    await expect(page.locator('text=ABC Insurance')).toBeVisible();
    await expect(page.locator('text=XYZ Insurance')).toBeVisible();
    await expect(page.locator('text=DEF Insurance')).toBeVisible();
  });

  test('Verify rejection of incomplete or invalid history data', async ({ page }) => {
    // Action: Navigate to applicant history section
    await page.click('[data-testid="applicant-history-link"]');
    
    // Expected Result: History entry form is displayed
    await expect(page.locator('[data-testid="history-entry-form"]')).toBeVisible();
    
    // Leave the mandatory 'Previous Insurer Name' field blank
    await page.fill('[data-testid="coverage-start-date"]', '01/01/2020');
    await page.fill('[data-testid="coverage-end-date"]', '12/31/2020');
    await page.click('[data-testid="save-history-btn"]');
    
    // Expected Result: Validation errors are displayed inline
    await expect(page.locator('[data-testid="error-previous-insurer-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-previous-insurer-name"]')).toContainText('required');
    
    // Enter insurer name but leave mandatory 'Coverage Start Date' field blank
    await page.fill('[data-testid="previous-insurer-name"]', 'ABC Insurance');
    await page.fill('[data-testid="coverage-start-date"]', '');
    await page.click('[data-testid="save-history-btn"]');
    
    await expect(page.locator('[data-testid="error-coverage-start-date"]')).toBeVisible();
    
    // Enter an invalid date format
    await page.fill('[data-testid="coverage-start-date"]', '13/45/2020');
    await page.click('[data-testid="save-history-btn"]');
    
    await expect(page.locator('[data-testid="error-coverage-start-date"]')).toContainText('invalid');
    
    // Enter end date before start date
    await page.fill('[data-testid="coverage-start-date"]', '01/01/2020');
    await page.fill('[data-testid="coverage-end-date"]', '12/31/2019');
    await page.click('[data-testid="save-history-btn"]');
    
    await expect(page.locator('[data-testid="error-coverage-end-date"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-coverage-end-date"]')).toContainText('before start date');
    
    // Enter claim date outside coverage period
    await page.fill('[data-testid="coverage-end-date"]', '12/31/2020');
    await page.fill('[data-testid="claim-date"]', '06/15/2019');
    await page.click('[data-testid="save-history-btn"]');
    
    await expect(page.locator('[data-testid="error-claim-date"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-claim-date"]')).toContainText('outside coverage period');
    
    // Enter a negative value in claim amount
    await page.fill('[data-testid="claim-date"]', '06/15/2020');
    await page.fill('[data-testid="claim-amount"]', '-1000');
    await page.click('[data-testid="save-history-btn"]');
    
    await expect(page.locator('[data-testid="error-claim-amount"]')).toBeVisible();
    
    // Enter non-numeric characters in claim amount
    await page.fill('[data-testid="claim-amount"]', 'ABC');
    await page.click('[data-testid="save-history-btn"]');
    
    await expect(page.locator('[data-testid="error-claim-amount"]')).toContainText('numeric');
    
    // Expected Result: Save is blocked until errors are corrected
    const errorCount = await page.locator('[data-testid^="error-"]').count();
    expect(errorCount).toBeGreaterThan(0);
    
    // Correct all validation errors
    await page.fill('[data-testid="claim-amount"]', '5000');
    await page.selectOption('[data-testid="claim-type"]', 'Property Damage');
    
    // Click the 'Save' button after correcting all errors
    await page.click('[data-testid="save-history-btn"]');
    
    // Verify no validation errors remain
    await expect(page.locator('[data-testid="save-confirmation"]')).toBeVisible();
  });

  test('Ensure editing and deletion of history entries function correctly', async ({ page }) => {
    // Navigate to applicant history section and add new record
    await page.click('[data-testid="applicant-history-link"]');
    await page.click('[data-testid="add-new-record-btn"]');
    
    // Enter first history record with valid data
    await page.fill('[data-testid="previous-insurer-name"]', 'ABC Insurance');
    await page.fill('[data-testid="coverage-start-date"]', '01/01/2020');
    await page.fill('[data-testid="coverage-end-date"]', '12/31/2020');
    await page.fill('[data-testid="claim-amount"]', '5000');
    await page.fill('[data-testid="claim-date"]', '06/15/2020');
    await page.selectOption('[data-testid="claim-type"]', 'Property Damage');
    
    // Click 'Add Another Record' and enter second history record
    await page.click('[data-testid="add-another-record-btn"]');
    await page.fill('[data-testid="previous-insurer-name-1"]', 'XYZ Insurance');
    await page.fill('[data-testid="coverage-start-date-1"]', '01/01/2021');
    await page.fill('[data-testid="coverage-end-date-1"]', '12/31/2021');
    await page.fill('[data-testid="claim-amount-1"]', '3500');
    await page.fill('[data-testid="claim-date-1"]', '09/20/2021');
    await page.selectOption('[data-testid="claim-type-1"]', 'Liability');
    
    // Click the 'Save' button to save both history records
    await page.click('[data-testid="save-history-btn"]');
    
    // Expected Result: Records saved successfully
    await expect(page.locator('[data-testid="save-confirmation"]')).toBeVisible();
    
    // Locate the first history record and click the 'Edit' button
    await page.click('[data-testid="edit-record-0"]');
    
    // Modify the claim amount and claim date
    await page.fill('[data-testid="edit-claim-amount"]', '6500');
    await page.fill('[data-testid="edit-claim-date"]', '07/20/2020');
    
    // Click the 'Save Changes' button
    await page.click('[data-testid="save-changes-btn"]');
    
    // Expected Result: Changes are saved and reflected correctly
    await expect(page.locator('[data-testid="update-confirmation"]')).toBeVisible();
    await expect(page.locator('text=$6,500')).toBeVisible();
    await expect(page.locator('text=07/20/2020')).toBeVisible();
    
    // Refresh the page and verify persistence
    await page.reload();
    await page.click('[data-testid="applicant-history-link"]');
    await expect(page.locator('text=$6,500')).toBeVisible();
    
    // Locate the second history record and click the 'Delete' button
    await page.click('[data-testid="delete-record-1"]');
    
    // Click 'Cancel' in the confirmation dialog
    await page.click('[data-testid="cancel-delete-btn"]');
    
    // Verify record still exists
    await expect(page.locator('text=XYZ Insurance')).toBeVisible();
    
    // Click the 'Delete' button again
    await page.click('[data-testid="delete-record-1"]');
    
    // Click 'Confirm' in the confirmation dialog
    await page.click('[data-testid="confirm-delete-btn"]');
    
    // Expected Result: Record is removed and changes persisted
    await expect(page.locator('text=XYZ Insurance')).not.toBeVisible();
    await expect(page.locator('text=ABC Insurance')).toBeVisible();
    
    // Refresh the page and verify deletion persistence
    await page.reload();
    await page.click('[data-testid="applicant-history-link"]');
    await expect(page.locator('text=XYZ Insurance')).not.toBeVisible();
    await expect(page.locator('text=ABC Insurance')).toBeVisible();
    await expect(page.locator('text=$6,500')).toBeVisible();
  });
});