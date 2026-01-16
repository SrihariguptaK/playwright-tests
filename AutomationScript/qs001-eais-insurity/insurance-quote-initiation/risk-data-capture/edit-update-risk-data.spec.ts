import { test, expect } from '@playwright/test';

test.describe('Edit and Update Risk Data', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as underwriter
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'underwriter@insurance.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful editing and saving of risk data', async ({ page }) => {
    // Step 1: Navigate to risk data list
    await page.click('[data-testid="risk-data-menu"]');
    await page.waitForSelector('[data-testid="risk-data-list"]');
    
    // Expected Result: List of risk entries is displayed
    await expect(page.locator('[data-testid="risk-data-list"]')).toBeVisible();
    const riskEntries = page.locator('[data-testid="risk-entry-row"]');
    await expect(riskEntries).toHaveCount(await riskEntries.count());
    expect(await riskEntries.count()).toBeGreaterThan(0);

    // Step 2: Select a risk entry and edit fields with valid data
    const firstRiskEntry = riskEntries.first();
    await firstRiskEntry.click();
    await page.click('[data-testid="edit-risk-button"]');
    await page.waitForSelector('[data-testid="risk-edit-form"]');
    
    // Edit fields with valid data
    await page.fill('[data-testid="property-value-input"]', '500000');
    await page.fill('[data-testid="coverage-amount-input"]', '450000');
    await page.selectOption('[data-testid="risk-type-select"]', 'Commercial Property');
    await page.fill('[data-testid="location-input"]', '123 Main Street, New York, NY 10001');
    
    // Expected Result: No validation errors are shown
    await expect(page.locator('[data-testid="validation-error"]')).toHaveCount(0);
    await expect(page.locator('.error-message')).toHaveCount(0);

    // Step 3: Save the updated risk data
    await page.click('[data-testid="save-risk-button"]');
    
    // Expected Result: Data is saved and confirmation is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Risk data updated successfully');
    
    // Verify the updated data is reflected in the list
    await page.waitForSelector('[data-testid="risk-data-list"]');
    await expect(page.locator('[data-testid="risk-entry-row"]').first()).toContainText('500000');
  });

  test('Verify validation errors during risk data editing', async ({ page }) => {
    // Step 1: Select a risk entry to edit
    await page.click('[data-testid="risk-data-menu"]');
    await page.waitForSelector('[data-testid="risk-data-list"]');
    
    const riskEntries = page.locator('[data-testid="risk-entry-row"]');
    await riskEntries.first().click();
    await page.click('[data-testid="edit-risk-button"]');
    
    // Expected Result: Edit form is displayed
    await expect(page.locator('[data-testid="risk-edit-form"]')).toBeVisible();

    // Step 2: Enter invalid data in fields
    await page.fill('[data-testid="property-value-input"]', '-1000');
    await page.fill('[data-testid="coverage-amount-input"]', 'invalid');
    await page.fill('[data-testid="location-input"]', '');
    
    // Trigger validation by clicking outside or tabbing
    await page.click('[data-testid="risk-edit-form"]');
    
    // Expected Result: Inline validation errors are displayed
    await expect(page.locator('[data-testid="property-value-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="property-value-error"]')).toContainText('Property value must be a positive number');
    
    await expect(page.locator('[data-testid="coverage-amount-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="coverage-amount-error"]')).toContainText('Coverage amount must be a valid number');
    
    await expect(page.locator('[data-testid="location-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="location-error"]')).toContainText('Location is required');

    // Step 3: Attempt to save changes
    await page.click('[data-testid="save-risk-button"]');
    
    // Expected Result: Save is blocked until errors are corrected
    await expect(page.locator('[data-testid="risk-edit-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="save-risk-button"]')).toBeDisabled();
    
    // Verify no success message appears
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
  });

  test('Ensure audit trail records updates correctly', async ({ page }) => {
    // Step 1: Edit and save risk data
    await page.click('[data-testid="risk-data-menu"]');
    await page.waitForSelector('[data-testid="risk-data-list"]');
    
    const riskEntries = page.locator('[data-testid="risk-entry-row"]');
    const targetRiskEntry = riskEntries.first();
    
    // Get the risk ID for audit trail verification
    const riskId = await targetRiskEntry.getAttribute('data-risk-id');
    
    await targetRiskEntry.click();
    await page.click('[data-testid="edit-risk-button"]');
    await page.waitForSelector('[data-testid="risk-edit-form"]');
    
    // Make specific changes to track in audit
    const newPropertyValue = '750000';
    const newCoverageAmount = '675000';
    
    await page.fill('[data-testid="property-value-input"]', newPropertyValue);
    await page.fill('[data-testid="coverage-amount-input"]', newCoverageAmount);
    
    await page.click('[data-testid="save-risk-button"]');
    
    // Expected Result: Update is persisted
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await page.waitForTimeout(1000); // Allow time for audit log to be written

    // Step 2: Query audit logs for the updated entry
    await page.click('[data-testid="audit-trail-menu"]');
    await page.waitForSelector('[data-testid="audit-trail-list"]');
    
    // Filter audit logs by risk ID
    await page.fill('[data-testid="audit-search-input"]', riskId || '');
    await page.click('[data-testid="audit-search-button"]');
    
    // Expected Result: Audit log shows details of the change with timestamp and user
    const auditEntries = page.locator('[data-testid="audit-entry-row"]');
    await expect(auditEntries.first()).toBeVisible();
    
    const latestAuditEntry = auditEntries.first();
    
    // Verify audit entry contains the risk ID
    await expect(latestAuditEntry).toContainText(riskId || '');
    
    // Verify audit entry shows the action type
    await expect(latestAuditEntry.locator('[data-testid="audit-action"]')).toContainText('UPDATE');
    
    // Verify audit entry shows the user who made the change
    await expect(latestAuditEntry.locator('[data-testid="audit-user"]')).toContainText('underwriter@insurance.com');
    
    // Verify audit entry has a timestamp
    const timestamp = latestAuditEntry.locator('[data-testid="audit-timestamp"]');
    await expect(timestamp).toBeVisible();
    const timestampText = await timestamp.textContent();
    expect(timestampText).toBeTruthy();
    
    // Verify audit entry shows changed fields
    await latestAuditEntry.click();
    await expect(page.locator('[data-testid="audit-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-details"]')).toContainText('property_value');
    await expect(page.locator('[data-testid="audit-details"]')).toContainText(newPropertyValue);
    await expect(page.locator('[data-testid="audit-details"]')).toContainText('coverage_amount');
    await expect(page.locator('[data-testid="audit-details"]')).toContainText(newCoverageAmount);
  });
});