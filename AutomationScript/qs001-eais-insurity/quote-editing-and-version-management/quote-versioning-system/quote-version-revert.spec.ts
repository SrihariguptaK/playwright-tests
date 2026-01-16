import { test, expect } from '@playwright/test';

test.describe('Quote Version Revert Functionality', () => {
  let quoteId: string;
  let previousVersionId: string;
  let previousVersionData: any;

  test.beforeEach(async ({ page }) => {
    // Navigate to quotes page and setup test data
    await page.goto('/quotes');
    
    // Assume we have a quote with multiple versions for testing
    quoteId = 'test-quote-123';
    previousVersionId = 'version-2';
    
    // Store previous version data for comparison
    previousVersionData = {
      customerName: 'Acme Corporation',
      totalAmount: 15000,
      lineItems: 3,
      status: 'Draft'
    };
  });

  test('Verify successful revert to previous quote version', async ({ page }) => {
    // Step 1: Navigate to the quote details page for the target quote
    await page.goto(`/quotes/${quoteId}`);
    await expect(page.locator('[data-testid="quote-details-header"]')).toBeVisible();

    // Step 2: Click on 'Version History' button or link to view all quote versions
    await page.click('[data-testid="version-history-button"]');
    await expect(page.locator('[data-testid="version-history-panel"]')).toBeVisible();

    // Step 3: Review the list of previous versions and select a specific previous version to revert to
    const versionList = page.locator('[data-testid="version-list"]');
    await expect(versionList).toBeVisible();
    
    const previousVersion = page.locator(`[data-testid="version-item-${previousVersionId}"]`);
    await expect(previousVersion).toBeVisible();
    
    // Verify version details are displayed
    await expect(previousVersion.locator('[data-testid="version-customer-name"]')).toContainText(previousVersionData.customerName);
    await expect(previousVersion.locator('[data-testid="version-total-amount"]')).toContainText(previousVersionData.totalAmount.toString());

    // Step 4: Click the 'Revert' button for the selected previous version
    await previousVersion.locator('[data-testid="revert-button"]').click();

    // Expected Result: Confirmation dialog is displayed
    const confirmationDialog = page.locator('[data-testid="revert-confirmation-dialog"]');
    await expect(confirmationDialog).toBeVisible();
    await expect(confirmationDialog.locator('[data-testid="dialog-title"]')).toContainText('Confirm Revert');
    await expect(confirmationDialog.locator('[data-testid="dialog-message"]')).toContainText('Are you sure you want to revert');

    // Step 5: Review the confirmation dialog details and click 'Confirm' or 'Yes' button
    await confirmationDialog.locator('[data-testid="confirm-revert-button"]').click();

    // Step 6: Wait for system processing to complete
    await expect(page.locator('[data-testid="loading-indicator"]')).toBeVisible();
    await expect(page.locator('[data-testid="loading-indicator"]')).toBeHidden({ timeout: 10000 });

    // Expected Result: New version is created identical to selected version
    const successMessage = page.locator('[data-testid="success-notification"]');
    await expect(successMessage).toBeVisible();
    await expect(successMessage).toContainText('Quote successfully reverted');

    // Step 7: View current quote details on the quote details page
    await expect(page.locator('[data-testid="quote-details-header"]')).toBeVisible();

    // Expected Result: Quote reflects reverted version data
    await expect(page.locator('[data-testid="quote-customer-name"]')).toContainText(previousVersionData.customerName);
    await expect(page.locator('[data-testid="quote-total-amount"]')).toContainText(previousVersionData.totalAmount.toString());
    await expect(page.locator('[data-testid="quote-status"]')).toContainText(previousVersionData.status);
    
    const lineItemsCount = await page.locator('[data-testid="quote-line-item"]').count();
    expect(lineItemsCount).toBe(previousVersionData.lineItems);

    // Step 8: Check version history again
    await page.click('[data-testid="version-history-button"]');
    await expect(page.locator('[data-testid="version-history-panel"]')).toBeVisible();

    // Step 9: Verify that the new version data matches exactly with the selected previous version data
    const latestVersion = page.locator('[data-testid="version-item"]:first-child');
    await expect(latestVersion).toBeVisible();
    await expect(latestVersion.locator('[data-testid="version-label"]')).toContainText('Reverted from');
    await expect(latestVersion.locator('[data-testid="version-customer-name"]')).toContainText(previousVersionData.customerName);
    await expect(latestVersion.locator('[data-testid="version-total-amount"]')).toContainText(previousVersionData.totalAmount.toString());
    await expect(latestVersion.locator('[data-testid="version-status"]')).toContainText(previousVersionData.status);
  });

  test('Verify revert confirmation dialog displays correct information', async ({ page }) => {
    // Navigate to quote details page
    await page.goto(`/quotes/${quoteId}`);
    
    // Open version history
    await page.click('[data-testid="version-history-button"]');
    await expect(page.locator('[data-testid="version-history-panel"]')).toBeVisible();
    
    // Select previous version and click revert
    const previousVersion = page.locator(`[data-testid="version-item-${previousVersionId}"]`);
    await previousVersion.locator('[data-testid="revert-button"]').click();
    
    // Verify confirmation dialog content
    const confirmationDialog = page.locator('[data-testid="revert-confirmation-dialog"]');
    await expect(confirmationDialog).toBeVisible();
    await expect(confirmationDialog.locator('[data-testid="dialog-title"]')).toBeVisible();
    await expect(confirmationDialog.locator('[data-testid="dialog-message"]')).toBeVisible();
    await expect(confirmationDialog.locator('[data-testid="confirm-revert-button"]')).toBeVisible();
    await expect(confirmationDialog.locator('[data-testid="cancel-revert-button"]')).toBeVisible();
  });

  test('Verify cancel revert action closes dialog without reverting', async ({ page }) => {
    // Navigate to quote details page
    await page.goto(`/quotes/${quoteId}`);
    
    // Store current version data
    const currentCustomerName = await page.locator('[data-testid="quote-customer-name"]').textContent();
    
    // Open version history and initiate revert
    await page.click('[data-testid="version-history-button"]');
    const previousVersion = page.locator(`[data-testid="version-item-${previousVersionId}"]`);
    await previousVersion.locator('[data-testid="revert-button"]').click();
    
    // Cancel the revert action
    const confirmationDialog = page.locator('[data-testid="revert-confirmation-dialog"]');
    await expect(confirmationDialog).toBeVisible();
    await confirmationDialog.locator('[data-testid="cancel-revert-button"]').click();
    
    // Verify dialog is closed
    await expect(confirmationDialog).toBeHidden();
    
    // Verify quote data remains unchanged
    await expect(page.locator('[data-testid="quote-customer-name"]')).toContainText(currentCustomerName || '');
  });

  test('Verify new version is created after successful revert', async ({ page }) => {
    // Navigate to quote details page
    await page.goto(`/quotes/${quoteId}`);
    
    // Open version history and count existing versions
    await page.click('[data-testid="version-history-button"]');
    const initialVersionCount = await page.locator('[data-testid="version-item"]').count();
    
    // Perform revert
    const previousVersion = page.locator(`[data-testid="version-item-${previousVersionId}"]`);
    await previousVersion.locator('[data-testid="revert-button"]').click();
    await page.locator('[data-testid="confirm-revert-button"]').click();
    
    // Wait for revert to complete
    await expect(page.locator('[data-testid="success-notification"]')).toBeVisible();
    
    // Verify new version is created
    await page.click('[data-testid="version-history-button"]');
    const newVersionCount = await page.locator('[data-testid="version-item"]').count();
    expect(newVersionCount).toBe(initialVersionCount + 1);
  });
});