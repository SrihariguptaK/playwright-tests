import { test, expect } from '@playwright/test';

test.describe('Quote Update Notifications - Story 15', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to quote management page
    await page.goto('/quotes');
    // Wait for page to load
    await page.waitForLoadState('networkidle');
  });

  test('Validate success notification after quote update - happy path', async ({ page }) => {
    // Step 1: Make valid edits to the quote fields
    // Click on a quote to edit
    await page.click('[data-testid="quote-item"]');
    await page.waitForSelector('[data-testid="quote-edit-form"]');

    // Update pricing field
    const pricingField = page.locator('[data-testid="quote-pricing-input"]');
    await pricingField.clear();
    await pricingField.fill('15000');

    // Modify terms field
    const termsField = page.locator('[data-testid="quote-terms-input"]');
    await termsField.clear();
    await termsField.fill('Net 30 days');

    // Change quantities field
    const quantityField = page.locator('[data-testid="quote-quantity-input"]');
    await quantityField.clear();
    await quantityField.fill('50');

    // Step 2: Click the Save or Submit button to save the quote edits
    await page.click('[data-testid="quote-save-button"]');

    // Step 3: Observe the screen immediately after the save operation completes
    // Wait for notification to appear
    const notification = page.locator('[data-testid="notification-success"]');
    await expect(notification).toBeVisible({ timeout: 5000 });

    // Step 4: Verify the notification contains a success indicator
    const successIcon = notification.locator('[data-testid="success-icon"]');
    await expect(successIcon).toBeVisible();

    // Verify positive color scheme (green for success)
    const notificationClass = await notification.getAttribute('class');
    expect(notificationClass).toContain('success');

    // Step 5: Read the notification content to verify it includes a summary of the changes made
    const notificationContent = notification.locator('[data-testid="notification-content"]');
    await expect(notificationContent).toBeVisible();
    
    const notificationText = await notificationContent.textContent();
    expect(notificationText).toContain('successfully updated');
    expect(notificationText).toMatch(/pricing|terms|quantity/i);

    // Step 6: Verify that no sensitive information is exposed in the notification
    // Check that notification does not contain internal IDs, system paths, or confidential data
    expect(notificationText).not.toMatch(/\/[a-z]+\/[a-z]+\//i); // No system paths
    expect(notificationText).not.toMatch(/id:\s*[0-9a-f-]{20,}/i); // No internal IDs
    expect(notificationText).not.toMatch(/password|secret|key|token/i); // No confidential data

    // Step 7: Locate and click the dismiss button on the notification
    const dismissButton = notification.locator('[data-testid="notification-dismiss"]');
    await expect(dismissButton).toBeVisible();
    await dismissButton.click();

    // Expected Result: Notification disappears without errors
    await expect(notification).not.toBeVisible({ timeout: 3000 });

    // Step 8: Verify the page remains functional after dismissing the notification
    // Verify quote form is still accessible
    await expect(page.locator('[data-testid="quote-edit-form"]')).toBeVisible();
    
    // Verify no error messages are displayed
    const errorNotification = page.locator('[data-testid="notification-error"]');
    await expect(errorNotification).not.toBeVisible();

    // Verify page is still interactive by checking if a field can be focused
    await pricingField.focus();
    await expect(pricingField).toBeFocused();
  });

  test('Validate success notification displays change summary', async ({ page }) => {
    // Navigate to quote edit page
    await page.click('[data-testid="quote-item"]');
    await page.waitForSelector('[data-testid="quote-edit-form"]');

    // Make specific changes to track in summary
    const pricingField = page.locator('[data-testid="quote-pricing-input"]');
    await pricingField.clear();
    await pricingField.fill('25000');

    // Submit quote edits
    await page.click('[data-testid="quote-save-button"]');

    // Expected Result: Success notification is displayed with change summary
    const notification = page.locator('[data-testid="notification-success"]');
    await expect(notification).toBeVisible({ timeout: 5000 });

    // Verify notification includes summary of changes
    const summarySection = notification.locator('[data-testid="notification-summary"]');
    await expect(summarySection).toBeVisible();

    const summaryText = await summarySection.textContent();
    expect(summaryText).toBeTruthy();
    expect(summaryText?.length).toBeGreaterThan(0);
  });

  test('Validate notification can be dismissed by user', async ({ page }) => {
    // Navigate to quote and make edits
    await page.click('[data-testid="quote-item"]');
    await page.waitForSelector('[data-testid="quote-edit-form"]');

    const pricingField = page.locator('[data-testid="quote-pricing-input"]');
    await pricingField.clear();
    await pricingField.fill('18000');

    // Submit edits
    await page.click('[data-testid="quote-save-button"]');

    // Wait for notification
    const notification = page.locator('[data-testid="notification-success"]');
    await expect(notification).toBeVisible();

    // Action: Dismiss the notification
    const dismissButton = notification.locator('[data-testid="notification-dismiss"]');
    await dismissButton.click();

    // Expected Result: Notification disappears without errors
    await expect(notification).not.toBeVisible({ timeout: 3000 });
    
    // Verify no errors occurred
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).not.toBeVisible();
  });

  test('Validate no sensitive information in notification', async ({ page }) => {
    // Navigate to quote and make edits
    await page.click('[data-testid="quote-item"]');
    await page.waitForSelector('[data-testid="quote-edit-form"]');

    const termsField = page.locator('[data-testid="quote-terms-input"]');
    await termsField.clear();
    await termsField.fill('Net 45 days');

    // Submit edits
    await page.click('[data-testid="quote-save-button"]');

    // Wait for notification
    const notification = page.locator('[data-testid="notification-success"]');
    await expect(notification).toBeVisible();

    // Get all text content from notification
    const notificationText = await notification.textContent();

    // Verify no sensitive information is exposed
    expect(notificationText).not.toMatch(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i); // No UUIDs
    expect(notificationText).not.toMatch(/\b\d{16,}\b/); // No long numeric IDs
    expect(notificationText).not.toMatch(/\/api\/|localhost|127\.0\.0\.1/i); // No system paths or URLs
    expect(notificationText).not.toMatch(/password|secret|apikey|token|credential/i); // No credential keywords
    expect(notificationText).not.toMatch(/\$\d+\.\d{3,}/); // No overly precise financial data
  });
});