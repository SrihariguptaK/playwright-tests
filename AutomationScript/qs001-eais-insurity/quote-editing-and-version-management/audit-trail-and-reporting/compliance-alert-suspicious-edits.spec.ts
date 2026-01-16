import { test, expect } from '@playwright/test';

test.describe('Story-18: Compliance Officer - Suspicious Quote Edit Alerts', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to application login page
    await page.goto('/login');
  });

  test('Validate alert generation for suspicious quote edits (happy-path)', async ({ page }) => {
    // Step 1: Log in to the system with valid user credentials who has quote editing permissions
    await page.fill('[data-testid="username-input"]', 'quote.editor@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePassword123!');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible({ timeout: 10000 });

    // Step 2: Navigate to the quote management section and select an existing test quote
    await page.click('[data-testid="quote-management-nav"]');
    await expect(page.locator('[data-testid="quote-list"]')).toBeVisible();
    await page.click('[data-testid="quote-item-test-quote-001"]');
    await expect(page.locator('[data-testid="quote-details"]')).toBeVisible();

    // Step 3: Click on the 'Edit Quote' button to modify the quote
    await page.click('[data-testid="edit-quote-button"]');
    await expect(page.locator('[data-testid="quote-edit-form"]')).toBeVisible();

    // Step 4: Perform a quote edit that meets suspicious criteria (e.g., apply a 60% discount or reduce price by $15,000)
    const originalPrice = await page.locator('[data-testid="quote-price-input"]').inputValue();
    const originalPriceValue = parseFloat(originalPrice.replace(/[^0-9.]/g, ''));
    const suspiciousPrice = originalPriceValue - 15000;
    
    await page.fill('[data-testid="quote-price-input"]', suspiciousPrice.toString());
    await page.fill('[data-testid="discount-percentage-input"]', '60');
    await page.fill('[data-testid="edit-reason-input"]', 'Special customer discount');
    await page.click('[data-testid="save-quote-button"]');
    
    await expect(page.locator('[data-testid="quote-saved-confirmation"]')).toBeVisible();
    const editTimestamp = Date.now();

    // Step 5: Wait for up to 1 minute and monitor the system for alert generation
    // Step 6: Verify that the Compliance Officer receives a notification
    await page.waitForTimeout(5000); // Wait 5 seconds for alert processing
    
    // Step 7: Log out from the current user session and log in as a Compliance Officer
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    await page.fill('[data-testid="username-input"]', 'compliance.officer@company.com');
    await page.fill('[data-testid="password-input"]', 'CompliancePass456!');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible({ timeout: 10000 });

    // Step 8: Access the alert dashboard from the main navigation menu
    await page.click('[data-testid="alerts-nav"]');
    await expect(page.locator('[data-testid="alert-dashboard"]')).toBeVisible();

    // Verify alert was delivered within 1 minute
    const currentTimestamp = Date.now();
    const timeDifference = (currentTimestamp - editTimestamp) / 1000; // Convert to seconds
    expect(timeDifference).toBeLessThan(60);

    // Step 9: Locate the alert generated in step 5 in the alert list
    const alertItem = page.locator('[data-testid^="alert-item-"]').first();
    await expect(alertItem).toBeVisible();
    
    // Verify alert contains suspicious edit indicator
    await expect(alertItem.locator('[data-testid="alert-type"]')).toContainText('Suspicious Quote Edit');
    await expect(alertItem.locator('[data-testid="alert-severity"]')).toContainText('High');

    // Step 10: Click on the alert to view full details
    await alertItem.click();
    await expect(page.locator('[data-testid="alert-details-panel"]')).toBeVisible();

    // Verify alert details are visible with relevant information
    await expect(page.locator('[data-testid="alert-quote-id"]')).toContainText('test-quote-001');
    await expect(page.locator('[data-testid="alert-discount-amount"]')).toContainText('60%');
    await expect(page.locator('[data-testid="alert-price-reduction"]')).toContainText('$15,000');
    await expect(page.locator('[data-testid="alert-editor-name"]')).toContainText('quote.editor@company.com');
    await expect(page.locator('[data-testid="alert-timestamp"]')).toBeVisible();

    // Step 11: Verify that the alert is logged in the audit trail
    await page.click('[data-testid="view-audit-trail-button"]');
    await expect(page.locator('[data-testid="audit-trail-panel"]')).toBeVisible();
    
    const auditEntry = page.locator('[data-testid^="audit-entry-"]').first();
    await expect(auditEntry).toBeVisible();
    await expect(auditEntry.locator('[data-testid="audit-event-type"]')).toContainText('Alert Generated');
    await expect(auditEntry.locator('[data-testid="audit-alert-type"]')).toContainText('Suspicious Quote Edit');
    await expect(auditEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
  });

  test('Validate alert generation for suspicious quote edits - automated test case', async ({ page }) => {
    // Step 1: Perform a quote edit that meets suspicious criteria
    await page.fill('[data-testid="username-input"]', 'quote.editor@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePassword123!');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    await page.click('[data-testid="quote-management-nav"]');
    await page.click('[data-testid="quote-item-test-quote-002"]');
    await page.click('[data-testid="edit-quote-button"]');

    // Perform suspicious edit - large discount
    await page.fill('[data-testid="discount-percentage-input"]', '65');
    await page.click('[data-testid="save-quote-button"]');
    
    const editTime = Date.now();

    // Expected Result: Alert is generated and sent to Compliance Officers within 1 minute
    await page.waitForTimeout(5000);
    
    // Switch to Compliance Officer account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.fill('[data-testid="username-input"]', 'compliance.officer@company.com');
    await page.fill('[data-testid="password-input"]', 'CompliancePass456!');
    await page.click('[data-testid="login-button"]');

    // Step 2: Access alert dashboard as Compliance Officer
    await page.click('[data-testid="alerts-nav"]');
    await expect(page.locator('[data-testid="alert-dashboard"]')).toBeVisible();

    // Expected Result: Alert is visible with relevant details
    const latestAlert = page.locator('[data-testid^="alert-item-"]').first();
    await expect(latestAlert).toBeVisible();
    
    // Verify alert was generated within 1 minute
    const alertTimestamp = await latestAlert.locator('[data-testid="alert-timestamp"]').getAttribute('data-timestamp');
    const alertTime = parseInt(alertTimestamp || '0');
    const timeDiff = (alertTime - editTime) / 1000;
    expect(timeDiff).toBeLessThan(60);

    // Verify alert contains relevant details
    await latestAlert.click();
    await expect(page.locator('[data-testid="alert-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-quote-id"]')).toContainText('test-quote-002');
    await expect(page.locator('[data-testid="alert-discount-amount"]')).toContainText('65%');
    await expect(page.locator('[data-testid="alert-description"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-severity"]')).toContainText('High');
  });
});