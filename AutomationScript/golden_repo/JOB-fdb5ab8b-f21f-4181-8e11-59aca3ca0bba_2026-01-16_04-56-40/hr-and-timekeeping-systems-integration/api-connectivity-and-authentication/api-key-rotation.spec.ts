import { test, expect } from '@playwright/test';
import { request } from '@playwright/test';

test.describe('API Key Rotation - Story 16', () => {
  const API_BASE_URL = process.env.API_BASE_URL || 'https://api.example.com';
  const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@example.com';
  let oldApiKey: string;
  let newApiKey: string;

  test.beforeEach(async ({ page }) => {
    // Navigate to API key management interface
    await page.goto('/admin/api-keys');
    await page.waitForLoadState('networkidle');
  });

  test('Validate secure generation of new API keys', async ({ page, request }) => {
    // Step 1: Trigger API key rotation process
    await page.click('button[data-testid="rotate-api-key-button"]');
    
    // Wait for rotation confirmation dialog
    await page.waitForSelector('[data-testid="rotation-confirmation-dialog"]');
    await page.click('button[data-testid="confirm-rotation-button"]');
    
    // Wait for new key generation
    await page.waitForSelector('[data-testid="new-api-key-generated"]', { timeout: 10000 });
    
    // Expected Result: New API key generated with correct format
    const newKeyElement = await page.locator('[data-testid="new-api-key-value"]');
    newApiKey = await newKeyElement.textContent() || '';
    
    // Verify key format (e.g., starts with 'sk_' and has correct length)
    expect(newApiKey).toMatch(/^sk_[a-zA-Z0-9]{32,64}$/);
    expect(newApiKey.length).toBeGreaterThanOrEqual(35);
    
    // Step 2: Verify new key stored securely in database
    // Navigate to database view or make API call to verify storage
    const apiContext = await request.newContext();
    const verifyResponse = await apiContext.get(`${API_BASE_URL}/admin/keys/verify`, {
      headers: {
        'Authorization': `Bearer ${process.env.ADMIN_TOKEN}`
      },
      params: {
        keyId: newApiKey.substring(0, 10)
      }
    });
    
    // Expected Result: Key stored with encryption and access controls
    expect(verifyResponse.ok()).toBeTruthy();
    const verifyData = await verifyResponse.json();
    expect(verifyData.encrypted).toBe(true);
    expect(verifyData.accessControls).toBeDefined();
    
    // Step 3: Check logs for rotation event entry
    await page.click('[data-testid="audit-logs-tab"]');
    await page.waitForSelector('[data-testid="audit-log-entries"]');
    
    // Filter logs by rotation events
    await page.fill('[data-testid="log-filter-input"]', 'API_KEY_ROTATION');
    await page.click('[data-testid="apply-filter-button"]');
    
    // Expected Result: Rotation event logged with timestamp and user info
    const latestLogEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(latestLogEntry).toContainText('API_KEY_ROTATION');
    await expect(latestLogEntry).toContainText(new Date().toISOString().split('T')[0]); // Today's date
    
    const logTimestamp = await latestLogEntry.locator('[data-testid="log-timestamp"]').textContent();
    const logUser = await latestLogEntry.locator('[data-testid="log-user"]').textContent();
    expect(logTimestamp).toBeTruthy();
    expect(logUser).toBeTruthy();
    
    // Verify expiration date is set
    await page.click('[data-testid="api-keys-tab"]');
    const keyRow = page.locator(`[data-testid="api-key-row"]:has-text("${newApiKey.substring(0, 10)}")`).first();
    const expirationDate = await keyRow.locator('[data-testid="key-expiration"]').textContent();
    expect(expirationDate).toBeTruthy();
    expect(new Date(expirationDate || '')).toBeInstanceOf(Date);
  });

  test('Test dual key usage during rotation grace period', async ({ page, request }) => {
    // Setup: Get current API keys
    await page.goto('/admin/api-keys');
    await page.waitForLoadState('networkidle');
    
    // Get old API key before rotation
    const oldKeyElement = page.locator('[data-testid="active-api-key"]').first();
    oldApiKey = await oldKeyElement.getAttribute('data-key-value') || '';
    
    // Trigger rotation to create grace period
    await page.click('button[data-testid="rotate-api-key-button"]');
    await page.waitForSelector('[data-testid="rotation-confirmation-dialog"]');
    await page.click('button[data-testid="confirm-rotation-button"]');
    await page.waitForSelector('[data-testid="grace-period-active"]', { timeout: 10000 });
    
    // Get new API key
    const newKeyElement = page.locator('[data-testid="new-api-key-value"]');
    newApiKey = await newKeyElement.textContent() || '';
    
    const apiContext = await request.newContext();
    
    // Step 1: Use old API key to make API call during grace period
    const oldKeyResponse = await apiContext.get(`${API_BASE_URL}/api/v1/data`, {
      headers: {
        'Authorization': `Bearer ${oldApiKey}`
      }
    });
    
    // Expected Result: API call succeeds
    expect(oldKeyResponse.ok()).toBeTruthy();
    expect(oldKeyResponse.status()).toBe(200);
    const oldKeyData = await oldKeyResponse.json();
    expect(oldKeyData).toBeDefined();
    
    // Verify no deprecation warnings in response headers
    const responseHeaders = oldKeyResponse.headers();
    expect(responseHeaders['x-api-key-deprecated']).toBeUndefined();
    
    // Step 2: Use new API key to make API call during grace period
    const newKeyResponse = await apiContext.get(`${API_BASE_URL}/api/v1/data`, {
      headers: {
        'Authorization': `Bearer ${newApiKey}`
      }
    });
    
    // Expected Result: API call succeeds
    expect(newKeyResponse.ok()).toBeTruthy();
    expect(newKeyResponse.status()).toBe(200);
    const newKeyData = await newKeyResponse.json();
    expect(newKeyData).toBeDefined();
    
    // Verify both keys can be used interchangeably
    for (let i = 0; i < 3; i++) {
      const alternateOldResponse = await apiContext.get(`${API_BASE_URL}/api/v1/data`, {
        headers: { 'Authorization': `Bearer ${oldApiKey}` }
      });
      expect(alternateOldResponse.ok()).toBeTruthy();
      
      const alternateNewResponse = await apiContext.get(`${API_BASE_URL}/api/v1/data`, {
        headers: { 'Authorization': `Bearer ${newApiKey}` }
      });
      expect(alternateNewResponse.ok()).toBeTruthy();
    }
    
    // Step 3: Simulate grace period expiration
    // Navigate to admin settings to expire grace period manually for testing
    await page.goto('/admin/api-keys/settings');
    await page.click('[data-testid="expire-grace-period-button"]');
    await page.waitForSelector('[data-testid="grace-period-expired"]', { timeout: 5000 });
    
    // After grace period, use old API key
    const expiredKeyResponse = await apiContext.get(`${API_BASE_URL}/api/v1/data`, {
      headers: {
        'Authorization': `Bearer ${oldApiKey}`
      }
    });
    
    // Expected Result: API call rejected with unauthorized error
    expect(expiredKeyResponse.ok()).toBeFalsy();
    expect(expiredKeyResponse.status()).toBe(401);
    
    const errorData = await expiredKeyResponse.json();
    expect(errorData.error).toContain('API key has been rotated');
    expect(errorData.error).toContain('no longer valid');
    
    // Verify new key still works after grace period
    const newKeyAfterExpirationResponse = await apiContext.get(`${API_BASE_URL}/api/v1/data`, {
      headers: {
        'Authorization': `Bearer ${newApiKey}`
      }
    });
    expect(newKeyAfterExpirationResponse.ok()).toBeTruthy();
    expect(newKeyAfterExpirationResponse.status()).toBe(200);
  });

  test('Verify administrator notification on key rotation', async ({ page, request }) => {
    // Step 1: Navigate to API key management interface and initiate rotation
    await page.goto('/admin/api-keys');
    await page.waitForLoadState('networkidle');
    
    // Initiate complete API key rotation process
    await page.click('button[data-testid="rotate-api-key-button"]');
    await page.waitForSelector('[data-testid="rotation-confirmation-dialog"]');
    await page.click('button[data-testid="confirm-rotation-button"]');
    
    // Wait for rotation to complete
    await page.waitForSelector('[data-testid="rotation-complete-message"]', { timeout: 15000 });
    await expect(page.locator('[data-testid="rotation-complete-message"]')).toContainText('Rotation completed successfully');
    
    // Step 2: Wait for notification processing and check notifications
    await page.waitForTimeout(2000); // Wait for notification to be sent
    
    // Navigate to notifications or email inbox simulation
    await page.goto('/admin/notifications');
    await page.waitForLoadState('networkidle');
    
    // Filter for recent notifications
    await page.selectOption('[data-testid="notification-type-filter"]', 'API_KEY_ROTATION');
    await page.click('[data-testid="apply-notification-filter"]');
    
    // Expected Result: Notification sent to configured administrators
    const latestNotification = page.locator('[data-testid="notification-item"]').first();
    await expect(latestNotification).toBeVisible();
    
    // Step 3: Verify subject line
    const notificationSubject = await latestNotification.locator('[data-testid="notification-subject"]').textContent();
    expect(notificationSubject).toContain('API Key Rotation Completed');
    
    // Open notification details
    await latestNotification.click();
    await page.waitForSelector('[data-testid="notification-details"]');
    
    // Step 4: Review email body content and verify rotation timestamp
    const notificationBody = page.locator('[data-testid="notification-body"]');
    await expect(notificationBody).toBeVisible();
    
    const bodyText = await notificationBody.textContent();
    expect(bodyText).toContain('Rotation completed on:');
    
    // Verify timestamp format (e.g., '2024-01-15 14:30:00 UTC')
    const timestampRegex = /\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+(UTC|GMT)/;
    expect(bodyText).toMatch(timestampRegex);
    
    // Step 5: Verify notification includes new API key ID or reference
    const keyIdElement = page.locator('[data-testid="notification-key-id"]');
    const keyIdText = await keyIdElement.textContent();
    expect(keyIdText).toBeTruthy();
    expect(keyIdText?.length).toBeLessThan(20); // Should be reference, not full key
    
    // Step 6: Check grace period information and old key deactivation schedule
    await expect(notificationBody).toContainText('grace period');
    await expect(notificationBody).toContainText('deactivation');
    
    const gracePeriodInfo = page.locator('[data-testid="notification-grace-period"]');
    await expect(gracePeriodInfo).toBeVisible();
    const gracePeriodText = await gracePeriodInfo.textContent();
    expect(gracePeriodText).toMatch(/\d+\s+(hours|days|minutes)/);
    
    // Step 7: Verify user who initiated the rotation
    const initiatorElement = page.locator('[data-testid="notification-initiator"]');
    await expect(initiatorElement).toBeVisible();
    const initiatorText = await initiatorElement.textContent();
    expect(initiatorText).toBeTruthy();
    expect(initiatorText).toMatch(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[A-Za-z\s]+/);
    
    // Step 8: Check for additional details
    const rotationReason = page.locator('[data-testid="notification-rotation-reason"]');
    if (await rotationReason.isVisible()) {
      const reasonText = await rotationReason.textContent();
      expect(reasonText).toBeTruthy();
    }
    
    const affectedServices = page.locator('[data-testid="notification-affected-services"]');
    if (await affectedServices.isVisible()) {
      await expect(affectedServices).toBeVisible();
    }
    
    const actionItems = page.locator('[data-testid="notification-action-items"]');
    if (await actionItems.isVisible()) {
      await expect(actionItems).toBeVisible();
    }
    
    // Verify notification recipient includes configured administrator
    const recipients = page.locator('[data-testid="notification-recipients"]');
    const recipientsText = await recipients.textContent();
    expect(recipientsText).toContain(ADMIN_EMAIL);
  });
});