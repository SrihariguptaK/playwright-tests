import { test, expect } from '@playwright/test';

test.describe('HR System API Integration', () => {
  const BASE_URL = process.env.BASE_URL || 'https://app.example.com';
  const VALID_API_KEY = process.env.HR_API_KEY || 'valid-api-key-12345';
  const VALID_OAUTH_TOKEN = process.env.HR_OAUTH_TOKEN || 'Bearer valid-oauth-token-67890';
  const INVALID_API_KEY = 'invalid-api-key-xyz';
  const INVALID_OAUTH_TOKEN = 'malformed-token';

  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE_URL}/integration-console`);
    await page.waitForLoadState('networkidle');
  });

  test('Validate successful API connection and data retrieval (happy-path)', async ({ page }) => {
    // Navigate to the integration console and locate the HR system API configuration section
    await page.click('[data-testid="hr-system-config"]');
    await expect(page.locator('[data-testid="api-configuration-section"]')).toBeVisible();

    // Enter valid API credentials (API key/OAuth token) in the designated fields
    await page.fill('[data-testid="api-key-input"]', VALID_API_KEY);
    await page.fill('[data-testid="oauth-token-input"]', VALID_OAUTH_TOKEN);
    await expect(page.locator('[data-testid="api-key-input"]')).toHaveValue(VALID_API_KEY);

    // Click the 'Test Connection' or 'Authenticate' button
    await page.click('[data-testid="test-connection-button"]');
    
    // Expected Result: System authenticates and establishes connection
    await expect(page.locator('[data-testid="connection-status"]')).toContainText('Connected', { timeout: 10000 });
    await expect(page.locator('[data-testid="authentication-success-message"]')).toBeVisible();

    // Save the API configuration settings
    await page.click('[data-testid="save-config-button"]');
    await expect(page.locator('[data-testid="config-saved-notification"]')).toBeVisible();

    // Navigate to the data synchronization section and click 'Trigger Sync' or 'Start Synchronization' button
    await page.click('[data-testid="data-sync-section"]');
    await page.click('[data-testid="trigger-sync-button"]');

    // Expected Result: Employee data is retrieved and mapped correctly
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('In Progress', { timeout: 5000 });
    
    // Monitor the synchronization process until completion
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('Completed', { timeout: 60000 });
    await expect(page.locator('[data-testid="sync-success-message"]')).toBeVisible();

    // Verify the synchronized employee data in the platform database
    await page.click('[data-testid="view-synced-data"]');
    await expect(page.locator('[data-testid="employee-data-table"]')).toBeVisible();
    const employeeCount = await page.locator('[data-testid="employee-row"]').count();
    expect(employeeCount).toBeGreaterThan(0);

    // Navigate to the logs section and filter for connection and data transfer events
    await page.click('[data-testid="logs-section"]');
    await page.selectOption('[data-testid="log-filter"]', 'connection');
    
    // Expected Result: Logs show successful connection and data sync events
    await expect(page.locator('[data-testid="log-entry"]').filter({ hasText: 'Connection established' })).toBeVisible();
    await expect(page.locator('[data-testid="log-entry"]').filter({ hasText: 'Data sync completed' })).toBeVisible();
    await expect(page.locator('[data-testid="log-timestamp"]').first()).toBeVisible();
  });

  test('Verify retry mechanism on transient API failure (edge-case)', async ({ page }) => {
    // Configure network simulation tool to introduce transient network failure during API call
    await page.route('**/api/hr/employees', async (route) => {
      const requestCount = await page.evaluate(() => {
        if (!window['apiRequestCount']) window['apiRequestCount'] = 0;
        return ++window['apiRequestCount'];
      });
      
      // Fail first 2 attempts, succeed on 3rd
      if (requestCount <= 2) {
        await route.abort('failed');
      } else {
        await route.continue();
      }
    });

    // Navigate to HR system API configuration
    await page.click('[data-testid="hr-system-config"]');
    await page.fill('[data-testid="api-key-input"]', VALID_API_KEY);
    await page.fill('[data-testid="oauth-token-input"]', VALID_OAUTH_TOKEN);
    await page.click('[data-testid="save-config-button"]');

    // Initiate data synchronization from the integration console
    await page.click('[data-testid="data-sync-section"]');
    await page.click('[data-testid="trigger-sync-button"]');

    // Expected Result: System retries connection automatically
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('Retrying', { timeout: 10000 });
    
    // Observe system behavior after initial failure and allow retry attempts
    await page.waitForTimeout(2000);
    
    // Expected Result: System completes data synchronization successfully after retries
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('Completed', { timeout: 60000 });
    await expect(page.locator('[data-testid="sync-success-message"]')).toBeVisible();

    // Verify synchronized data integrity in platform database
    await page.click('[data-testid="view-synced-data"]');
    await expect(page.locator('[data-testid="employee-data-table"]')).toBeVisible();

    // Navigate to logs section and review connection attempt records
    await page.click('[data-testid="logs-section"]');
    await page.selectOption('[data-testid="log-filter"]', 'all');
    
    // Expected Result: Logs show retry attempts and final success
    const retryLogs = page.locator('[data-testid="log-entry"]').filter({ hasText: 'Retry attempt' });
    const retryCount = await retryLogs.count();
    expect(retryCount).toBeGreaterThanOrEqual(1);
    expect(retryCount).toBeLessThanOrEqual(3);
    
    await expect(page.locator('[data-testid="log-entry"]').filter({ hasText: 'Connection established' })).toBeVisible();
    await expect(page.locator('[data-testid="log-entry"]').filter({ hasText: 'Data sync completed' })).toBeVisible();
  });

  test('Test handling of invalid API credentials (error-case)', async ({ page }) => {
    // Navigate to the integration console and locate the HR system API configuration section
    await page.click('[data-testid="hr-system-config"]');
    await expect(page.locator('[data-testid="api-configuration-section"]')).toBeVisible();

    // Enter invalid API credentials (incorrect API key or malformed OAuth token) in the credential fields
    await page.fill('[data-testid="api-key-input"]', INVALID_API_KEY);
    await page.fill('[data-testid="oauth-token-input"]', INVALID_OAUTH_TOKEN);

    // Click the 'Test Connection' or 'Authenticate' button
    await page.click('[data-testid="test-connection-button"]');

    // Expected Result: System rejects credentials and displays error message
    await expect(page.locator('[data-testid="connection-error-message"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="connection-error-message"]')).toContainText('Invalid credentials');
    await expect(page.locator('[data-testid="connection-status"]')).toContainText('Failed');

    // Observe the authentication response
    await expect(page.locator('[data-testid="authentication-failed-indicator"]')).toBeVisible();

    // Expected Result: Connection is not established
    await expect(page.locator('[data-testid="connection-status"]')).not.toContainText('Connected');

    // Attempt to save the configuration with invalid credentials
    await page.click('[data-testid="save-config-button"]');
    await expect(page.locator('[data-testid="save-error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="save-error-message"]')).toContainText('Cannot save invalid configuration');

    // Attempt to trigger data synchronization with invalid credentials
    await page.click('[data-testid="data-sync-section"]');
    const syncButton = page.locator('[data-testid="trigger-sync-button"]');
    
    if (await syncButton.isEnabled()) {
      await syncButton.click();
      await expect(page.locator('[data-testid="sync-error-message"]')).toBeVisible();
      await expect(page.locator('[data-testid="sync-error-message"]')).toContainText('Authentication failed');
    } else {
      await expect(syncButton).toBeDisabled();
    }

    // Navigate to the error logs section and search for authentication failure events
    await page.click('[data-testid="logs-section"]');
    await page.selectOption('[data-testid="log-filter"]', 'error');
    await page.fill('[data-testid="log-search-input"]', 'authentication');
    await page.click('[data-testid="log-search-button"]');

    // Expected Result: Error details are recorded in logs with timestamp
    const errorLog = page.locator('[data-testid="log-entry"]').filter({ hasText: 'Authentication failed' }).first();
    await expect(errorLog).toBeVisible();
    await expect(errorLog.locator('[data-testid="log-timestamp"]')).toBeVisible();
    
    // Verify error log contains sufficient detail for troubleshooting
    await errorLog.click();
    await expect(page.locator('[data-testid="log-detail-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-detail-error-code"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-detail-error-message"]')).toContainText('Invalid credentials');
    await expect(page.locator('[data-testid="log-detail-timestamp"]')).toBeVisible();
  });
});