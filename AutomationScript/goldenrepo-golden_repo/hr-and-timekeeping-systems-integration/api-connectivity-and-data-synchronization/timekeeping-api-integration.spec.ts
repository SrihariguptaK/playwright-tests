import { test, expect } from '@playwright/test';

test.describe('Timekeeping API Integration - Story 14', () => {
  const BASE_URL = process.env.BASE_URL || 'https://app.example.com';
  const VALID_API_TOKEN = process.env.TIMEKEEPING_API_TOKEN || 'valid_test_token_12345';
  const INVALID_API_TOKEN = 'invalid_token_xyz';

  test.beforeEach(async ({ page }) => {
    // Navigate to integration console
    await page.goto(`${BASE_URL}/integration/console`);
    await expect(page).toHaveTitle(/Integration Console/);
  });

  test('Validate successful connection and time log retrieval (happy-path)', async ({ page }) => {
    // Navigate to the integration console and locate the timekeeping system API configuration section
    await page.click('[data-testid="timekeeping-systems-tab"]');
    await expect(page.locator('[data-testid="api-configuration-section"]')).toBeVisible();

    // Enter valid timekeeping API credentials
    await page.fill('[data-testid="api-token-input"]', VALID_API_TOKEN);
    await page.fill('[data-testid="api-endpoint-input"]', 'https://api.timekeeping.example.com/v1');

    // Click the 'Test Connection' or 'Authenticate' button
    await page.click('[data-testid="test-connection-button"]');

    // Expected Result: System authenticates and connects successfully
    await expect(page.locator('[data-testid="connection-status"]')).toContainText('Connected', { timeout: 10000 });
    await expect(page.locator('[data-testid="authentication-success-message"]')).toBeVisible();

    // Save the timekeeping API configuration settings
    await page.click('[data-testid="save-configuration-button"]');
    await expect(page.locator('[data-testid="save-success-notification"]')).toContainText('Configuration saved successfully');

    // Navigate to the time log synchronization section
    await page.click('[data-testid="time-log-sync-tab"]');
    await expect(page.locator('[data-testid="sync-section"]')).toBeVisible();

    // Click 'Trigger Sync' or 'Start Time Log Synchronization' button
    await page.click('[data-testid="trigger-sync-button"]');

    // Expected Result: Time log data is retrieved and mapped correctly
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('In Progress', { timeout: 5000 });
    
    // Monitor the synchronization process until completion
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('Completed', { timeout: 60000 });
    await expect(page.locator('[data-testid="sync-records-count"]')).not.toBeEmpty();

    // Verify the synchronized time log data in the platform database
    await page.click('[data-testid="view-synced-data-button"]');
    await expect(page.locator('[data-testid="time-log-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="time-log-row"]').first()).toBeVisible();

    // Navigate to the synchronization logs section
    await page.click('[data-testid="sync-logs-tab"]');
    await page.selectOption('[data-testid="log-filter-dropdown"]', 'time-log-sync');

    // Expected Result: Logs show successful sync with timestamps
    await expect(page.locator('[data-testid="log-entry"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="log-entry"]').first()).toContainText('Success');
    await expect(page.locator('[data-testid="log-timestamp"]').first()).not.toBeEmpty();

    // Verify sync status display in the integration console
    await page.click('[data-testid="integration-console-home"]');
    await expect(page.locator('[data-testid="timekeeping-sync-status"]')).toContainText('Last sync: Success');
  });

  test('Test conflict resolution during time log synchronization (edge-case)', async ({ page }) => {
    // Verify that conflicting time log entries exist in the source timekeeping system
    await page.click('[data-testid="timekeeping-systems-tab"]');
    await page.click('[data-testid="test-data-setup-button"]');
    await page.check('[data-testid="simulate-conflicts-checkbox"]');
    await page.click('[data-testid="apply-test-data-button"]');
    await expect(page.locator('[data-testid="test-data-confirmation"]')).toContainText('Conflicting entries created');

    // Review the predefined conflict resolution rules
    await page.click('[data-testid="conflict-resolution-settings"]');
    await expect(page.locator('[data-testid="resolution-rule-display"]')).toContainText('latest timestamp wins');
    const resolutionRule = await page.locator('[data-testid="active-resolution-rule"]').textContent();
    expect(resolutionRule).toBeTruthy();

    // Initiate time log synchronization from the integration console
    await page.click('[data-testid="time-log-sync-tab"]');
    await page.click('[data-testid="trigger-sync-button"]');

    // Expected Result: System detects conflicts during sync
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('In Progress', { timeout: 5000 });
    await expect(page.locator('[data-testid="conflicts-detected-indicator"]')).toBeVisible({ timeout: 15000 });
    const conflictCount = await page.locator('[data-testid="conflict-count"]').textContent();
    expect(parseInt(conflictCount || '0')).toBeGreaterThan(0);

    // Observe the automatic application of predefined conflict resolution rules
    await expect(page.locator('[data-testid="conflict-resolution-status"]')).toContainText('Applying resolution rules');

    // Expected Result: Conflicts resolved according to rules without data loss
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('Completed', { timeout: 60000 });
    await expect(page.locator('[data-testid="conflicts-resolved-count"]')).not.toBeEmpty();

    // Verify the final synchronized time log data in the platform database
    await page.click('[data-testid="view-synced-data-button"]');
    await expect(page.locator('[data-testid="time-log-table"]')).toBeVisible();
    const recordCount = await page.locator('[data-testid="time-log-row"]').count();
    expect(recordCount).toBeGreaterThan(0);

    // Review specific conflicting records to confirm correct resolution
    await page.click('[data-testid="filter-resolved-conflicts"]');
    await expect(page.locator('[data-testid="resolved-conflict-row"]').first()).toBeVisible();
    await page.click('[data-testid="resolved-conflict-row"]').first();
    await expect(page.locator('[data-testid="resolution-details"]')).toContainText('Resolved by: latest timestamp wins');

    // Navigate to synchronization logs and review conflict resolution events
    await page.click('[data-testid="sync-logs-tab"]');
    await page.selectOption('[data-testid="log-filter-dropdown"]', 'conflict-resolution');
    await expect(page.locator('[data-testid="log-entry"]').first()).toContainText('Conflict resolved');

    // Expected Result: Data reflects resolved conflicts accurately
    // Verify no time log data was lost during conflict resolution
    await expect(page.locator('[data-testid="data-loss-indicator"]')).toContainText('0 records lost');
    await expect(page.locator('[data-testid="sync-summary"]')).toContainText('All conflicts resolved successfully');
  });

  test('Verify handling of invalid API credentials (error-case)', async ({ page }) => {
    // Navigate to the integration console and locate the timekeeping system API configuration section
    await page.click('[data-testid="timekeeping-systems-tab"]');
    await expect(page.locator('[data-testid="api-configuration-section"]')).toBeVisible();

    // Enter invalid timekeeping API credentials
    await page.fill('[data-testid="api-token-input"]', INVALID_API_TOKEN);
    await page.fill('[data-testid="api-endpoint-input"]', 'https://api.timekeeping.example.com/v1');

    // Click the 'Test Connection' or 'Authenticate' button
    await page.click('[data-testid="test-connection-button"]');

    // Expected Result: System rejects credentials and displays error
    await expect(page.locator('[data-testid="connection-status"]')).toContainText('Failed', { timeout: 10000 });
    await expect(page.locator('[data-testid="authentication-error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="authentication-error-message"]')).toContainText('Invalid credentials');

    // Verify that no connection is established to the timekeeping system
    await expect(page.locator('[data-testid="connection-indicator"]')).toHaveClass(/disconnected/);

    // Attempt to save the configuration with invalid credentials
    await page.click('[data-testid="save-configuration-button"]');
    await expect(page.locator('[data-testid="save-error-notification"]')).toContainText('Cannot save invalid configuration');

    // Attempt to trigger time log synchronization with invalid credentials
    await page.click('[data-testid="time-log-sync-tab"]');
    await page.click('[data-testid="trigger-sync-button"]');

    // Expected Result: Synchronization does not proceed
    await expect(page.locator('[data-testid="sync-error-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="sync-error-message"]')).toContainText('Authentication required');
    await expect(page.locator('[data-testid="sync-status"]')).not.toContainText('In Progress');

    // Navigate to the error logs section and search for authentication failure events
    await page.click('[data-testid="error-logs-tab"]');
    await page.fill('[data-testid="log-search-input"]', 'authentication failure');
    await page.click('[data-testid="search-logs-button"]');

    // Expected Result: Error details are recorded with timestamps
    await expect(page.locator('[data-testid="error-log-entry"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="error-log-entry"]').first()).toContainText('Authentication failed');
    await expect(page.locator('[data-testid="error-log-entry"]').first()).toContainText('Invalid credentials');
    
    // Verify error log contains complete details with timestamp
    const errorLogTimestamp = await page.locator('[data-testid="error-log-timestamp"]').first().textContent();
    expect(errorLogTimestamp).toBeTruthy();
    expect(errorLogTimestamp).toMatch(/\d{4}-\d{2}-\d{2}/);

    // Confirm no time log data was accessed or synchronized
    await page.click('[data-testid="time-log-sync-tab"]');
    await expect(page.locator('[data-testid="last-sync-status"]')).toContainText('Never synced');
    const syncRecordCount = await page.locator('[data-testid="sync-records-count"]').textContent();
    expect(syncRecordCount).toBe('0');
  });
});