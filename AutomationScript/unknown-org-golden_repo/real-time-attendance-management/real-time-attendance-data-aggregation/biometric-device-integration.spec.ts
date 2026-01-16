import { test, expect } from '@playwright/test';

test.describe('Biometric Device Integration', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const ADMIN_EMAIL = 'admin@company.com';
  const ADMIN_PASSWORD = 'Admin@123';

  test.beforeEach(async ({ page }) => {
    // Login as administrator
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('TC#1: Validate successful data retrieval from biometric device', async ({ page }) => {
    // Step 1: Configure biometric device connection settings
    await page.goto(`${BASE_URL}/admin/biometric-devices`);
    await page.click('[data-testid="add-device-button"]');
    
    await page.fill('[data-testid="device-name-input"]', 'Main Entrance Device');
    await page.fill('[data-testid="device-ip-input"]', '192.168.1.100');
    await page.fill('[data-testid="device-port-input"]', '4370');
    await page.fill('[data-testid="api-key-input"]', 'test-api-key-12345');
    await page.selectOption('[data-testid="device-type-select"]', 'ZKTeco');
    
    await page.click('[data-testid="save-device-button"]');
    
    // Expected Result: Settings saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Device settings saved successfully');
    await expect(page.locator('[data-testid="device-status"]')).toContainText('Connected');

    // Step 2: Trigger data polling service
    await page.click('[data-testid="trigger-polling-button"]');
    
    // Expected Result: Data retrieved from device without errors
    await page.waitForSelector('[data-testid="polling-status"]', { state: 'visible', timeout: 10000 });
    await expect(page.locator('[data-testid="polling-status"]')).toContainText('Data retrieval successful');
    await expect(page.locator('[data-testid="error-count"]')).toContainText('0');

    // Step 3: Verify data stored in attendance database
    await page.goto(`${BASE_URL}/admin/attendance-logs`);
    await page.click('[data-testid="refresh-logs-button"]');
    
    // Expected Result: Data matches device records and is timestamped correctly
    const firstLogEntry = page.locator('[data-testid="attendance-log-row"]').first();
    await expect(firstLogEntry).toBeVisible();
    
    const timestamp = await firstLogEntry.locator('[data-testid="log-timestamp"]').textContent();
    const currentTime = new Date();
    const logTime = new Date(timestamp || '');
    const timeDifference = Math.abs(currentTime.getTime() - logTime.getTime()) / 1000;
    
    expect(timeDifference).toBeLessThan(60); // Within 1 minute
    await expect(firstLogEntry.locator('[data-testid="employee-id"]')).not.toBeEmpty();
    await expect(firstLogEntry.locator('[data-testid="device-source"]')).toContainText('Main Entrance Device');
  });

  test('TC#2: Verify system handles corrupted data gracefully', async ({ page }) => {
    // Navigate to biometric device management
    await page.goto(`${BASE_URL}/admin/biometric-devices`);
    
    // Step 1: Simulate corrupted data from biometric device
    await page.click('[data-testid="device-actions-menu"]');
    await page.click('[data-testid="simulate-corrupted-data"]');
    
    await page.selectOption('[data-testid="corruption-type-select"]', 'invalid-timestamp');
    await page.click('[data-testid="send-corrupted-data-button"]');
    
    // Expected Result: System rejects data and logs error
    await page.waitForSelector('[data-testid="error-notification"]', { state: 'visible', timeout: 5000 });
    await expect(page.locator('[data-testid="error-notification"]')).toContainText('Data validation failed');
    
    // Navigate to error logs
    await page.goto(`${BASE_URL}/admin/system-logs`);
    await page.selectOption('[data-testid="log-type-filter"]', 'error');
    await page.click('[data-testid="apply-filter-button"]');
    
    const errorLog = page.locator('[data-testid="log-entry"]').first();
    await expect(errorLog).toContainText('Data validation failed');
    await expect(errorLog).toContainText('invalid-timestamp');

    // Step 2: Check administrator alert for data retrieval failure
    await page.goto(`${BASE_URL}/admin/alerts`);
    
    // Expected Result: Alert received with detailed error information
    const alert = page.locator('[data-testid="alert-item"]').first();
    await expect(alert).toBeVisible();
    await expect(alert.locator('[data-testid="alert-type"]')).toContainText('Data Retrieval Failure');
    await expect(alert.locator('[data-testid="alert-details"]')).toContainText('Corrupted data detected');
    await expect(alert.locator('[data-testid="alert-device"]')).toContainText('Main Entrance Device');

    // Step 3: Verify system retries connection automatically
    await page.goto(`${BASE_URL}/admin/biometric-devices`);
    await page.click('[data-testid="view-device-logs"]');
    
    // Expected Result: Retries occur up to 3 times before alerting
    const retryLogs = page.locator('[data-testid="retry-log-entry"]');
    await expect(retryLogs).toHaveCount(3);
    
    for (let i = 0; i < 3; i++) {
      const retryLog = retryLogs.nth(i);
      await expect(retryLog.locator('[data-testid="retry-attempt"]')).toContainText(`Attempt ${i + 1}`);
      await expect(retryLog.locator('[data-testid="retry-status"]')).toContainText('Failed');
    }
    
    await expect(page.locator('[data-testid="final-alert-sent"]')).toContainText('Administrator alerted after 3 failed attempts');
  });

  test('TC#3: Test retry mechanism on connection failure', async ({ page }) => {
    // Navigate to biometric device management
    await page.goto(`${BASE_URL}/admin/biometric-devices`);
    
    // Select existing device
    await page.click('[data-testid="device-row"]');
    
    // Step 1: Disconnect biometric device temporarily
    await page.click('[data-testid="device-actions-menu"]');
    await page.click('[data-testid="simulate-disconnect"]');
    await page.click('[data-testid="confirm-disconnect-button"]');
    
    // Expected Result: Connection failure detected
    await page.waitForSelector('[data-testid="connection-status"]', { state: 'visible', timeout: 5000 });
    await expect(page.locator('[data-testid="connection-status"]')).toContainText('Disconnected');
    await expect(page.locator('[data-testid="connection-error"]')).toContainText('Connection failure detected');

    // Step 2: Observe system retry attempts
    await page.click('[data-testid="view-retry-logs"]');
    
    // Expected Result: System retries 3 times with exponential backoff
    await page.waitForSelector('[data-testid="retry-log-entry"]', { state: 'visible', timeout: 15000 });
    
    const retryEntries = page.locator('[data-testid="retry-log-entry"]');
    await expect(retryEntries).toHaveCount(3);
    
    // Verify exponential backoff timing
    const retry1 = retryEntries.nth(0);
    const retry2 = retryEntries.nth(1);
    const retry3 = retryEntries.nth(2);
    
    await expect(retry1.locator('[data-testid="retry-delay"]')).toContainText('2 seconds');
    await expect(retry2.locator('[data-testid="retry-delay"]')).toContainText('4 seconds');
    await expect(retry3.locator('[data-testid="retry-delay"]')).toContainText('8 seconds');
    
    await expect(retry1.locator('[data-testid="retry-result"]')).toContainText('Failed');
    await expect(retry2.locator('[data-testid="retry-result"]')).toContainText('Failed');
    await expect(retry3.locator('[data-testid="retry-result"]')).toContainText('Failed');

    // Step 3: Reconnect device and verify data retrieval resumes
    await page.goto(`${BASE_URL}/admin/biometric-devices`);
    await page.click('[data-testid="device-actions-menu"]');
    await page.click('[data-testid="simulate-reconnect"]');
    await page.click('[data-testid="confirm-reconnect-button"]');
    
    // Expected Result: Data polling resumes successfully without manual intervention
    await page.waitForSelector('[data-testid="connection-status"]', { state: 'visible', timeout: 10000 });
    await expect(page.locator('[data-testid="connection-status"]')).toContainText('Connected');
    
    // Wait for automatic polling to resume
    await page.waitForTimeout(65000); // Wait for next polling cycle (60 seconds + buffer)
    
    await page.click('[data-testid="refresh-status-button"]');
    await expect(page.locator('[data-testid="last-poll-status"]')).toContainText('Success');
    await expect(page.locator('[data-testid="last-poll-time"]')).not.toBeEmpty();
    
    // Verify no manual intervention was required
    await page.goto(`${BASE_URL}/admin/system-logs`);
    await page.selectOption('[data-testid="log-type-filter"]', 'info');
    await page.fill('[data-testid="search-logs-input"]', 'automatic recovery');
    await page.click('[data-testid="search-button"]');
    
    const recoveryLog = page.locator('[data-testid="log-entry"]').first();
    await expect(recoveryLog).toContainText('Connection restored automatically');
    await expect(recoveryLog).toContainText('Data polling resumed');
  });
});