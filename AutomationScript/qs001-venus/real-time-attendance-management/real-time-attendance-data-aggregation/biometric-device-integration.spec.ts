import { test, expect } from '@playwright/test';

test.describe('Biometric Device Integration - Story 13', () => {
  const ADMIN_URL = process.env.ADMIN_URL || 'https://attendance-admin.example.com';
  const BIOMETRIC_API_ENDPOINT = 'https://biometric-device.example.com/api';
  const TEST_DEVICE_ID = 'BIO-DEVICE-001';
  const TEST_EMPLOYEE_ID = 'EMP-12345';
  
  test.beforeEach(async ({ page }) => {
    // Login as administrator
    await page.goto(`${ADMIN_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'admin@example.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="admin-dashboard"]')).toBeVisible({ timeout: 10000 });
  });

  test('Validate successful connection and data reception from biometric devices', async ({ page }) => {
    // Navigate to biometric device configuration section
    await page.click('[data-testid="settings-menu"]');
    await page.click('[data-testid="biometric-devices-link"]');
    await expect(page.locator('[data-testid="biometric-config-page"]')).toBeVisible();

    // Enter biometric device configuration
    await page.fill('[data-testid="device-api-endpoint"]', BIOMETRIC_API_ENDPOINT);
    await page.fill('[data-testid="device-auth-username"]', 'device_admin');
    await page.fill('[data-testid="device-auth-password"]', 'DevicePass123');
    await page.fill('[data-testid="device-identifier"]', TEST_DEVICE_ID);

    // Test connection
    await page.click('[data-testid="test-connection-button"]');
    await expect(page.locator('[data-testid="connection-status"]')).toContainText('Connected', { timeout: 15000 });
    await expect(page.locator('[data-testid="connection-indicator"]')).toHaveClass(/success|connected/);

    // Save configuration
    await page.click('[data-testid="save-device-config-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Configuration saved successfully');

    // Navigate to dashboard to monitor real-time data
    await page.click('[data-testid="dashboard-link"]');
    await expect(page.locator('[data-testid="realtime-feed"]')).toBeVisible();

    // Record timestamp before simulating event
    const eventTimestamp = new Date();

    // Simulate attendance event (via API call in real scenario, here we mock the UI update)
    await page.evaluate(async (data) => {
      await fetch('/api/test/simulate-biometric-event', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          deviceId: data.deviceId,
          employeeId: data.employeeId,
          timestamp: data.timestamp,
          eventType: 'check-in'
        })
      });
    }, { deviceId: TEST_DEVICE_ID, employeeId: TEST_EMPLOYEE_ID, timestamp: eventTimestamp.toISOString() });

    // Monitor dashboard for attendance event within 1 minute
    await expect(page.locator(`[data-testid="attendance-event-${TEST_EMPLOYEE_ID}"]`)).toBeVisible({ timeout: 60000 });
    await expect(page.locator(`[data-testid="attendance-event-${TEST_EMPLOYEE_ID}"]`)).toContainText(TEST_EMPLOYEE_ID);

    // Navigate to attendance database query interface
    await page.click('[data-testid="attendance-records-link"]');
    await page.fill('[data-testid="search-employee-id"]', TEST_EMPLOYEE_ID);
    await page.click('[data-testid="search-button"]');

    // Verify event data in database
    const latestRecord = page.locator('[data-testid="attendance-record-row"]').first();
    await expect(latestRecord).toBeVisible();
    await expect(latestRecord.locator('[data-testid="employee-id"]')).toContainText(TEST_EMPLOYEE_ID);
    await expect(latestRecord.locator('[data-testid="device-id"]')).toContainText(TEST_DEVICE_ID);
    await expect(latestRecord.locator('[data-testid="event-type"]')).toContainText('check-in');

    // Verify timestamp is within 1 minute of event occurrence
    const recordTimestamp = await latestRecord.locator('[data-testid="timestamp"]').textContent();
    const recordDate = new Date(recordTimestamp || '');
    const timeDifference = Math.abs(recordDate.getTime() - eventTimestamp.getTime());
    expect(timeDifference).toBeLessThan(60000); // Less than 1 minute
  });

  test('Verify system handles corrupted attendance data', async ({ page }) => {
    // Navigate to test data simulation tool
    await page.click('[data-testid="admin-tools-menu"]');
    await page.click('[data-testid="test-simulation-link"]');
    await expect(page.locator('[data-testid="test-simulation-page"]')).toBeVisible();

    // Prepare and send corrupted data with missing employee ID
    await page.click('[data-testid="manual-event-tab"]');
    await page.fill('[data-testid="device-id-input"]', TEST_DEVICE_ID);
    await page.fill('[data-testid="employee-id-input"]', ''); // Empty employee ID
    await page.fill('[data-testid="timestamp-input"]', new Date().toISOString());
    await page.selectOption('[data-testid="event-type-select"]', 'check-in');
    
    await page.click('[data-testid="send-test-event-button"]');

    // Verify error response
    await expect(page.locator('[data-testid="api-response-status"]')).toContainText('400', { timeout: 5000 });
    await expect(page.locator('[data-testid="api-response-message"]')).toContainText('Bad Request');

    // Navigate to system error logs
    await page.click('[data-testid="monitoring-menu"]');
    await page.click('[data-testid="error-logs-link"]');
    await expect(page.locator('[data-testid="error-logs-page"]')).toBeVisible();

    // Search for error entry
    await page.fill('[data-testid="log-search-input"]', 'missing employee ID');
    await page.click('[data-testid="search-logs-button"]');

    const errorLogEntry = page.locator('[data-testid="error-log-entry"]').first();
    await expect(errorLogEntry).toBeVisible({ timeout: 10000 });
    await expect(errorLogEntry).toContainText('missing employee ID');
    await expect(errorLogEntry).toContainText(TEST_DEVICE_ID);

    // Check admin dashboard for error notification
    await page.click('[data-testid="dashboard-link"]');
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="error-notification"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="error-notification"]').first()).toContainText('Invalid attendance data');

    // Query attendance database to verify no corrupted data stored
    await page.click('[data-testid="attendance-records-link"]');
    await page.fill('[data-testid="search-device-id"]', TEST_DEVICE_ID);
    await page.selectOption('[data-testid="filter-status"]', 'all');
    await page.click('[data-testid="search-button"]');

    const recordCount = await page.locator('[data-testid="total-records-count"]').textContent();
    const initialCount = parseInt(recordCount || '0');

    // Send additional corrupted data with invalid timestamp
    await page.click('[data-testid="admin-tools-menu"]');
    await page.click('[data-testid="test-simulation-link"]');
    await page.fill('[data-testid="device-id-input"]', TEST_DEVICE_ID);
    await page.fill('[data-testid="employee-id-input"]', TEST_EMPLOYEE_ID);
    await page.fill('[data-testid="timestamp-input"]', 'invalid-timestamp-format');
    await page.click('[data-testid="send-test-event-button"]');
    await expect(page.locator('[data-testid="api-response-status"]')).toContainText('400');

    // Verify database integrity - record count should not increase
    await page.click('[data-testid="attendance-records-link"]');
    await page.fill('[data-testid="search-device-id"]', TEST_DEVICE_ID);
    await page.click('[data-testid="search-button"]');
    
    const updatedRecordCount = await page.locator('[data-testid="total-records-count"]').textContent();
    const finalCount = parseInt(updatedRecordCount || '0');
    expect(finalCount).toBe(initialCount);

    // Verify only valid records exist
    const allRecords = page.locator('[data-testid="attendance-record-row"]');
    const count = await allRecords.count();
    for (let i = 0; i < count; i++) {
      const record = allRecords.nth(i);
      await expect(record.locator('[data-testid="employee-id"]')).not.toBeEmpty();
      await expect(record.locator('[data-testid="timestamp"]')).not.toBeEmpty();
    }
  });

  test('Test device disconnection and automatic reconnection', async ({ page }) => {
    // Navigate to biometric device monitoring dashboard
    await page.click('[data-testid="monitoring-menu"]');
    await page.click('[data-testid="device-status-link"]');
    await expect(page.locator('[data-testid="device-status-page"]')).toBeVisible();

    // Verify device status shows Connected
    const deviceStatus = page.locator(`[data-testid="device-status-${TEST_DEVICE_ID}"]`);
    await expect(deviceStatus).toContainText('Connected');
    await expect(deviceStatus.locator('[data-testid="status-indicator"]')).toHaveClass(/green|success|connected/);

    // Note current timestamp and event count
    const initialEventCount = await page.locator('[data-testid="total-events-count"]').textContent();
    const disconnectionTimestamp = new Date();

    // Simulate device disconnection
    await page.click('[data-testid="admin-tools-menu"]');
    await page.click('[data-testid="device-simulation-link"]');
    await page.selectOption('[data-testid="device-select"]', TEST_DEVICE_ID);
    await page.click('[data-testid="simulate-disconnect-button"]');
    await expect(page.locator('[data-testid="simulation-status"]')).toContainText('Device disconnected');

    // Monitor dashboard for status change
    await page.click('[data-testid="monitoring-menu"]');
    await page.click('[data-testid="device-status-link"]');
    
    await expect(deviceStatus).toContainText('Disconnected', { timeout: 15000 });
    await expect(deviceStatus.locator('[data-testid="status-indicator"]')).toHaveClass(/red|error|disconnected/);

    // Check for admin alert notification
    await page.click('[data-testid="notifications-icon"]');
    const disconnectAlert = page.locator('[data-testid="alert-notification"]').filter({ hasText: 'disconnected' }).first();
    await expect(disconnectAlert).toBeVisible();
    await expect(disconnectAlert).toContainText(TEST_DEVICE_ID);

    // Verify system logs contain disconnection event
    await page.click('[data-testid="monitoring-menu"]');
    await page.click('[data-testid="system-logs-link"]');
    await page.fill('[data-testid="log-search-input"]', `${TEST_DEVICE_ID} disconnection`);
    await page.click('[data-testid="search-logs-button"]');
    
    const disconnectLogEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(disconnectLogEntry).toBeVisible();
    await expect(disconnectLogEntry).toContainText('disconnection');
    await expect(disconnectLogEntry).toContainText(TEST_DEVICE_ID);

    // Wait for 2 minutes to observe system behavior during disconnection
    await page.waitForTimeout(120000);

    // Restore device connection
    await page.click('[data-testid="admin-tools-menu"]');
    await page.click('[data-testid="device-simulation-link"]');
    await page.selectOption('[data-testid="device-select"]', TEST_DEVICE_ID);
    await page.click('[data-testid="simulate-reconnect-button"]');
    await expect(page.locator('[data-testid="simulation-status"]')).toContainText('Device reconnected');

    // Monitor dashboard for automatic reconnection
    await page.click('[data-testid="monitoring-menu"]');
    await page.click('[data-testid="device-status-link"]');
    
    await expect(deviceStatus).toContainText('Connected', { timeout: 30000 });
    await expect(deviceStatus.locator('[data-testid="status-indicator"]')).toHaveClass(/green|success|connected/);

    // Check for reconnection success notification
    await page.click('[data-testid="notifications-icon"]');
    const reconnectNotification = page.locator('[data-testid="success-notification"]').filter({ hasText: 'reconnected' }).first();
    await expect(reconnectNotification).toBeVisible();
    await expect(reconnectNotification).toContainText(TEST_DEVICE_ID);

    // Simulate new attendance event on reconnected device
    const reconnectTimestamp = new Date();
    await page.evaluate(async (data) => {
      await fetch('/api/test/simulate-biometric-event', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          deviceId: data.deviceId,
          employeeId: data.employeeId,
          timestamp: data.timestamp,
          eventType: 'check-out'
        })
      });
    }, { deviceId: TEST_DEVICE_ID, employeeId: TEST_EMPLOYEE_ID, timestamp: reconnectTimestamp.toISOString() });

    // Verify new event is received and stored within 1 minute
    await page.click('[data-testid="dashboard-link"]');
    await expect(page.locator('[data-testid="realtime-feed"]')).toBeVisible();
    await expect(page.locator(`[data-testid="attendance-event-${TEST_EMPLOYEE_ID}"]`).filter({ hasText: 'check-out' })).toBeVisible({ timeout: 60000 });

    // Verify in database
    await page.click('[data-testid="attendance-records-link"]');
    await page.fill('[data-testid="search-employee-id"]', TEST_EMPLOYEE_ID);
    await page.click('[data-testid="search-button"]');
    
    const latestRecord = page.locator('[data-testid="attendance-record-row"]').first();
    await expect(latestRecord.locator('[data-testid="event-type"]')).toContainText('check-out');

    // Review system logs for disconnection period
    await page.click('[data-testid="monitoring-menu"]');
    await page.click('[data-testid="system-logs-link"]');
    await page.fill('[data-testid="log-search-input"]', TEST_DEVICE_ID);
    await page.selectOption('[data-testid="log-level-filter"]', 'all');
    await page.click('[data-testid="search-logs-button"]');

    // Verify disconnection period is logged
    const disconnectionPeriodLog = page.locator('[data-testid="log-entry"]').filter({ hasText: 'disconnection period' });
    await expect(disconnectionPeriodLog).toBeVisible();

    // Verify no data loss - system properly logged and resumed
    const reconnectionLog = page.locator('[data-testid="log-entry"]').filter({ hasText: 'resumed normal operation' });
    await expect(reconnectionLog).toBeVisible();
    await expect(reconnectionLog).toContainText(TEST_DEVICE_ID);
  });
});