import { test, expect } from '@playwright/test';

test.describe('Biometric Device Disconnection Handling', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as administrator
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'admin@biometric.com');
    await page.fill('[data-testid="password-input"]', 'Admin@123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Detect and retry biometric device disconnection', async ({ page }) => {
    // Navigate to biometric device management interface
    await page.click('[data-testid="device-management-menu"]');
    await expect(page.locator('[data-testid="device-management-page"]')).toBeVisible();
    
    // Verify target device shows 'Connected' status
    const targetDevice = page.locator('[data-testid="device-row-001"]');
    await expect(targetDevice.locator('[data-testid="device-status"]')).toHaveText('Connected');
    await expect(targetDevice.locator('[data-testid="status-indicator"]')).toHaveClass(/connected/);
    
    // Simulate device disconnection
    await page.click('[data-testid="device-row-001"] [data-testid="device-actions-menu"]');
    await page.click('[data-testid="simulate-disconnection"]');
    
    // Monitor system response - verify disconnection detected within 10 seconds
    const disconnectionTime = Date.now();
    await expect(targetDevice.locator('[data-testid="device-status"]')).toHaveText('Disconnected', { timeout: 10000 });
    const detectionTime = Date.now() - disconnectionTime;
    expect(detectionTime).toBeLessThanOrEqual(10000);
    
    // Verify disconnection notification appears
    await expect(page.locator('[data-testid="disconnection-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="disconnection-notification"]')).toContainText('Device 001 disconnected');
    
    // Observe automatic retry attempts over 2 minutes
    await page.waitForTimeout(35000); // Wait for first retry attempt (30 seconds + buffer)
    
    // Check device connection logs to verify retry attempts
    await page.click('[data-testid="device-row-001"] [data-testid="view-logs-button"]');
    await expect(page.locator('[data-testid="device-logs-modal"]')).toBeVisible();
    
    const retryLogEntries = page.locator('[data-testid="log-entry"]').filter({ hasText: 'Retry attempt' });
    await expect(retryLogEntries.first()).toBeVisible({ timeout: 5000 });
    
    // Verify retry attempts are being recorded every 30 seconds
    const firstRetryTime = await retryLogEntries.first().locator('[data-testid="log-timestamp"]').textContent();
    expect(firstRetryTime).toBeTruthy();
    
    await page.click('[data-testid="close-logs-modal"]');
    
    // Continue monitoring for 5 minutes to trigger administrator alert
    await page.waitForTimeout(270000); // Wait remaining time to reach 5 minutes total
    
    // Verify alert sent after 5 minutes of disconnection
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();
    
    const alertNotification = page.locator('[data-testid="alert-notification"]').filter({ hasText: 'Device 001' });
    await expect(alertNotification).toBeVisible();
    
    // Verify alert contains required information
    await expect(alertNotification).toContainText('Device 001');
    await expect(alertNotification).toContainText('Location');
    await expect(alertNotification).toContainText('Disconnection time');
    await expect(alertNotification).toContainText('recommended actions');
    
    // Close notifications panel
    await page.click('[data-testid="close-notifications"]');
    
    // Reconnect the device
    await page.click('[data-testid="device-row-001"] [data-testid="device-actions-menu"]');
    await page.click('[data-testid="simulate-reconnection"]');
    
    // Verify device status updates to 'Connected'
    await expect(targetDevice.locator('[data-testid="device-status"]')).toHaveText('Connected', { timeout: 15000 });
    await expect(targetDevice.locator('[data-testid="status-indicator"]')).toHaveClass(/connected/);
    
    // Verify reconnection event is logged
    await page.click('[data-testid="device-row-001"] [data-testid="view-logs-button"]');
    await expect(page.locator('[data-testid="device-logs-modal"]')).toBeVisible();
    
    const reconnectionLogEntry = page.locator('[data-testid="log-entry"]').filter({ hasText: 'Reconnection successful' });
    await expect(reconnectionLogEntry.first()).toBeVisible();
    
    await page.click('[data-testid="close-logs-modal"]');
  });

  test('View real-time device status on dashboard', async ({ page }) => {
    // Navigate to Device Status Dashboard
    await page.click('[data-testid="device-management-menu"]');
    await page.click('text=Device Status Dashboard');
    await expect(page.locator('[data-testid="device-status-dashboard"]')).toBeVisible();
    
    // Verify dashboard layout and all registered devices are displayed
    const deviceRows = page.locator('[data-testid^="device-row-"]');
    await expect(deviceRows).toHaveCount(await deviceRows.count(), { timeout: 5000 });
    expect(await deviceRows.count()).toBeGreaterThan(0);
    
    // Check each device entry for required information
    const firstDevice = deviceRows.first();
    await expect(firstDevice.locator('[data-testid="device-name"]')).toBeVisible();
    await expect(firstDevice.locator('[data-testid="device-location"]')).toBeVisible();
    await expect(firstDevice.locator('[data-testid="device-status"]')).toBeVisible();
    await expect(firstDevice.locator('[data-testid="last-activity-timestamp"]')).toBeVisible();
    
    // Identify a currently connected device
    const connectedDevice = page.locator('[data-testid="device-row-002"]');
    await expect(connectedDevice.locator('[data-testid="device-status"]')).toHaveText('Connected');
    await expect(connectedDevice.locator('[data-testid="status-indicator"]')).toHaveClass(/green|connected/);
    
    const initialDeviceName = await connectedDevice.locator('[data-testid="device-name"]').textContent();
    const initialTimestamp = await connectedDevice.locator('[data-testid="last-activity-timestamp"]').textContent();
    
    // Simulate device disconnection
    await page.click('[data-testid="device-row-002"] [data-testid="device-actions-menu"]');
    await page.click('[data-testid="simulate-disconnection"]');
    
    // Monitor dashboard for automatic status updates without refreshing
    await expect(connectedDevice.locator('[data-testid="device-status"]')).toHaveText('Disconnected', { timeout: 15000 });
    await expect(connectedDevice.locator('[data-testid="status-indicator"]')).toHaveClass(/red|disconnected/);
    
    // Verify disconnection timestamp is displayed and updates in real-time
    const disconnectionTimestamp = connectedDevice.locator('[data-testid="disconnection-timestamp"]');
    await expect(disconnectionTimestamp).toBeVisible();
    const disconnectionTime = await disconnectionTimestamp.textContent();
    expect(disconnectionTime).toBeTruthy();
    expect(disconnectionTime).not.toBe(initialTimestamp);
    
    // Reconnect the device
    await page.click('[data-testid="device-row-002"] [data-testid="device-actions-menu"]');
    await page.click('[data-testid="simulate-reconnection"]');
    
    // Observe dashboard for automatic status update to reflect reconnection
    await expect(connectedDevice.locator('[data-testid="device-status"]')).toHaveText('Connected', { timeout: 15000 });
    await expect(connectedDevice.locator('[data-testid="status-indicator"]')).toHaveClass(/green|connected/);
    
    // Verify reconnection timestamp and current heartbeat status
    const reconnectionTimestamp = connectedDevice.locator('[data-testid="last-activity-timestamp"]');
    await expect(reconnectionTimestamp).toBeVisible();
    const reconnectionTime = await reconnectionTimestamp.textContent();
    expect(reconnectionTime).toBeTruthy();
    expect(reconnectionTime).not.toBe(disconnectionTime);
    
    // Verify heartbeat status
    const heartbeatStatus = connectedDevice.locator('[data-testid="heartbeat-status"]');
    await expect(heartbeatStatus).toBeVisible();
    await expect(heartbeatStatus).toHaveClass(/active|healthy/);
    
    // Check additional dashboard information
    await expect(connectedDevice.locator('[data-testid="connection-uptime"]')).toBeVisible();
    await expect(connectedDevice.locator('[data-testid="total-disconnection-events"]')).toBeVisible();
    await expect(connectedDevice.locator('[data-testid="device-health-metrics"]')).toBeVisible();
    
    // Verify device health metrics display
    const healthMetrics = connectedDevice.locator('[data-testid="device-health-metrics"]');
    const healthMetricsText = await healthMetrics.textContent();
    expect(healthMetricsText).toContain('Health');
    
    // Verify total disconnection events counter has incremented
    const disconnectionEvents = connectedDevice.locator('[data-testid="total-disconnection-events"]');
    const eventsCount = await disconnectionEvents.textContent();
    expect(parseInt(eventsCount || '0')).toBeGreaterThan(0);
  });
});