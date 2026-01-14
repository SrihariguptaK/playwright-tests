import { test, expect } from '@playwright/test';

test.describe('Biometric Device Monitoring', () => {
  const technicianCredentials = {
    username: 'technician@company.com',
    password: 'TechPass123!'
  };

  const unauthorizedCredentials = {
    username: 'employee@company.com',
    password: 'EmpPass123!'
  };

  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const TEST_DEVICE_ID = 'device-001';

  test('Display real-time device connectivity status (happy-path)', async ({ page }) => {
    // Navigate to the login page and enter valid Biometric Device Technician credentials
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', technicianCredentials.username);
    await page.fill('[data-testid="password-input"]', technicianCredentials.password);
    await page.click('[data-testid="login-button"]');

    // Verify access to monitoring dashboard is granted
    await expect(page).toHaveURL(/.*\/monitoring-dashboard/);
    await expect(page.locator('[data-testid="monitoring-dashboard"]')).toBeVisible();

    // View the list of all biometric devices on the monitoring dashboard
    await expect(page.locator('[data-testid="devices-list"]')).toBeVisible();
    const devicesList = page.locator('[data-testid="device-item"]');
    const devicesCount = await devicesList.count();
    expect(devicesCount).toBeGreaterThan(0);

    // Verify each device displays current connectivity status with appropriate visual indicators
    for (let i = 0; i < devicesCount; i++) {
      const device = devicesList.nth(i);
      await expect(device.locator('[data-testid="device-status-indicator"]')).toBeVisible();
      const statusText = await device.locator('[data-testid="device-status-text"]').textContent();
      expect(['Online', 'Offline', 'Warning']).toContain(statusText);
    }

    // Note the current timestamp and status of a specific test device
    const testDevice = page.locator(`[data-testid="device-item-${TEST_DEVICE_ID}"]`);
    await expect(testDevice).toBeVisible();
    const initialStatus = await testDevice.locator('[data-testid="device-status-text"]').textContent();
    const initialTimestamp = await testDevice.locator('[data-testid="device-last-update"]').textContent();
    expect(initialStatus).toBe('Online');

    // Simulate device disconnection by disconnecting the test device from network
    await page.click(`[data-testid="device-actions-${TEST_DEVICE_ID}"]`);
    await page.click('[data-testid="simulate-disconnect"]');
    await page.click('[data-testid="confirm-simulate"]');

    // Monitor the dashboard and wait for status update (maximum 1 minute)
    await expect(testDevice.locator('[data-testid="device-status-text"]')).toHaveText('Offline', { timeout: 60000 });

    // Verify alert notification appears for the disconnected device
    const alertNotification = page.locator('[data-testid="alert-notification"]');
    await expect(alertNotification).toBeVisible({ timeout: 60000 });
    await expect(alertNotification).toContainText(TEST_DEVICE_ID);
    await expect(alertNotification).toContainText('disconnected');

    // Reconnect the test device to the network
    await page.click(`[data-testid="device-actions-${TEST_DEVICE_ID}"]`);
    await page.click('[data-testid="simulate-reconnect"]');
    await page.click('[data-testid="confirm-simulate"]');

    // Monitor the dashboard for status update (maximum 1 minute)
    await expect(testDevice.locator('[data-testid="device-status-text"]')).toHaveText('Online', { timeout: 60000 });
    const updatedTimestamp = await testDevice.locator('[data-testid="device-last-update"]').textContent();
    expect(updatedTimestamp).not.toBe(initialTimestamp);
  });

  test('Generate alerts for device malfunctions (happy-path)', async ({ page }) => {
    // Login as technician
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', technicianCredentials.username);
    await page.fill('[data-testid="password-input"]', technicianCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*\/monitoring-dashboard/);

    // Access the device monitoring dashboard
    await expect(page.locator('[data-testid="monitoring-dashboard"]')).toBeVisible();

    // Verify the alerts panel shows no active alerts for the test device
    const alertsPanel = page.locator('[data-testid="alerts-panel"]');
    await expect(alertsPanel).toBeVisible();
    const deviceAlerts = page.locator(`[data-testid="alert-item-${TEST_DEVICE_ID}"]`);
    const initialAlertCount = await deviceAlerts.count();

    // Simulate device error condition (e.g., authentication failure, sensor malfunction, or data transmission error)
    await page.click(`[data-testid="device-actions-${TEST_DEVICE_ID}"]`);
    await page.click('[data-testid="simulate-error"]');
    await page.selectOption('[data-testid="error-type-select"]', 'sensor-malfunction');
    await page.click('[data-testid="confirm-simulate"]');

    // Monitor the dashboard for alert generation (maximum 1 minute)
    const newAlert = page.locator(`[data-testid="alert-item-${TEST_DEVICE_ID}"]`).first();
    await expect(newAlert).toBeVisible({ timeout: 60000 });

    // Verify alert notification appears in the alerts panel
    await expect(newAlert).toContainText('sensor-malfunction');
    await expect(newAlert.locator('[data-testid="alert-status"]')).toHaveText('Active');

    // Click on the alert to view detailed information
    await newAlert.click();
    const alertDetails = page.locator('[data-testid="alert-details-modal"]');
    await expect(alertDetails).toBeVisible();
    await expect(alertDetails.locator('[data-testid="alert-device-id"]')).toContainText(TEST_DEVICE_ID);
    await expect(alertDetails.locator('[data-testid="alert-error-type"]')).toContainText('sensor-malfunction');
    await expect(alertDetails.locator('[data-testid="alert-timestamp"]')).toBeVisible();

    // Click 'Acknowledge Alert' button
    await page.click('[data-testid="acknowledge-alert-button"]');

    // Confirm alert acknowledgement
    await page.click('[data-testid="confirm-acknowledge-button"]');

    // Verify alert remains visible but marked as acknowledged
    await expect(newAlert.locator('[data-testid="alert-status"]')).toHaveText('Acknowledged', { timeout: 5000 });
    await expect(newAlert).toBeVisible();

    // Check alert history log
    await page.click('[data-testid="alert-history-tab"]');
    const alertHistory = page.locator('[data-testid="alert-history-list"]');
    await expect(alertHistory).toBeVisible();
    const historyEntry = alertHistory.locator(`[data-testid="history-entry-${TEST_DEVICE_ID}"]`).first();
    await expect(historyEntry).toBeVisible();
    await expect(historyEntry).toContainText('Acknowledged');
  });

  test('Restrict monitoring access to authorized technicians (error-case)', async ({ page, request }) => {
    // Navigate to the login page and enter credentials of an unauthorized user (non-technician role)
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', unauthorizedCredentials.username);
    await page.fill('[data-testid="password-input"]', unauthorizedCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*\/dashboard/);

    // Attempt to navigate to the biometric device monitoring dashboard URL directly
    await page.goto(`${BASE_URL}/monitoring-dashboard`);
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');

    // Verify monitoring dashboard menu option is not visible in navigation
    const navigationMenu = page.locator('[data-testid="navigation-menu"]');
    await expect(navigationMenu).toBeVisible();
    const monitoringMenuItem = navigationMenu.locator('[data-testid="monitoring-menu-item"]');
    await expect(monitoringMenuItem).not.toBeVisible();

    // Open browser developer tools and attempt to make direct API call to GET /api/biometric/devices/status endpoint using current session
    const unauthorizedApiResponse = await page.evaluate(async () => {
      const response = await fetch('/api/biometric/devices/status', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      });
      return {
        status: response.status,
        statusText: response.statusText
      };
    });
    expect(unauthorizedApiResponse.status).toBe(403);

    // Logout from the unauthorized user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*\/login/);

    // Login with valid Biometric Device Technician credentials
    await page.fill('[data-testid="username-input"]', technicianCredentials.username);
    await page.fill('[data-testid="password-input"]', technicianCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*\/monitoring-dashboard/);

    // Verify monitoring dashboard is accessible and displays device information
    await expect(page.locator('[data-testid="monitoring-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="devices-list"]')).toBeVisible();
    const devicesList = page.locator('[data-testid="device-item"]');
    const devicesCount = await devicesList.count();
    expect(devicesCount).toBeGreaterThan(0);

    // Verify device monitoring menu option is visible in navigation
    const techNavigationMenu = page.locator('[data-testid="navigation-menu"]');
    await expect(techNavigationMenu).toBeVisible();
    const techMonitoringMenuItem = techNavigationMenu.locator('[data-testid="monitoring-menu-item"]');
    await expect(techMonitoringMenuItem).toBeVisible();

    // Make API call to GET /api/biometric/devices/status endpoint using technician session
    const authorizedApiResponse = await page.evaluate(async () => {
      const response = await fetch('/api/biometric/devices/status', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      });
      return {
        status: response.status,
        data: await response.json()
      };
    });
    expect(authorizedApiResponse.status).toBe(200);
    expect(Array.isArray(authorizedApiResponse.data)).toBe(true);
    expect(authorizedApiResponse.data.length).toBeGreaterThan(0);
  });
});