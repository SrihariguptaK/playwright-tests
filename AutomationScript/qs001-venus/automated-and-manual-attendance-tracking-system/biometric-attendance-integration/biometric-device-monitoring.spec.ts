import { test, expect } from '@playwright/test';

test.describe('Biometric Device Monitoring - Story 25', () => {
  const adminCredentials = {
    username: 'biometric.admin@company.com',
    password: 'Admin@123'
  };

  const nonAdminCredentials = {
    username: 'regular.employee@company.com',
    password: 'Employee@123'
  };

  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const apiBaseURL = process.env.API_BASE_URL || 'http://localhost:3000/api';

  test('Validate real-time device status display', async ({ page }) => {
    // Step 1: Login as biometric system administrator
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access granted to monitoring dashboard
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="user-role"]')).toContainText('Biometric System Administrator');

    // Navigate to monitoring dashboard
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="biometric-monitoring-link"]');
    await expect(page).toHaveURL(/.*biometric\/monitoring/);

    // Step 2: View device status panel
    await page.waitForSelector('[data-testid="device-status-panel"]', { timeout: 10000 });
    const deviceStatusPanel = page.locator('[data-testid="device-status-panel"]');
    await expect(deviceStatusPanel).toBeVisible();

    // Expected Result: All devices show current status accurately
    const deviceCards = page.locator('[data-testid="device-card"]');
    const deviceCount = await deviceCards.count();
    expect(deviceCount).toBeGreaterThan(0);

    // Verify each device has status information
    for (let i = 0; i < deviceCount; i++) {
      const deviceCard = deviceCards.nth(i);
      await expect(deviceCard.locator('[data-testid="device-name"]')).toBeVisible();
      await expect(deviceCard.locator('[data-testid="device-status"]')).toBeVisible();
      await expect(deviceCard.locator('[data-testid="device-last-sync"]')).toBeVisible();
    }

    // Observe real-time status updates by waiting for polling cycle
    const initialTimestamp = await page.locator('[data-testid="device-card"]').first().locator('[data-testid="device-last-sync"]').textContent();
    await page.waitForTimeout(65000); // Wait for next polling cycle (1 minute + buffer)
    const updatedTimestamp = await page.locator('[data-testid="device-card"]').first().locator('[data-testid="device-last-sync"]').textContent();
    expect(updatedTimestamp).not.toBe(initialTimestamp);

    // Step 3: Simulate device offline event
    // Using test control panel to simulate offline device
    await page.click('[data-testid="test-controls-toggle"]');
    await page.click('[data-testid="simulate-device-offline"]');
    await page.selectOption('[data-testid="device-selector"]', { index: 0 });
    await page.click('[data-testid="apply-simulation"]');

    // Expected Result: Alert notification is triggered and displayed
    await page.waitForSelector('[data-testid="alert-notification"]', { timeout: 70000 });
    const alertNotification = page.locator('[data-testid="alert-notification"]');
    await expect(alertNotification).toBeVisible();
    await expect(alertNotification).toContainText('Device Offline');
    await expect(alertNotification.locator('[data-testid="alert-severity"]')).toContainText('Error');

    // Verify device status shows offline
    const offlineDevice = page.locator('[data-testid="device-card"]').first();
    await expect(offlineDevice.locator('[data-testid="device-status"]')).toContainText('Offline');
    await expect(offlineDevice.locator('[data-testid="device-status-indicator"]')).toHaveClass(/offline|error/);

    // Reconnect device and observe status update
    await page.click('[data-testid="test-controls-toggle"]');
    await page.click('[data-testid="simulate-device-online"]');
    await page.selectOption('[data-testid="device-selector"]', { index: 0 });
    await page.click('[data-testid="apply-simulation"]');

    // Wait for device to come back online
    await page.waitForTimeout(65000);
    await expect(offlineDevice.locator('[data-testid="device-status"]')).toContainText('Online');
    await expect(offlineDevice.locator('[data-testid="device-status-indicator"]')).toHaveClass(/online|active/);
  });

  test('Verify access restriction to monitoring dashboard', async ({ page, request }) => {
    // Step 1: Login as non-administrator user
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', nonAdminCredentials.username);
    await page.fill('[data-testid="password-input"]', nonAdminCredentials.password);
    await page.click('[data-testid="login-button"]');

    // Expected Result: Access to monitoring dashboard is denied
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="user-role"]')).not.toContainText('Biometric System Administrator');

    // Attempt to navigate via menu
    await page.click('[data-testid="main-menu"]');
    const monitoringLink = page.locator('[data-testid="biometric-monitoring-link"]');
    await expect(monitoringLink).not.toBeVisible();

    // Attempt to access via direct URL
    await page.goto(`${baseURL}/biometric/monitoring`);
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    await expect(page).toHaveURL(/.*unauthorized|.*access-denied/);

    // Step 2: Attempt to access monitoring API endpoints
    const cookies = await page.context().cookies();
    const authCookie = cookies.find(c => c.name === 'auth_token' || c.name === 'session');
    
    const apiResponse = await request.get(`${apiBaseURL}/biometric/devices/status`, {
      headers: {
        'Cookie': authCookie ? `${authCookie.name}=${authCookie.value}` : ''
      }
    });

    // Expected Result: API returns unauthorized error
    expect(apiResponse.status()).toBe(401);
    const responseBody = await apiResponse.json();
    expect(responseBody.error).toMatch(/unauthorized|forbidden|access denied/i);

    // Verify no monitoring data is accessible
    await page.goto(`${baseURL}/dashboard`);
    const monitoringWidgets = page.locator('[data-testid="biometric-monitoring-widget"]');
    await expect(monitoringWidgets).not.toBeVisible();

    // Logout from non-administrator account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Login as Biometric System Administrator
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to monitoring dashboard
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="biometric-monitoring-link"]');
    await expect(page).toHaveURL(/.*biometric\/monitoring/);
    await expect(page.locator('[data-testid="device-status-panel"]')).toBeVisible();

    // Access monitoring API endpoint with admin credentials
    const adminCookies = await page.context().cookies();
    const adminAuthCookie = adminCookies.find(c => c.name === 'auth_token' || c.name === 'session');
    
    const adminApiResponse = await request.get(`${apiBaseURL}/biometric/devices/status`, {
      headers: {
        'Cookie': adminAuthCookie ? `${adminAuthCookie.name}=${adminAuthCookie.value}` : ''
      }
    });

    // Expected Result: API returns success with device data
    expect(adminApiResponse.status()).toBe(200);
    const adminResponseBody = await adminApiResponse.json();
    expect(adminResponseBody.devices).toBeDefined();
    expect(Array.isArray(adminResponseBody.devices)).toBe(true);
    expect(adminResponseBody.devices.length).toBeGreaterThan(0);
  });
});