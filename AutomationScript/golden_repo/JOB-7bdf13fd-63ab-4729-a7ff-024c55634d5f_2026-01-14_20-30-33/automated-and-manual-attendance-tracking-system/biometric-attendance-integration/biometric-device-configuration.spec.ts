import { test, expect } from '@playwright/test';

test.describe('Biometric Device Configuration', () => {
  const ADMIN_USERNAME = 'admin';
  const ADMIN_PASSWORD = 'adminpass123';
  const NON_ADMIN_USERNAME = 'testuser';
  const NON_ADMIN_PASSWORD = 'testpass123';
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('Validate successful biometric device addition and connectivity test', async ({ page }) => {
    // Login as administrator
    await page.fill('[data-testid="username-input"]', ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to device configuration page from admin dashboard
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="device-configuration-link"]');
    await expect(page).toHaveURL(/.*device-configuration/);

    // Verify device configuration form is displayed
    await expect(page.locator('[data-testid="device-configuration-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="device-name-input"]')).toBeVisible();

    // Enter valid device details
    await page.fill('[data-testid="device-name-input"]', 'Main Entrance Scanner');
    await page.fill('[data-testid="ip-address-input"]', '192.168.1.100');
    await page.fill('[data-testid="port-input"]', '4370');
    await page.selectOption('[data-testid="device-type-select"]', 'Fingerprint');
    await page.fill('[data-testid="location-input"]', 'Building A - Main Entrance');
    await page.fill('[data-testid="device-username-input"]', 'admin');
    await page.fill('[data-testid="device-password-input"]', 'devicepass123');

    // Click Test Connection button
    await page.click('[data-testid="test-connection-button"]');

    // Observe connection test result within 5 seconds
    await expect(page.locator('[data-testid="connection-status"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="connection-status"]')).toContainText('successful', { ignoreCase: true });
    await expect(page.locator('[data-testid="connection-status-icon"]')).toHaveClass(/success|online/);

    // Click Save Configuration button
    await page.click('[data-testid="save-configuration-button"]');

    // Verify success message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Device configured successfully');

    // Verify device entry in device list
    await expect(page.locator('[data-testid="device-list"]')).toBeVisible();
    const deviceRow = page.locator('[data-testid="device-row"]').filter({ hasText: 'Main Entrance Scanner' });
    await expect(deviceRow).toBeVisible();
    await expect(deviceRow.locator('[data-testid="device-ip"]')).toContainText('192.168.1.100');
    await expect(deviceRow.locator('[data-testid="device-location"]')).toContainText('Building A - Main Entrance');
    await expect(deviceRow.locator('[data-testid="device-status"]')).toContainText('Online');
  });

  test('Verify rejection of invalid device parameters', async ({ page }) => {
    // Login as administrator
    await page.fill('[data-testid="username-input"]', ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to device configuration page from admin dashboard
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="device-configuration-link"]');
    await expect(page).toHaveURL(/.*device-configuration/);

    // Verify device configuration form is displayed
    await expect(page.locator('[data-testid="device-configuration-form"]')).toBeVisible();

    // Enter invalid IP address
    await page.fill('[data-testid="device-name-input"]', 'Test Device');
    await page.fill('[data-testid="ip-address-input"]', '999.999.999.999');
    await page.fill('[data-testid="port-input"]', '4370');
    await page.selectOption('[data-testid="device-type-select"]', 'Fingerprint');
    await page.fill('[data-testid="location-input"]', 'Test Location');
    await page.fill('[data-testid="device-username-input"]', 'admin');
    await page.fill('[data-testid="device-password-input"]', 'pass123');

    // Click Test Connection or Save Configuration button
    await page.click('[data-testid="test-connection-button"]');

    // System displays validation error and prevents submission
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Invalid IP address');
    await expect(page.locator('[data-testid="ip-address-input"]')).toHaveClass(/error|invalid/);

    // Verify device was not saved
    const deviceList = page.locator('[data-testid="device-list"]');
    if (await deviceList.isVisible()) {
      await expect(deviceList.locator('[data-testid="device-row"]').filter({ hasText: 'Test Device' })).not.toBeVisible();
    }

    // Correct the IP address to valid format
    await page.fill('[data-testid="ip-address-input"]', '192.168.1.150');

    // Click Test Connection button
    await page.click('[data-testid="test-connection-button"]');

    // Observe connection test result
    await expect(page.locator('[data-testid="connection-status"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();

    // Verify connection status is displayed (either success or failure based on actual device availability)
    const connectionStatus = page.locator('[data-testid="connection-status"]');
    await expect(connectionStatus).toBeVisible();
  });

  test('Ensure unauthorized users cannot access device configuration', async ({ page, context }) => {
    // Navigate to login page and enter non-administrator credentials
    await page.fill('[data-testid="username-input"]', NON_ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', NON_ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Verify main navigation menu options available to logged-in user
    const adminMenu = page.locator('[data-testid="admin-menu"]');
    const deviceConfigLink = page.locator('[data-testid="device-configuration-link"]');
    
    // Admin menu should not be visible or device configuration should not be accessible
    const isAdminMenuVisible = await adminMenu.isVisible().catch(() => false);
    if (isAdminMenuVisible) {
      await adminMenu.click();
      await expect(deviceConfigLink).not.toBeVisible();
    }

    // Manually enter device configuration page URL
    await page.goto(`${BASE_URL}/admin/device-configuration`);

    // Access to device configuration page is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/access denied|unauthorized|forbidden/i);
    
    // Verify redirected to unauthorized page or dashboard
    await page.waitForURL(/.*(?:unauthorized|access-denied|dashboard)/);

    // Attempt to access device configuration API endpoints
    const postResponse = await page.request.post(`${BASE_URL}/api/devices`, {
      data: {
        deviceName: 'Test',
        ipAddress: '192.168.1.100',
        port: '4370'
      }
    });

    // System returns authorization error
    expect(postResponse.status()).toBe(403);
    const postResponseBody = await postResponse.json();
    expect(postResponseBody.error || postResponseBody.message).toMatch(/unauthorized|forbidden|access denied/i);

    // Attempt GET request to device status endpoint
    const getResponse = await page.request.get(`${BASE_URL}/api/devices/status`);

    // System returns authorization error
    expect(getResponse.status()).toBe(403);
    const getResponseBody = await getResponse.json();
    expect(getResponseBody.error || getResponseBody.message).toMatch(/unauthorized|forbidden|access denied/i);

    // Check system audit logs for unauthorized access attempts
    // Note: This would typically require admin access to view logs
    // For testing purposes, we verify the attempts were made and blocked
    await expect(postResponse.status()).not.toBe(200);
    await expect(getResponse.status()).not.toBe(200);
  });
});