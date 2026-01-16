import { test, expect } from '@playwright/test';

test.describe('Biometric Device Configuration', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const ADMIN_EMAIL = 'admin@company.com';
  const ADMIN_PASSWORD = 'Admin@123';
  const NON_ADMIN_EMAIL = 'employee@company.com';
  const NON_ADMIN_PASSWORD = 'Employee@123';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('Validate successful device configuration with valid inputs', async ({ page }) => {
    // Login as admin
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to device configuration page
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="device-configuration-link"]');
    await expect(page.locator('[data-testid="device-configuration-form"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Device Configuration');

    // Enter valid IP address and credentials
    await page.fill('[data-testid="device-ip-input"]', '192.168.1.100');
    await page.fill('[data-testid="device-name-input"]', 'Main Entrance Device');
    await page.fill('[data-testid="device-username-input"]', 'deviceadmin');
    await page.fill('[data-testid="device-password-input"]', 'DevicePass@123');
    await page.selectOption('[data-testid="device-type-select"]', 'Fingerprint Scanner');

    // Verify form accepts inputs without validation errors
    await expect(page.locator('[data-testid="device-ip-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="device-name-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="device-username-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="device-password-error"]')).not.toBeVisible();

    // Submit the configuration form
    await page.click('[data-testid="submit-device-config-button"]');

    // System saves configuration and displays success message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Device configuration saved successfully');
    
    // Verify device appears in the device list
    await expect(page.locator('[data-testid="device-list"]')).toContainText('Main Entrance Device');
    await expect(page.locator('[data-testid="device-list"]')).toContainText('192.168.1.100');
  });

  test('Verify device connectivity test functionality', async ({ page }) => {
    // Login as admin
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to device configuration page
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="device-configuration-link"]');
    await expect(page.locator('[data-testid="device-configuration-form"]')).toBeVisible();

    // Locate configured device in the device list
    const deviceRow = page.locator('[data-testid="device-row"]').filter({ hasText: 'Main Entrance Device' });
    await expect(deviceRow).toBeVisible();

    // Select configured device and click test connection
    await deviceRow.click();
    const startTime = Date.now();
    await page.click('[data-testid="test-connection-button"]');

    // System attempts connection and displays success or failure
    await expect(page.locator('[data-testid="connection-test-result"]')).toBeVisible({ timeout: 10000 });
    const connectionResult = await page.locator('[data-testid="connection-test-result"]').textContent();
    expect(connectionResult).toMatch(/(success|failure|Connection successful|Connection failed)/i);

    // Simulate device offline scenario
    await page.route('**/api/biometric-devices/test-connection', route => {
      route.fulfill({
        status: 500,
        body: JSON.stringify({ success: false, message: 'Connection failed: Device offline' })
      });
    });
    await page.click('[data-testid="test-connection-button"]');

    // System displays error message indicating connection failure
    await expect(page.locator('[data-testid="connection-test-result"]')).toBeVisible();
    await expect(page.locator('[data-testid="connection-test-result"]')).toContainText(/Connection failed|Device offline|error/i);
    await expect(page.locator('[data-testid="connection-status-icon"]')).toHaveClass(/error|failed|offline/);

    // Simulate device online scenario
    await page.unroute('**/api/biometric-devices/test-connection');
    await page.route('**/api/biometric-devices/test-connection', route => {
      route.fulfill({
        status: 200,
        body: JSON.stringify({ success: true, message: 'Connection successful' })
      });
    });
    await page.click('[data-testid="test-connection-button"]');

    // System displays success message confirming connection
    await expect(page.locator('[data-testid="connection-test-result"]')).toBeVisible();
    await expect(page.locator('[data-testid="connection-test-result"]')).toContainText(/Connection successful|success|online/i);
    await expect(page.locator('[data-testid="connection-status-icon"]')).toHaveClass(/success|online/);

    // Verify connection test response time is under 5 seconds
    const endTime = Date.now();
    const responseTime = endTime - startTime;
    expect(responseTime).toBeLessThan(5000);
  });

  test('Ensure unauthorized users cannot access device configuration', async ({ page }) => {
    // Login as non-admin user
    await page.fill('[data-testid="email-input"]', NON_ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', NON_ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Attempt to navigate to device configuration page
    await page.goto(`${BASE_URL}/admin/device-configuration`);

    // Access to device configuration page is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/Access denied|Unauthorized|Permission denied/i);
    await expect(page).not.toHaveURL(/.*device-configuration/);

    // Attempt to access device configuration API endpoint
    const postResponse = await page.request.post(`${BASE_URL}/api/biometric-devices`, {
      data: {
        ipAddress: '192.168.1.101',
        deviceName: 'Unauthorized Device',
        username: 'test',
        password: 'test123'
      }
    });

    // System returns authorization error
    expect(postResponse.status()).toBe(403);
    const postBody = await postResponse.json();
    expect(postBody.message || postBody.error).toMatch(/Unauthorized|Forbidden|Access denied/i);

    // Attempt to access device status API endpoint
    const getResponse = await page.request.get(`${BASE_URL}/api/biometric-devices/status`);

    // System returns authorization error
    expect(getResponse.status()).toBe(403);
    const getBody = await getResponse.json();
    expect(getBody.message || getBody.error).toMatch(/Unauthorized|Forbidden|Access denied/i);

    // Logout from non-admin user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Login as admin user
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to device configuration page
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="device-configuration-link"]');

    // Access to device configuration page is granted
    await expect(page).toHaveURL(/.*device-configuration/);
    await expect(page.locator('[data-testid="device-configuration-form"]')).toBeVisible();

    // Access device configuration API endpoints
    const adminPostResponse = await page.request.post(`${BASE_URL}/api/biometric-devices`, {
      data: {
        ipAddress: '192.168.1.102',
        deviceName: 'Admin Device',
        username: 'admin',
        password: 'admin123',
        deviceType: 'Fingerprint Scanner'
      }
    });

    expect(adminPostResponse.status()).toBe(200);

    const adminGetResponse = await page.request.get(`${BASE_URL}/api/biometric-devices/status`);
    expect(adminGetResponse.status()).toBe(200);
    const statusBody = await adminGetResponse.json();
    expect(statusBody).toHaveProperty('devices');
  });
});