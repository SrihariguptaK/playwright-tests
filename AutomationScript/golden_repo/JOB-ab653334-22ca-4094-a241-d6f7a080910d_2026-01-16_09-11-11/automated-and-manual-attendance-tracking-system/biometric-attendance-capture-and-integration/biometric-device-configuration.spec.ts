import { test, expect } from '@playwright/test';

test.describe('Biometric Device Configuration', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const ADMIN_EMAIL = 'admin@company.com';
  const ADMIN_PASSWORD = 'Admin@123';
  const NON_ADMIN_EMAIL = 'user@company.com';
  const NON_ADMIN_PASSWORD = 'User@123';

  test.beforeEach(async ({ page }) => {
    // Login as admin for most tests
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate successful device configuration with valid inputs', async ({ page }) => {
    // Login as admin
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');

    // Step 1: Navigate to device configuration page
    await page.click('[data-testid="settings-menu"]');
    await page.click('[data-testid="biometric-devices-link"]');
    await page.waitForSelector('[data-testid="device-configuration-form"]');
    
    // Expected Result: Device configuration form is displayed
    await expect(page.locator('[data-testid="device-configuration-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="device-ip-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="device-credentials-input"]')).toBeVisible();

    // Step 2: Enter valid IP address and credentials
    await page.fill('[data-testid="device-name-input"]', 'Main Entrance Device');
    await page.fill('[data-testid="device-ip-input"]', '192.168.1.100');
    await page.fill('[data-testid="device-port-input"]', '4370');
    await page.selectOption('[data-testid="device-type-select"]', 'ZKTeco');
    await page.fill('[data-testid="device-username-input"]', 'admin');
    await page.fill('[data-testid="device-password-input"]', 'device@123');
    
    // Expected Result: Form accepts inputs without validation errors
    await expect(page.locator('[data-testid="ip-validation-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="credentials-validation-error"]')).not.toBeVisible();

    // Step 3: Submit the configuration form
    await page.click('[data-testid="save-device-button"]');
    await page.waitForSelector('[data-testid="success-message"]', { timeout: 10000 });
    
    // Expected Result: System saves configuration and displays success message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Device configuration saved successfully');
    await expect(page.locator('[data-testid="device-list"]')).toContainText('Main Entrance Device');
    await expect(page.locator('[data-testid="device-list"]')).toContainText('192.168.1.100');
  });

  test('Verify device connectivity test functionality', async ({ page }) => {
    // Login as admin
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');

    // Navigate to device configuration page
    await page.click('[data-testid="settings-menu"]');
    await page.click('[data-testid="biometric-devices-link"]');
    await page.waitForSelector('[data-testid="device-list"]');

    // Step 1: Select configured device and click test connection
    await page.click('[data-testid="device-row-1"]');
    await page.click('[data-testid="test-connection-button"]');
    await page.waitForSelector('[data-testid="connection-test-result"]', { timeout: 10000 });
    
    // Expected Result: System attempts connection and displays success or failure
    await expect(page.locator('[data-testid="connection-test-result"]')).toBeVisible();
    const resultText = await page.locator('[data-testid="connection-test-result"]').textContent();
    expect(resultText).toMatch(/(Connection successful|Connection failed)/);

    // Step 2: Simulate device offline scenario
    await page.click('[data-testid="edit-device-button"]');
    await page.fill('[data-testid="device-ip-input"]', '192.168.1.254');
    await page.click('[data-testid="save-device-button"]');
    await page.waitForSelector('[data-testid="success-message"]');
    await page.click('[data-testid="test-connection-button"]');
    await page.waitForSelector('[data-testid="connection-test-result"]', { timeout: 10000 });
    
    // Expected Result: System displays error message indicating connection failure
    await expect(page.locator('[data-testid="connection-test-result"]')).toBeVisible();
    await expect(page.locator('[data-testid="connection-test-result"]')).toContainText('Connection failed');
    await expect(page.locator('[data-testid="connection-status-icon"]')).toHaveClass(/error|failed/);

    // Step 3: Simulate device online scenario
    await page.click('[data-testid="edit-device-button"]');
    await page.fill('[data-testid="device-ip-input"]', '192.168.1.100');
    await page.click('[data-testid="save-device-button"]');
    await page.waitForSelector('[data-testid="success-message"]');
    await page.click('[data-testid="test-connection-button"]');
    await page.waitForSelector('[data-testid="connection-test-result"]', { timeout: 10000 });
    
    // Expected Result: System displays success message confirming connection
    await expect(page.locator('[data-testid="connection-test-result"]')).toBeVisible();
    await expect(page.locator('[data-testid="connection-test-result"]')).toContainText('Connection successful');
    await expect(page.locator('[data-testid="connection-status-icon"]')).toHaveClass(/success|connected/);
    await expect(page.locator('[data-testid="last-sync-time"]')).toBeVisible();
  });

  test('Ensure unauthorized users cannot access device configuration', async ({ page }) => {
    // Step 1: Login as non-admin user
    await page.fill('[data-testid="email-input"]', NON_ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', NON_ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');

    // Attempt to navigate to device configuration page
    await page.goto(`${BASE_URL}/settings/biometric-devices`);
    
    // Expected Result: Access to device configuration page is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    await expect(page.locator('[data-testid="device-configuration-form"]')).not.toBeVisible();

    // Step 2: Attempt to access device configuration API endpoints
    const response = await page.request.get(`${BASE_URL}/api/biometric-devices`);
    
    // Expected Result: System returns authorization error
    expect(response.status()).toBe(403);
    const responseBody = await response.json();
    expect(responseBody.error).toMatch(/(Unauthorized|Forbidden|Access denied)/);

    // Attempt POST request
    const postResponse = await page.request.post(`${BASE_URL}/api/biometric-devices`, {
      data: {
        name: 'Unauthorized Device',
        ipAddress: '192.168.1.101',
        port: 4370
      }
    });
    expect(postResponse.status()).toBe(403);

    // Logout non-admin user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.waitForURL('**/login');

    // Step 3: Login as admin user
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');

    // Navigate to device configuration page
    await page.click('[data-testid="settings-menu"]');
    await page.click('[data-testid="biometric-devices-link"]');
    
    // Expected Result: Access to device configuration page and APIs is granted
    await expect(page.locator('[data-testid="device-configuration-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="device-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="add-device-button"]')).toBeVisible();

    // Verify API access
    const adminResponse = await page.request.get(`${BASE_URL}/api/biometric-devices`);
    expect(adminResponse.status()).toBe(200);
    const adminResponseBody = await adminResponse.json();
    expect(Array.isArray(adminResponseBody.devices)).toBeTruthy();
  });
});