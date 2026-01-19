import { test, expect } from '@playwright/test';

test.describe('Biometric Device Configuration', () => {
  const ADMIN_USERNAME = 'admin@company.com';
  const ADMIN_PASSWORD = 'AdminPass123!';
  const NON_ADMIN_USERNAME = 'employee@company.com';
  const NON_ADMIN_PASSWORD = 'EmployeePass123!';
  const BASE_URL = 'http://localhost:3000';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('Validate successful biometric device configuration', async ({ page }) => {
    // Login as admin
    await page.fill('[data-testid="username-input"]', ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="admin-dashboard"]')).toBeVisible();

    // Navigate to biometric device configuration page
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="biometric-config-link"]');
    
    // Expected Result: Configuration form is displayed
    await expect(page.locator('[data-testid="device-config-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="device-name-input"]')).toBeVisible();

    // Enter valid device details
    await page.fill('[data-testid="device-name-input"]', 'Main Entrance Device 01');
    await page.fill('[data-testid="device-ip-input"]', '192.168.1.100');
    await page.fill('[data-testid="device-port-input"]', '8080');
    await page.fill('[data-testid="device-identifier-input"]', 'DEV-001');
    await page.selectOption('[data-testid="device-type-select"]', 'Fingerprint Scanner');
    await page.fill('[data-testid="api-username-input"]', 'device_api_user');
    await page.fill('[data-testid="api-password-input"]', 'device_api_pass123');

    // Test connection
    await page.click('[data-testid="test-connection-button"]');
    await expect(page.locator('[data-testid="connection-status"]')).toContainText('Connection successful', { timeout: 10000 });

    // Submit configuration
    await page.click('[data-testid="save-configuration-button"]');
    
    // Expected Result: System validates and confirms successful device registration
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Device registered successfully');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Navigate to device status dashboard
    await page.click('[data-testid="device-status-dashboard-link"]');
    
    // Expected Result: Device status shows as connected and active
    await expect(page.locator('[data-testid="device-dashboard"]')).toBeVisible();
    const deviceRow = page.locator('[data-testid="device-row"]', { hasText: 'Main Entrance Device 01' });
    await expect(deviceRow).toBeVisible();
    await expect(deviceRow.locator('[data-testid="device-status"]')).toContainText('Connected');
    await expect(deviceRow.locator('[data-testid="device-active-status"]')).toContainText('Active');
  });

  test('Verify error handling for invalid device configuration', async ({ page }) => {
    // Login as admin
    await page.fill('[data-testid="username-input"]', ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="admin-dashboard"]')).toBeVisible();

    // Navigate to biometric device configuration page
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="biometric-config-link"]');
    
    // Expected Result: Configuration form is displayed
    await expect(page.locator('[data-testid="device-config-form"]')).toBeVisible();

    // Enter invalid device details
    await page.fill('[data-testid="device-name-input"]', 'Invalid Device');
    await page.fill('[data-testid="device-ip-input"]', '999.999.999.999');
    await page.fill('[data-testid="device-port-input"]', '99999');
    await page.fill('[data-testid="device-identifier-input"]', 'DEV-INVALID');
    await page.selectOption('[data-testid="device-type-select"]', 'Fingerprint Scanner');
    await page.fill('[data-testid="api-username-input"]', 'wrong_user');
    await page.fill('[data-testid="api-password-input"]', 'wrong_pass');

    // Test connection with invalid details
    await page.click('[data-testid="test-connection-button"]');
    await expect(page.locator('[data-testid="connection-status"]')).toContainText('Connection failed', { timeout: 10000 });

    // Attempt to submit without fixing errors
    await page.click('[data-testid="save-configuration-button"]');
    
    // Expected Result: System displays descriptive error message and prevents saving
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Invalid IP address format');
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Port number must be between 1 and 65535');
    await expect(page.locator('[data-testid="device-config-form"]')).toBeVisible();

    // Navigate to device status dashboard
    await page.click('[data-testid="device-status-dashboard-link"]');
    
    // Attempt to capture attendance data from non-existent device
    const invalidDevice = page.locator('[data-testid="device-row"]', { hasText: 'Invalid Device' });
    
    // Expected Result: No data captured from invalid device
    await expect(invalidDevice).not.toBeVisible();
  });

  test('Ensure only authorized admins can configure devices', async ({ page }) => {
    // Login as non-admin user
    await page.fill('[data-testid="username-input"]', NON_ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', NON_ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="employee-dashboard"]')).toBeVisible();

    // Verify device configuration menu option is not visible
    await page.click('[data-testid="main-menu"]');
    await expect(page.locator('[data-testid="biometric-config-link"]')).not.toBeVisible();

    // Attempt to navigate directly via URL
    await page.goto(`${BASE_URL}/admin/biometric-config`);
    
    // Expected Result: Access denied message displayed
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');
    await expect(page.locator('[data-testid="device-config-form"]')).not.toBeVisible();

    // Logout from non-admin account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-button"]')).toBeVisible();

    // Login as admin user
    await page.fill('[data-testid="username-input"]', ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="admin-dashboard"]')).toBeVisible();

    // Navigate to device configuration page
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="biometric-config-link"]');
    
    // Expected Result: Configuration page accessible
    await expect(page.locator('[data-testid="device-config-form"]')).toBeVisible();

    // Enter valid device details
    await page.fill('[data-testid="device-name-input"]', 'Reception Device 01');
    await page.fill('[data-testid="device-ip-input"]', '192.168.1.101');
    await page.fill('[data-testid="device-port-input"]', '8080');
    await page.fill('[data-testid="device-identifier-input"]', 'DEV-002');
    await page.selectOption('[data-testid="device-type-select"]', 'Fingerprint Scanner');
    await page.fill('[data-testid="api-username-input"]', 'device_api_user');
    await page.fill('[data-testid="api-password-input"]', 'device_api_pass123');

    // Test connection
    await page.click('[data-testid="test-connection-button"]');
    await expect(page.locator('[data-testid="connection-status"]')).toContainText('Connection successful', { timeout: 10000 });

    // Save configuration
    await page.click('[data-testid="save-configuration-button"]');
    
    // Expected Result: Device registered and active
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Device registered successfully');

    // Verify device appears in status dashboard
    await page.click('[data-testid="device-status-dashboard-link"]');
    const deviceRow = page.locator('[data-testid="device-row"]', { hasText: 'Reception Device 01' });
    await expect(deviceRow).toBeVisible();
    await expect(deviceRow.locator('[data-testid="device-status"]')).toContainText('Connected');
    await expect(deviceRow.locator('[data-testid="device-active-status"]')).toContainText('Active');
  });
});