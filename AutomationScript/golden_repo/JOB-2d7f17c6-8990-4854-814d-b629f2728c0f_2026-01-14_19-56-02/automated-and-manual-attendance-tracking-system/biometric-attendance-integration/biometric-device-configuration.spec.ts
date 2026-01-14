import { test, expect } from '@playwright/test';

test.describe('Biometric Device Configuration', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to admin login and authenticate
    await page.goto('/admin/login');
    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'Admin@123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*admin\/dashboard/);
  });

  test('Validate successful biometric device configuration', async ({ page }) => {
    // Step 1: Navigate to biometric device configuration page
    await page.click('[data-testid="biometric-devices-menu"]');
    await page.click('[data-testid="device-configuration-link"]');
    await expect(page.locator('[data-testid="device-config-form"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Biometric Device Configuration');

    // Step 2: Enter valid device connection parameters
    await page.fill('[data-testid="device-ip-input"]', '192.168.1.100');
    await page.fill('[data-testid="device-port-input"]', '4370');
    await page.fill('[data-testid="device-username-input"]', 'deviceadmin');
    await page.fill('[data-testid="device-password-input"]', 'Device@Pass123');
    await page.fill('[data-testid="device-name-input"]', 'Main Entrance Device');

    // Navigate to user mapping section
    await page.click('[data-testid="user-mapping-tab"]');
    await expect(page.locator('[data-testid="user-mapping-section"]')).toBeVisible();

    // Map biometric device users to employee IDs
    await page.click('[data-testid="add-user-mapping-button"]');
    await page.selectOption('[data-testid="biometric-user-select-0"]', 'bio_user_001');
    await page.selectOption('[data-testid="employee-id-select-0"]', 'EMP001');

    await page.click('[data-testid="add-user-mapping-button"]');
    await page.selectOption('[data-testid="biometric-user-select-1"]', 'bio_user_002');
    await page.selectOption('[data-testid="employee-id-select-1"]', 'EMP002');

    // Verify no validation errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();

    // Step 3: Test connection and save configuration
    await page.click('[data-testid="test-connection-button"]');
    await expect(page.locator('[data-testid="connection-test-loading"]')).toBeVisible();
    await expect(page.locator('[data-testid="connection-success-message"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="connection-success-message"]')).toContainText('Connection test successful');

    await page.click('[data-testid="save-configuration-button"]');
    await expect(page.locator('[data-testid="config-saved-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="config-saved-message"]')).toContainText('Configuration saved successfully');

    // Verify device appears in device list with Active status
    await page.click('[data-testid="device-list-link"]');
    await expect(page.locator('[data-testid="device-list-table"]')).toBeVisible();
    const deviceRow = page.locator('[data-testid="device-row-Main-Entrance-Device"]');
    await expect(deviceRow).toBeVisible();
    await expect(deviceRow.locator('[data-testid="device-status"]')).toContainText('Active');
  });

  test('Verify error handling for invalid device parameters', async ({ page }) => {
    // Navigate to biometric device configuration page
    await page.click('[data-testid="biometric-devices-menu"]');
    await page.click('[data-testid="device-configuration-link"]');
    await expect(page.locator('[data-testid="device-config-form"]')).toBeVisible();

    // Step 1: Enter invalid IP address format
    await page.fill('[data-testid="device-ip-input"]', '999.999.999.999');
    await page.fill('[data-testid="device-port-input"]', '4370');
    await page.click('[data-testid="device-name-input"]'); // Trigger validation
    await expect(page.locator('[data-testid="ip-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="ip-validation-error"]')).toContainText('Invalid IP address format');

    // Correct IP and enter invalid port number
    await page.fill('[data-testid="device-ip-input"]', '192.168.1.100');
    await page.fill('[data-testid="device-port-input"]', '99999');
    await page.click('[data-testid="device-name-input"]'); // Trigger validation
    await expect(page.locator('[data-testid="port-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="port-validation-error"]')).toContainText('Port number must be between 1 and 65535');

    // Test with negative port
    await page.fill('[data-testid="device-port-input"]', '-1');
    await page.click('[data-testid="device-name-input"]');
    await expect(page.locator('[data-testid="port-validation-error"]')).toBeVisible();

    // Correct port and leave credentials empty
    await page.fill('[data-testid="device-port-input"]', '4370');
    await page.fill('[data-testid="device-username-input"]', '');
    await page.fill('[data-testid="device-password-input"]', '');
    await page.fill('[data-testid="device-name-input"]', 'Test Device');
    await page.click('[data-testid="test-connection-button"]');
    await expect(page.locator('[data-testid="credentials-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="credentials-validation-error"]')).toContainText('Username and password are required');

    // Step 2: Enter valid format but unreachable device
    await page.fill('[data-testid="device-ip-input"]', '192.168.99.99');
    await page.fill('[data-testid="device-port-input"]', '4370');
    await page.fill('[data-testid="device-username-input"]', 'testuser');
    await page.fill('[data-testid="device-password-input"]', 'testpass');
    await page.click('[data-testid="test-connection-button"]');
    await expect(page.locator('[data-testid="connection-test-loading"]')).toBeVisible();
    await expect(page.locator('[data-testid="connection-error-message"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="connection-error-message"]')).toContainText(/Connection failed|Device unreachable|Timeout/);

    // Step 3: Correct all parameters with valid data
    await page.fill('[data-testid="device-ip-input"]', '192.168.1.100');
    await page.fill('[data-testid="device-port-input"]', '4370');
    await page.fill('[data-testid="device-username-input"]', 'deviceadmin');
    await page.fill('[data-testid="device-password-input"]', 'Device@Pass123');
    await page.click('[data-testid="test-connection-button"]');
    await expect(page.locator('[data-testid="connection-success-message"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="connection-success-message"]')).toContainText('Connection test successful');

    // Save configuration
    await page.click('[data-testid="save-configuration-button"]');
    await expect(page.locator('[data-testid="config-saved-message"]')).toBeVisible();
  });

  test('Ensure device status dashboard updates correctly', async ({ page }) => {
    // Step 1: Navigate to device status dashboard
    await page.click('[data-testid="biometric-devices-menu"]');
    await page.click('[data-testid="device-status-dashboard-link"]');
    await expect(page.locator('[data-testid="device-status-dashboard"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Device Status Dashboard');

    // Step 2: Verify current status of test device
    const testDevice = page.locator('[data-testid="device-card-Main-Entrance-Device"]');
    await expect(testDevice).toBeVisible();
    const initialStatus = await testDevice.locator('[data-testid="device-status-badge"]').textContent();
    await expect(testDevice.locator('[data-testid="device-status-badge"]')).toContainText(/Online|Active/);

    // Step 3: Simulate device offline status
    // This would typically be done through API or test utilities
    await page.evaluate(() => {
      window.localStorage.setItem('simulate-device-offline', 'Main-Entrance-Device');
    });
    
    // Manually refresh or wait for auto-refresh
    await page.click('[data-testid="refresh-dashboard-button"]');
    await page.waitForTimeout(2000); // Wait for refresh

    // Verify dashboard shows device offline
    await expect(testDevice.locator('[data-testid="device-status-badge"]')).toContainText(/Offline|Disconnected/, { timeout: 10000 });
    await expect(testDevice.locator('[data-testid="device-alert-icon"]')).toBeVisible();

    // Step 4: Click on offline device for detailed status
    await testDevice.click();
    await expect(page.locator('[data-testid="device-detail-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="device-detail-status"]')).toContainText(/Offline|Disconnected/);
    await expect(page.locator('[data-testid="device-last-seen"]')).toBeVisible();
    await page.click('[data-testid="close-detail-modal"]');

    // Step 5: Restore device connectivity
    await page.evaluate(() => {
      window.localStorage.removeItem('simulate-device-offline');
      window.localStorage.setItem('simulate-device-online', 'Main-Entrance-Device');
    });

    // Wait for auto-refresh or manually refresh
    await page.click('[data-testid="refresh-dashboard-button"]');
    await page.waitForTimeout(2000);

    // Step 6: Verify device shows online status
    await expect(testDevice.locator('[data-testid="device-status-badge"]')).toContainText(/Online|Active/, { timeout: 10000 });
    await expect(testDevice.locator('[data-testid="device-alert-icon"]')).not.toBeVisible();

    // Step 7: Verify alert history shows status changes
    await page.click('[data-testid="alert-history-tab"]');
    await expect(page.locator('[data-testid="alert-history-table"]')).toBeVisible();
    
    const alertRows = page.locator('[data-testid="alert-history-row"]');
    await expect(alertRows).toHaveCount(2, { timeout: 5000 });
    
    // Verify offline alert exists
    const offlineAlert = alertRows.filter({ hasText: /Offline|Disconnected/ }).first();
    await expect(offlineAlert).toBeVisible();
    await expect(offlineAlert).toContainText('Main Entrance Device');
    
    // Verify online alert exists
    const onlineAlert = alertRows.filter({ hasText: /Online|Connected/ }).first();
    await expect(onlineAlert).toBeVisible();
    await expect(onlineAlert).toContainText('Main Entrance Device');
  });
});