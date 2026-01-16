import { test, expect } from '@playwright/test';

test.describe('Biometric Device Configuration', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin@example.com';
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Admin@123';
  const NON_ADMIN_USERNAME = process.env.NON_ADMIN_USERNAME || 'employee@example.com';
  const NON_ADMIN_PASSWORD = process.env.NON_ADMIN_PASSWORD || 'Employee@123';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('Validate adding biometric device with valid parameters', async ({ page }) => {
    // Login as administrator
    await page.fill('[data-testid="username-input"]', ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to device configuration page from the main menu or dashboard
    await page.click('[data-testid="device-configuration-menu"]');
    await expect(page).toHaveURL(/.*device-configuration/);
    await expect(page.locator('[data-testid="device-configuration-form"]')).toBeVisible();

    // Enter valid IP address (e.g., 192.168.1.100) in the IP address field
    await page.fill('[data-testid="device-ip-input"]', '192.168.1.100');
    await expect(page.locator('[data-testid="device-ip-input"]')).toHaveValue('192.168.1.100');

    // Enter valid port number (e.g., 4370) in the port field
    await page.fill('[data-testid="device-port-input"]', '4370');
    await expect(page.locator('[data-testid="device-port-input"]')).toHaveValue('4370');

    // Enter device name (e.g., Main Entrance Device) in the device name field
    await page.fill('[data-testid="device-name-input"]', 'Main Entrance Device');
    await expect(page.locator('[data-testid="device-name-input"]')).toHaveValue('Main Entrance Device');

    // Select communication protocol from dropdown (e.g., TCP/IP)
    await page.click('[data-testid="protocol-dropdown"]');
    await page.click('[data-testid="protocol-option-tcp-ip"]');
    await expect(page.locator('[data-testid="protocol-dropdown"]')).toContainText('TCP/IP');

    // Click the Submit or Save Configuration button
    await page.click('[data-testid="save-configuration-button"]');

    // Wait for connectivity test to complete
    await expect(page.locator('[data-testid="connectivity-test-status"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="connectivity-test-status"]')).toContainText('Connected');

    // Verify the newly added device appears in the device list
    await expect(page.locator('[data-testid="device-list"]')).toContainText('Main Entrance Device');
    await expect(page.locator('[data-testid="device-list"]')).toContainText('192.168.1.100');
    await expect(page.locator('[data-testid="device-list"]')).toContainText('4370');
  });

  test('Reject invalid IP address during device configuration', async ({ page }) => {
    // Login as administrator
    await page.fill('[data-testid="username-input"]', ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to device configuration page from the main menu or dashboard
    await page.click('[data-testid="device-configuration-menu"]');
    await expect(page).toHaveURL(/.*device-configuration/);
    await expect(page.locator('[data-testid="device-configuration-form"]')).toBeVisible();

    // Enter invalid IP address format in the IP address field (e.g., 999.999.999.999)
    await page.fill('[data-testid="device-ip-input"]', '999.999.999.999');

    // Enter valid port number (e.g., 4370) in the port field
    await page.fill('[data-testid="device-port-input"]', '4370');

    // Attempt to click the Submit or Save Configuration button
    await page.click('[data-testid="save-configuration-button"]');

    // Verify inline validation error is displayed
    await expect(page.locator('[data-testid="device-ip-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="device-ip-error"]')).toContainText(/invalid.*ip.*address/i);

    // Clear the IP address field and enter another invalid format (e.g., 192.168.1)
    await page.fill('[data-testid="device-ip-input"]', '');
    await page.fill('[data-testid="device-ip-input"]', '192.168.1');

    // Attempt to submit the configuration again
    await page.click('[data-testid="save-configuration-button"]');

    // Verify validation error is displayed
    await expect(page.locator('[data-testid="device-ip-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="device-ip-error"]')).toContainText(/invalid.*ip.*address/i);

    // Enter alphabetic characters in IP address field (e.g., abc.def.ghi.jkl)
    await page.fill('[data-testid="device-ip-input"]', '');
    await page.fill('[data-testid="device-ip-input"]', 'abc.def.ghi.jkl');

    // Attempt to submit the configuration
    await page.click('[data-testid="save-configuration-button"]');

    // Verify validation error is displayed
    await expect(page.locator('[data-testid="device-ip-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="device-ip-error"]')).toContainText(/invalid.*ip.*address/i);

    // Verify submission is blocked and device is not added to the list
    await expect(page.locator('[data-testid="device-list"]')).not.toContainText('abc.def.ghi.jkl');
  });

  test('Restrict device configuration access to authorized users', async ({ page }) => {
    // Login to the system using non-administrator user credentials
    await page.fill('[data-testid="username-input"]', NON_ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', NON_ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Verify that device configuration menu item is not visible or is disabled in the navigation menu
    const deviceConfigMenu = page.locator('[data-testid="device-configuration-menu"]');
    await expect(deviceConfigMenu).not.toBeVisible().catch(async () => {
      // If visible, check if it's disabled
      await expect(deviceConfigMenu).toBeDisabled();
    });

    // Attempt to navigate to device configuration page by entering URL directly
    await page.goto(`${BASE_URL}/device-configuration`);

    // Verify access is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/access.*denied|unauthorized|permission/i);

    // Logout from the non-administrator account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Login to the system using administrator user credentials
    await page.fill('[data-testid="username-input"]', ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to device configuration page from the menu
    await page.click('[data-testid="device-configuration-menu"]');
    await expect(page).toHaveURL(/.*device-configuration/);

    // Verify that all device configuration features are accessible
    await expect(page.locator('[data-testid="device-configuration-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="add-device-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="device-list"]')).toBeVisible();

    // Verify edit and delete buttons are present for existing devices
    const deviceListItems = page.locator('[data-testid="device-list-item"]');
    const deviceCount = await deviceListItems.count();
    if (deviceCount > 0) {
      await expect(deviceListItems.first().locator('[data-testid="edit-device-button"]')).toBeVisible();
      await expect(deviceListItems.first().locator('[data-testid="delete-device-button"]')).toBeVisible();
      await expect(deviceListItems.first().locator('[data-testid="test-connectivity-button"]')).toBeVisible();
    }
  });
});