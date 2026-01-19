import { test, expect } from '@playwright/test';

test.describe('Biometric Device Configuration', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const ADMIN_USERNAME = 'admin001';
  const ADMIN_PASSWORD = 'Admin@123';
  const EMPLOYEE_USERNAME = 'employee001';
  const EMPLOYEE_PASSWORD = 'Employee@123';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('Validate successful biometric device registration', async ({ page }) => {
    // Login as administrator
    await page.fill('[data-testid="username-input"]', ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to device configuration page from the main menu
    await page.click('[data-testid="device-management-menu"]');
    await page.click('[data-testid="device-configuration-link"]');
    
    // Expected Result: Device registration form is displayed
    await expect(page.locator('[data-testid="device-registration-form"]')).toBeVisible();
    await expect(page.locator('h1, h2').filter({ hasText: /Device Registration|Add New Device/i })).toBeVisible();

    // Enter valid device details
    await page.fill('[data-testid="device-id-input"]', 'BIO-001');
    await page.fill('[data-testid="device-name-input"]', 'Main Entrance Scanner');
    await page.fill('[data-testid="ip-address-input"]', '192.168.1.100');
    await page.selectOption('[data-testid="protocol-select"]', 'TCP/IP');
    await page.fill('[data-testid="location-input"]', 'Building A - Floor 1');

    // Click the 'Submit' or 'Register Device' button
    await page.click('[data-testid="submit-device-button"]');

    // Expected Result: Device is registered and confirmation message is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/Device registered successfully|Registration successful/i);

    // Navigate to device status dashboard
    await page.click('[data-testid="device-status-dashboard-link"]');
    
    // Expected Result: New device appears with 'Connected' status
    await expect(page.locator('[data-testid="device-list"]')).toBeVisible();
    const deviceRow = page.locator('[data-testid="device-row"]').filter({ hasText: 'BIO-001' });
    await expect(deviceRow).toBeVisible();
    await expect(deviceRow.locator('[data-testid="device-status"]')).toContainText(/Connected|Active/i);
    await expect(deviceRow).toContainText('Main Entrance Scanner');
    await expect(deviceRow).toContainText('192.168.1.100');
  });

  test('Verify error handling for invalid device configuration', async ({ page }) => {
    // Login as administrator
    await page.fill('[data-testid="username-input"]', ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to device configuration page from the main menu
    await page.click('[data-testid="device-management-menu"]');
    await page.click('[data-testid="device-configuration-link"]');
    
    // Expected Result: Device registration form is displayed
    await expect(page.locator('[data-testid="device-registration-form"]')).toBeVisible();

    // Enter invalid IP address '999.999.999.999' in the IP Address field
    await page.fill('[data-testid="ip-address-input"]', '999.999.999.999');
    
    // Click the 'Submit' or 'Register Device' button
    await page.click('[data-testid="submit-device-button"]');

    // Expected Result: Inline error message 'Invalid IP address format' is displayed
    await expect(page.locator('[data-testid="ip-address-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="ip-address-error"]')).toContainText(/Invalid IP address format/i);

    // Clear the IP Address field and correct it to '192.168.1.101'
    await page.fill('[data-testid="ip-address-input"]', '192.168.1.101');
    
    // Fill other required fields except Device ID
    await page.fill('[data-testid="device-name-input"]', 'Test Device');
    await page.selectOption('[data-testid="protocol-select"]', 'TCP/IP');
    await page.fill('[data-testid="location-input"]', 'Test Location');
    
    // Clear the required Device ID field
    await page.fill('[data-testid="device-id-input"]', '');
    
    // Attempt to submit the form with missing Device ID field
    await page.click('[data-testid="submit-device-button"]');

    // Expected Result: Submission blocked with appropriate error messages
    await expect(page.locator('[data-testid="device-id-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="device-id-error"]')).toContainText(/Device ID is required|This field is required/i);

    // Fill Device ID but leave Device Name field empty
    await page.fill('[data-testid="device-id-input"]', 'BIO-002');
    await page.fill('[data-testid="device-name-input"]', '');
    
    // Attempt to submit
    await page.click('[data-testid="submit-device-button"]');
    
    // Expected Result: Error message for missing Device Name
    await expect(page.locator('[data-testid="device-name-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="device-name-error"]')).toContainText(/Device Name is required|This field is required/i);
  });

  test('Ensure only authorized users can access device configuration', async ({ page }) => {
    // Login to the configuration portal using non-administrator user credentials
    await page.fill('[data-testid="username-input"]', EMPLOYEE_USERNAME);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Attempt to navigate to device configuration page by entering the URL directly
    await page.goto(`${BASE_URL}/device-configuration`);
    
    // Expected Result: Access to device configuration page is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/Access Denied|Unauthorized|You do not have permission/i);
    
    // Alternative check: verify device configuration menu is not visible
    const deviceConfigMenu = page.locator('[data-testid="device-configuration-link"]');
    await expect(deviceConfigMenu).not.toBeVisible();

    // Logout from the non-administrator account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Login to the configuration portal using Biometric System Administrator credentials
    await page.fill('[data-testid="username-input"]', ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to device configuration page from the main menu
    await page.click('[data-testid="device-management-menu"]');
    await page.click('[data-testid="device-configuration-link"]');
    
    // Expected Result: Access to device configuration page is granted
    await expect(page.locator('[data-testid="device-registration-form"]')).toBeVisible();
    await expect(page).toHaveURL(/.*device-configuration/);
    await expect(page.locator('h1, h2').filter({ hasText: /Device Configuration|Device Registration/i })).toBeVisible();
  });
});