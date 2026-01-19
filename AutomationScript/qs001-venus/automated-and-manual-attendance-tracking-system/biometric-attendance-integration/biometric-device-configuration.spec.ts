import { test, expect } from '@playwright/test';

test.describe('Biometric Device Configuration - Story 22', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const adminCredentials = {
    username: 'admin@company.com',
    password: 'Admin@123'
  };
  const nonAdminCredentials = {
    username: 'employee@company.com',
    password: 'Employee@123'
  };

  test.beforeEach(async ({ page }) => {
    await page.goto(baseURL);
  });

  test('Validate successful device configuration addition (happy-path)', async ({ page }) => {
    // Login as administrator
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to biometric device configuration page from the main menu or dashboard
    await page.click('[data-testid="settings-menu"]');
    await page.click('[data-testid="biometric-devices-link"]');
    
    // Expected Result: Configuration form is displayed
    await expect(page.locator('[data-testid="device-configuration-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="device-ip-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="device-port-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="device-username-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="device-password-input"]')).toBeVisible();

    // Enter valid device IP address (e.g., 192.168.1.100) in the IP field
    await page.fill('[data-testid="device-ip-input"]', '192.168.1.100');
    
    // Enter valid port number (e.g., 4370) in the port field
    await page.fill('[data-testid="device-port-input"]', '4370');
    
    // Enter valid device credentials (username and password) in the respective fields
    await page.fill('[data-testid="device-username-input"]', 'deviceadmin');
    await page.fill('[data-testid="device-password-input"]', 'DevicePass@123');
    
    // Expected Result: Inputs accepted without validation errors
    await expect(page.locator('[data-testid="ip-validation-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="port-validation-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="credentials-validation-error"]')).not.toBeVisible();

    // Click the Submit or Save button to save the configuration
    await page.click('[data-testid="save-device-button"]');
    
    // Wait for connectivity test to complete
    await expect(page.locator('[data-testid="connectivity-test-status"]')).toBeVisible({ timeout: 10000 });
    
    // Expected Result: Configuration saved and connectivity test passes
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Configuration saved successfully');
    await expect(page.locator('[data-testid="connectivity-test-status"]')).toContainText('Connected');
    
    // Verify device appears in the device list
    await expect(page.locator('[data-testid="device-list"]')).toContainText('192.168.1.100');
  });

  test('Verify rejection of invalid device parameters (error-case)', async ({ page }) => {
    // Login as administrator
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to biometric device configuration page from the main menu or dashboard
    await page.click('[data-testid="settings-menu"]');
    await page.click('[data-testid="biometric-devices-link"]');
    
    // Expected Result: Configuration form is displayed
    await expect(page.locator('[data-testid="device-configuration-form"]')).toBeVisible();

    // Enter invalid IP address format (e.g., '999.999.999.999' or 'invalid-ip') in the IP field
    await page.fill('[data-testid="device-ip-input"]', '999.999.999.999');
    
    // Enter invalid port number (e.g., '99999' or '-1' or 'abc') in the port field
    await page.fill('[data-testid="device-port-input"]', '99999');
    
    // Trigger validation by clicking outside or tabbing
    await page.click('[data-testid="device-username-input"]');
    
    // Expected Result: Inline validation errors displayed
    await expect(page.locator('[data-testid="ip-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="ip-validation-error"]')).toContainText(/invalid.*ip/i);
    await expect(page.locator('[data-testid="port-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="port-validation-error"]')).toContainText(/port.*range/i);

    // Attempt to submit form
    await page.click('[data-testid="save-device-button"]');
    
    // Expected Result: Submission blocked with error messages
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/invalid.*parameters/i);
    await expect(page.locator('[data-testid="device-configuration-form"]')).toBeVisible();

    // Correct the IP address to valid format (e.g., 192.168.1.100) but leave port as invalid
    await page.fill('[data-testid="device-ip-input"]', '192.168.1.100');
    await page.click('[data-testid="device-username-input"]');
    
    // Verify IP validation error is cleared
    await expect(page.locator('[data-testid="ip-validation-error"]')).not.toBeVisible();
    
    // Port validation error should still be visible
    await expect(page.locator('[data-testid="port-validation-error"]')).toBeVisible();

    // Attempt to submit the form again
    await page.click('[data-testid="save-device-button"]');
    
    // Expected Result: Submission still blocked due to invalid port
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="port-validation-error"]')).toBeVisible();
    
    // Test with invalid IP format 'invalid-ip'
    await page.fill('[data-testid="device-ip-input"]', 'invalid-ip');
    await page.fill('[data-testid="device-port-input"]', '-1');
    await page.click('[data-testid="device-username-input"]');
    
    await expect(page.locator('[data-testid="ip-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="port-validation-error"]')).toBeVisible();
    
    // Test with alphabetic port
    await page.fill('[data-testid="device-port-input"]', 'abc');
    await page.click('[data-testid="device-username-input"]');
    
    await expect(page.locator('[data-testid="port-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="port-validation-error"]')).toContainText(/numeric|number|invalid/i);
  });

  test('Ensure access control restricts unauthorized users (error-case)', async ({ page }) => {
    // Login to the system using non-administrator user credentials
    await page.fill('[data-testid="username-input"]', nonAdminCredentials.username);
    await page.fill('[data-testid="password-input"]', nonAdminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Attempt to navigate to the biometric device configuration page via menu or direct URL
    const configPageURL = `${baseURL}/settings/biometric-devices`;
    await page.goto(configPageURL);
    
    // Expected Result: Access to device configuration page is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/unauthorized|access denied|permission/i);
    await expect(page.locator('[data-testid="device-configuration-form"]')).not.toBeVisible();

    // Attempt to directly access the configuration API endpoint POST /api/biometric/devices
    const postResponse = await page.request.post(`${baseURL}/api/biometric/devices`, {
      data: {
        ip: '192.168.1.100',
        port: 4370,
        username: 'deviceadmin',
        password: 'DevicePass@123'
      }
    });
    
    // Expected Result: API returns unauthorized error
    expect(postResponse.status()).toBe(401);
    const postResponseBody = await postResponse.json();
    expect(postResponseBody).toHaveProperty('error');
    expect(postResponseBody.error).toMatch(/unauthorized|forbidden|access denied/i);

    // Attempt to access the device status API endpoint GET /api/biometric/devices/status
    const getResponse = await page.request.get(`${baseURL}/api/biometric/devices/status`);
    
    // Expected Result: API returns unauthorized error
    expect(getResponse.status()).toBe(401);
    const getResponseBody = await getResponse.json();
    expect(getResponseBody).toHaveProperty('error');
    expect(getResponseBody.error).toMatch(/unauthorized|forbidden|access denied/i);

    // Logout from the non-administrator account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Login to the system using administrator credentials
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the biometric device configuration page
    await page.goto(configPageURL);
    
    // Expected Result: Full access granted to configuration features
    await expect(page.locator('[data-testid="device-configuration-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="device-ip-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="device-port-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="save-device-button"]')).toBeVisible();

    // Access the configuration API endpoints POST /api/biometric/devices
    const adminPostResponse = await page.request.post(`${baseURL}/api/biometric/devices`, {
      data: {
        ip: '192.168.1.101',
        port: 4370,
        username: 'deviceadmin',
        password: 'DevicePass@123'
      }
    });
    
    // Expected Result: API accepts request from administrator
    expect([200, 201]).toContain(adminPostResponse.status());

    // Access GET /api/biometric/devices/status
    const adminGetResponse = await page.request.get(`${baseURL}/api/biometric/devices/status`);
    
    // Expected Result: API returns data for administrator
    expect(adminGetResponse.status()).toBe(200);
    const adminGetResponseBody = await adminGetResponse.json();
    expect(adminGetResponseBody).toBeDefined();
    expect(Array.isArray(adminGetResponseBody) || typeof adminGetResponseBody === 'object').toBeTruthy();
  });
});