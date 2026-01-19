import { test, expect } from '@playwright/test';

test.describe('Biometric Device Monitoring - Story 6', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const ADMIN_EMAIL = 'admin@company.com';
  const ADMIN_PASSWORD = 'Admin@123';
  const UNAUTHORIZED_EMAIL = 'employee@company.com';
  const UNAUTHORIZED_PASSWORD = 'Employee@123';

  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate real-time device connectivity status display (happy-path)', async ({ page }) => {
    // Step 1: Open web browser and navigate to the system login page
    await expect(page).toHaveURL(/.*login/);
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Step 2: Enter valid system administrator credentials and click Login button
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 3: Navigate to the device monitoring dashboard from the main menu
    await page.click('[data-testid="monitoring-menu"]');
    await page.click('[data-testid="device-monitoring-link"]');
    await expect(page).toHaveURL(/.*monitoring\/devices/);
    
    // Expected Result: Dashboard displays all biometric devices with current status
    await expect(page.locator('[data-testid="device-monitoring-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="device-list"]')).toBeVisible();
    const deviceItems = page.locator('[data-testid="device-item"]');
    await expect(deviceItems).toHaveCount(await deviceItems.count());
    
    // Verify each device has status indicator
    const firstDevice = deviceItems.first();
    await expect(firstDevice.locator('[data-testid="device-status"]')).toBeVisible();
    await expect(firstDevice.locator('[data-testid="device-name"]')).toBeVisible();

    // Step 4: Verify the status refresh interval by observing the timestamp updates
    const initialTimestamp = await page.locator('[data-testid="last-updated-timestamp"]').textContent();
    await page.waitForTimeout(31000); // Wait for 31 seconds to exceed 30-second refresh interval
    const updatedTimestamp = await page.locator('[data-testid="last-updated-timestamp"]').textContent();
    expect(initialTimestamp).not.toBe(updatedTimestamp);

    // Step 5: Simulate device disconnection
    await page.click('[data-testid="test-simulation-tool"]');
    await page.click('[data-testid="simulate-disconnect-button"]');
    await page.selectOption('[data-testid="device-select"]', { label: 'Device-001' });
    await page.click('[data-testid="apply-simulation-button"]');

    // Expected Result: Device status changes to 'Disconnected' and alert is generated
    await expect(page.locator('[data-testid="device-item"][data-device-id="Device-001"] [data-testid="device-status"]')).toHaveText('Disconnected');
    await expect(page.locator('[data-testid="alert-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-panel"]')).toContainText('Device-001');

    // Step 6: Verify the alert details by clicking on the generated alert
    await page.click('[data-testid="alert-item"]');
    await expect(page.locator('[data-testid="alert-details-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-device-name"]')).toContainText('Device-001');
    await expect(page.locator('[data-testid="alert-type"]')).toContainText('Disconnection');
    await expect(page.locator('[data-testid="alert-timestamp"]')).toBeVisible();

    // Step 7: Click the 'Acknowledge' button on the alert
    await page.click('[data-testid="acknowledge-alert-button"]');

    // Expected Result: Alert status changes to 'Acknowledged'
    await expect(page.locator('[data-testid="alert-status"]')).toHaveText('Acknowledged');

    // Step 8: Verify the acknowledged alert appears in the alerts history section
    await page.click('[data-testid="close-alert-details"]');
    await page.click('[data-testid="alerts-history-tab"]');
    await expect(page.locator('[data-testid="alerts-history-list"]')).toBeVisible();
    const acknowledgedAlert = page.locator('[data-testid="history-alert-item"]').filter({ hasText: 'Device-001' });
    await expect(acknowledgedAlert).toBeVisible();
    await expect(acknowledgedAlert.locator('[data-testid="history-alert-status"]')).toHaveText('Acknowledged');
  });

  test('Verify alert generation and notification (happy-path)', async ({ page }) => {
    // Login as administrator
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to device monitoring dashboard
    await page.click('[data-testid="monitoring-menu"]');
    await page.click('[data-testid="device-monitoring-link"]');
    await expect(page).toHaveURL(/.*monitoring\/devices/);

    // Step 1: From the device monitoring dashboard, identify a currently connected biometric device
    const connectedDevice = page.locator('[data-testid="device-item"]').filter({ has: page.locator('[data-testid="device-status"]', { hasText: 'Connected' }) }).first();
    await expect(connectedDevice).toBeVisible();
    const deviceName = await connectedDevice.locator('[data-testid="device-name"]').textContent();

    // Step 2: Disconnect the selected biometric device from the network
    await page.click('[data-testid="test-simulation-tool"]');
    await page.click('[data-testid="simulate-disconnect-button"]');
    await page.selectOption('[data-testid="device-select"]', { label: deviceName || 'Device-001' });
    await page.click('[data-testid="apply-simulation-button"]');

    // Step 3: Monitor the dashboard for alert generation
    // Expected Result: System generates alert and notifies administrators
    await expect(page.locator('[data-testid="alert-notification"]')).toBeVisible({ timeout: 10000 });

    // Step 4: Check the alerts panel for the new alert entry
    await expect(page.locator('[data-testid="alert-panel"]')).toBeVisible();
    const newAlert = page.locator('[data-testid="alert-item"]').filter({ hasText: deviceName || 'Device-001' });
    await expect(newAlert).toBeVisible();
    await expect(newAlert.locator('[data-testid="alert-severity"]')).toHaveText('Critical');

    // Step 5: Verify that administrators are notified through configured notification channels
    await expect(page.locator('[data-testid="notification-badge"]')).toBeVisible();
    const notificationCount = await page.locator('[data-testid="notification-badge"]').textContent();
    expect(parseInt(notificationCount || '0')).toBeGreaterThan(0);

    // Step 6: Resolve the device issue by reconnecting the biometric device to the network
    await page.click('[data-testid="test-simulation-tool"]');
    await page.click('[data-testid="simulate-reconnect-button"]');
    await page.selectOption('[data-testid="device-select"]', { label: deviceName || 'Device-001' });
    await page.click('[data-testid="apply-simulation-button"]');

    // Step 7: Monitor the dashboard for device status update
    // Expected Result: Alert is cleared and device status updates to 'Connected'
    await expect(page.locator(`[data-testid="device-item"][data-device-name="${deviceName}"] [data-testid="device-status"]`)).toHaveText('Connected', { timeout: 35000 });

    // Step 8: Verify the alert history shows the complete lifecycle of the alert
    await page.click('[data-testid="alerts-history-tab"]');
    const historicalAlert = page.locator('[data-testid="history-alert-item"]').filter({ hasText: deviceName || 'Device-001' }).first();
    await expect(historicalAlert).toBeVisible();
    await historicalAlert.click();
    await expect(page.locator('[data-testid="alert-lifecycle-timeline"]')).toBeVisible();
    await expect(page.locator('[data-testid="lifecycle-event"]').filter({ hasText: 'Disconnected' })).toBeVisible();
    await expect(page.locator('[data-testid="lifecycle-event"]').filter({ hasText: 'Reconnected' })).toBeVisible();
  });

  test('Ensure access control for monitoring dashboard (error-case)', async ({ page }) => {
    // Step 1: Open web browser and navigate to the system login page
    await expect(page).toHaveURL(/.*login/);

    // Step 2: Enter credentials for an unauthorized user
    await page.fill('[data-testid="email-input"]', UNAUTHORIZED_EMAIL);
    await page.fill('[data-testid="password-input"]', UNAUTHORIZED_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 3: Attempt to navigate to the device monitoring dashboard
    // Expected Result: Access to monitoring dashboard is denied
    
    // Step 4: Verify that the device monitoring menu option is not visible
    const monitoringMenu = page.locator('[data-testid="monitoring-menu"]');
    await expect(monitoringMenu).not.toBeVisible();

    // Attempt direct URL access
    await page.goto(`${BASE_URL}/monitoring/devices`);
    
    // Verify access denied message or redirect
    const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
    const unauthorizedError = page.locator('text=/Access Denied|Unauthorized|403/');
    
    await expect(accessDeniedMessage.or(unauthorizedError)).toBeVisible({ timeout: 5000 });
    
    // Verify user is redirected away from monitoring dashboard
    await expect(page).not.toHaveURL(/.*monitoring\/devices/);

    // Step 5: Log out from the unauthorized user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 6: Enter valid system administrator credentials and click Login
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 7: Verify that the device monitoring option is visible in the navigation menu
    // Expected Result: Access to monitoring dashboard is granted
    await expect(page.locator('[data-testid="monitoring-menu"]')).toBeVisible();

    // Step 8: Click on the device monitoring dashboard link
    await page.click('[data-testid="monitoring-menu"]');
    await page.click('[data-testid="device-monitoring-link"]');
    await expect(page).toHaveURL(/.*monitoring\/devices/);

    // Step 9: Verify all monitoring features are accessible
    await expect(page.locator('[data-testid="device-monitoring-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="device-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="alerts-history-tab"]')).toBeVisible();
    
    // Verify historical logs are accessible
    await page.click('[data-testid="alerts-history-tab"]');
    await expect(page.locator('[data-testid="alerts-history-list"]')).toBeVisible();
  });
});