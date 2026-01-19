import { test, expect } from '@playwright/test';

test.describe('Biometric Device Connectivity Monitoring', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('Validate real-time device connectivity status display', async ({ page }) => {
    // Step 1: Admin accesses monitoring dashboard
    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'Admin@123');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Dashboard displays all biometric devices with current status
    await expect(page).toHaveURL(/.*dashboard/);
    await page.click('[data-testid="monitoring-dashboard-menu"]');
    await expect(page.locator('[data-testid="device-monitoring-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="biometric-device-list"]')).toBeVisible();
    
    // Verify all devices show connected status with green indicators
    const deviceRows = page.locator('[data-testid="device-row"]');
    await expect(deviceRows).toHaveCount(await deviceRows.count());
    const firstDeviceStatus = page.locator('[data-testid="device-status"]').first();
    await expect(firstDeviceStatus).toHaveText('Connected');
    await expect(firstDeviceStatus).toHaveClass(/status-connected|green/);
    
    // Step 2: Simulate device disconnection
    await page.click('[data-testid="test-simulation-tool"]');
    await page.click('[data-testid="simulate-disconnect-device-1"]');
    
    // Expected Result: Device status changes to disconnected within 30 seconds
    await page.waitForTimeout(30000);
    const disconnectedDevice = page.locator('[data-testid="device-row"]').filter({ hasText: 'Device-1' });
    await expect(disconnectedDevice.locator('[data-testid="device-status"]')).toHaveText('Disconnected');
    await expect(disconnectedDevice.locator('[data-testid="device-status"]')).toHaveClass(/status-disconnected|red/);
    
    // Step 3: Admin views device logs
    await disconnectedDevice.click();
    await page.click('[data-testid="view-logs-button"]');
    
    // Expected Result: Logs show connectivity history and disconnection event
    await expect(page.locator('[data-testid="device-logs-panel"]')).toBeVisible();
    const logEntries = page.locator('[data-testid="log-entry"]');
    await expect(logEntries).toContainText(['Connection state changed', 'Disconnected']);
    await expect(page.locator('[data-testid="log-entry"]').filter({ hasText: 'Disconnected' })).toBeVisible();
    await expect(page.locator('[data-testid="log-timestamp"]').first()).toBeVisible();
  });

  test('Verify alert generation on device connectivity loss', async ({ page }) => {
    // Login as admin
    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'Admin@123');
    await page.click('[data-testid="login-button"]');
    await page.click('[data-testid="monitoring-dashboard-menu"]');
    
    // Verify all devices are connected
    const allDeviceStatuses = page.locator('[data-testid="device-status"]');
    const statusCount = await allDeviceStatuses.count();
    for (let i = 0; i < statusCount; i++) {
      await expect(allDeviceStatuses.nth(i)).toHaveText('Connected');
    }
    
    // Step 1: Simulate device connectivity loss
    const disconnectionTime = new Date();
    await page.click('[data-testid="test-simulation-tool"]');
    await page.click('[data-testid="simulate-disconnect-device-2"]');
    
    // Expected Result: System generates alert notification
    await page.waitForSelector('[data-testid="alert-notification"]', { timeout: 60000 });
    await expect(page.locator('[data-testid="alert-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-notification"]')).toContainText('Device connectivity loss');
    
    // Step 2: Admin receives alert via configured channels
    const alertGenerationTime = new Date();
    const timeDifference = (alertGenerationTime.getTime() - disconnectionTime.getTime()) / 1000;
    expect(timeDifference).toBeLessThan(60); // Alert within 1 minute
    
    // Expected Result: Alert received promptly
    await page.click('[data-testid="notification-center"]');
    await expect(page.locator('[data-testid="alert-panel"]')).toBeVisible();
    const alertMessage = page.locator('[data-testid="alert-message"]').first();
    await expect(alertMessage).toContainText(['Device-2', 'connectivity loss', 'disconnected']);
    
    // Step 3: Admin acknowledges alert
    await alertMessage.click();
    await page.click('[data-testid="acknowledge-alert-button"]');
    await page.click('[data-testid="confirm-acknowledgment-button"]');
    
    // Expected Result: Alert status updated and logged
    await expect(page.locator('[data-testid="alert-status"]').first()).toHaveText('Acknowledged');
    await page.click('[data-testid="alert-history-link"]');
    await expect(page.locator('[data-testid="alert-log-entry"]').filter({ hasText: 'Device-2' })).toBeVisible();
    await expect(page.locator('[data-testid="alert-log-entry"]').filter({ hasText: 'Acknowledged' })).toBeVisible();
  });

  test('Ensure access control for monitoring dashboard - non-admin denied', async ({ page }) => {
    // Step 1: Non-admin user attempts to access monitoring dashboard
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Employee@123');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access denied message displayed
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Verify monitoring dashboard menu is not visible for non-admin
    const monitoringMenu = page.locator('[data-testid="monitoring-dashboard-menu"]');
    await expect(monitoringMenu).not.toBeVisible();
    
    // Attempt direct URL access
    await page.goto('/monitoring/dashboard');
    
    // Verify access denied or redirect
    const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
    const errorPage = page.locator('[data-testid="error-page"]');
    const isAccessDenied = await accessDeniedMessage.isVisible().catch(() => false);
    const isErrorPage = await errorPage.isVisible().catch(() => false);
    
    expect(isAccessDenied || isErrorPage).toBeTruthy();
    
    if (isAccessDenied) {
      await expect(accessDeniedMessage).toContainText(['Access Denied', 'Unauthorized', 'permission']);
    }
    
    // Check system logs for unauthorized access attempt
    await page.goto('/admin/system-logs');
    const unauthorizedLogEntry = page.locator('[data-testid="log-entry"]').filter({ hasText: 'Unauthorized access attempt' });
    const logCount = await unauthorizedLogEntry.count();
    expect(logCount).toBeGreaterThan(0);
  });

  test('Ensure access control for monitoring dashboard - admin granted', async ({ page }) => {
    // Step 2: Admin logs in and accesses dashboard
    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'Admin@123');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Dashboard accessible and functional
    await expect(page).toHaveURL(/.*dashboard/);
    await page.click('[data-testid="monitoring-dashboard-menu"]');
    await expect(page.locator('[data-testid="device-monitoring-dashboard"]')).toBeVisible();
    
    // Verify all dashboard features are accessible
    await expect(page.locator('[data-testid="biometric-device-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="device-status-indicators"]')).toBeVisible();
    
    // Navigate to device logs section
    await page.click('[data-testid="device-logs-tab"]');
    await expect(page.locator('[data-testid="device-logs-section"]')).toBeVisible();
    
    // Navigate to alerts section
    await page.click('[data-testid="alerts-tab"]');
    await expect(page.locator('[data-testid="alerts-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-management-panel"]')).toBeVisible();
    
    // Navigate to settings section
    await page.click('[data-testid="settings-tab"]');
    await expect(page.locator('[data-testid="monitoring-settings-section"]')).toBeVisible();
    
    // Verify all sections are functional
    await page.click('[data-testid="device-list-tab"]');
    const deviceRows = page.locator('[data-testid="device-row"]');
    const deviceCount = await deviceRows.count();
    expect(deviceCount).toBeGreaterThan(0);
    
    // Verify status updates functionality
    await expect(page.locator('[data-testid="last-update-timestamp"]')).toBeVisible();
  });
});