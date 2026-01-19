import { test, expect } from '@playwright/test';

test.describe('Biometric Device Failure Notifications', () => {
  const ATTENDANCE_MANAGER_EMAIL = 'attendance.manager@company.com';
  const ATTENDANCE_MANAGER_PASSWORD = 'SecurePass123!';
  const UNAUTHORIZED_USER_EMAIL = 'regular.employee@company.com';
  const UNAUTHORIZED_USER_PASSWORD = 'UserPass123!';
  const BASE_URL = 'https://attendance-system.company.com';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('Validate notification delivery on device failure', async ({ page, context }) => {
    // Login as attendance manager
    await page.fill('[data-testid="email-input"]', ATTENDANCE_MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', ATTENDANCE_MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 1: Verify the current status of biometric devices on the attendance management dashboard
    await page.click('[data-testid="attendance-management-menu"]');
    await page.click('[data-testid="device-status-submenu"]');
    await expect(page.locator('[data-testid="device-status-dashboard"]')).toBeVisible();
    
    const deviceCount = await page.locator('[data-testid="biometric-device-item"]').count();
    expect(deviceCount).toBeGreaterThan(0);

    // Step 2: Note the current time and simulate a biometric device failure
    const failureTime = new Date();
    await page.click('[data-testid="device-simulation-tools"]');
    await page.click('[data-testid="simulate-failure-button"]');
    await page.selectOption('[data-testid="device-select"]', 'device-001');
    await page.click('[data-testid="trigger-failure-button"]');
    await expect(page.locator('[data-testid="failure-simulation-success"]')).toBeVisible();

    // Step 3: Monitor the system for failure detection (within 1 minute)
    await page.waitForTimeout(5000); // Wait for system to detect failure
    await page.reload();
    
    const failedDevice = page.locator('[data-testid="device-001-status"]');
    await expect(failedDevice).toContainText('Failed', { timeout: 60000 });

    // Step 4: Check the attendance manager's email inbox
    const emailPage = await context.newPage();
    await emailPage.goto('https://mail.company.com');
    await emailPage.fill('[data-testid="email-login"]', ATTENDANCE_MANAGER_EMAIL);
    await emailPage.fill('[data-testid="email-password"]', ATTENDANCE_MANAGER_PASSWORD);
    await emailPage.click('[data-testid="email-login-button"]');
    
    await emailPage.waitForSelector('[data-testid="inbox"]');
    const notificationEmail = emailPage.locator('[data-testid="email-subject"]', { hasText: 'Biometric Device Failure Alert' }).first();
    await expect(notificationEmail).toBeVisible({ timeout: 60000 });

    // Step 5: Verify the email notification content
    await notificationEmail.click();
    await expect(emailPage.locator('[data-testid="email-body"]')).toContainText('device-001');
    await expect(emailPage.locator('[data-testid="email-body"]')).toContainText('failure');
    await emailPage.close();

    // Step 6: Return to the attendance management dashboard and check the alerts section
    await page.click('[data-testid="alerts-menu"]');
    await expect(page.locator('[data-testid="alerts-section"]')).toBeVisible();

    // Step 7: Verify the alert notification banner appears on the dashboard
    const alertBanner = page.locator('[data-testid="alert-banner"]');
    await expect(alertBanner).toBeVisible();
    await expect(alertBanner).toContainText('Device Failure');

    // Step 8: Click on the alert to view full details
    const deviceAlert = page.locator('[data-testid="alert-item"]', { hasText: 'device-001' }).first();
    await deviceAlert.click();
    await expect(page.locator('[data-testid="alert-details-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-device-id"]')).toContainText('device-001');
    await expect(page.locator('[data-testid="alert-type"]')).toContainText('Device Failure');
    await expect(page.locator('[data-testid="alert-timestamp"]')).toBeVisible();
  });

  test('Verify alert acknowledgment functionality', async ({ page }) => {
    // Login as attendance manager
    await page.fill('[data-testid="email-input"]', ATTENDANCE_MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', ATTENDANCE_MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 1: Navigate to the alerts section on the attendance management dashboard
    await page.click('[data-testid="alerts-menu"]');
    await expect(page.locator('[data-testid="alerts-section"]')).toBeVisible();

    // Step 2: Identify the unacknowledged device failure alert and click on it to view details
    const unacknowledgedAlert = page.locator('[data-testid="alert-item"][data-status="unacknowledged"]').first();
    await expect(unacknowledgedAlert).toBeVisible();
    const alertId = await unacknowledgedAlert.getAttribute('data-alert-id');
    await unacknowledgedAlert.click();
    await expect(page.locator('[data-testid="alert-details-modal"]')).toBeVisible();

    // Step 3: Click the 'Acknowledge' button on the alert
    await page.click('[data-testid="acknowledge-button"]');
    await expect(page.locator('[data-testid="acknowledgment-form"]')).toBeVisible();

    // Step 4: Enter an optional comment and click 'Confirm'
    await page.fill('[data-testid="acknowledgment-comment"]', 'Investigating device failure');
    await page.click('[data-testid="confirm-acknowledgment-button"]');
    await expect(page.locator('[data-testid="acknowledgment-success-message"]')).toBeVisible();

    // Step 5: Verify the alert status has changed on the dashboard
    await page.click('[data-testid="close-modal-button"]');
    const acknowledgedAlert = page.locator(`[data-testid="alert-item"][data-alert-id="${alertId}"]`);
    await expect(acknowledgedAlert).toHaveAttribute('data-status', 'acknowledged');
    await expect(acknowledgedAlert.locator('[data-testid="alert-status-badge"]')).toContainText('Acknowledged');

    // Step 6: Check the alert details to verify acknowledgment information
    await acknowledgedAlert.click();
    await expect(page.locator('[data-testid="alert-details-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="acknowledged-by"]')).toContainText(ATTENDANCE_MANAGER_EMAIL);
    await expect(page.locator('[data-testid="acknowledgment-comment-display"]')).toContainText('Investigating device failure');
    await expect(page.locator('[data-testid="acknowledgment-timestamp"]')).toBeVisible();
    await page.click('[data-testid="close-modal-button"]');

    // Step 7: Navigate to the system logs or audit trail section
    await page.click('[data-testid="system-logs-menu"]');
    await expect(page.locator('[data-testid="audit-trail-section"]')).toBeVisible();

    // Step 8: Verify the acknowledgment is logged in the audit trail
    const auditLogEntry = page.locator('[data-testid="audit-log-entry"]', { hasText: 'Alert Acknowledged' }).first();
    await expect(auditLogEntry).toBeVisible();
    await expect(auditLogEntry).toContainText(alertId);
    await expect(auditLogEntry).toContainText(ATTENDANCE_MANAGER_EMAIL);

    // Step 9: Verify the acknowledged alert is moved to the appropriate section or filtered view
    await page.click('[data-testid="alerts-menu"]');
    await page.click('[data-testid="filter-acknowledged"]');
    await expect(page.locator(`[data-testid="alert-item"][data-alert-id="${alertId}"]`)).toBeVisible();

    // Step 10: Attempt to acknowledge the same alert again
    await page.locator(`[data-testid="alert-item"][data-alert-id="${alertId}"]`).click();
    await expect(page.locator('[data-testid="alert-details-modal"]')).toBeVisible();
    const acknowledgeButton = page.locator('[data-testid="acknowledge-button"]');
    await expect(acknowledgeButton).toBeDisabled();
  });

  test('Ensure notification access control', async ({ page }) => {
    // Step 1: Open web browser and navigate to the system login page
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Step 2: Enter credentials for an unauthorized user and click Login
    await page.fill('[data-testid="email-input"]', UNAUTHORIZED_USER_EMAIL);
    await page.fill('[data-testid="password-input"]', UNAUTHORIZED_USER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 3: Attempt to navigate to the alerts section
    const alertsMenu = page.locator('[data-testid="alerts-menu"]');
    
    // Step 4: Verify that the alerts menu option is not visible in the navigation for unauthorized users
    await expect(alertsMenu).not.toBeVisible();

    // Step 5: Attempt to access the alerts URL directly
    const alertsResponse = await page.goto(`${BASE_URL}/alerts`);
    
    // Verify access denied or redirect
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');

    // Step 6: Attempt to access the alerts API endpoint directly
    const apiResponse = await page.request.get(`${BASE_URL}/api/notifications/alerts`);
    expect(apiResponse.status()).toBe(403);

    // Step 7: Verify that no email notifications were sent to the unauthorized user
    // This would typically be verified through email system checks or database queries
    // For automation purposes, we verify the user has no access to notification settings
    await page.goto(`${BASE_URL}/dashboard`);
    const notificationSettings = page.locator('[data-testid="notification-settings"]');
    await expect(notificationSettings).not.toBeVisible();

    // Step 8: Log out from the unauthorized user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Step 9: Log in with valid attendance manager credentials
    await page.fill('[data-testid="email-input"]', ATTENDANCE_MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', ATTENDANCE_MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 10: Navigate to the alerts section
    await page.click('[data-testid="alerts-menu"]');
    await expect(page.locator('[data-testid="alerts-section"]')).toBeVisible();

    // Step 11: Verify all alert management features are accessible
    await expect(page.locator('[data-testid="alert-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="filter-options"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-item"]').first()).toBeVisible();
    
    // Verify acknowledge functionality is available
    await page.locator('[data-testid="alert-item"]').first().click();
    await expect(page.locator('[data-testid="alert-details-modal"]')).toBeVisible();
    const acknowledgeBtn = page.locator('[data-testid="acknowledge-button"]');
    await expect(acknowledgeBtn).toBeVisible();
  });
});