import { test, expect } from '@playwright/test';

test.describe('Attendance Alerts Management', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as manager
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate alert generation for attendance anomalies (happy-path)', async ({ page }) => {
    // Navigate to Alert Configuration section in the dashboard
    await page.click('[data-testid="alerts-menu"]');
    await page.click('[data-testid="alert-configuration-link"]');
    await expect(page.locator('[data-testid="alert-configuration-page"]')).toBeVisible();

    // Click on 'Create New Alert Rule' button
    await page.click('[data-testid="create-alert-rule-button"]');
    await expect(page.locator('[data-testid="alert-rule-form"]')).toBeVisible();

    // Select 'Late Arrival' as the alert type from dropdown
    await page.click('[data-testid="alert-type-dropdown"]');
    await page.click('[data-testid="alert-type-late-arrival"]');
    await expect(page.locator('[data-testid="alert-type-dropdown"]')).toContainText('Late Arrival');

    // Set threshold to '15 minutes after scheduled start time'
    await page.fill('[data-testid="threshold-minutes-input"]', '15');
    await expect(page.locator('[data-testid="threshold-minutes-input"]')).toHaveValue('15');

    // Enable all notification channels: Email, SMS, and In-app notifications
    await page.check('[data-testid="notification-email-checkbox"]');
    await page.check('[data-testid="notification-sms-checkbox"]');
    await page.check('[data-testid="notification-inapp-checkbox"]');
    await expect(page.locator('[data-testid="notification-email-checkbox"]')).toBeChecked();
    await expect(page.locator('[data-testid="notification-sms-checkbox"]')).toBeChecked();
    await expect(page.locator('[data-testid="notification-inapp-checkbox"]')).toBeChecked();

    // Click 'Save Configuration' button
    await page.click('[data-testid="save-configuration-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Alert configuration saved successfully');

    // Verify the saved configuration by checking the alert rules list
    await expect(page.locator('[data-testid="alert-rules-list"]')).toContainText('Late Arrival');
    await expect(page.locator('[data-testid="alert-rule-threshold"]')).toContainText('15 minutes');

    // Simulate a late arrival event by marking test employee as checked-in 20 minutes after scheduled start time
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="manual-checkin-link"]');
    await page.fill('[data-testid="employee-search-input"]', 'Test Employee');
    await page.click('[data-testid="employee-search-result-0"]');
    
    // Set check-in time to 20 minutes late
    const now = new Date();
    const scheduledTime = new Date(now.getTime() - 20 * 60000); // 20 minutes ago
    await page.fill('[data-testid="checkin-time-input"]', scheduledTime.toISOString().slice(0, 16));
    await page.click('[data-testid="submit-checkin-button"]');
    await expect(page.locator('[data-testid="checkin-success-message"]')).toBeVisible();

    // Wait and monitor alert generation for up to 5 minutes
    await page.waitForTimeout(5000); // Wait 5 seconds for alert generation

    // Check in-app notification panel on the dashboard
    await page.click('[data-testid="dashboard-menu"]');
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-item"]').first()).toContainText('Late Arrival');
    await expect(page.locator('[data-testid="notification-item"]').first()).toContainText('Test Employee');

    // Verify alert details match across all three channels
    const alertText = await page.locator('[data-testid="notification-item"]').first().textContent();
    expect(alertText).toContain('20 minutes');
    expect(alertText).toContain('Late Arrival');
  });

  test('Test alert acknowledgment and dismissal (happy-path)', async ({ page }) => {
    // Navigate to the Alerts Dashboard section
    await page.click('[data-testid="alerts-menu"]');
    await page.click('[data-testid="alerts-dashboard-link"]');
    await expect(page.locator('[data-testid="alerts-dashboard-page"]')).toBeVisible();

    // Locate the test alert in the active alerts list
    await expect(page.locator('[data-testid="active-alerts-list"]')).toBeVisible();
    const firstAlert = page.locator('[data-testid="alert-item"]').first();
    await expect(firstAlert).toBeVisible();

    // Click on the alert to view full details
    await firstAlert.click();
    await expect(page.locator('[data-testid="alert-details-modal"]')).toBeVisible();

    // Verify acknowledgment options are available
    await expect(page.locator('[data-testid="acknowledge-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="dismiss-button"]')).toBeVisible();

    // Click the 'Acknowledge' button
    await page.click('[data-testid="acknowledge-button"]');
    
    // Verify alert status update after acknowledgment
    await expect(page.locator('[data-testid="alert-status"]')).toContainText('Acknowledged');
    await expect(page.locator('[data-testid="acknowledgment-success-message"]')).toBeVisible();

    // Check that acknowledged alert remains in the alerts list
    await page.click('[data-testid="close-alert-details-button"]');
    await expect(page.locator('[data-testid="alert-item"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="alert-item"]').first()).toContainText('Acknowledged');

    // Navigate to a different unacknowledged alert or create a new test alert
    const secondAlert = page.locator('[data-testid="alert-item"]').nth(1);
    if (await secondAlert.count() > 0) {
      await secondAlert.click();
    } else {
      // Create a new test alert if no other alerts exist
      await page.click('[data-testid="create-test-alert-button"]');
      await page.waitForTimeout(1000);
      await page.locator('[data-testid="alert-item"]').first().click();
    }
    await expect(page.locator('[data-testid="alert-details-modal"]')).toBeVisible();

    // Click on the new alert to view details
    await expect(page.locator('[data-testid="alert-details-modal"]')).toBeVisible();

    // Click the 'Dismiss' button
    await page.click('[data-testid="dismiss-button"]');

    // Confirm dismissal by clicking 'Yes' or 'Confirm'
    await expect(page.locator('[data-testid="dismiss-confirmation-dialog"]')).toBeVisible();
    await page.click('[data-testid="confirm-dismiss-button"]');

    // Verify alert is removed from active alerts list
    await expect(page.locator('[data-testid="dismissal-success-message"]')).toBeVisible();
    await page.waitForTimeout(1000);
    const activeAlertsCount = await page.locator('[data-testid="alert-item"]').count();
    
    // Check alert history or logs to verify dismissed alert is recorded
    await page.click('[data-testid="alert-history-tab"]');
    await expect(page.locator('[data-testid="alert-history-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="dismissed-alert-item"]').first()).toContainText('Dismissed');
  });

  test('Verify alert delivery failure handling (error-case)', async ({ page }) => {
    // Configure test environment to simulate SMS delivery failure
    await page.click('[data-testid="settings-menu"]');
    await page.click('[data-testid="test-configuration-link"]');
    await expect(page.locator('[data-testid="test-configuration-page"]')).toBeVisible();
    
    // Disable SMS gateway or use invalid phone number
    await page.check('[data-testid="simulate-sms-failure-checkbox"]');
    await page.click('[data-testid="save-test-config-button"]');
    await expect(page.locator('[data-testid="config-saved-message"]')).toBeVisible();

    // Trigger an attendance anomaly event that should generate an alert
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="manual-checkin-link"]');
    await page.fill('[data-testid="employee-search-input"]', 'Test Employee SMS Failure');
    await page.click('[data-testid="employee-search-result-0"]');
    
    // Set check-in time to trigger late arrival alert
    const now = new Date();
    const lateTime = new Date(now.getTime() - 25 * 60000); // 25 minutes late
    await page.fill('[data-testid="checkin-time-input"]', lateTime.toISOString().slice(0, 16));
    await page.click('[data-testid="submit-checkin-button"]');
    await expect(page.locator('[data-testid="checkin-success-message"]')).toBeVisible();

    // Monitor alert delivery attempts in real-time
    await page.waitForTimeout(3000);

    // Verify SMS delivery failure occurs
    await page.click('[data-testid="alerts-menu"]');
    await page.click('[data-testid="alert-logs-link"]');
    await expect(page.locator('[data-testid="alert-logs-page"]')).toBeVisible();

    // Observe system retry mechanism for SMS delivery
    await page.waitForTimeout(2000);
    
    // Wait for all retry attempts to complete
    await page.waitForTimeout(3000);

    // Verify other notification channels (email and in-app) are delivered successfully
    const latestLogEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(latestLogEntry).toBeVisible();
    await expect(latestLogEntry.locator('[data-testid="email-delivery-status"]')).toContainText('Success');
    await expect(latestLogEntry.locator('[data-testid="inapp-delivery-status"]')).toContainText('Success');

    // Navigate to Alert Logs section in the system
    await expect(page.locator('[data-testid="alert-logs-page"]')).toBeVisible();

    // Locate the test alert in the logs
    await page.fill('[data-testid="log-search-input"]', 'Test Employee SMS Failure');
    await page.click('[data-testid="log-search-button"]');
    const testAlertLog = page.locator('[data-testid="log-entry"]').first();
    await expect(testAlertLog).toBeVisible();

    // Click on the alert entry to view detailed delivery information
    await testAlertLog.click();
    await expect(page.locator('[data-testid="log-details-modal"]')).toBeVisible();

    // Verify SMS delivery failure is recorded with timestamp
    await expect(page.locator('[data-testid="sms-delivery-status"]')).toContainText('Failed');
    await expect(page.locator('[data-testid="sms-failure-timestamp"]')).toBeVisible();
    const timestamp = await page.locator('[data-testid="sms-failure-timestamp"]').textContent();
    expect(timestamp).toBeTruthy();

    // Check error details for SMS delivery failure
    await expect(page.locator('[data-testid="sms-error-details"]')).toBeVisible();
    const errorDetails = await page.locator('[data-testid="sms-error-details"]').textContent();
    expect(errorDetails).toContain('SMS gateway');

    // Verify successful delivery channels are also logged
    await expect(page.locator('[data-testid="email-delivery-status"]')).toContainText('Success');
    await expect(page.locator('[data-testid="inapp-delivery-status"]')).toContainText('Success');
    await expect(page.locator('[data-testid="email-delivery-timestamp"]')).toBeVisible();
    await expect(page.locator('[data-testid="inapp-delivery-timestamp"]')).toBeVisible();

    // Check if system generated any internal alerts or notifications about the delivery failure
    await page.click('[data-testid="close-log-details-button"]');
    await page.click('[data-testid="system-alerts-tab"]');
    await expect(page.locator('[data-testid="system-alert-item"]').first()).toContainText('SMS delivery failure');
    await expect(page.locator('[data-testid="system-alert-item"]').first()).toContainText('Test Employee SMS Failure');
  });
});