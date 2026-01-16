import { test, expect } from '@playwright/test';

test.describe('Scheduling Conflict Alerts - Real-time Notifications', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling application
    await page.goto('/dashboard');
    // Login as scheduler user
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();
  });

  test('Verify alert delivery within 5 seconds', async ({ page }) => {
    // Navigate to scheduling page
    await page.goto('/scheduling');
    await expect(page.locator('[data-testid="scheduling-page"]')).toBeVisible();

    // Create a scheduling conflict by booking the same resource for overlapping time slots
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Conference Room A');
    await page.fill('[data-testid="start-time-input"]', '2024-02-15T10:00');
    await page.fill('[data-testid="end-time-input"]', '2024-02-15T11:00');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="booking-success-message"]')).toBeVisible();

    // Create overlapping booking to trigger conflict
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Conference Room A');
    await page.fill('[data-testid="start-time-input"]', '2024-02-15T10:30');
    await page.fill('[data-testid="end-time-input"]', '2024-02-15T11:30');
    
    // Start timer immediately after conflict is created
    const startTime = Date.now();
    await page.click('[data-testid="save-booking-button"]');

    // Monitor all configured notification channels for alert delivery
    const alertLocator = page.locator('[data-testid="alert-notification"]');
    await alertLocator.waitFor({ state: 'visible', timeout: 5000 });
    
    // Stop timer when alert is received and record the delivery time
    const endTime = Date.now();
    const deliveryTime = endTime - startTime;

    // Expected Result: Conflict detected
    await expect(page.locator('[data-testid="conflict-detected-message"]')).toBeVisible();
    
    // Expected Result: Alert received within 5 seconds
    expect(deliveryTime).toBeLessThanOrEqual(5000);
    await expect(alertLocator).toContainText('Scheduling Conflict');

    // Verify alert delivery confirmation in system logs
    await page.click('[data-testid="system-logs-link"]');
    await expect(page.locator('[data-testid="alert-delivery-log"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="alert-delivery-status"]').first()).toContainText('Delivered');
  });

  test('Validate alert content and user acknowledgment', async ({ page }) => {
    // Trigger a conflict to receive alert
    await page.goto('/scheduling');
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Meeting Room B');
    await page.fill('[data-testid="start-time-input"]', '2024-02-16T14:00');
    await page.fill('[data-testid="end-time-input"]', '2024-02-16T15:00');
    await page.click('[data-testid="save-booking-button"]');

    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Meeting Room B');
    await page.fill('[data-testid="start-time-input"]', '2024-02-16T14:30');
    await page.fill('[data-testid="end-time-input"]', '2024-02-16T15:30');
    await page.click('[data-testid="save-booking-button"]');

    // Open the received alert notification
    const alertNotification = page.locator('[data-testid="alert-notification"]');
    await alertNotification.waitFor({ state: 'visible', timeout: 5000 });
    await alertNotification.click();

    // Review alert content for conflict details
    const alertDetails = page.locator('[data-testid="alert-details-modal"]');
    await expect(alertDetails).toBeVisible();
    
    // Expected Result: Alert contains detailed conflict information
    await expect(page.locator('[data-testid="conflict-resource-name"]')).toContainText('Meeting Room B');
    await expect(page.locator('[data-testid="conflict-time-slot-1"]')).toContainText('14:00');
    await expect(page.locator('[data-testid="conflict-time-slot-2"]')).toContainText('14:30');
    await expect(page.locator('[data-testid="affected-bookings"]')).toBeVisible();

    // Verify alert includes actionable information such as links to affected bookings
    const bookingLink = page.locator('[data-testid="affected-booking-link"]').first();
    await expect(bookingLink).toBeVisible();
    await expect(bookingLink).toHaveAttribute('href', /.+/);

    // Click the 'Acknowledge' button on the alert
    await page.click('[data-testid="acknowledge-alert-button"]');
    await expect(page.locator('[data-testid="alert-acknowledged-message"]')).toBeVisible();

    // Click the 'Dismiss' button to remove alert from active notifications
    await page.click('[data-testid="dismiss-alert-button"]');
    
    // Expected Result: Alert status updated and removed from active notifications
    await expect(alertDetails).not.toBeVisible();
    await expect(page.locator('[data-testid="active-alerts-count"]')).toContainText('0');

    // Navigate to alert history to verify dismissed alert is recorded
    await page.click('[data-testid="alert-history-link"]');
    await expect(page.locator('[data-testid="alert-history-page"]')).toBeVisible();
    const dismissedAlert = page.locator('[data-testid="alert-history-item"]').first();
    await expect(dismissedAlert).toBeVisible();
    await expect(dismissedAlert.locator('[data-testid="alert-status"]')).toContainText('Dismissed');
  });

  test('Test user alert preference configuration', async ({ page }) => {
    // Navigate to user profile or settings page
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-link"]');
    await expect(page.locator('[data-testid="settings-page"]')).toBeVisible();

    // Locate alert preferences configuration section
    await page.click('[data-testid="alert-preferences-tab"]');
    const alertPreferencesSection = page.locator('[data-testid="alert-preferences-section"]');
    await expect(alertPreferencesSection).toBeVisible();

    // Select specific notification channels (enable in-app and email, disable SMS)
    const inAppCheckbox = page.locator('[data-testid="notification-channel-in-app"]');
    const emailCheckbox = page.locator('[data-testid="notification-channel-email"]');
    const smsCheckbox = page.locator('[data-testid="notification-channel-sms"]');

    await inAppCheckbox.check();
    await emailCheckbox.check();
    await smsCheckbox.uncheck();

    // Click 'Save' or 'Update Preferences' button
    await page.click('[data-testid="save-preferences-button"]');
    
    // Expected Result: Preferences saved successfully
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toBeVisible();

    // Refresh the page and verify saved preferences persist
    await page.reload();
    await page.click('[data-testid="alert-preferences-tab"]');
    await expect(page.locator('[data-testid="notification-channel-in-app"]')).toBeChecked();
    await expect(page.locator('[data-testid="notification-channel-email"]')).toBeChecked();
    await expect(page.locator('[data-testid="notification-channel-sms"]')).not.toBeChecked();

    // Trigger a scheduling conflict to test alert delivery
    await page.goto('/scheduling');
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Training Room C');
    await page.fill('[data-testid="start-time-input"]', '2024-02-17T09:00');
    await page.fill('[data-testid="end-time-input"]', '2024-02-17T10:00');
    await page.click('[data-testid="save-booking-button"]');

    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Training Room C');
    await page.fill('[data-testid="start-time-input"]', '2024-02-17T09:30');
    await page.fill('[data-testid="end-time-input"]', '2024-02-17T10:30');
    await page.click('[data-testid="save-booking-button"]');

    // Monitor all notification channels for alert delivery
    // Expected Result: Alert sent via configured channels only
    await expect(page.locator('[data-testid="alert-notification"]')).toBeVisible({ timeout: 5000 });

    // Verify in-app notification is received
    await expect(page.locator('[data-testid="in-app-alert"]')).toBeVisible();

    // Navigate to notification logs to verify channels used
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="notification-logs-link"]');
    const latestNotificationLog = page.locator('[data-testid="notification-log-entry"]').first();
    await expect(latestNotificationLog).toBeVisible();
    await expect(latestNotificationLog.locator('[data-testid="channel-in-app"]')).toContainText('Sent');
    await expect(latestNotificationLog.locator('[data-testid="channel-email"]')).toContainText('Sent');
    
    // Verify no alerts are sent to disabled notification channels
    await expect(latestNotificationLog.locator('[data-testid="channel-sms"]')).toContainText('Disabled');
  });
});