import { test, expect } from '@playwright/test';

test.describe('Scheduling Conflict Alerts', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application
    await page.goto('/dashboard');
    // Assume user is already logged in or handle login here
  });

  test('Validate alert notification for detected conflict', async ({ page }) => {
    // Step 1: Trigger or simulate a scheduling conflict
    await page.click('[data-testid="schedule-menu"]');
    await page.click('[data-testid="create-appointment-btn"]');
    
    // Fill in appointment details that will create a conflict
    await page.fill('[data-testid="appointment-resource"]', 'Conference Room A');
    await page.fill('[data-testid="appointment-date"]', '2024-03-15');
    await page.fill('[data-testid="appointment-time"]', '10:00 AM');
    await page.fill('[data-testid="appointment-duration"]', '60');
    await page.click('[data-testid="save-appointment-btn"]');
    
    // Expected Result: Alert notification is generated
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 5000 });
    
    // Step 2: Navigate to user profile settings and check notification preferences
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-option"]');
    await page.click('[data-testid="notification-settings-tab"]');
    
    // Expected Result: User preferences are correctly configured
    const notificationPreferences = page.locator('[data-testid="notification-preferences-section"]');
    await expect(notificationPreferences).toBeVisible();
    
    const inAppEnabled = await page.locator('[data-testid="in-app-notification-toggle"]').isChecked();
    const emailEnabled = await page.locator('[data-testid="email-notification-toggle"]').isChecked();
    const smsEnabled = await page.locator('[data-testid="sms-notification-toggle"]').isChecked();
    
    expect(inAppEnabled || emailEnabled || smsEnabled).toBeTruthy();
    
    // Step 3: Check the chosen notification method for the alert
    await page.click('[data-testid="notification-center-icon"]');
    
    // Expected Result: Alert contains accurate conflict details
    const alertNotification = page.locator('[data-testid="alert-notification-item"]').first();
    await expect(alertNotification).toBeVisible();
    await expect(alertNotification).toContainText('scheduling conflict');
    await expect(alertNotification).toContainText('Conference Room A');
    await expect(alertNotification).toContainText('2024-03-15');
    await expect(alertNotification).toContainText('10:00 AM');
    
    // Verify alert was received within 5 seconds (already checked with timeout above)
    const alertTimestamp = await alertNotification.locator('[data-testid="alert-timestamp"]').textContent();
    expect(alertTimestamp).toBeTruthy();
  });

  test('Ensure alerts are customizable', async ({ page }) => {
    // Step 1: Navigate to user settings menu and select Alert Settings
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-option"]');
    
    // Expected Result: Alert settings page is displayed
    await page.click('[data-testid="alert-settings-tab"]');
    const alertSettingsPage = page.locator('[data-testid="alert-settings-page"]');
    await expect(alertSettingsPage).toBeVisible();
    await expect(page.locator('h1, h2').filter({ hasText: /Alert Settings|Notification Preferences/i })).toBeVisible();
    
    // Step 2: Modify alert preferences
    // Enable SMS alerts
    const smsToggle = page.locator('[data-testid="sms-notification-toggle"]');
    const isSmsEnabled = await smsToggle.isChecked();
    if (!isSmsEnabled) {
      await smsToggle.check();
    }
    await expect(smsToggle).toBeChecked();
    
    // Disable email alerts
    const emailToggle = page.locator('[data-testid="email-notification-toggle"]');
    const isEmailEnabled = await emailToggle.isChecked();
    if (isEmailEnabled) {
      await emailToggle.uncheck();
    }
    await expect(emailToggle).not.toBeChecked();
    
    // Keep in-app enabled
    const inAppToggle = page.locator('[data-testid="in-app-notification-toggle"]');
    const isInAppEnabled = await inAppToggle.isChecked();
    if (!isInAppEnabled) {
      await inAppToggle.check();
    }
    await expect(inAppToggle).toBeChecked();
    
    // Save preferences
    await page.click('[data-testid="save-preferences-btn"]');
    
    // Expected Result: Preferences are saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/saved|updated successfully/i);
    
    // Step 3: Trigger a scheduling conflict after preference changes
    await page.click('[data-testid="schedule-menu"]');
    await page.click('[data-testid="create-appointment-btn"]');
    
    // Create conflicting appointment
    await page.fill('[data-testid="appointment-resource"]', 'Meeting Room B');
    await page.fill('[data-testid="appointment-date"]', '2024-03-20');
    await page.fill('[data-testid="appointment-time"]', '02:00 PM');
    await page.fill('[data-testid="appointment-duration"]', '90');
    await page.click('[data-testid="save-appointment-btn"]');
    
    // Expected Result: Alert is sent according to new preferences (in-app and SMS, not email)
    await page.click('[data-testid="notification-center-icon"]');
    const newAlert = page.locator('[data-testid="alert-notification-item"]').first();
    await expect(newAlert).toBeVisible({ timeout: 5000 });
    await expect(newAlert).toContainText('scheduling conflict');
    
    // Verify SMS notification was sent (check notification log or indicator)
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-option"]');
    await page.click('[data-testid="notification-history-tab"]');
    
    const notificationHistory = page.locator('[data-testid="notification-history-list"]');
    await expect(notificationHistory).toBeVisible();
    
    const latestNotification = notificationHistory.locator('[data-testid="notification-history-item"]').first();
    await expect(latestNotification).toContainText('SMS');
    await expect(latestNotification).toContainText('In-App');
    await expect(latestNotification).not.toContainText('Email');
  });
});