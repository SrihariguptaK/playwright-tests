import { test, expect } from '@playwright/test';

test.describe('Schedule Notifications', () => {
  test.beforeEach(async ({ page }) => {
    // Login as scheduler
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate notification sent on schedule creation', async ({ page }) => {
    // Step 1: Navigate to the schedule creation page and select an employee
    await page.goto('/schedules/create');
    await expect(page.locator('[data-testid="schedule-creation-page"]')).toBeVisible();
    
    await page.click('[data-testid="employee-select"]');
    await page.click('[data-testid="employee-option-john-doe"]');
    
    // Step 2: Fill in all required schedule details
    await page.fill('[data-testid="shift-date-input"]', '2024-02-15');
    await page.fill('[data-testid="start-time-input"]', '09:00');
    await page.fill('[data-testid="end-time-input"]', '17:00');
    await page.fill('[data-testid="shift-notes-input"]', 'Regular shift');
    
    // Step 3: Click Save button to create the schedule
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Schedule is saved
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule created successfully');
    await expect(page.locator('[data-testid="schedule-list"]')).toContainText('John Doe');
    
    // Step 4: Navigate to notification delivery logs
    await page.goto('/admin/notification-logs');
    await expect(page.locator('[data-testid="notification-logs-page"]')).toBeVisible();
    
    // Step 5: Search for notification event related to newly created schedule
    await page.fill('[data-testid="log-search-input"]', 'Schedule created');
    await page.click('[data-testid="search-button"]');
    
    // Expected Result: Notification event is logged
    await expect(page.locator('[data-testid="notification-log-entry"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="notification-log-entry"]').first()).toContainText('Schedule created');
    await expect(page.locator('[data-testid="notification-status"]').first()).toContainText('Delivered');
    await expect(page.locator('[data-testid="notification-recipient"]').first()).toContainText('john.doe@example.com');
    
    // Step 6: Verify email notification delivery
    const emailLogEntry = page.locator('[data-testid="notification-log-entry"]').filter({ hasText: 'email' }).first();
    await expect(emailLogEntry).toBeVisible();
    await expect(emailLogEntry.locator('[data-testid="delivery-channel"]')).toContainText('email');
    await expect(emailLogEntry.locator('[data-testid="delivery-status"]')).toContainText('Sent');
    
    // Step 7: Verify in-app notification delivery
    const inAppLogEntry = page.locator('[data-testid="notification-log-entry"]').filter({ hasText: 'in-app' }).first();
    await expect(inAppLogEntry).toBeVisible();
    await expect(inAppLogEntry.locator('[data-testid="delivery-channel"]')).toContainText('in-app');
    await expect(inAppLogEntry.locator('[data-testid="delivery-status"]')).toContainText('Delivered');
    
    // Expected Result: User receives timely notifications (within 1 minute)
    const timestamp = await emailLogEntry.locator('[data-testid="delivery-timestamp"]').textContent();
    const deliveryTime = new Date(timestamp || '');
    const currentTime = new Date();
    const timeDifferenceInSeconds = (currentTime.getTime() - deliveryTime.getTime()) / 1000;
    expect(timeDifferenceInSeconds).toBeLessThan(60);
  });

  test('Verify user can configure notification preferences', async ({ page }) => {
    // Step 1: Navigate to user profile settings
    await page.click('[data-testid="user-profile-icon"]');
    await page.click('[data-testid="profile-settings-menu-item"]');
    
    // Expected Result: Notification preferences section is visible
    await expect(page).toHaveURL(/.*profile\/settings/);
    await expect(page.locator('[data-testid="profile-settings-page"]')).toBeVisible();
    
    // Step 2: Locate and click on notification preferences section
    await page.click('[data-testid="notification-preferences-tab"]');
    await expect(page.locator('[data-testid="notification-preferences-section"]')).toBeVisible();
    
    // Step 3: Update notification channels - toggle email off, keep in-app on
    const emailToggle = page.locator('[data-testid="email-notification-toggle"]');
    const inAppToggle = page.locator('[data-testid="in-app-notification-toggle"]');
    
    // Check current state and toggle email notifications off
    const isEmailEnabled = await emailToggle.isChecked();
    if (isEmailEnabled) {
      await emailToggle.click();
    }
    await expect(emailToggle).not.toBeChecked();
    
    // Ensure in-app notifications are on
    const isInAppEnabled = await inAppToggle.isChecked();
    if (!isInAppEnabled) {
      await inAppToggle.click();
    }
    await expect(inAppToggle).toBeChecked();
    
    // Step 4: Save notification preferences
    await page.click('[data-testid="save-preferences-button"]');
    
    // Expected Result: Preferences are saved successfully
    await expect(page.locator('[data-testid="success-notification"]')).toContainText('Preferences saved successfully');
    
    // Verify preferences persist after page reload
    await page.reload();
    await page.click('[data-testid="notification-preferences-tab"]');
    await expect(page.locator('[data-testid="email-notification-toggle"]')).not.toBeChecked();
    await expect(page.locator('[data-testid="in-app-notification-toggle"]')).toBeChecked();
    
    // Step 5: Trigger notification event by creating a schedule
    await page.goto('/schedules/create');
    await page.click('[data-testid="employee-select"]');
    await page.click('[data-testid="employee-option-jane-smith"]');
    await page.fill('[data-testid="shift-date-input"]', '2024-02-16');
    await page.fill('[data-testid="start-time-input"]', '10:00');
    await page.fill('[data-testid="end-time-input"]', '18:00');
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule created successfully');
    
    // Step 6: Verify notification sent according to updated preferences
    await page.goto('/admin/notification-logs');
    await page.fill('[data-testid="log-search-input"]', 'jane.smith@example.com');
    await page.click('[data-testid="search-button"]');
    
    // Expected Result: In-app notification is received
    const inAppNotification = page.locator('[data-testid="notification-log-entry"]').filter({ hasText: 'in-app' }).first();
    await expect(inAppNotification).toBeVisible();
    await expect(inAppNotification.locator('[data-testid="delivery-status"]')).toContainText('Delivered');
    
    // Expected Result: Email notification is NOT sent
    const emailNotificationCount = await page.locator('[data-testid="notification-log-entry"]').filter({ hasText: 'email' }).count();
    expect(emailNotificationCount).toBe(0);
    
    // Verify in-app notification center shows the notification
    await page.click('[data-testid="user-profile-icon"]');
    await page.click('[data-testid="notifications-menu-item"]');
    await expect(page.locator('[data-testid="notification-center"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-item"]').first()).toContainText('Schedule created');
  });
});