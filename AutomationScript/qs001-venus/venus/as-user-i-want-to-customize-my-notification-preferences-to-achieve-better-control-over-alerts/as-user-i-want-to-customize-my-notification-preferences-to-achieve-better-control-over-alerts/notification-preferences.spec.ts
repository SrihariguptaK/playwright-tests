import { test, expect } from '@playwright/test';

test.describe('Notification Preferences Customization', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'testuser@example.com');
    await page.fill('[data-testid="password-input"]', 'TestPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate saving of notification preferences', async ({ page }) => {
    // Step 1: Navigate to notification settings
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-link"]');
    await page.click('[data-testid="notification-settings-tab"]');
    
    // Expected Result: Settings page is displayed
    await expect(page.locator('[data-testid="notification-settings-page"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Notification Settings');

    // Step 2: Select preferred notification channels
    await page.check('[data-testid="notification-channel-email"]');
    await page.check('[data-testid="notification-channel-sms"]');
    await page.check('[data-testid="notification-channel-inapp"]');
    
    // Expected Result: Channels are selected without errors
    await expect(page.locator('[data-testid="notification-channel-email"]')).toBeChecked();
    await expect(page.locator('[data-testid="notification-channel-sms"]')).toBeChecked();
    await expect(page.locator('[data-testid="notification-channel-inapp"]')).toBeChecked();
    
    // Select notification frequency
    await page.selectOption('[data-testid="notification-frequency-select"]', 'immediate');
    await expect(page.locator('[data-testid="notification-frequency-select"]')).toHaveValue('immediate');
    
    // Choose conflict types to be notified about
    await page.check('[data-testid="conflict-type-scheduling"]');
    await page.check('[data-testid="conflict-type-resource"]');
    await page.check('[data-testid="conflict-type-priority"]');
    
    // Step 3: Save preferences
    await page.click('[data-testid="save-preferences-button"]');
    
    // Expected Result: Preferences are saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');
    
    // Verify preferences are retained after page refresh
    await page.reload();
    await expect(page.locator('[data-testid="notification-channel-email"]')).toBeChecked();
    await expect(page.locator('[data-testid="notification-channel-sms"]')).toBeChecked();
    await expect(page.locator('[data-testid="notification-channel-inapp"]')).toBeChecked();
    await expect(page.locator('[data-testid="notification-frequency-select"]')).toHaveValue('immediate');
    
    // Navigate away and return to verify persistence
    await page.click('[data-testid="dashboard-link"]');
    await expect(page).toHaveURL(/.*dashboard/);
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-link"]');
    await page.click('[data-testid="notification-settings-tab"]');
    
    await expect(page.locator('[data-testid="notification-channel-email"]')).toBeChecked();
    await expect(page.locator('[data-testid="notification-channel-sms"]')).toBeChecked();
    await expect(page.locator('[data-testid="notification-channel-inapp"]')).toBeChecked();
  });

  test('Ensure preferences are applied consistently', async ({ page }) => {
    // Step 1: Navigate to notification settings page
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-link"]');
    await page.click('[data-testid="notification-settings-tab"]');
    await expect(page.locator('[data-testid="notification-settings-page"]')).toBeVisible();

    // Step 2: Change notification preferences
    // Initially set to email only
    await page.uncheck('[data-testid="notification-channel-sms"]');
    await page.uncheck('[data-testid="notification-channel-inapp"]');
    await page.check('[data-testid="notification-channel-email"]');
    
    // Now change to email + SMS
    await page.check('[data-testid="notification-channel-sms"]');
    
    // Modify frequency settings
    await page.selectOption('[data-testid="notification-frequency-select"]', 'immediate');
    
    // Select conflict types
    await page.check('[data-testid="conflict-type-scheduling"]');
    await page.check('[data-testid="conflict-type-resource"]');
    
    // Expected Result: Preferences are updated
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');

    // Step 3: Trigger a scheduling conflict
    await page.click('[data-testid="scheduling-link"]');
    await expect(page).toHaveURL(/.*scheduling/);
    
    // Create a double-booking scenario
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="booking-title-input"]', 'Test Meeting 1');
    await page.fill('[data-testid="booking-date-input"]', '2024-02-15');
    await page.fill('[data-testid="booking-time-input"]', '10:00');
    await page.fill('[data-testid="booking-resource-input"]', 'Conference Room A');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="booking-success-message"]')).toBeVisible();
    
    // Create conflicting booking
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="booking-title-input"]', 'Test Meeting 2');
    await page.fill('[data-testid="booking-date-input"]', '2024-02-15');
    await page.fill('[data-testid="booking-time-input"]', '10:00');
    await page.fill('[data-testid="booking-resource-input"]', 'Conference Room A');
    await page.click('[data-testid="save-booking-button"]');
    
    // Expected Result: Notification is sent via the selected channel
    await expect(page.locator('[data-testid="conflict-warning"]')).toBeVisible();
    
    // Check notifications
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();
    
    // Step 4: Verify notification content
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toBeVisible();
    
    // Expected Result: Notification matches user preferences
    await expect(notification).toContainText('Scheduling Conflict');
    await expect(notification).toContainText('Conference Room A');
    await expect(notification).toContainText('2024-02-15');
    await expect(notification).toContainText('10:00');
    
    // Verify notification channels used
    await expect(notification.locator('[data-testid="notification-channel-badge-email"]')).toBeVisible();
    await expect(notification.locator('[data-testid="notification-channel-badge-sms"]')).toBeVisible();
    await expect(notification.locator('[data-testid="notification-channel-badge-inapp"]')).not.toBeVisible();
    
    // Verify notification includes recommended actions
    await notification.click();
    await expect(page.locator('[data-testid="notification-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-details"]')).toContainText('Recommended Actions');
    await expect(page.locator('[data-testid="notification-details"]')).toContainText('Reschedule');
    
    // Trigger another scheduling conflict of a different type (resource conflict)
    await page.click('[data-testid="close-notification-details"]');
    await page.click('[data-testid="scheduling-link"]');
    
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="booking-title-input"]', 'Test Meeting 3');
    await page.fill('[data-testid="booking-date-input"]', '2024-02-16');
    await page.fill('[data-testid="booking-time-input"]', '14:00');
    await page.fill('[data-testid="booking-resource-input"]', 'Projector');
    await page.fill('[data-testid="booking-resource-quantity"]', '5');
    await page.click('[data-testid="save-booking-button"]');
    
    // Verify consistency - check for resource conflict notification
    await page.click('[data-testid="notifications-icon"]');
    const resourceNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Resource Conflict' }).first();
    await expect(resourceNotification).toBeVisible();
    await expect(resourceNotification).toContainText('Projector');
    
    // Verify same channels are used
    await expect(resourceNotification.locator('[data-testid="notification-channel-badge-email"]')).toBeVisible();
    await expect(resourceNotification.locator('[data-testid="notification-channel-badge-sms"]')).toBeVisible();
    await expect(resourceNotification.locator('[data-testid="notification-channel-badge-inapp"]')).not.toBeVisible();
  });
});