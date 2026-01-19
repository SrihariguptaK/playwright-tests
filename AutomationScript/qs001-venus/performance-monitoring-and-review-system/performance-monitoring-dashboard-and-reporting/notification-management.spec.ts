import { test, expect } from '@playwright/test';

test.describe('Performance Review Notification Management', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto('/login');
  });

  test('Validate scheduled notification delivery', async ({ page }) => {
    // Step 1: Log in as Performance Manager with valid credentials
    await page.fill('[data-testid="email-input"]', 'performance.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePassword123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to the Review Cycle Management section
    await page.click('[data-testid="review-cycles-menu"]');
    await expect(page.locator('[data-testid="review-cycles-page"]')).toBeVisible();

    // Step 3: Select a specific review cycle for notification configuration
    await page.click('[data-testid="review-cycle-q1-2024"]');
    await expect(page.locator('[data-testid="review-cycle-details"]')).toBeVisible();

    // Step 4: Click on Configure Notifications button
    await page.click('[data-testid="configure-notifications-button"]');
    await expect(page.locator('[data-testid="notification-config-modal"]')).toBeVisible();

    // Step 5: Set notification schedule to trigger in 5 minutes from current time
    const futureTime = new Date(Date.now() + 5 * 60 * 1000);
    const timeString = futureTime.toTimeString().slice(0, 5);
    await page.fill('[data-testid="notification-time-input"]', timeString);
    await expect(page.locator('[data-testid="notification-time-input"]')).toHaveValue(timeString);

    // Step 6: Select both Email and In-app notification delivery methods
    await page.check('[data-testid="notification-method-email"]');
    await page.check('[data-testid="notification-method-inapp"]');
    await expect(page.locator('[data-testid="notification-method-email"]')).toBeChecked();
    await expect(page.locator('[data-testid="notification-method-inapp"]')).toBeChecked();

    // Step 7: Click Save to save the notification schedule
    await page.click('[data-testid="save-notification-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule is saved successfully');

    // Step 8: Wait for the scheduled notification time (5 minutes)
    // For testing purposes, we'll use a shorter wait or mock the time
    await page.waitForTimeout(5 * 60 * 1000);

    // Step 9: Check the manager's email inbox for the notification
    // Note: In real scenario, this would integrate with email testing service
    // For now, we'll verify the notification was sent via API or UI indicator
    await page.goto('/notifications/sent');
    await expect(page.locator('[data-testid="sent-notification-email"]').first()).toBeVisible();

    // Step 10: Check the in-app notification center
    await page.click('[data-testid="notification-bell-icon"]');
    await expect(page.locator('[data-testid="notification-center"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-item"]').first()).toContainText('Review Cycle');

    // Step 11: Click on the in-app notification to acknowledge it
    await page.click('[data-testid="notification-item"]');
    await expect(page.locator('[data-testid="notification-acknowledged"]')).toBeVisible();

    // Step 12: Navigate to notification logs or audit trail
    await page.goto('/notifications/logs');
    await expect(page.locator('[data-testid="notification-logs-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-entry-acknowledged"]').first()).toContainText('Acknowledged');
  });

  test('Verify user can customize notification preferences', async ({ page }) => {
    // Step 1: Log in with valid user credentials
    await page.fill('[data-testid="email-input"]', 'user@company.com');
    await page.fill('[data-testid="password-input"]', 'UserPassword123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to user profile or settings menu
    await page.click('[data-testid="user-profile-menu"]');
    await expect(page.locator('[data-testid="profile-dropdown"]')).toBeVisible();

    // Step 3: Click on Notification Preferences option
    await page.click('[data-testid="notification-preferences-link"]');
    await expect(page.locator('[data-testid="notification-preferences-page"]')).toBeVisible();

    // Step 4: Review the current notification preferences displayed
    const emailNotificationStatus = await page.locator('[data-testid="email-notification-toggle"]').isChecked();
    const inappNotificationStatus = await page.locator('[data-testid="inapp-notification-toggle"]').isChecked();
    expect(emailNotificationStatus).toBeDefined();
    expect(inappNotificationStatus).toBeDefined();

    // Step 5: Change email notification setting from enabled to disabled for review cycle reminders
    await page.uncheck('[data-testid="email-notification-review-cycle"]');
    await expect(page.locator('[data-testid="email-notification-review-cycle"]')).not.toBeChecked();

    // Step 6: Change in-app notification setting from disabled to enabled for performance metric updates
    await page.check('[data-testid="inapp-notification-performance-metrics"]');
    await expect(page.locator('[data-testid="inapp-notification-performance-metrics"]')).toBeChecked();

    // Step 7: Modify notification frequency preference from immediate to daily digest
    await page.selectOption('[data-testid="notification-frequency-select"]', 'daily-digest');
    await expect(page.locator('[data-testid="notification-frequency-select"]')).toHaveValue('daily-digest');

    // Step 8: Click Save or Update Preferences button
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toContainText('Settings are saved and applied');

    // Step 9: Log out and log back in to verify persistence
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    await page.fill('[data-testid="email-input"]', 'user@company.com');
    await page.fill('[data-testid="password-input"]', 'UserPassword123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 10: Navigate back to Notification Preferences page
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="notification-preferences-link"]');
    await expect(page.locator('[data-testid="notification-preferences-page"]')).toBeVisible();

    // Verify preferences persisted
    await expect(page.locator('[data-testid="email-notification-review-cycle"]')).not.toBeChecked();
    await expect(page.locator('[data-testid="inapp-notification-performance-metrics"]')).toBeChecked();
    await expect(page.locator('[data-testid="notification-frequency-select"]')).toHaveValue('daily-digest');

    // Step 11: Trigger a test notification for review cycle reminders
    await page.click('[data-testid="test-notification-review-cycle-button"]');
    await expect(page.locator('[data-testid="test-notification-sent-message"]')).toBeVisible();

    // Step 12: Trigger a test notification for performance metric updates
    await page.click('[data-testid="test-notification-performance-metrics-button"]');
    await expect(page.locator('[data-testid="test-notification-sent-message"]')).toBeVisible();

    // Step 13: Verify that suppressed notifications are not delivered
    // Check that email notification for review cycle was not sent
    await page.goto('/notifications/inbox');
    const emailNotifications = await page.locator('[data-testid="email-notification-item"]').count();
    const reviewCycleEmailNotification = await page.locator('[data-testid="email-notification-item"]', { hasText: 'Review Cycle' }).count();
    expect(reviewCycleEmailNotification).toBe(0);

    // Verify in-app notification for performance metrics was delivered
    await page.click('[data-testid="notification-bell-icon"]');
    await expect(page.locator('[data-testid="notification-item"]', { hasText: 'Performance Metric' })).toBeVisible();
  });
});