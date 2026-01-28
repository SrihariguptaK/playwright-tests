import { test, expect } from '@playwright/test';

test.describe('Story-5: Scheduling Conflict Notifications', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'testuser@example.com');
    await page.fill('[data-testid="password-input"]', 'TestPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL('/dashboard');
  });

  test('Validate notification delivery for detected conflicts (happy-path)', async ({ page }) => {
    // Step 1: Create a new event that overlaps with an existing event
    await page.goto('/calendar');
    
    // Create first event
    await page.click('[data-testid="create-event-button"]');
    await page.fill('[data-testid="event-title-input"]', 'Existing Meeting');
    await page.fill('[data-testid="event-date-input"]', '2024-02-15');
    await page.fill('[data-testid="event-start-time-input"]', '10:00');
    await page.fill('[data-testid="event-end-time-input"]', '11:00');
    await page.click('[data-testid="save-event-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Create overlapping event to trigger conflict
    await page.click('[data-testid="create-event-button"]');
    await page.fill('[data-testid="event-title-input"]', 'Conflicting Meeting');
    await page.fill('[data-testid="event-date-input"]', '2024-02-15');
    await page.fill('[data-testid="event-start-time-input"]', '10:30');
    await page.fill('[data-testid="event-end-time-input"]', '11:30');
    await page.click('[data-testid="save-event-button"]');
    
    // Expected Result: Notification is generated
    await expect(page.locator('[data-testid="conflict-notification"]')).toBeVisible({ timeout: 3000 });
    
    // Step 2: Check user notification preferences
    await page.goto('/profile/settings');
    await page.click('[data-testid="notifications-tab"]');
    
    // Expected Result: Notification is sent via the preferred channel
    const preferredChannel = await page.locator('[data-testid="preferred-notification-channel"]').inputValue();
    expect(preferredChannel).toBeTruthy();
    
    // Step 3: Verify notification content
    await page.goto('/notifications');
    const notificationItem = page.locator('[data-testid="notification-item"]').first();
    await expect(notificationItem).toBeVisible();
    
    // Expected Result: Notification contains correct conflict details
    await notificationItem.click();
    await expect(page.locator('[data-testid="notification-title"]')).toContainText('Scheduling Conflict');
    await expect(page.locator('[data-testid="notification-details"]')).toContainText('Existing Meeting');
    await expect(page.locator('[data-testid="notification-details"]')).toContainText('Conflicting Meeting');
    await expect(page.locator('[data-testid="notification-details"]')).toContainText('10:30');
    await expect(page.locator('[data-testid="notification-details"]')).toContainText('2024-02-15');
    
    // Verify notification delivery status
    await page.goto('/admin/notifications');
    const deliveryStatus = page.locator('[data-testid="notification-delivery-status"]').first();
    await expect(deliveryStatus).toContainText('Delivered');
  });

  test('Ensure notifications are not sent for non-conflicting events (edge-case)', async ({ page }) => {
    // Step 1: Schedule the first event
    await page.goto('/calendar');
    await page.click('[data-testid="create-event-button"]');
    await page.fill('[data-testid="event-title-input"]', 'Meeting A');
    await page.fill('[data-testid="event-date-input"]', '2024-02-20');
    await page.fill('[data-testid="event-start-time-input"]', '10:00');
    await page.fill('[data-testid="event-end-time-input"]', '11:00');
    await page.click('[data-testid="save-event-button"]');
    
    // Expected Result: No conflict is detected
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-notification"]')).not.toBeVisible();
    
    // Step 2: Schedule a second non-overlapping event
    await page.click('[data-testid="create-event-button"]');
    await page.fill('[data-testid="event-title-input"]', 'Meeting B');
    await page.fill('[data-testid="event-date-input"]', '2024-02-20');
    await page.fill('[data-testid="event-start-time-input"]', '14:00');
    await page.fill('[data-testid="event-end-time-input"]', '15:00');
    await page.click('[data-testid="save-event-button"]');
    
    // Expected Result: No conflict is detected
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-notification"]')).not.toBeVisible();
    
    // Wait to ensure no delayed notifications
    await page.waitForTimeout(3000);
    
    // Step 3: Check notification logs
    await page.goto('/admin/notifications/logs');
    
    // Expected Result: No notifications are sent
    const notificationLogs = page.locator('[data-testid="notification-log-entry"]');
    const logCount = await notificationLogs.count();
    
    // Filter for conflict notifications only
    const conflictNotifications = page.locator('[data-testid="notification-log-entry"][data-type="conflict"]');
    await expect(conflictNotifications).toHaveCount(0);
    
    // Step 4: Review user notifications
    await page.goto('/notifications');
    
    // Expected Result: User has no new notifications
    const noNotificationsMessage = page.locator('[data-testid="no-notifications-message"]');
    const notificationsList = page.locator('[data-testid="notification-item"]');
    
    const hasNotifications = await notificationsList.count();
    if (hasNotifications === 0) {
      await expect(noNotificationsMessage).toBeVisible();
    } else {
      // Verify no conflict notifications exist
      const conflictNotifs = page.locator('[data-testid="notification-item"][data-type="conflict"]');
      await expect(conflictNotifs).toHaveCount(0);
    }
    
    // Verify system conflict detection logic
    await page.goto('/calendar');
    const meetingA = page.locator('[data-testid="event-item"]', { hasText: 'Meeting A' });
    const meetingB = page.locator('[data-testid="event-item"]', { hasText: 'Meeting B' });
    
    await expect(meetingA).toBeVisible();
    await expect(meetingB).toBeVisible();
    
    // Verify no conflict indicator on events
    await expect(meetingA.locator('[data-testid="conflict-indicator"]')).not.toBeVisible();
    await expect(meetingB.locator('[data-testid="conflict-indicator"]')).not.toBeVisible();
  });
});