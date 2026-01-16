import { test, expect } from '@playwright/test';

test.describe('Comment Notifications for Tasks', () => {
  test.beforeEach(async ({ page }) => {
    // Login as employee
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'employee@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify notification sent on new comment addition', async ({ page, context }) => {
    // Navigate to a specific task
    await page.goto('/tasks/task-123');
    await expect(page.locator('[data-testid="task-title"]')).toBeVisible();

    // Open a second page to simulate another employee adding a comment
    const secondPage = await context.newPage();
    await secondPage.goto('/login');
    await secondPage.fill('[data-testid="email-input"]', 'commenter@example.com');
    await secondPage.fill('[data-testid="password-input"]', 'password123');
    await secondPage.click('[data-testid="login-button"]');
    await expect(secondPage).toHaveURL(/.*dashboard/);

    // Employee adds new comment to task
    await secondPage.goto('/tasks/task-123');
    await secondPage.fill('[data-testid="comment-input"]', 'This is a new comment on the task');
    await secondPage.click('[data-testid="add-comment-button"]');

    // Verify comment was added
    await expect(secondPage.locator('[data-testid="comment-text"]').last()).toContainText('This is a new comment on the task');

    // Check notification on original page
    await page.waitForTimeout(2000); // Wait for notification to be delivered
    await page.reload();

    // Verify notification appears
    const notificationBell = page.locator('[data-testid="notification-bell"]');
    await expect(notificationBell).toBeVisible();
    await expect(notificationBell.locator('[data-testid="notification-badge"]')).toBeVisible();

    // Click notification bell to view notifications
    await notificationBell.click();
    await expect(page.locator('[data-testid="notification-dropdown"]')).toBeVisible();

    // Verify notification content is accurate and timely
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toContainText('new comment');
    await expect(notification).toContainText('task-123');
    await expect(notification.locator('[data-testid="notification-timestamp"]')).toBeVisible();

    await secondPage.close();
  });

  test('Test comment notification preference settings', async ({ page }) => {
    // Navigate to notification preferences
    await page.goto('/settings/notifications');
    await expect(page.locator('[data-testid="notification-settings-title"]')).toBeVisible();

    // Employee updates comment notification preferences
    const commentNotificationToggle = page.locator('[data-testid="comment-notification-toggle"]');
    const emailNotificationCheckbox = page.locator('[data-testid="email-notification-checkbox"]');
    const inAppNotificationCheckbox = page.locator('[data-testid="in-app-notification-checkbox"]');

    // Enable comment notifications
    if (!(await commentNotificationToggle.isChecked())) {
      await commentNotificationToggle.check();
    }

    // Select notification channels
    await emailNotificationCheckbox.check();
    await inAppNotificationCheckbox.check();

    // Save preferences
    await page.click('[data-testid="save-preferences-button"]');

    // Verify preferences saved
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');

    // Reload page to verify persistence
    await page.reload();
    await expect(commentNotificationToggle).toBeChecked();
    await expect(emailNotificationCheckbox).toBeChecked();
    await expect(inAppNotificationCheckbox).toBeChecked();

    // Navigate to a task and add a comment
    await page.goto('/tasks/task-456');
    await page.fill('[data-testid="comment-input"]', 'Testing notification preferences');
    await page.click('[data-testid="add-comment-button"]');

    // Verify comment added
    await expect(page.locator('[data-testid="comment-text"]').last()).toContainText('Testing notification preferences');

    // Check that notification was sent according to preferences
    await page.waitForTimeout(2000);
    await page.goto('/notifications');
    await expect(page.locator('[data-testid="notification-list"]')).toBeVisible();
    const latestNotification = page.locator('[data-testid="notification-item"]').first();
    await expect(latestNotification).toContainText('Testing notification preferences');

    // Verify notification channels used
    await expect(latestNotification.locator('[data-testid="notification-channel-email"]')).toBeVisible();
    await expect(latestNotification.locator('[data-testid="notification-channel-in-app"]')).toBeVisible();
  });

  test('Ensure unauthorized users do not receive comment notifications', async ({ page, context }) => {
    // Login as authorized employee assigned to task
    await page.goto('/tasks/task-789');
    await expect(page.locator('[data-testid="task-title"]')).toBeVisible();

    // Get initial notification count
    const notificationBell = page.locator('[data-testid="notification-bell"]');
    const initialBadge = await notificationBell.locator('[data-testid="notification-badge"]').textContent().catch(() => '0');

    // Open new page for unauthorized user
    const unauthorizedPage = await context.newPage();
    await unauthorizedPage.goto('/login');
    await unauthorizedPage.fill('[data-testid="email-input"]', 'unauthorized@example.com');
    await unauthorizedPage.fill('[data-testid="password-input"]', 'password123');
    await unauthorizedPage.click('[data-testid="login-button"]');
    await expect(unauthorizedPage).toHaveURL(/.*dashboard/);

    // Unauthorized user attempts to access task
    await unauthorizedPage.goto('/tasks/task-789');

    // Verify unauthorized user cannot access task or receives access denied
    const accessDenied = unauthorizedPage.locator('[data-testid="access-denied-message"]');
    const taskNotFound = unauthorizedPage.locator('[data-testid="task-not-found"]');
    
    await expect(accessDenied.or(taskNotFound)).toBeVisible();

    // Add comment from authorized user
    await page.fill('[data-testid="comment-input"]', 'Comment for authorized users only');
    await page.click('[data-testid="add-comment-button"]');
    await expect(page.locator('[data-testid="comment-text"]').last()).toContainText('Comment for authorized users only');

    // Wait for notification processing
    await page.waitForTimeout(2000);

    // Verify unauthorized user did not receive notification
    await unauthorizedPage.goto('/notifications');
    
    // Check if notifications page is accessible
    const unauthorizedNotifications = unauthorizedPage.locator('[data-testid="notification-list"]');
    if (await unauthorizedNotifications.isVisible()) {
      // If accessible, verify no notification for task-789
      const taskNotifications = unauthorizedPage.locator('[data-testid="notification-item"]').filter({ hasText: 'task-789' });
      await expect(taskNotifications).toHaveCount(0);
    }

    // Verify no notification badge for unauthorized user
    const unauthorizedBell = unauthorizedPage.locator('[data-testid="notification-bell"]');
    const unauthorizedBadge = unauthorizedBell.locator('[data-testid="notification-badge"]');
    
    // Badge should not exist or show 0
    const badgeCount = await unauthorizedBadge.count();
    if (badgeCount > 0) {
      const badgeText = await unauthorizedBadge.textContent();
      expect(badgeText).toBe('0');
    }

    await unauthorizedPage.close();
  });
});