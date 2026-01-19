import { test, expect } from '@playwright/test';

test.describe('Story-17: Dismiss Notifications', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as employee
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate notification dismissal process', async ({ page }) => {
    // Navigate to the notifications section on the dashboard
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();

    // Identify a notification to dismiss and note its details
    const notificationItem = page.locator('[data-testid="notification-item"]').first();
    await expect(notificationItem).toBeVisible();
    const notificationId = await notificationItem.getAttribute('data-notification-id');
    const notificationContent = await notificationItem.locator('[data-testid="notification-content"]').textContent();

    // Click the 'Dismiss' button on the selected notification
    await notificationItem.locator('[data-testid="dismiss-button"]').click();

    // Expected Result: Confirmation dialog is displayed
    const confirmationDialog = page.locator('[data-testid="confirmation-dialog"]');
    await expect(confirmationDialog).toBeVisible();
    await expect(confirmationDialog.locator('[data-testid="dialog-message"]')).toContainText('Are you sure you want to dismiss this notification?');

    // Click the 'Confirm' button in the confirmation dialog
    await page.click('[data-testid="confirm-dismiss-button"]');

    // Expected Result: Notification is removed from list
    await expect(notificationItem).not.toBeVisible({ timeout: 3000 });

    // Verify the notification with the same ID is no longer in the list
    const dismissedNotification = page.locator(`[data-notification-id="${notificationId}"]`);
    await expect(dismissedNotification).toHaveCount(0);

    // Refresh the page to confirm the dismissal persists
    await page.reload();
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator(`[data-notification-id="${notificationId}"]`)).toHaveCount(0);

    // Verify backend status updated (check via API call)
    const response = await page.request.get(`/api/notifications/${notificationId}`);
    expect(response.ok()).toBeTruthy();
    const notificationData = await response.json();
    expect(notificationData.status).toBe('dismissed');
  });

  test('Verify dismissal action completes within performance SLA', async ({ page }) => {
    // Navigate to the notifications section on the dashboard
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();

    // Get the first notification to dismiss
    const notificationItem = page.locator('[data-testid="notification-item"]').first();
    await expect(notificationItem).toBeVisible();

    // Start timing the dismissal action
    const startTime = Date.now();

    // Set up API response listener to capture timing
    const apiResponsePromise = page.waitForResponse(
      response => response.url().includes('/api/notifications/dismiss') && response.status() === 200
    );

    // Click the 'Dismiss' button on the notification
    await notificationItem.locator('[data-testid="dismiss-button"]').click();

    // Confirm dismissal in the dialog
    await expect(page.locator('[data-testid="confirmation-dialog"]')).toBeVisible();
    await page.click('[data-testid="confirm-dismiss-button"]');

    // Wait for API response and measure time
    const apiResponse = await apiResponsePromise;
    const apiEndTime = Date.now();
    const apiResponseTime = apiEndTime - startTime;

    // Verify notification is removed from UI
    await expect(notificationItem).not.toBeVisible({ timeout: 3000 });
    const endTime = Date.now();
    const totalTime = endTime - startTime;

    // Expected Result: Action completes within 2 seconds (2000ms)
    expect(totalTime).toBeLessThan(2000);
    expect(apiResponseTime).toBeLessThan(2000);

    // Test additional notifications for consistent performance
    for (let i = 0; i < 2; i++) {
      const nextNotification = page.locator('[data-testid="notification-item"]').first();
      const notificationExists = await nextNotification.count();
      
      if (notificationExists > 0) {
        const iterationStartTime = Date.now();
        
        const iterationApiPromise = page.waitForResponse(
          response => response.url().includes('/api/notifications/dismiss') && response.status() === 200
        );

        await nextNotification.locator('[data-testid="dismiss-button"]').click();
        await page.click('[data-testid="confirm-dismiss-button"]');
        
        await iterationApiPromise;
        await expect(nextNotification).not.toBeVisible({ timeout: 3000 });
        
        const iterationEndTime = Date.now();
        const iterationTime = iterationEndTime - iterationStartTime;
        
        expect(iterationTime).toBeLessThan(2000);
      }
    }
  });

  test('Verify confirmation dialog can be cancelled', async ({ page }) => {
    // Navigate to the notifications section
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();

    // Get initial notification count
    const initialCount = await page.locator('[data-testid="notification-item"]').count();
    const notificationItem = page.locator('[data-testid="notification-item"]').first();
    const notificationId = await notificationItem.getAttribute('data-notification-id');

    // Click dismiss button
    await notificationItem.locator('[data-testid="dismiss-button"]').click();
    await expect(page.locator('[data-testid="confirmation-dialog"]')).toBeVisible();

    // Click cancel button
    await page.click('[data-testid="cancel-dismiss-button"]');

    // Verify notification is still visible
    await expect(page.locator(`[data-notification-id="${notificationId}"]`)).toBeVisible();
    const finalCount = await page.locator('[data-testid="notification-item"]').count();
    expect(finalCount).toBe(initialCount);
  });

  test('Verify dismissed notification status in backend', async ({ page }) => {
    // Navigate to notifications
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();

    // Get notification details
    const notificationItem = page.locator('[data-testid="notification-item"]').first();
    const notificationId = await notificationItem.getAttribute('data-notification-id');

    // Dismiss the notification
    await notificationItem.locator('[data-testid="dismiss-button"]').click();
    await page.click('[data-testid="confirm-dismiss-button"]');
    await expect(notificationItem).not.toBeVisible();

    // Verify backend status via API
    const response = await page.request.get(`/api/notifications/${notificationId}`);
    expect(response.ok()).toBeTruthy();
    const notificationData = await response.json();
    expect(notificationData.status).toBe('dismissed');
    expect(notificationData.dismissedAt).toBeTruthy();
  });
});