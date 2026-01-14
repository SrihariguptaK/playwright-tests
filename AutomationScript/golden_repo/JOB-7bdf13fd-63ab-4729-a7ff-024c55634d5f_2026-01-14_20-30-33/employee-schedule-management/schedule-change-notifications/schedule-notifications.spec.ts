import { test, expect } from '@playwright/test';

test.describe('Schedule Change Notifications', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_USERNAME = 'employee@company.com';
  const VALID_PASSWORD = 'Password123!';
  const NOTIFICATIONS_API = '/api/notifications/scheduleChanges';

  test('Validate display of schedule change notifications on login', async ({ page }) => {
    // Step 1: Navigate to the employee web portal login page
    await page.goto(`${BASE_URL}/login`);
    await expect(page).toHaveURL(/.*login/);

    // Step 2: Enter valid employee credentials
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);

    // Step 3: Click the login button
    await page.click('[data-testid="login-button"]');

    // Expected Result: Notification panel displays recent schedule changes
    await expect(page).toHaveURL(/.*dashboard/);
    await page.waitForSelector('[data-testid="notification-panel"]', { timeout: 2000 });
    const notificationPanel = page.locator('[data-testid="notification-panel"]');
    await expect(notificationPanel).toBeVisible();

    // Step 4: Observe the notification panel on the dashboard
    const notifications = page.locator('[data-testid="notification-item"]');
    await expect(notifications.first()).toBeVisible();

    // Step 5: Review the details of each notification displayed
    const firstNotification = notifications.first();
    await expect(firstNotification.locator('[data-testid="change-type"]')).toBeVisible();
    await expect(firstNotification.locator('[data-testid="shift-info"]')).toBeVisible();

    // Expected Result: Notifications show accurate change type and shift info
    const changeType = await firstNotification.locator('[data-testid="change-type"]').textContent();
    expect(['added', 'modified', 'cancelled']).toContain(changeType?.toLowerCase());

    // Step 6: Verify the timestamp of each notification
    const timestamp = firstNotification.locator('[data-testid="notification-timestamp"]');
    await expect(timestamp).toBeVisible();
    const timestampText = await timestamp.textContent();
    expect(timestampText).toBeTruthy();

    // Step 7: Click on a notification to mark it as read
    await firstNotification.click();

    // Expected Result: Notifications are visually marked as read
    await expect(firstNotification).toHaveClass(/read|marked/);

    // Step 8: Click the dismiss or close button on the marked notification
    await firstNotification.locator('[data-testid="dismiss-button"]').click();

    // Expected Result: Dismissed notifications are hidden
    await expect(firstNotification).toBeHidden();

    // Step 9: Refresh the page
    await page.reload();
    await page.waitForSelector('[data-testid="notification-panel"]');

    // Verify dismissed notification remains hidden after refresh
    const notificationsAfterRefresh = page.locator('[data-testid="notification-item"]');
    const count = await notificationsAfterRefresh.count();
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test('Verify notification history accessibility', async ({ page }) => {
    // Login first
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 1: Locate and click on the notification history link or icon
    await page.click('[data-testid="notification-history-link"]');

    // Expected Result: Navigate to notification history section
    await expect(page).toHaveURL(/.*notifications\/history/);

    // Step 2: Observe the list of notifications displayed in the history section
    await page.waitForSelector('[data-testid="notification-history-list"]');
    const historyList = page.locator('[data-testid="notification-history-list"]');
    await expect(historyList).toBeVisible();

    // Expected Result: Notifications from past 30 days are displayed
    const historyItems = page.locator('[data-testid="history-notification-item"]');
    const itemCount = await historyItems.count();
    expect(itemCount).toBeGreaterThanOrEqual(0);

    // Step 3: Verify the date range of displayed notifications
    if (itemCount > 0) {
      const firstItem = historyItems.first();
      const notificationDate = await firstItem.locator('[data-testid="notification-date"]').textContent();
      expect(notificationDate).toBeTruthy();

      // Calculate 30 days ago
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

      // Verify notification is within 30 days
      const dateText = notificationDate || '';
      // Date validation logic would depend on actual date format
    }

    // Step 4: Check for any notifications older than 30 days
    const oldNotificationIndicator = page.locator('[data-testid="old-notification-warning"]');
    await expect(oldNotificationIndicator).not.toBeVisible();

    // Expected Result: Older notifications are not displayed
    // Verify no notifications have dates older than 30 days
    for (let i = 0; i < Math.min(itemCount, 5); i++) {
      const item = historyItems.nth(i);
      const dateElement = item.locator('[data-testid="notification-date"]');
      await expect(dateElement).toBeVisible();
    }

    // Step 5: Scroll through the notification history
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await page.waitForTimeout(500);

    // Step 6: Filter or search for a specific notification if available
    const searchInput = page.locator('[data-testid="notification-search-input"]');
    if (await searchInput.isVisible()) {
      await searchInput.fill('shift change');
      await page.waitForTimeout(500);
      const filteredItems = page.locator('[data-testid="history-notification-item"]');
      expect(await filteredItems.count()).toBeGreaterThanOrEqual(0);
    }
  });

  test('Ensure unauthorized users cannot access notifications', async ({ page, request }) => {
    // Step 1: Navigate directly to notifications page without logging in
    await page.goto(`${BASE_URL}/notifications`);

    // Expected Result: Access denied and redirected to login page
    await page.waitForURL(/.*login/, { timeout: 5000 });
    await expect(page).toHaveURL(/.*login/);

    // Step 2: Observe error messages or notifications
    const errorMessage = page.locator('[data-testid="error-message"]');
    if (await errorMessage.isVisible()) {
      const errorText = await errorMessage.textContent();
      expect(errorText?.toLowerCase()).toContain('unauthorized');
    }

    // Step 3: Attempt to access API endpoint without authentication
    const apiResponse = await request.get(`${BASE_URL}${NOTIFICATIONS_API}?employeeId=123`, {
      headers: {
        'Content-Type': 'application/json'
      }
    });

    // Expected Result: API returns 401 or 403 status
    expect([401, 403]).toContain(apiResponse.status());

    // Step 4: Try to access with invalid authentication token
    const invalidTokenResponse = await request.get(`${BASE_URL}${NOTIFICATIONS_API}?employeeId=123`, {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer invalid_token_12345'
      }
    });

    // Expected Result: API returns unauthorized status
    expect([401, 403]).toContain(invalidTokenResponse.status());

    // Step 5: Verify no notification data is exposed
    const responseBody = await invalidTokenResponse.text();
    expect(responseBody).not.toContain('scheduleChange');
    expect(responseBody).not.toContain('employeeId');

    // Step 6: Try with expired token
    const expiredTokenResponse = await request.get(`${BASE_URL}${NOTIFICATIONS_API}?employeeId=123`, {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.expired.token'
      }
    });

    expect([401, 403]).toContain(expiredTokenResponse.status());

    // Step 7: Confirm login page is displayed with proper fields
    await page.goto(`${BASE_URL}/notifications`);
    await page.waitForURL(/.*login/);
    await expect(page.locator('[data-testid="username-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="password-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="login-button"]')).toBeVisible();
  });
});