import { test, expect } from '@playwright/test';

test.describe('Schedule Change Notifications', () => {
  const adminCredentials = {
    username: 'admin@company.com',
    password: 'Admin123!'
  };

  const employeeCredentials = {
    username: 'employee@company.com',
    password: 'Employee123!'
  };

  test('Validate notification generation on schedule change', async ({ page, context }) => {
    // Step 1: Log in to the system as an admin user with valid credentials
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to the schedule management section
    await page.click('[data-testid="schedule-management-link"]');
    await expect(page.locator('[data-testid="schedule-management-page"]')).toBeVisible();

    // Step 3: Select the target employee's schedule from the list
    await page.click('[data-testid="employee-schedule-list"]');
    await page.click(`text=${employeeCredentials.username}`);
    await expect(page.locator('[data-testid="employee-schedule-details"]')).toBeVisible();

    // Step 4: Modify the employee's schedule (change shift time, date, or assignment)
    await page.click('[data-testid="edit-schedule-button"]');
    await page.fill('[data-testid="shift-time-input"]', '09:00');
    await page.fill('[data-testid="shift-date-input"]', '2024-02-15');

    // Step 5: Save the schedule changes
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule updated successfully');

    // Step 6: Log out from the admin account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 7: Log in to the web interface as the employee whose schedule was changed
    await page.fill('[data-testid="username-input"]', employeeCredentials.username);
    await page.fill('[data-testid="password-input"]', employeeCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 8: Observe the notification area on the web interface
    // Expected Result: Notification is displayed prominently
    const notificationBadge = page.locator('[data-testid="notification-badge"]');
    await expect(notificationBadge).toBeVisible();
    await expect(notificationBadge).toContainText('1');

    // Step 9: Click on the notification to view details
    await page.click('[data-testid="notification-icon"]');
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toBeVisible();
    await expect(notification).toContainText('Schedule changed');

    // Step 10: Click the acknowledge button on the notification
    await page.click('[data-testid="acknowledge-notification-button"]');

    // Step 11: Verify the notification is no longer in the active notifications list
    // Expected Result: Notification is marked as read and removed from active list
    await expect(page.locator('[data-testid="notification-badge"]')).not.toBeVisible();
    await page.click('[data-testid="notification-icon"]');
    const activeNotifications = page.locator('[data-testid="notification-item"]');
    await expect(activeNotifications).toHaveCount(0);
  });

  test('Verify notification delivery within 5 minutes', async ({ page }) => {
    // Step 1: Log in to the system as an admin user
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to the schedule management section and select an employee's schedule
    await page.click('[data-testid="schedule-management-link"]');
    await page.click('[data-testid="employee-schedule-list"]');
    await page.click(`text=${employeeCredentials.username}`);

    // Step 3: Note the current system time before making changes
    const changeStartTime = Date.now();

    // Step 4: Make a change to the employee's schedule (modify shift time or date)
    await page.click('[data-testid="edit-schedule-button"]');
    await page.fill('[data-testid="shift-time-input"]', '14:00');

    // Step 5: Save the schedule changes and note the exact time of save
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    const changeSaveTime = Date.now();

    // Step 6: Wait for 1 minute after saving the schedule change
    await page.waitForTimeout(60000);

    // Step 7: Verify notification generation in the backend system or database within 1 minute
    const notificationGenerationTime = Date.now();
    const generationDelay = (notificationGenerationTime - changeSaveTime) / 1000;
    expect(generationDelay).toBeLessThanOrEqual(60);

    // Step 8: Log out and log in as the affected employee within 5 minutes
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.fill('[data-testid="username-input"]', employeeCredentials.username);
    await page.fill('[data-testid="password-input"]', employeeCredentials.password);
    await page.click('[data-testid="login-button"]');

    // Step 9: Check the notification area immediately upon login
    // Expected Result: Notification is visible
    await expect(page.locator('[data-testid="notification-badge"]')).toBeVisible();
    await page.click('[data-testid="notification-icon"]');
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toBeVisible();

    // Step 10: Verify the notification timestamp shows it was generated within 5 minutes
    const notificationTimestamp = await notification.locator('[data-testid="notification-timestamp"]').textContent();
    const loginTime = Date.now();
    const totalDelay = (loginTime - changeSaveTime) / 1000;
    expect(totalDelay).toBeLessThanOrEqual(300);
  });

  test('Ensure employees can dismiss notifications', async ({ page }) => {
    // Step 1: Log in to the web interface as an employee with pending notifications
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', employeeCredentials.username);
    await page.fill('[data-testid="password-input"]', employeeCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to the notifications section or click on the notification indicator
    await expect(page.locator('[data-testid="notification-badge"]')).toBeVisible();
    const initialNotificationCount = await page.locator('[data-testid="notification-badge"]').textContent();
    await page.click('[data-testid="notification-icon"]');

    // Step 3: Select a specific notification to view its details
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toBeVisible();
    const notificationText = await notification.textContent();

    // Step 4: Verify that a dismiss button or dismiss option is visible on the notification
    // Expected Result: Dismiss button is available
    const dismissButton = notification.locator('[data-testid="dismiss-notification-button"]');
    await expect(dismissButton).toBeVisible();

    // Step 5: Click the dismiss button on the notification
    await dismissButton.click();

    // Step 6: Verify the notification is removed from the active notifications list
    // Expected Result: Notification is removed from active notifications
    await expect(notification).not.toBeVisible();

    // Step 7: Check the notification counter or badge
    const notificationBadge = page.locator('[data-testid="notification-badge"]');
    if (parseInt(initialNotificationCount || '0') > 1) {
      const updatedCount = await notificationBadge.textContent();
      expect(parseInt(updatedCount || '0')).toBeLessThan(parseInt(initialNotificationCount || '0'));
    } else {
      await expect(notificationBadge).not.toBeVisible();
    }

    // Step 8: Navigate to notification history (if available) to verify dismissed notification is archived
    await page.click('[data-testid="notification-history-link"]');
    await expect(page.locator('[data-testid="notification-history-page"]')).toBeVisible();
    const dismissedNotification = page.locator('[data-testid="dismissed-notification-item"]').filter({ hasText: notificationText || '' });
    await expect(dismissedNotification).toBeVisible();

    // Step 9: Refresh the page or log out and log back in
    await page.reload();
    await expect(page.locator('[data-testid="notification-badge"]')).not.toContainText(initialNotificationCount || '');

    // Log out and log back in to verify persistence
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.fill('[data-testid="username-input"]', employeeCredentials.username);
    await page.fill('[data-testid="password-input"]', employeeCredentials.password);
    await page.click('[data-testid="login-button"]');

    // Verify dismissed notification is still not in active list
    await page.click('[data-testid="notification-icon"]');
    const activeNotifications = page.locator('[data-testid="notification-item"]');
    await expect(activeNotifications.filter({ hasText: notificationText || '' })).not.toBeVisible();
  });
});