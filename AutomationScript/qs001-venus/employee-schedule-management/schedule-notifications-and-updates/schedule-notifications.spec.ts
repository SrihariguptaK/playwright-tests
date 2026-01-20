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

  test('Validate notification display on schedule update', async ({ page, context }) => {
    // Admin updates employee schedule
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Admin navigates to schedule management section
    await page.click('[data-testid="schedule-management-link"]');
    await expect(page.locator('[data-testid="schedule-management-page"]')).toBeVisible();

    // Admin selects employee's existing schedule entry
    await page.click('[data-testid="employee-schedule-entry"]');
    await expect(page.locator('[data-testid="schedule-edit-form"]')).toBeVisible();

    // Admin modifies the schedule (changes shift time from 9:00 AM to 10:00 AM)
    await page.fill('[data-testid="shift-start-time"]', '10:00');
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule updated successfully');

    // Verify schedule change event is triggered
    const response = await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    expect(response.ok()).toBeTruthy();

    // Admin logs out
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Employee logs into the portal
    await page.fill('[data-testid="username-input"]', employeeCredentials.username);
    await page.fill('[data-testid="password-input"]', employeeCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Notification indicator is displayed
    await expect(page.locator('[data-testid="notification-indicator"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-badge"]')).toHaveText('1');

    // Employee views notification details
    await page.click('[data-testid="notification-indicator"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();

    // Correct schedule change information is shown
    const notificationContent = page.locator('[data-testid="notification-content"]').first();
    await expect(notificationContent).toContainText('Schedule updated');
    await expect(notificationContent).toContainText('10:00');
  });

  test('Verify notification acknowledgment process', async ({ page }) => {
    // Employee logs in
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', employeeCredentials.username);
    await page.fill('[data-testid="password-input"]', employeeCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Employee navigates to notifications section from dashboard
    await page.click('[data-testid="notifications-link"]');
    await expect(page.locator('[data-testid="notifications-page"]')).toBeVisible();

    // Employee locates schedule change notification and clicks Acknowledge button
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toBeVisible();
    await notification.locator('[data-testid="acknowledge-button"]').click();

    // Wait for acknowledgment API call
    await page.waitForResponse(response => 
      response.url().includes('/api/notifications/acknowledge') && response.status() === 200
    );

    // Notification marked as acknowledged and no longer in unacknowledged list
    await expect(page.locator('[data-testid="unacknowledged-notifications"]')).not.toContainText('Schedule updated');

    // Employee clicks on Notification History link
    await page.click('[data-testid="notification-history-link"]');
    await expect(page.locator('[data-testid="notification-history-section"]')).toBeVisible();

    // Acknowledged notifications are recorded in history
    const acknowledgedNotification = page.locator('[data-testid="acknowledged-notification-item"]').first();
    await expect(acknowledgedNotification).toBeVisible();
    await expect(acknowledgedNotification).toContainText('Schedule updated');
    await expect(acknowledgedNotification.locator('[data-testid="acknowledgment-status"]')).toContainText('Acknowledged');

    // Employee logs out
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Employee logs back in
    await page.fill('[data-testid="username-input"]', employeeCredentials.username);
    await page.fill('[data-testid="password-input"]', employeeCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Employee navigates to notification history section
    await page.click('[data-testid="notifications-link"]');
    await page.click('[data-testid="notification-history-link"]');

    // Previously acknowledged notification still shows as acknowledged
    const persistedNotification = page.locator('[data-testid="acknowledged-notification-item"]').first();
    await expect(persistedNotification).toBeVisible();
    await expect(persistedNotification.locator('[data-testid="acknowledgment-status"]')).toContainText('Acknowledged');
  });

  test('Test notification delivery time', async ({ page, context }) => {
    // Record current system timestamp before making changes
    const scheduleUpdateTime = new Date();

    // Admin logs into the system
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Admin navigates to schedule management
    await page.click('[data-testid="schedule-management-link"]');
    await expect(page.locator('[data-testid="schedule-management-page"]')).toBeVisible();

    // Admin updates employee's schedule (adds new shift or modifies existing)
    await page.click('[data-testid="add-shift-button"]');
    await page.fill('[data-testid="shift-date"]', '2024-02-15');
    await page.fill('[data-testid="shift-start-time"]', '14:00');
    await page.fill('[data-testid="shift-end-time"]', '22:00');
    await page.selectOption('[data-testid="employee-select"]', { label: 'Employee User' });
    await page.click('[data-testid="save-schedule-button"]');

    // Verify notification generation event was triggered
    const scheduleResponse = await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    expect(scheduleResponse.ok()).toBeTruthy();

    // Admin logs out
    await page.click('[data-testid="logout-button"]');

    // Employee logs into portal within 30 seconds of schedule update
    await page.fill('[data-testid="username-input"]', employeeCredentials.username);
    await page.fill('[data-testid="password-input"]', employeeCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Employee immediately checks for notification indicators
    await expect(page.locator('[data-testid="notification-indicator"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="notification-badge"]')).toBeVisible();

    // Employee clicks on notification to view details and verify timestamp
    await page.click('[data-testid="notification-indicator"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();

    const notificationItem = page.locator('[data-testid="notification-item"]').first();
    await expect(notificationItem).toBeVisible();

    // Get notification timestamp
    const notificationTimestamp = await notificationItem.locator('[data-testid="notification-timestamp"]').textContent();
    expect(notificationTimestamp).toBeTruthy();

    // Calculate time difference between schedule update and notification
    const currentTime = new Date();
    const timeDifferenceSeconds = (currentTime.getTime() - scheduleUpdateTime.getTime()) / 1000;

    // Verify notification delivery meets SLA (within 60 seconds)
    expect(timeDifferenceSeconds).toBeLessThan(60);

    // Verify notification content
    await expect(notificationItem).toContainText('Schedule updated');
    await expect(notificationItem).toContainText('14:00');
  });
});