import { test, expect } from '@playwright/test';

test.describe('Schedule Change Notifications', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const adminCredentials = { username: 'admin@company.com', password: 'Admin123!' };
  const employeeACredentials = { username: 'employeeA@company.com', password: 'EmployeeA123!' };
  const employeeBCredentials = { username: 'employeeB@company.com', password: 'EmployeeB123!' };

  test('Validate real-time delivery of schedule change notifications (happy-path)', async ({ page, context }) => {
    // Step 1: Access backend system with administrator privileges
    await page.goto(`${baseURL}/admin/login`);
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="admin-dashboard"]')).toBeVisible();

    // Step 2: Navigate to employee schedule management section
    await page.click('[data-testid="schedule-management-link"]');
    await expect(page.locator('[data-testid="schedule-management-page"]')).toBeVisible();

    // Step 3: Locate target employee's schedule and modify a shift
    await page.fill('[data-testid="employee-search-input"]', 'Employee A');
    await page.click('[data-testid="search-button"]');
    await page.click('[data-testid="employee-schedule-row"]');
    await page.click('[data-testid="edit-shift-button"]');
    
    // Change shift time
    await page.fill('[data-testid="shift-time-input"]', '14:00');
    await page.fill('[data-testid="shift-date-input"]', '2024-02-15');
    
    // Step 4: Save schedule changes and note timestamp
    const changeTimestamp = Date.now();
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule updated successfully');

    // Step 5: Wait for notification generation (up to 1 minute)
    await page.waitForTimeout(5000); // Simulating notification processing time

    // Step 6: Employee logs into web interface
    const employeePage = await context.newPage();
    await employeePage.goto(`${baseURL}/employee/login`);
    await employeePage.fill('[data-testid="username-input"]', employeeACredentials.username);
    await employeePage.fill('[data-testid="password-input"]', employeeACredentials.password);
    await employeePage.click('[data-testid="login-button"]');
    await expect(employeePage.locator('[data-testid="employee-dashboard"]')).toBeVisible();

    // Step 7: Navigate to notifications section
    await employeePage.click('[data-testid="notifications-icon"]');
    await expect(employeePage.locator('[data-testid="notifications-panel"]')).toBeVisible();

    // Step 8: Verify new notification is visible
    const notification = employeePage.locator('[data-testid="notification-item"]').first();
    await expect(notification).toBeVisible();
    await expect(notification).toContainText('Schedule change');
    await expect(notification.locator('[data-testid="notification-status"]')).toContainText('unread');

    // Step 9: Acknowledge notification
    await notification.click();
    await employeePage.click('[data-testid="acknowledge-notification-button"]');
    
    // Step 10: Verify notification is marked as read
    await employeePage.click('[data-testid="notifications-icon"]');
    await expect(notification.locator('[data-testid="notification-status"]')).toContainText('read');
    
    // Verify notification delivery time was within 1 minute
    const notificationTime = await notification.locator('[data-testid="notification-timestamp"]').getAttribute('data-timestamp');
    const deliveryLatency = parseInt(notificationTime!) - changeTimestamp;
    expect(deliveryLatency).toBeLessThan(60000); // Less than 1 minute
  });

  test('Verify notification visibility and security (error-case)', async ({ page, context }) => {
    // Step 1: Log into web interface using Employee A's credentials
    await page.goto(`${baseURL}/employee/login`);
    await page.fill('[data-testid="username-input"]', employeeACredentials.username);
    await page.fill('[data-testid="password-input"]', employeeACredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="employee-dashboard"]')).toBeVisible();

    // Step 2: Navigate to notifications section
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();

    // Step 3: Review all visible notifications and verify content
    const employeeANotifications = page.locator('[data-testid="notification-item"]');
    const employeeANotificationCount = await employeeANotifications.count();
    
    // Verify all notifications belong to Employee A
    for (let i = 0; i < employeeANotificationCount; i++) {
      const notification = employeeANotifications.nth(i);
      const recipientId = await notification.getAttribute('data-recipient-id');
      expect(recipientId).toBe('employeeA');
    }

    // Step 4: Verify no notifications from other employees are displayed
    const employeeBNotifications = page.locator('[data-testid="notification-item"][data-recipient-id="employeeB"]');
    await expect(employeeBNotifications).toHaveCount(0);

    // Step 5: Log out from Employee A's account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-page"]')).toBeVisible();

    // Step 6: Log into web interface using Employee B's credentials
    await page.fill('[data-testid="username-input"]', employeeBCredentials.username);
    await page.fill('[data-testid="password-input"]', employeeBCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="employee-dashboard"]')).toBeVisible();

    // Step 7: Navigate to notifications section
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();

    // Step 8: Review all visible notifications and verify content
    const employeeBNotificationsList = page.locator('[data-testid="notification-item"]');
    const employeeBNotificationCount = await employeeBNotificationsList.count();
    
    // Verify all notifications belong to Employee B
    for (let i = 0; i < employeeBNotificationCount; i++) {
      const notification = employeeBNotificationsList.nth(i);
      const recipientId = await notification.getAttribute('data-recipient-id');
      expect(recipientId).toBe('employeeB');
    }

    // Step 9: Verify Employee A's notifications are not visible to Employee B
    const employeeANotificationsInB = page.locator('[data-testid="notification-item"][data-recipient-id="employeeA"]');
    await expect(employeeANotificationsInB).toHaveCount(0);

    // Step 10: Attempt to access Employee A's notification via URL manipulation
    const employeeANotificationId = 'notification-employeeA-001';
    await page.goto(`${baseURL}/employee/notifications/${employeeANotificationId}`);
    
    // Verify access is denied or redirected
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Access denied');
    // OR verify redirect to dashboard/error page
    await expect(page).toHaveURL(new RegExp('(dashboard|error|unauthorized)'));
  });

  test('Test notification history accessibility (happy-path)', async ({ page }) => {
    // Login as employee
    await page.goto(`${baseURL}/employee/login`);
    await page.fill('[data-testid="username-input"]', employeeACredentials.username);
    await page.fill('[data-testid="password-input"]', employeeACredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="employee-dashboard"]')).toBeVisible();

    // Step 1: Locate and click on notifications section or notification history link
    await page.click('[data-testid="notifications-link"]');
    
    // Step 2: Verify notification history section is accessible and loads properly
    await expect(page.locator('[data-testid="notification-history-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-history-title"]')).toContainText('Notification History');

    // Step 3: Review the list of notifications displayed in history
    const notificationList = page.locator('[data-testid="notification-item"]');
    await expect(notificationList).not.toHaveCount(0);

    // Step 4: Verify each notification displays read/unread status clearly
    const notificationCount = await notificationList.count();
    for (let i = 0; i < notificationCount; i++) {
      const notification = notificationList.nth(i);
      const statusBadge = notification.locator('[data-testid="notification-status"]');
      await expect(statusBadge).toBeVisible();
      const statusText = await statusBadge.textContent();
      expect(['read', 'unread']).toContain(statusText?.toLowerCase());
    }

    // Step 5: Check that unread notifications are visually distinct from read notifications
    const unreadNotifications = page.locator('[data-testid="notification-item"][data-status="unread"]');
    const readNotifications = page.locator('[data-testid="notification-item"][data-status="read"]');
    
    if (await unreadNotifications.count() > 0) {
      const unreadBgColor = await unreadNotifications.first().evaluate(el => window.getComputedStyle(el).backgroundColor);
      const readBgColor = await readNotifications.first().evaluate(el => window.getComputedStyle(el).backgroundColor);
      expect(unreadBgColor).not.toBe(readBgColor);
    }

    // Step 6: Verify each notification includes relevant details
    const firstNotification = notificationList.first();
    await expect(firstNotification.locator('[data-testid="notification-message"]')).toBeVisible();
    await expect(firstNotification.locator('[data-testid="notification-timestamp"]')).toBeVisible();
    await expect(firstNotification.locator('[data-testid="notification-type"]')).toBeVisible();
    
    const notificationMessage = await firstNotification.locator('[data-testid="notification-message"]').textContent();
    expect(notificationMessage).toContain('schedule');

    // Step 7: Scroll through notification history to verify all notifications are accessible
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await page.waitForTimeout(1000);
    const lastNotification = notificationList.last();
    await expect(lastNotification).toBeVisible();

    // Step 8: Click on an individual notification to view full details
    await firstNotification.click();
    await expect(page.locator('[data-testid="notification-detail-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-detail-content"]')).toBeVisible();

    // Step 9: Verify notification count matches total notifications received
    const notificationCountBadge = page.locator('[data-testid="notification-count-badge"]');
    const displayedCount = await notificationCountBadge.textContent();
    const actualCount = await notificationList.count();
    expect(parseInt(displayedCount!)).toBe(actualCount);
  });
});