import { test, expect } from '@playwright/test';

test.describe('Schedule Change Notifications', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const employeeACredentials = {
    username: 'employee.a@company.com',
    password: 'Password123!'
  };
  const employeeBCredentials = {
    username: 'employee.b@company.com',
    password: 'Password123!'
  };

  test.beforeEach(async ({ page }) => {
    await page.goto(`${baseURL}/login`);
  });

  test('Validate display of schedule change notifications on login', async ({ page }) => {
    // Step 1: Navigate to the web portal login page
    await expect(page).toHaveURL(/.*login/);
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Step 2: Enter valid employee credentials
    await page.fill('[data-testid="username-input"]', employeeACredentials.username);
    await page.fill('[data-testid="password-input"]', employeeACredentials.password);

    // Step 3: Click the login button to authenticate
    await page.click('[data-testid="login-button"]');

    // Step 4: Observe the dashboard page immediately after login
    await expect(page).toHaveURL(/.*dashboard/);
    await page.waitForLoadState('networkidle');

    // Expected Result: Notification banner appears with change details
    const notificationBanner = page.locator('[data-testid="notification-banner"]');
    await expect(notificationBanner).toBeVisible({ timeout: 10000 });
    await expect(notificationBanner).toContainText(/schedule change/i);

    // Step 5: Review the notification banner content
    const notificationText = await notificationBanner.textContent();
    expect(notificationText).toBeTruthy();

    // Step 6: Click on the notification banner or 'View Details' link
    const viewDetailsButton = page.locator('[data-testid="notification-view-details"]');
    await viewDetailsButton.click();

    // Step 7: Review the detailed notification information
    // Expected Result: Detailed information about schedule changes is displayed
    const notificationDetails = page.locator('[data-testid="notification-details"]');
    await expect(notificationDetails).toBeVisible();
    await expect(notificationDetails).toContainText(/shift/i);
    await expect(notificationDetails).toContainText(/date|time/i);
  });

  test('Verify notification dismissal functionality', async ({ page }) => {
    // Login as employee with notifications
    await page.fill('[data-testid="username-input"]', employeeACredentials.username);
    await page.fill('[data-testid="password-input"]', employeeACredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    await page.waitForLoadState('networkidle');

    // Step 1: Locate the visible schedule change notification on the dashboard
    const notification = page.locator('[data-testid="notification-banner"]').first();
    await expect(notification).toBeVisible();

    // Step 2: Identify the dismiss button or close icon on the notification
    const dismissButton = page.locator('[data-testid="notification-dismiss-button"]').first();
    await expect(dismissButton).toBeVisible();

    // Step 3: Click the dismiss button on the notification
    await dismissButton.click();

    // Expected Result: Notification is removed and does not reappear
    // Step 4: Verify the notification is no longer visible on the current page
    await expect(notification).not.toBeVisible({ timeout: 5000 });

    // Step 5: Refresh the browser page
    await page.reload();
    await page.waitForLoadState('networkidle');

    // Verify notification does not reappear after refresh
    await expect(page.locator('[data-testid="notification-banner"]')).not.toBeVisible();

    // Step 6: Log out of the web portal
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 7: Log back into the web portal with the same employee credentials
    await page.fill('[data-testid="username-input"]', employeeACredentials.username);
    await page.fill('[data-testid="password-input"]', employeeACredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    await page.waitForLoadState('networkidle');

    // Step 8: Check the dashboard for the previously dismissed notification
    // Expected Result: Dismissed notification does not reappear on subsequent logins
    await expect(page.locator('[data-testid="notification-banner"]')).not.toBeVisible();
  });

  test('Test notification visibility restricted to affected employee', async ({ page }) => {
    // Step 1: Log in as Employee A who has pending schedule change notifications
    await page.fill('[data-testid="username-input"]', employeeACredentials.username);
    await page.fill('[data-testid="password-input"]', employeeACredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    await page.waitForLoadState('networkidle');

    // Step 2: Note the specific details of Employee A's schedule change notifications
    const employeeANotifications = page.locator('[data-testid="notification-banner"]');
    const employeeANotificationCount = await employeeANotifications.count();
    let employeeANotificationDetails: string[] = [];
    
    if (employeeANotificationCount > 0) {
      for (let i = 0; i < employeeANotificationCount; i++) {
        const notificationText = await employeeANotifications.nth(i).textContent();
        if (notificationText) {
          employeeANotificationDetails.push(notificationText);
        }
      }
    }

    // Step 3: Log out of Employee A's account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 4: Log in as Employee B using their valid credentials
    await page.fill('[data-testid="username-input"]', employeeBCredentials.username);
    await page.fill('[data-testid="password-input"]', employeeBCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    await page.waitForLoadState('networkidle');

    // Step 5: Check the dashboard for any schedule change notifications
    const employeeBNotifications = page.locator('[data-testid="notification-banner"]');
    const employeeBNotificationCount = await employeeBNotifications.count();

    // Step 6: Verify that only Employee B's own notifications (if any exist) are visible
    // Expected Result: No notifications for schedule changes not related to them are displayed
    if (employeeBNotificationCount > 0) {
      for (let i = 0; i < employeeBNotificationCount; i++) {
        const notificationText = await employeeBNotifications.nth(i).textContent();
        // Verify Employee B's notifications don't match Employee A's notifications
        if (notificationText && employeeANotificationDetails.length > 0) {
          expect(employeeANotificationDetails).not.toContain(notificationText);
        }
      }
    }

    // Step 7: Attempt to access notification history or notification details
    const notificationHistoryLink = page.locator('[data-testid="notification-history-link"]');
    if (await notificationHistoryLink.isVisible()) {
      await notificationHistoryLink.click();
      const notificationHistory = page.locator('[data-testid="notification-history-list"]');
      await expect(notificationHistory).toBeVisible();
      
      // Verify notification history only shows Employee B's notifications
      const historyItems = page.locator('[data-testid="notification-history-item"]');
      const historyCount = await historyItems.count();
      
      for (let i = 0; i < historyCount; i++) {
        const historyItemText = await historyItems.nth(i).textContent();
        if (historyItemText && employeeANotificationDetails.length > 0) {
          expect(employeeANotificationDetails).not.toContain(historyItemText);
        }
      }
    }

    // Step 8: Verify API response by checking network traffic
    const apiResponse = await page.waitForResponse(
      response => response.url().includes('/api/notifications/scheduleChanges') && response.status() === 200,
      { timeout: 5000 }
    ).catch(() => null);

    if (apiResponse) {
      const responseData = await apiResponse.json();
      // Verify response only contains notifications for Employee B
      expect(responseData).toBeDefined();
      if (responseData.notifications && Array.isArray(responseData.notifications)) {
        responseData.notifications.forEach((notification: any) => {
          expect(notification.employeeId).not.toBe(employeeACredentials.username);
        });
      }
    }
  });
});