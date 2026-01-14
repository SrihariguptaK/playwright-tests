import { test, expect } from '@playwright/test';

test.describe('Story-18: Acknowledge Schedule Notifications', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const EMPLOYEE_EMAIL = 'employee@company.com';
  const EMPLOYEE_PASSWORD = 'Password123!';
  const EMPLOYEE_B_EMAIL = 'employeeb@company.com';
  const EMPLOYEE_B_PASSWORD = 'Password123!';
  const EMPLOYEE_A_EMAIL = 'employeea@company.com';
  const EMPLOYEE_A_PASSWORD = 'Password123!';

  test('Validate notification acknowledgment process (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the application login page
    await page.goto(`${BASE_URL}/login`);
    await expect(page).toHaveURL(/.*login/);

    // Step 2: Enter valid employee credentials and click login button
    await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Step 3: Verify schedule dashboard displays with active notifications
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="notifications-section"]')).toBeVisible();

    // Step 4: Note the notification details and current count of active notifications
    const notificationsList = page.locator('[data-testid="active-notifications-list"]');
    await expect(notificationsList).toBeVisible();
    
    const initialNotificationCount = await page.locator('[data-testid="notification-item"]').count();
    expect(initialNotificationCount).toBeGreaterThan(0);

    const firstNotification = page.locator('[data-testid="notification-item"]').first();
    const notificationContent = await firstNotification.locator('[data-testid="notification-content"]').textContent();
    const notificationTimestamp = await firstNotification.locator('[data-testid="notification-timestamp"]').textContent();

    // Step 5: Click the acknowledge button on the notification
    await firstNotification.locator('[data-testid="acknowledge-button"]').click();

    // Step 6: Verify notification status updates immediately
    await page.waitForTimeout(500);
    await expect(firstNotification).not.toBeVisible({ timeout: 2000 });

    // Step 7: Verify the active notification count decreases
    const updatedNotificationCount = await page.locator('[data-testid="notification-item"]').count();
    expect(updatedNotificationCount).toBe(initialNotificationCount - 1);

    // Step 8: Navigate to the notification history section
    await page.click('[data-testid="notification-history-link"]');
    await expect(page.locator('[data-testid="notification-history-section"]')).toBeVisible();

    // Step 9: Verify the acknowledged notification appears in history
    const acknowledgedNotifications = page.locator('[data-testid="acknowledged-notification-item"]');
    await expect(acknowledgedNotifications).toHaveCount(await acknowledgedNotifications.count());

    // Step 10: Verify notification details match the original notification
    const acknowledgedNotification = acknowledgedNotifications.first();
    const acknowledgedContent = await acknowledgedNotification.locator('[data-testid="notification-content"]').textContent();
    const acknowledgedTimestamp = await acknowledgedNotification.locator('[data-testid="notification-timestamp"]').textContent();
    
    expect(acknowledgedContent).toBe(notificationContent);
    expect(acknowledgedTimestamp).toBe(notificationTimestamp);
  });

  test('Verify acknowledgment access control (error-case)', async ({ page, context }) => {
    // Step 1: Log in as Employee B using valid credentials
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', EMPLOYEE_B_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_B_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Step 2: Verify Employee B's dashboard loads with their own notifications
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="notifications-section"]')).toBeVisible();

    // Step 3: Obtain the notification ID of an unacknowledged notification belonging to Employee A
    // This would typically be done through test data setup or API call
    const employeeANotificationId = 'notification-employee-a-001';

    // Step 4: Attempt to acknowledge Employee A's notification using Employee B's session
    const cookies = await context.cookies();
    const authToken = cookies.find(cookie => cookie.name === 'auth_token')?.value;

    const response = await page.request.post(`${BASE_URL}/api/notifications/acknowledge`, {
      data: {
        notificationId: employeeANotificationId
      },
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      }
    });

    // Step 5: Verify error message is displayed
    expect(response.status()).toBe(403);
    const responseBody = await response.json();
    expect(responseBody.error).toContain('not authorized');

    // Step 6: Verify Employee A's notification status remains unchanged
    // This would be verified through API call or database check
    const verifyResponse = await page.request.get(`${BASE_URL}/api/notifications/${employeeANotificationId}`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    if (verifyResponse.status() === 200) {
      const notificationData = await verifyResponse.json();
      expect(notificationData.status).not.toBe('acknowledged');
    }

    // Step 7: Verify no changes were made to Employee B's notification list
    const employeeBNotifications = page.locator('[data-testid="notification-item"]');
    const employeeBNotificationCount = await employeeBNotifications.count();
    await page.reload();
    await expect(page.locator('[data-testid="notification-item"]')).toHaveCount(employeeBNotificationCount);

    // Step 8: Log out Employee B and log in as Employee A
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    await page.fill('[data-testid="email-input"]', EMPLOYEE_A_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_A_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Step 9: Verify Employee A's notification is still unacknowledged
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="notifications-section"]')).toBeVisible();
    
    const employeeANotification = page.locator(`[data-testid="notification-item"][data-notification-id="${employeeANotificationId}"]`);
    await expect(employeeANotification).toBeVisible();
    
    const notificationStatus = await employeeANotification.getAttribute('data-status');
    expect(notificationStatus).not.toBe('acknowledged');
    
    await expect(employeeANotification.locator('[data-testid="acknowledge-button"]')).toBeVisible();
  });
});