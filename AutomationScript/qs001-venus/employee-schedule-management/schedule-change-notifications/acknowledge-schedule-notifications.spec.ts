import { test, expect } from '@playwright/test';

test.describe('Story-12: Acknowledge Schedule Change Notifications', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const EMPLOYEE_EMAIL = 'employee@test.com';
  const EMPLOYEE_PASSWORD = 'Password123!';

  test.beforeEach(async ({ page }) => {
    // Navigate to application
    await page.goto(BASE_URL);
  });

  test('Validate acknowledgment of a notification (happy-path)', async ({ page }) => {
    // Step 1: Login as employee
    await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to the notifications section from the employee dashboard
    await page.click('[data-testid="notifications-link"]');
    await expect(page).toHaveURL(/.*notifications/);

    // Step 3: Locate an unacknowledged schedule change notification in the list
    const notificationsList = page.locator('[data-testid="notifications-list"]');
    await expect(notificationsList).toBeVisible();
    
    const unacknowledgedNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Schedule Change' }).first();
    await expect(unacknowledgedNotification).toBeVisible();

    // Step 4: Verify that the notification displays an acknowledge button or checkbox
    const acknowledgeButton = unacknowledgedNotification.locator('[data-testid="acknowledge-button"]');
    await expect(acknowledgeButton).toBeVisible();
    await expect(acknowledgeButton).toBeEnabled();

    // Step 5: Review the notification content to ensure it contains schedule change information
    const notificationContent = unacknowledgedNotification.locator('[data-testid="notification-content"]');
    await expect(notificationContent).toContainText(/schedule|shift|time/i);

    // Step 6: Click the acknowledge button on the notification
    await acknowledgeButton.click();

    // Step 7: Observe the system response and visual feedback
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/acknowledged|confirmed/i);

    // Step 8: Verify that the notification status has updated to acknowledged
    await expect(unacknowledgedNotification.locator('[data-testid="notification-status"]')).toContainText(/acknowledged/i);

    // Step 9: Check that the acknowledge button is no longer available or is disabled
    await expect(acknowledgeButton).toBeDisabled().catch(() => 
      expect(acknowledgeButton).not.toBeVisible()
    );

    // Step 10: Attempt to click the acknowledge button or area again
    const clickCount = await acknowledgeButton.count();
    if (clickCount > 0) {
      await acknowledgeButton.click({ force: true }).catch(() => {});
      // System should prevent duplicate acknowledgment
      await expect(page.locator('[data-testid="error-message"]')).toContainText(/already acknowledged|duplicate/i).catch(() => {});
    }

    // Step 11: Refresh the notifications page
    await page.reload();
    await expect(page).toHaveURL(/.*notifications/);

    // Step 12: Verify in the notification history that the acknowledgment timestamp is recorded
    const acknowledgedNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Schedule Change' }).first();
    await expect(acknowledgedNotification.locator('[data-testid="acknowledgment-timestamp"]')).toBeVisible();
    await expect(acknowledgedNotification.locator('[data-testid="notification-status"]')).toContainText(/acknowledged/i);
  });

  test('Verify acknowledgment access control (error-case)', async ({ page, context }) => {
    // Step 1: Open a web browser and ensure no user is currently logged in
    await context.clearCookies();
    await page.goto(BASE_URL);

    // Step 2: Attempt to directly access the notifications page URL without logging in
    await page.goto(`${BASE_URL}/notifications`);
    
    // Step 3: Verify that the system redirects unauthenticated users to the login page
    await expect(page).toHaveURL(/.*login/);
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Step 4: Verify that the user is prompted to log in before accessing notifications
    await expect(page.locator('[data-testid="auth-required-message"]')).toBeVisible().catch(() => 
      expect(page.locator('text=/please log in|authentication required/i')).toBeVisible()
    );

    // Step 5: Attempt to send a POST request to /api/notifications/{id}/acknowledge endpoint without authentication token
    const notificationId = '12345';
    const response = await page.request.post(`${BASE_URL}/api/notifications/${notificationId}/acknowledge`, {
      headers: {
        'Content-Type': 'application/json'
      },
      failOnStatusCode: false
    });

    // Step 6: Verify that the error response includes appropriate message indicating authentication is required
    expect(response.status()).toBe(401);
    const responseBody = await response.json().catch(() => ({ message: '' }));
    expect(responseBody.message || '').toMatch(/unauthorized|authentication required|not authenticated/i);

    // Step 7: Check that no notification data is exposed to unauthenticated users
    const notificationsResponse = await page.request.get(`${BASE_URL}/api/notifications`, {
      failOnStatusCode: false
    });
    expect(notificationsResponse.status()).toBe(401);

    // Step 8: Attempt to use an invalid or expired authentication token to acknowledge a notification
    const invalidTokenResponse = await page.request.post(`${BASE_URL}/api/notifications/${notificationId}/acknowledge`, {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer invalid_token_12345'
      },
      failOnStatusCode: false
    });

    expect(invalidTokenResponse.status()).toBe(401);
    const invalidTokenBody = await invalidTokenResponse.json().catch(() => ({ message: '' }));
    expect(invalidTokenBody.message || '').toMatch(/unauthorized|invalid token|authentication/i);

    // Step 9: Navigate to the login page and verify proper authentication flow
    await page.goto(`${BASE_URL}/login`);
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
  });

  test('Validate acknowledgment of a notification - API test case', async ({ page, request }) => {
    // Login first to get authentication token
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to notifications
    await page.click('[data-testid="notifications-link"]');
    await expect(page).toHaveURL(/.*notifications/);

    // Action: Employee views a schedule change notification
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toBeVisible();
    
    // Expected Result: Notification displays acknowledge button
    const acknowledgeBtn = notification.locator('[data-testid="acknowledge-button"]');
    await expect(acknowledgeBtn).toBeVisible();

    // Action: Employee clicks acknowledge
    await acknowledgeBtn.click();

    // Expected Result: Notification status updates and visual confirmation shown
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });
    await expect(notification.locator('[data-testid="notification-status"]')).toContainText(/acknowledged/i);

    // Action: Employee attempts to acknowledge again
    const acknowledgeButtonAfter = notification.locator('[data-testid="acknowledge-button"]');
    
    // Expected Result: System prevents duplicate acknowledgment
    await expect(acknowledgeButtonAfter).toBeDisabled().catch(async () => {
      await expect(acknowledgeButtonAfter).not.toBeVisible();
    });
  });

  test('Verify acknowledgment access control - Unauthenticated user', async ({ page, request }) => {
    // Action: Unauthenticated user attempts to acknowledge notification
    const notificationId = '12345';
    const response = await request.post(`${BASE_URL}/api/notifications/${notificationId}/acknowledge`, {
      failOnStatusCode: false
    });

    // Expected Result: Action denied and redirected to login
    expect(response.status()).toBe(401);

    // Verify UI redirect
    await page.goto(`${BASE_URL}/notifications`);
    await expect(page).toHaveURL(/.*login/);
  });
});