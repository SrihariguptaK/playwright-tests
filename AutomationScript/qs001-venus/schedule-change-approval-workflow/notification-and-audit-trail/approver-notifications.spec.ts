import { test, expect } from '@playwright/test';

test.describe('Approver Notifications for Schedule Change Requests', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login');
  });

  test('Verify notification sent to approver upon assignment (happy-path)', async ({ page }) => {
    // Log in as a user with schedule change request submission permissions
    await page.fill('[data-testid="username-input"]', 'employee.user@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to schedule change request form
    await page.click('[data-testid="schedule-change-menu"]');
    await page.click('[data-testid="new-request-button"]');

    // Fill out the schedule change request form with valid data
    await page.fill('[data-testid="employee-name-input"]', 'John Doe');
    await page.fill('[data-testid="current-schedule-input"]', 'Monday-Friday 9AM-5PM');
    await page.fill('[data-testid="requested-schedule-input"]', 'Tuesday-Saturday 10AM-6PM');
    await page.fill('[data-testid="reason-textarea"]', 'Personal circumstances require schedule adjustment');
    await page.fill('[data-testid="effective-date-input"]', '2024-02-01');

    // Submit the schedule change request
    await page.click('[data-testid="submit-request-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule change request submitted successfully');

    // Get the request ID from the success message or URL
    const requestId = await page.locator('[data-testid="request-id"]').textContent();

    // Log out and log in as the assigned approver
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    await page.fill('[data-testid="username-input"]', 'approver.user@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the in-app notifications section
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();

    // Verify notification displays request summary and link
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toBeVisible();
    await expect(notification).toContainText('Schedule change request');
    await expect(notification).toContainText('John Doe');
    await expect(notification.locator('[data-testid="notification-link"]')).toBeVisible();

    // Click on the in-app notification to view details
    await notification.click();
    await expect(page).toHaveURL(/.*approval.*/);
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();

    // Verify request details are displayed
    await expect(page.locator('[data-testid="employee-name"]')).toContainText('John Doe');
    await expect(page.locator('[data-testid="requested-schedule"]')).toContainText('Tuesday-Saturday 10AM-6PM');
  });

  test('Ensure notifications are delivered within 5 minutes (boundary)', async ({ page }) => {
    // Note the current system timestamp before triggering the notification event
    const startTime = Date.now();

    // Log in as a user with schedule change request submission permissions
    await page.fill('[data-testid="username-input"]', 'employee.user@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to schedule change request form
    await page.click('[data-testid="schedule-change-menu"]');
    await page.click('[data-testid="new-request-button"]');

    // Fill out and submit a schedule change request
    await page.fill('[data-testid="employee-name-input"]', 'Jane Smith');
    await page.fill('[data-testid="current-schedule-input"]', 'Monday-Friday 8AM-4PM');
    await page.fill('[data-testid="requested-schedule-input"]', 'Monday-Friday 9AM-5PM');
    await page.fill('[data-testid="reason-textarea"]', 'Childcare scheduling needs');
    await page.fill('[data-testid="effective-date-input"]', '2024-02-15');

    // Submit the schedule change request and record submission time
    await page.click('[data-testid="submit-request-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    const submissionTime = Date.now();

    // Log out and log in as the approver
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    await page.fill('[data-testid="username-input"]', 'approver.user@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Check the in-app notification center
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();

    // Wait for notification to appear (with timeout of 5 minutes)
    const notification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Jane Smith' }).first();
    await expect(notification).toBeVisible({ timeout: 300000 }); // 5 minutes timeout

    // Record the notification received time
    const notificationReceivedTime = Date.now();
    const deliveryTime = (notificationReceivedTime - submissionTime) / 1000; // Convert to seconds

    // Verify the notification timestamp
    const notificationTimestamp = await notification.locator('[data-testid="notification-timestamp"]').textContent();
    expect(notificationTimestamp).toBeTruthy();

    // Verify notification was delivered within 5 minutes (300 seconds)
    expect(deliveryTime).toBeLessThanOrEqual(300);

    // Verify notification contains required information
    await expect(notification).toContainText('Schedule change request');
    await expect(notification).toContainText('Jane Smith');
  });

  test('Validate notification access and privacy (error-case)', async ({ page, context }) => {
    // Log in as an authorized approver
    await page.fill('[data-testid="username-input"]', 'approver.user@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the notification history section
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="profile-link"]');
    await page.click('[data-testid="notification-history-tab"]');
    await expect(page.locator('[data-testid="notification-history"]')).toBeVisible();

    // Note the notification ID or URL of a specific notification
    const notificationItem = page.locator('[data-testid="notification-history-item"]').first();
    await expect(notificationItem).toBeVisible();
    const notificationId = await notificationItem.getAttribute('data-notification-id');
    const notificationUrl = page.url();
    const specificNotificationUrl = `${notificationUrl}/${notificationId}`;

    // Log out from the approver account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Log in as an unauthorized user (different role, not assigned as approver)
    await page.fill('[data-testid="username-input"]', 'regular.user@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Attempt to navigate directly to the approver's notification history page
    await page.goto(notificationUrl);
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/Access denied|Unauthorized|403/);

    // Attempt to access the specific notification using the recorded notification ID
    await page.goto(specificNotificationUrl);
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/Access denied|Unauthorized|403/);

    // Attempt to make a direct API call to retrieve the approver's notifications
    const apiResponse = await page.request.get('/api/notifications', {
      headers: {
        'Authorization': `Bearer ${await context.storageState().then(state => state.cookies.find(c => c.name === 'auth_token')?.value || '')}`,
      },
      failOnStatusCode: false
    });

    // Verify that access is denied
    expect(apiResponse.status()).toBe(403);
    const responseBody = await apiResponse.json().catch(() => ({}));
    expect(responseBody).not.toHaveProperty('notifications');

    // Verify that no notification data is exposed in the error response
    const responseText = await apiResponse.text();
    expect(responseText).not.toContain(notificationId || '');
    expect(responseText).not.toContain('approver.user@company.com');

    // Log out from unauthorized user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Log back in as the original approver
    await page.fill('[data-testid="username-input"]', 'approver.user@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Verify approver can still access their own notifications
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-item"]').first()).toBeVisible();
  });
});