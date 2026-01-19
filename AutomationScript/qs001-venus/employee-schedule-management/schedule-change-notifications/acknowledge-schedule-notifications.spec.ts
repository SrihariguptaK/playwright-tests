import { test, expect } from '@playwright/test';

test.describe('Story-17: Acknowledge Schedule Change Notifications', () => {
  let notificationId: string;
  let employeeId: string;

  test.beforeEach(async ({ page }) => {
    // Login as employee
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@test.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate acknowledgment of schedule change notification - happy path', async ({ page, request }) => {
    // Navigate to the employee dashboard where notifications are displayed
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');

    // Identify an unacknowledged schedule change notification in the notification list
    const notificationList = page.locator('[data-testid="notification-list"]');
    await expect(notificationList).toBeVisible();
    
    const unacknowledgedNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Schedule Change' }).first();
    await expect(unacknowledgedNotification).toBeVisible();
    
    // Store notification ID for later verification
    notificationId = await unacknowledgedNotification.getAttribute('data-notification-id') || '';
    expect(notificationId).toBeTruthy();

    // Click the 'Acknowledge' button on the notification
    const acknowledgeButton = unacknowledgedNotification.locator('[data-testid="acknowledge-button"]');
    await expect(acknowledgeButton).toBeEnabled();
    await acknowledgeButton.click();

    // Verify notification status updates visually on the UI
    await expect(unacknowledgedNotification.locator('[data-testid="notification-status"]')).toContainText('Acknowledged');

    // Check for confirmation message displayed to the employee
    const confirmationMessage = page.locator('[data-testid="confirmation-message"]');
    await expect(confirmationMessage).toBeVisible();
    await expect(confirmationMessage).toContainText('Notification acknowledged successfully');

    // Verify the 'Acknowledge' button is disabled or removed from the acknowledged notification
    await expect(acknowledgeButton).toBeDisabled().catch(async () => {
      await expect(acknowledgeButton).not.toBeVisible();
    });

    // Refresh the page or navigate away and return to the dashboard
    await page.goto('/profile');
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');

    // Locate the same notification and attempt to click 'Acknowledge' again (if button is still visible)
    const acknowledgedNotification = page.locator(`[data-notification-id="${notificationId}"]`);
    await expect(acknowledgedNotification).toBeVisible();
    
    const acknowledgeButtonAfterRefresh = acknowledgedNotification.locator('[data-testid="acknowledge-button"]');
    const isButtonVisible = await acknowledgeButtonAfterRefresh.isVisible().catch(() => false);
    
    if (isButtonVisible) {
      const isButtonEnabled = await acknowledgeButtonAfterRefresh.isEnabled();
      expect(isButtonEnabled).toBe(false);
    }

    // Attempt to send duplicate acknowledgment via direct API call
    const apiResponse = await request.post('/api/notifications/acknowledge', {
      data: {
        notificationId: notificationId
      }
    });

    // System prevents duplicate acknowledgment
    expect(apiResponse.status()).toBe(400);
    const responseBody = await apiResponse.json();
    expect(responseBody.error).toContain('already acknowledged');
  });

  test('Verify acknowledgment logging - happy path', async ({ page }) => {
    // Record the current system timestamp before performing acknowledgment
    const timestampBeforeAcknowledgment = new Date();

    // Navigate to employee dashboard and identify the notification ID of an unacknowledged notification
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');

    const notificationList = page.locator('[data-testid="notification-list"]');
    await expect(notificationList).toBeVisible();

    const unacknowledgedNotification = page.locator('[data-testid="notification-item"]')
      .filter({ has: page.locator('[data-testid="acknowledge-button"]:enabled') })
      .first();
    await expect(unacknowledgedNotification).toBeVisible();

    // Store notification ID for database verification
    notificationId = await unacknowledgedNotification.getAttribute('data-notification-id') || '';
    expect(notificationId).toBeTruthy();

    // Click the 'Acknowledge' button on the selected notification
    const acknowledgeButton = unacknowledgedNotification.locator('[data-testid="acknowledge-button"]');
    await acknowledgeButton.click();

    // Wait for acknowledgment to be processed
    await page.waitForTimeout(1000);

    // Verify confirmation message
    const confirmationMessage = page.locator('[data-testid="confirmation-message"]');
    await expect(confirmationMessage).toBeVisible();

    // Query the NotificationStatus table in the database for the specific notification ID
    // This would typically be done via API endpoint for testing purposes
    const response = await page.request.get(`/api/notifications/${notificationId}/status`);
    expect(response.ok()).toBeTruthy();
    
    const notificationData = await response.json();

    // Verify the acknowledgment status field is set to 'Acknowledged' or equivalent value
    expect(notificationData.status).toBe('Acknowledged');

    // Verify the acknowledgment timestamp is recorded in the database
    expect(notificationData.acknowledgedAt).toBeTruthy();
    const acknowledgedTimestamp = new Date(notificationData.acknowledgedAt);
    expect(acknowledgedTimestamp.getTime()).toBeGreaterThanOrEqual(timestampBeforeAcknowledgment.getTime());
    expect(acknowledgedTimestamp.getTime()).toBeLessThanOrEqual(new Date().getTime());

    // Verify the employee ID/user ID is recorded with the acknowledgment
    expect(notificationData.acknowledgedBy).toBeTruthy();
    employeeId = notificationData.acknowledgedBy;
    expect(employeeId).toMatch(/^[a-zA-Z0-9-]+$/);

    // Check for any additional audit fields (created_by, modified_by, IP address if applicable)
    if (notificationData.createdBy) {
      expect(notificationData.createdBy).toBeTruthy();
    }
    if (notificationData.modifiedBy) {
      expect(notificationData.modifiedBy).toBe(employeeId);
    }
    if (notificationData.ipAddress) {
      expect(notificationData.ipAddress).toMatch(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
    }

    // Verify the acknowledgment timestamp format is consistent with system standards (ISO 8601 or configured format)
    const iso8601Regex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z?$/;
    expect(notificationData.acknowledgedAt).toMatch(iso8601Regex);
  });
});