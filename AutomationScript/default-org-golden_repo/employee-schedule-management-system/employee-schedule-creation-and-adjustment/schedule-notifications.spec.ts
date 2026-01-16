import { test, expect } from '@playwright/test';

test.describe('Schedule Notification System', () => {
  test.beforeEach(async ({ page }) => {
    // Login as scheduler before each test
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@company.com');
    await page.fill('[data-testid="password-input"]', 'schedulerPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify automatic notification on schedule creation', async ({ page }) => {
    // Navigate to schedule creation page
    await page.goto('/schedules/create');
    await expect(page.locator('[data-testid="schedule-creation-page"]')).toBeVisible();

    // Select an employee from dropdown
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-john-doe"]');
    await expect(page.locator('[data-testid="employee-dropdown"]')).toContainText('John Doe');

    // Enter schedule details
    await page.fill('[data-testid="schedule-date-input"]', '2024-02-15');
    await page.fill('[data-testid="schedule-start-time"]', '09:00');
    await page.fill('[data-testid="schedule-end-time"]', '17:00');
    await page.selectOption('[data-testid="shift-type-select"]', 'Morning Shift');
    await page.selectOption('[data-testid="location-select"]', 'Main Office');

    // Note timestamp before saving
    const startTime = Date.now();

    // Click save button
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule created successfully');

    // Navigate to notification status dashboard
    await page.goto('/scheduler/notifications');
    await expect(page.locator('[data-testid="notification-dashboard"]')).toBeVisible();

    // Wait for notification to be triggered (within 1 minute)
    await page.waitForSelector('[data-testid="notification-status-sent"]', { timeout: 60000 });
    const endTime = Date.now();
    const elapsedTime = (endTime - startTime) / 1000;

    // Verify notification was sent within 1 minute
    expect(elapsedTime).toBeLessThan(60);

    // Verify notification delivery status
    const notificationRow = page.locator('[data-testid="notification-row"]').first();
    await expect(notificationRow.locator('[data-testid="notification-status"]')).toContainText('Sent');
    await expect(notificationRow.locator('[data-testid="recipient-name"]')).toContainText('John Doe');

    // Verify notification contains accurate schedule details
    await notificationRow.click();
    await expect(page.locator('[data-testid="notification-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-date"]')).toContainText('2024-02-15');
    await expect(page.locator('[data-testid="notification-shift-type"]')).toContainText('Morning Shift');
    await expect(page.locator('[data-testid="notification-time"]')).toContainText('09:00');
    await expect(page.locator('[data-testid="notification-time"]')).toContainText('17:00');
    await expect(page.locator('[data-testid="notification-location"]')).toContainText('Main Office');
  });

  test('Resend notification manually', async ({ page }) => {
    // Navigate to scheduler dashboard
    await page.goto('/scheduler/dashboard');
    await expect(page.locator('[data-testid="scheduler-dashboard"]')).toBeVisible();

    // Navigate to notification management section
    await page.click('[data-testid="notifications-menu-item"]');
    await expect(page).toHaveURL(/.*notifications/);

    // Locate and access notification status view
    await expect(page.locator('[data-testid="notification-status-view"]')).toBeVisible();

    // View notification status for a specific schedule
    const notificationRow = page.locator('[data-testid="notification-row"]').first();
    await expect(notificationRow).toBeVisible();

    // Verify delivery status is displayed
    const deliveryStatus = notificationRow.locator('[data-testid="delivery-status"]');
    await expect(deliveryStatus).toBeVisible();
    const statusText = await deliveryStatus.textContent();
    expect(statusText).toBeTruthy();

    // Identify notification that needs to be resent
    await notificationRow.click();
    await expect(page.locator('[data-testid="notification-details-panel"]')).toBeVisible();

    // Click resend notification button
    const resendButton = page.locator('[data-testid="resend-notification-button"]');
    await expect(resendButton).toBeVisible();
    await resendButton.click();

    // Confirm resend action if prompted
    const confirmDialog = page.locator('[data-testid="confirm-resend-dialog"]');
    if (await confirmDialog.isVisible()) {
      await page.click('[data-testid="confirm-resend-yes-button"]');
    }

    // Verify success message
    await expect(page.locator('[data-testid="resend-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="resend-success-message"]')).toContainText('Notification resent successfully');

    // Refresh notification status view
    await page.reload();
    await expect(page.locator('[data-testid="notification-status-view"]')).toBeVisible();

    // Verify status updated
    const updatedNotification = page.locator('[data-testid="notification-row"]').first();
    await expect(updatedNotification.locator('[data-testid="delivery-status"]')).toContainText('Resent');
    await expect(updatedNotification.locator('[data-testid="last-sent-time"]')).toBeVisible();
  });

  test('Ensure notification privacy and security - unauthorized access denied', async ({ page }) => {
    // Log out from existing session
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Log in with unauthorized user account
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'employeePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Attempt to navigate directly to notification status page
    await page.goto('/scheduler/notifications');
    
    // Verify access is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/Access Denied|Unauthorized|403/);

    // Attempt to access notification management URL
    await page.goto('/scheduler/notification-management');
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();

    // Attempt to access notification details via direct link
    await page.goto('/scheduler/notifications/12345');
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();

    // Search for navigation menu items related to notifications
    const navigationMenu = page.locator('[data-testid="navigation-menu"]');
    const notificationMenuItem = navigationMenu.locator('[data-testid="notifications-menu-item"]');
    await expect(notificationMenuItem).not.toBeVisible();

    // Attempt to manipulate URL parameters to view another employee's notifications
    await page.goto('/notifications?employeeId=99999');
    const unauthorizedContent = page.locator('[data-testid="notification-details"]');
    if (await unauthorizedContent.isVisible()) {
      // If page loads, verify it shows access denied or no data
      const pageContent = await page.textContent('body');
      expect(pageContent).toMatch(/Access Denied|Unauthorized|No notifications found/);
    } else {
      // Verify access denied message is shown
      await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    }

    // Log out and log in with Scheduler role
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.fill('[data-testid="username-input"]', 'scheduler@company.com');
    await page.fill('[data-testid="password-input"]', 'schedulerPass123');
    await page.click('[data-testid="login-button"]');

    // Verify scheduler can access notifications
    await page.goto('/scheduler/notifications');
    await expect(page.locator('[data-testid="notification-dashboard"]')).toBeVisible();

    // Verify notification content does not expose sensitive information
    const notificationContent = page.locator('[data-testid="notification-row"]').first();
    await notificationContent.click();
    const detailsPanel = page.locator('[data-testid="notification-details-panel"]');
    await expect(detailsPanel).toBeVisible();
    
    // Verify no sensitive data like passwords, SSN, or personal identifiers are exposed
    const panelText = await detailsPanel.textContent();
    expect(panelText).not.toMatch(/password|ssn|social security|credit card/i);
  });
});