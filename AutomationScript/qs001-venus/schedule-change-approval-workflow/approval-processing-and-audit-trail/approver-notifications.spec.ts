import { test, expect } from '@playwright/test';

test.describe('Approver Notification System - Story 12', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const REQUESTER_EMAIL = 'requester@example.com';
  const REQUESTER_PASSWORD = 'Password123!';
  const APPROVER_EMAIL = 'approver@example.com';
  const APPROVER_PASSWORD = 'Password123!';
  const NOTIFICATION_WAIT_TIME = 5 * 60 * 1000; // 5 minutes in milliseconds

  test('Validate notification delivery for new pending approvals (happy-path)', async ({ page, context }) => {
    // Step 1: Login as a requester user and navigate to the schedule change request submission form
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', REQUESTER_EMAIL);
    await page.fill('[data-testid="password-input"]', REQUESTER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    await page.goto(`${BASE_URL}/schedule-change-request`);
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Step 2: Fill in all required fields and select an approver
    const requestId = `REQ-${Date.now()}`;
    await page.fill('[data-testid="schedule-details-input"]', 'Change shift from morning to evening');
    await page.fill('[data-testid="justification-input"]', 'Personal medical appointment scheduled');
    await page.fill('[data-testid="affected-date-start"]', '2024-02-01');
    await page.fill('[data-testid="affected-date-end"]', '2024-02-01');
    await page.selectOption('[data-testid="approver-dropdown"]', { label: APPROVER_EMAIL });

    // Step 3: Click 'Submit' button to submit the schedule change request
    await page.click('[data-testid="submit-request-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule change request submitted successfully');
    
    // Extract request ID from success message or page
    const submittedRequestId = await page.locator('[data-testid="request-id"]').textContent();

    // Step 4: Wait up to 5 minutes and check the assigned approver's email inbox
    // Note: In real implementation, this would integrate with email testing service
    await page.waitForTimeout(10000); // Wait 10 seconds for notification processing

    // Step 5: Login as the assigned approver and check the in-app notification center
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', APPROVER_EMAIL);
    await page.fill('[data-testid="password-input"]', APPROVER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Check notification badge
    await expect(page.locator('[data-testid="notification-badge"]')).toBeVisible();
    const notificationCount = await page.locator('[data-testid="notification-badge"]').textContent();
    expect(parseInt(notificationCount || '0')).toBeGreaterThan(0);

    // Step 6: Click on the notification to view details
    await page.click('[data-testid="notification-icon"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();
    
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toBeVisible();

    // Step 7: Verify notification content includes all required information
    await expect(notification).toContainText('New schedule change request');
    await expect(notification).toContainText(REQUESTER_EMAIL);
    
    await notification.click();
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-id-display"]')).toContainText(submittedRequestId || '');
    await expect(page.locator('[data-testid="requester-name"]')).toContainText(REQUESTER_EMAIL);
    await expect(page.locator('[data-testid="request-summary"]')).toContainText('Change shift from morning to evening');
  });

  test('Verify escalation notification for overdue approvals (edge-case)', async ({ page }) => {
    // Step 1: Create or identify a schedule change request that has been pending beyond SLA threshold
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', 'admin@example.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to admin panel to simulate overdue request
    await page.goto(`${BASE_URL}/admin/requests`);
    await expect(page.locator('[data-testid="admin-requests-table"]')).toBeVisible();

    // Identify or create an overdue request
    const overdueRequest = page.locator('[data-testid="request-row"]').filter({ hasText: 'Pending' }).first();
    const requestId = await overdueRequest.locator('[data-testid="request-id-cell"]').textContent();

    // Step 2: Trigger the escalation notification job manually
    await page.goto(`${BASE_URL}/admin/jobs`);
    await page.click('[data-testid="escalation-job-trigger"]');
    await expect(page.locator('[data-testid="job-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="job-success-message"]')).toContainText('Escalation notification job executed successfully');

    // Step 3: Check the approver's email inbox for escalation notification
    // Note: Email verification would be done via email testing service integration
    await page.waitForTimeout(5000);

    // Step 4: Login as approver and check in-app notification center for escalation alert
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', APPROVER_EMAIL);
    await page.fill('[data-testid="password-input"]', APPROVER_PASSWORD);
    await page.click('[data-testid="login-button"]');

    await page.click('[data-testid="notification-icon"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();

    const escalationNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Escalation' }).first();
    await expect(escalationNotification).toBeVisible();
    await expect(escalationNotification).toContainText('overdue');

    // Step 5: Navigate to notification logs to verify escalation notification was logged
    await page.goto(`${BASE_URL}/notifications/logs`);
    await expect(page.locator('[data-testid="notification-logs-table"]')).toBeVisible();

    const escalationLog = page.locator('[data-testid="log-row"]').filter({ hasText: 'Escalation' }).first();
    await expect(escalationLog).toBeVisible();

    // Step 6: Verify the escalation notification contains accurate information
    await expect(escalationLog.locator('[data-testid="log-type"]')).toContainText('Escalation');
    await expect(escalationLog.locator('[data-testid="log-recipient"]')).toContainText(APPROVER_EMAIL);
    await expect(escalationLog.locator('[data-testid="log-status"]')).toContainText('Sent');
    
    const logDetails = escalationLog.locator('[data-testid="log-message"]');
    await expect(logDetails).toContainText('pending');
  });

  test('Test notification preference management (happy-path)', async ({ page }) => {
    // Step 1: Navigate to user settings and locate notification preferences
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', APPROVER_EMAIL);
    await page.fill('[data-testid="password-input"]', APPROVER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="settings-link"]');
    await expect(page).toHaveURL(/.*settings/);

    await page.click('[data-testid="notifications-tab"]');
    await expect(page.locator('[data-testid="notification-preferences-section"]')).toBeVisible();

    // Step 2: Review current notification preferences displayed
    const emailNotificationToggle = page.locator('[data-testid="email-notification-toggle"]');
    const inAppNotificationToggle = page.locator('[data-testid="inapp-notification-toggle"]');
    
    await expect(emailNotificationToggle).toBeVisible();
    await expect(inAppNotificationToggle).toBeVisible();

    // Step 3: Disable email notifications
    const isEmailEnabled = await emailNotificationToggle.isChecked();
    if (isEmailEnabled) {
      await emailNotificationToggle.click();
    }
    await expect(emailNotificationToggle).not.toBeChecked();

    // Step 4: Keep in-app notifications enabled and save preferences
    const isInAppEnabled = await inAppNotificationToggle.isChecked();
    if (!isInAppEnabled) {
      await inAppNotificationToggle.click();
    }
    await expect(inAppNotificationToggle).toBeChecked();

    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toContainText('Preferences saved successfully');

    // Step 5: Verify preferences are saved by refreshing the page
    await page.reload();
    await page.click('[data-testid="notifications-tab"]');
    
    await expect(page.locator('[data-testid="email-notification-toggle"]')).not.toBeChecked();
    await expect(page.locator('[data-testid="inapp-notification-toggle"]')).toBeChecked();

    // Step 6: Trigger a notification event by submitting a new request
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', REQUESTER_EMAIL);
    await page.fill('[data-testid="password-input"]', REQUESTER_PASSWORD);
    await page.click('[data-testid="login-button"]');

    await page.goto(`${BASE_URL}/schedule-change-request`);
    await page.fill('[data-testid="schedule-details-input"]', 'Test notification preferences');
    await page.fill('[data-testid="justification-input"]', 'Testing notification delivery with updated preferences');
    await page.fill('[data-testid="affected-date-start"]', '2024-02-15');
    await page.fill('[data-testid="affected-date-end"]', '2024-02-15');
    await page.selectOption('[data-testid="approver-dropdown"]', { label: APPROVER_EMAIL });
    await page.click('[data-testid="submit-request-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Step 7: Wait and check approver's email inbox (should not receive email)
    await page.waitForTimeout(10000);

    // Step 8: Check the approver's in-app notification center
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', APPROVER_EMAIL);
    await page.fill('[data-testid="password-input"]', APPROVER_PASSWORD);
    await page.click('[data-testid="login-button"]');

    await page.click('[data-testid="notification-icon"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();
    
    const newNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Test notification preferences' }).first();
    await expect(newNotification).toBeVisible();

    // Step 9: Verify in notification logs that only in-app notification was sent
    await page.goto(`${BASE_URL}/notifications/logs`);
    await expect(page.locator('[data-testid="notification-logs-table"]')).toBeVisible();

    const recentLogs = page.locator('[data-testid="log-row"]').filter({ hasText: APPROVER_EMAIL }).first();
    await expect(recentLogs.locator('[data-testid="log-channel"]')).toContainText('In-App');
    await expect(recentLogs.locator('[data-testid="log-channel"]')).not.toContainText('Email');
  });
});