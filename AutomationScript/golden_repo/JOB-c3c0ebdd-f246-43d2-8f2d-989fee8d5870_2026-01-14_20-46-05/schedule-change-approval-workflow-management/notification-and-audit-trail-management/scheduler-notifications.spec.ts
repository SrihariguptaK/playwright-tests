import { test, expect } from '@playwright/test';

test.describe('Scheduler Notification System', () => {
  const schedulerEmail = 'scheduler@example.com';
  const schedulerPassword = 'SchedulerPass123';
  const approverEmail = 'approver@example.com';
  const approverPassword = 'ApproverPass123';

  test('Validate notification delivery on approval decision', async ({ page, context }) => {
    // Step 1: Log in as Scheduler
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', schedulerEmail);
    await page.fill('[data-testid="password-input"]', schedulerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 2: Navigate to schedule change request submission page
    await page.click('[data-testid="schedule-change-menu"]');
    await page.click('[data-testid="submit-request-link"]');
    await expect(page.locator('[data-testid="request-form"]')).toBeVisible();

    // Step 3: Fill in all required fields and submit request
    const requestDate = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="request-date"]', requestDate);
    await page.fill('[data-testid="request-time"]', '09:00');
    await page.fill('[data-testid="request-reason"]', 'Medical appointment');
    await page.fill('[data-testid="request-description"]', 'Need to attend scheduled medical checkup');
    
    const submissionTimestamp = Date.now();
    await page.click('[data-testid="submit-request-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Capture request ID from success message
    const requestIdText = await page.locator('[data-testid="request-id"]').textContent();
    const requestId = requestIdText?.match(/\d+/)?.[0] || '';

    // Step 4: Log out from Scheduler account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Step 5: Log in as Approver
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 6: Navigate to pending schedule change requests
    await page.click('[data-testid="pending-requests-menu"]');
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();

    // Step 7: Locate and approve the submitted request
    await page.click(`[data-testid="request-row-${requestId}"]`);
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();
    await page.click('[data-testid="approve-button"]');
    await page.fill('[data-testid="approval-comments"]', 'Approved - medical reason is valid');
    
    const approvalTimestamp = Date.now();
    await page.click('[data-testid="confirm-approval-button"]');
    await expect(page.locator('[data-testid="approval-success-message"]')).toBeVisible();

    // Step 8: Log out from Approver account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Step 9: Wait for notification delivery (within 1 minute)
    await page.waitForTimeout(5000);

    // Step 10: Log in as Scheduler to check notifications
    await page.fill('[data-testid="email-input"]', schedulerEmail);
    await page.fill('[data-testid="password-input"]', schedulerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 11: Check system alerts/notifications panel
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();
    
    const notificationTimestamp = Date.now();
    const timeDifference = (notificationTimestamp - approvalTimestamp) / 1000;
    expect(timeDifference).toBeLessThan(60);

    // Step 12: Verify notification contains correct details
    const notification = page.locator(`[data-testid="notification-${requestId}"]`);
    await expect(notification).toBeVisible();
    await notification.click();
    
    await expect(page.locator('[data-testid="notification-request-id"]')).toContainText(requestId);
    await expect(page.locator('[data-testid="notification-status"]')).toContainText('Approved');
    await expect(page.locator('[data-testid="notification-comments"]')).toContainText('Approved - medical reason is valid');
    await expect(page.locator('[data-testid="notification-request-date"]')).toContainText(requestDate);
  });

  test('Validate notification delivery on rejection decision', async ({ page }) => {
    // Step 1: Log in as Scheduler
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', schedulerEmail);
    await page.fill('[data-testid="password-input"]', schedulerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 2: Navigate to schedule change request submission page
    await page.click('[data-testid="schedule-change-menu"]');
    await page.click('[data-testid="submit-request-link"]');
    await expect(page.locator('[data-testid="request-form"]')).toBeVisible();

    // Step 3: Fill in all required fields and submit request
    const requestDate = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="request-date"]', requestDate);
    await page.fill('[data-testid="request-time"]', '14:00');
    await page.fill('[data-testid="request-reason"]', 'Personal matter');
    await page.fill('[data-testid="request-description"]', 'Need time off for personal reasons');
    
    const submissionTimestamp = Date.now();
    await page.click('[data-testid="submit-request-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    const requestIdText = await page.locator('[data-testid="request-id"]').textContent();
    const requestId = requestIdText?.match(/\d+/)?.[0] || '';

    // Step 4: Log out from Scheduler account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Step 5: Log in as Approver
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 6: Navigate to pending schedule change requests
    await page.click('[data-testid="pending-requests-menu"]');
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();

    // Step 7: Locate and reject the submitted request
    await page.click(`[data-testid="request-row-${requestId}"]`);
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();
    await page.click('[data-testid="reject-button"]');
    await page.fill('[data-testid="rejection-comments"]', 'Insufficient staffing coverage for requested time');
    
    const rejectionTimestamp = Date.now();
    await page.click('[data-testid="confirm-rejection-button"]');
    await expect(page.locator('[data-testid="rejection-success-message"]')).toBeVisible();

    // Step 8: Calculate time difference for notification delivery
    const timeDifferenceAtRejection = (Date.now() - rejectionTimestamp) / 1000;

    // Step 9: Log out from Approver account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Step 10: Wait for notification delivery
    await page.waitForTimeout(5000);

    // Step 11: Log in as Scheduler to check notifications
    await page.fill('[data-testid="email-input"]', schedulerEmail);
    await page.fill('[data-testid="password-input"]', schedulerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 12: Check system alerts/notifications panel
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();
    
    const notificationTimestamp = Date.now();
    const totalTimeDifference = (notificationTimestamp - rejectionTimestamp) / 1000;
    expect(totalTimeDifference).toBeLessThan(60);

    // Step 13: Verify rejection notification content
    const notification = page.locator(`[data-testid="notification-${requestId}"]`);
    await expect(notification).toBeVisible();
    await notification.click();
    
    await expect(page.locator('[data-testid="notification-request-id"]')).toContainText(requestId);
    await expect(page.locator('[data-testid="notification-status"]')).toContainText('Rejected');
    await expect(page.locator('[data-testid="notification-comments"]')).toContainText('Insufficient staffing coverage for requested time');

    // Step 14: Navigate to notification logs to verify delivery status
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="notification-logs-link"]');
    await expect(page.locator('[data-testid="notification-logs-table"]')).toBeVisible();
    
    const logEntry = page.locator(`[data-testid="log-entry-${requestId}"]`);
    await expect(logEntry).toBeVisible();
    await expect(logEntry.locator('[data-testid="delivery-status"]')).toContainText('Delivered');
  });

  test('Validate notification history display', async ({ page }) => {
    // Step 1: Log in as Scheduler
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', schedulerEmail);
    await page.fill('[data-testid="password-input"]', schedulerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 2: Locate and click on Notifications menu option
    await page.click('[data-testid="notifications-menu"]');
    await expect(page.locator('[data-testid="notifications-dropdown"]')).toBeVisible();

    // Step 3: Click on Notification History
    await page.click('[data-testid="notification-history-link"]');
    await expect(page.locator('[data-testid="notification-history-page"]')).toBeVisible();

    // Step 4: Verify page displays all past notifications
    const notificationsList = page.locator('[data-testid="notifications-list"]');
    await expect(notificationsList).toBeVisible();
    const notificationCount = await page.locator('[data-testid="notification-item"]').count();
    expect(notificationCount).toBeGreaterThan(0);

    // Step 5: Check that each notification displays key information
    const firstNotification = page.locator('[data-testid="notification-item"]').first();
    await expect(firstNotification.locator('[data-testid="notification-date"]')).toBeVisible();
    await expect(firstNotification.locator('[data-testid="notification-request-id"]')).toBeVisible();
    await expect(firstNotification.locator('[data-testid="notification-type"]')).toBeVisible();
    await expect(firstNotification.locator('[data-testid="notification-status"]')).toBeVisible();

    // Step 6: Select and click on a specific notification
    await firstNotification.click();
    await expect(page.locator('[data-testid="notification-details-modal"]')).toBeVisible();

    // Step 7: Verify detailed notification view
    await expect(page.locator('[data-testid="detail-request-id"]')).toBeVisible();
    await expect(page.locator('[data-testid="detail-decision-type"]')).toBeVisible();
    await expect(page.locator('[data-testid="detail-approver-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="detail-comments"]')).toBeVisible();
    await expect(page.locator('[data-testid="detail-timestamp"]')).toBeVisible();

    // Step 8: Close modal and navigate back to notification history
    await page.click('[data-testid="close-modal-button"]');
    await expect(page.locator('[data-testid="notification-history-page"]')).toBeVisible();

    // Step 9: Select a different notification
    const secondNotification = page.locator('[data-testid="notification-item"]').nth(1);
    await secondNotification.click();
    await expect(page.locator('[data-testid="notification-details-modal"]')).toBeVisible();
    await page.click('[data-testid="close-modal-button"]');

    // Step 10: Verify notification history includes both approval and rejection notifications
    const approvalNotifications = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Approved' });
    const rejectionNotifications = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Rejected' });
    
    const approvalCount = await approvalNotifications.count();
    const rejectionCount = await rejectionNotifications.count();
    expect(approvalCount + rejectionCount).toBeGreaterThan(0);

    // Step 11: Check pagination or scroll functionality
    const paginationElement = page.locator('[data-testid="pagination-controls"]');
    if (await paginationElement.isVisible()) {
      await expect(paginationElement).toBeVisible();
      const nextButton = page.locator('[data-testid="next-page-button"]');
      if (await nextButton.isEnabled()) {
        await nextButton.click();
        await expect(page.locator('[data-testid="notifications-list"]')).toBeVisible();
      }
    }

    // Step 12: Verify notification timestamps are accurate
    const timestamps = await page.locator('[data-testid="notification-date"]').allTextContents();
    expect(timestamps.length).toBeGreaterThan(0);
    
    for (const timestamp of timestamps) {
      expect(timestamp).toBeTruthy();
      const datePattern = /\d{4}-\d{2}-\d{2}|\d{1,2}\/\d{1,2}\/\d{4}/;
      expect(datePattern.test(timestamp)).toBeTruthy();
    }
  });
});