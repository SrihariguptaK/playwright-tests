import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Notifications', () => {
  const employeeEmail = 'employee@company.com';
  const employeePassword = 'Employee123!';
  const approverEmail = 'approver@company.com';
  const approverPassword = 'Approver123!';
  const unauthorizedEmail = 'unauthorized@company.com';
  const unauthorizedPassword = 'Unauthorized123!';

  test('Verify notification sent on schedule change request submission (happy-path)', async ({ page, context }) => {
    // Step 1: Navigate to the schedule change request submission page from the employee dashboard
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    await page.click('[data-testid="schedule-change-request-link"]');
    await expect(page).toHaveURL(/.*schedule-change-request/);

    // Step 2: Fill in all required fields with valid data and submit
    await page.fill('[data-testid="change-date-input"]', '2024-03-15');
    await page.fill('[data-testid="change-time-input"]', '09:00');
    await page.fill('[data-testid="change-reason-input"]', 'Medical appointment scheduled');
    await page.click('[data-testid="submit-request-button"]');

    // Expected Result: Submission confirmation notification is sent via email and in-app
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule change request submitted successfully');

    // Step 3: Check the employee's email inbox for submission confirmation notification within 1 minute
    // Wait for notification to be sent
    await page.waitForTimeout(5000);

    // Step 4: Navigate to the in-app notifications section
    await page.click('[data-testid="notifications-bell-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();

    // Step 5: Click on the in-app notification to view details
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toContainText('Schedule change request submitted');
    await expect(notification).toContainText('Medical appointment scheduled');
    await notification.click();

    // Expected Result: Notification with correct details is received
    await expect(page.locator('[data-testid="notification-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-date"]')).toContainText('2024-03-15');
    await expect(page.locator('[data-testid="notification-time"]')).toContainText('09:00');
    await expect(page.locator('[data-testid="notification-reason"]')).toContainText('Medical appointment scheduled');

    // Step 6: Navigate to notification history or logs section
    await page.click('[data-testid="notification-history-link"]');
    await expect(page.locator('[data-testid="notification-log-entry"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="notification-log-entry"]').first()).toContainText('Submission confirmation');
  });

  test('Verify notification sent on approval decision (happy-path)', async ({ page, context }) => {
    // Step 1: Log in as an approver with valid credentials
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to pending approvals dashboard and select the employee's schedule change request
    await page.click('[data-testid="pending-approvals-link"]');
    await expect(page).toHaveURL(/.*pending-approvals/);
    
    const pendingRequest = page.locator('[data-testid="pending-request-item"]').first();
    await expect(pendingRequest).toBeVisible();
    await pendingRequest.click();

    // Step 3: Click 'Approve' button, enter approval comments, and submit
    await page.click('[data-testid="approve-button"]');
    await page.fill('[data-testid="approval-comments-input"]', 'Approved as requested');
    await page.click('[data-testid="submit-approval-button"]');

    // Expected Result: Approval notification is sent to the employee
    await expect(page.locator('[data-testid="approval-success-message"]')).toContainText('Request approved successfully');

    // Step 4: Log out as approver and log in as the employee
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 5: Check the employee's email inbox for approval notification within 1 minute
    await page.waitForTimeout(5000);

    // Step 6: Navigate to in-app notifications section
    await page.click('[data-testid="notifications-bell-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();

    // Step 7: Click on the notification to view full details
    const approvalNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'approved' }).first();
    await expect(approvalNotification).toBeVisible();
    await approvalNotification.click();

    // Expected Result: Notification includes approval status and comments
    await expect(page.locator('[data-testid="notification-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-status"]')).toContainText('Approved');
    await expect(page.locator('[data-testid="notification-comments"]')).toContainText('Approved as requested');

    // Step 8: Verify notification logging in the system logs
    await page.click('[data-testid="notification-history-link"]');
    const approvalLog = page.locator('[data-testid="notification-log-entry"]').filter({ hasText: 'Approved' }).first();
    await expect(approvalLog).toBeVisible();
    await expect(approvalLog).toContainText('Approved as requested');
  });

  test('Ensure notifications are not sent to unauthorized users (error-case)', async ({ page, request }) => {
    let requestId: string;

    // Step 1: Identify a schedule change request submitted by Employee A
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    await page.click('[data-testid="my-requests-link"]');
    const requestItem = page.locator('[data-testid="request-item"]').first();
    await expect(requestItem).toBeVisible();
    requestId = await requestItem.getAttribute('data-request-id') || '12345';

    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Step 2: Attempt to trigger a notification for this request to Employee B (unauthorized user)
    const notificationResponse = await request.post('/api/notifications', {
      data: {
        requestId: requestId,
        recipientEmail: unauthorizedEmail,
        notificationType: 'approval',
        message: 'Your schedule change request has been approved'
      }
    });

    // Expected Result: Notification is blocked and logged
    expect(notificationResponse.status()).toBe(403);
    const responseBody = await notificationResponse.json();
    expect(responseBody.error).toContain('unauthorized');

    // Step 3: Check Employee B's email inbox and in-app notifications
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', unauthorizedEmail);
    await page.fill('[data-testid="password-input"]', unauthorizedPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    await page.click('[data-testid="notifications-bell-icon"]');
    const unauthorizedNotifications = page.locator('[data-testid="notification-item"]').filter({ hasText: requestId });
    await expect(unauthorizedNotifications).toHaveCount(0);

    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Step 4: Review notification logs for the blocked notification attempt
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');

    await page.click('[data-testid="admin-panel-link"]');
    await page.click('[data-testid="notification-logs-link"]');
    
    const blockedLog = page.locator('[data-testid="notification-log-entry"]').filter({ hasText: 'blocked' }).filter({ hasText: unauthorizedEmail });
    await expect(blockedLog).toBeVisible();
    await expect(blockedLog).toContainText('unauthorized');

    // Step 5: Trigger a legitimate notification for the same request to Employee A
    await page.click('[data-testid="pending-approvals-link"]');
    const targetRequest = page.locator(`[data-testid="pending-request-item"][data-request-id="${requestId}"]`);
    await targetRequest.click();
    await page.click('[data-testid="approve-button"]');
    await page.fill('[data-testid="approval-comments-input"]', 'Approved after security check');
    await page.click('[data-testid="submit-approval-button"]');

    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Step 6: Verify Employee A receives the notification while Employee B does not
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');

    await page.waitForTimeout(5000);
    await page.click('[data-testid="notifications-bell-icon"]');
    const employeeANotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Approved' }).first();
    await expect(employeeANotification).toBeVisible();
    await expect(employeeANotification).toContainText('Approved after security check');

    // Step 7: Check notification logs to confirm proper delivery
    await page.click('[data-testid="notification-history-link"]');
    const deliveryLog = page.locator('[data-testid="notification-log-entry"]').filter({ hasText: 'delivered' }).filter({ hasText: employeeEmail }).first();
    await expect(deliveryLog).toBeVisible();
    
    const unauthorizedDeliveryLog = page.locator('[data-testid="notification-log-entry"]').filter({ hasText: 'delivered' }).filter({ hasText: unauthorizedEmail });
    await expect(unauthorizedDeliveryLog).toHaveCount(0);
  });
});