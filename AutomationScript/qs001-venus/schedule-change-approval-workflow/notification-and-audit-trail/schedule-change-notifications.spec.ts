import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Notifications', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const employeeEmail = 'employee@company.com';
  const employeePassword = 'Employee123!';
  const approverEmail = 'approver@company.com';
  const approverPassword = 'Approver123!';

  test.beforeEach(async ({ page }) => {
    await page.goto(baseURL);
  });

  test('Verify notification sent upon schedule change request submission (happy-path)', async ({ page }) => {
    // Login as employee
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to the schedule change request page
    await page.click('[data-testid="schedule-menu"]');
    await page.click('[data-testid="change-request-link"]');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Fill in all required fields for the schedule change request
    const requestDate = new Date();
    requestDate.setDate(requestDate.getDate() + 7);
    const formattedDate = requestDate.toISOString().split('T')[0];
    
    await page.fill('[data-testid="request-date-input"]', formattedDate);
    await page.fill('[data-testid="request-time-input"]', '09:00');
    await page.fill('[data-testid="request-reason-input"]', 'Medical appointment scheduled for this date');

    // Record submission timestamp
    const submissionTime = new Date();

    // Click the Submit button to submit the schedule change request
    await page.click('[data-testid="submit-request-button"]');
    
    // Verify submission confirmation message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule change request submitted successfully');

    // Navigate to the notification center in the user profile
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="notification-center-link"]');
    await expect(page.locator('[data-testid="notification-center"]')).toBeVisible();

    // Check the notification list for the submission confirmation
    const submissionNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Schedule change request submitted' }).first();
    await expect(submissionNotification).toBeVisible();
    
    // Verify notification contains correct details
    await expect(submissionNotification).toContainText(formattedDate);
    await expect(submissionNotification).toContainText('Medical appointment');
    
    // Verify notification is marked as unread
    await expect(submissionNotification.locator('[data-testid="unread-indicator"]')).toBeVisible();
  });

  test('Validate notification sent upon approval decision (happy-path)', async ({ page, context }) => {
    // First, create a request as employee
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    await page.click('[data-testid="schedule-menu"]');
    await page.click('[data-testid="change-request-link"]');
    
    const requestDate = new Date();
    requestDate.setDate(requestDate.getDate() + 10);
    const formattedDate = requestDate.toISOString().split('T')[0];
    
    await page.fill('[data-testid="request-date-input"]', formattedDate);
    await page.fill('[data-testid="request-time-input"]', '14:00');
    await page.fill('[data-testid="request-reason-input"]', 'Family emergency');
    await page.click('[data-testid="submit-request-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Logout as employee
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Login as approver and navigate to the pending schedule change requests page
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    await page.click('[data-testid="approvals-menu"]');
    await page.click('[data-testid="pending-requests-link"]');
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();

    // Select a specific schedule change request from the list
    const pendingRequest = page.locator('[data-testid="request-item"]').filter({ hasText: 'Family emergency' }).first();
    await expect(pendingRequest).toBeVisible();
    await pendingRequest.click();

    // Review the request details and click the Approve button
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-details"]')).toContainText(formattedDate);
    await expect(page.locator('[data-testid="request-details"]')).toContainText('Family emergency');
    
    await page.click('[data-testid="approve-button"]');

    // Add approval comments (optional) and confirm the approval action
    await page.fill('[data-testid="approval-comments-input"]', 'Approved due to family emergency circumstances');
    await page.click('[data-testid="confirm-approval-button"]');
    await expect(page.locator('[data-testid="approval-success-message"]')).toBeVisible();

    // Logout as approver
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Login as the employee who submitted the request
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to the notification center in the employee's user profile
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="notification-center-link"]');
    await expect(page.locator('[data-testid="notification-center"]')).toBeVisible();

    // Locate and click on the approval notification
    const approvalNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'approved' }).first();
    await expect(approvalNotification).toBeVisible();
    await approvalNotification.click();

    // Verify the notification content includes actionable information
    await expect(page.locator('[data-testid="notification-detail"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-detail"]')).toContainText('approved');
    await expect(page.locator('[data-testid="notification-detail"]')).toContainText(formattedDate);
    await expect(page.locator('[data-testid="notification-detail"]')).toContainText('Approved due to family emergency circumstances');
    await expect(page.locator('[data-testid="notification-detail"]')).toContainText('Next steps');
    
    // Verify actionable elements are present
    const viewRequestButton = page.locator('[data-testid="view-request-button"]');
    await expect(viewRequestButton).toBeVisible();
  });

  test('Ensure notifications are delivered within 5 minutes (boundary)', async ({ page }) => {
    // Login as employee
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Record the current system timestamp before triggering the notification event (T1)
    const submissionTimestamp = Date.now();

    // Submit a schedule change request as an employee
    await page.click('[data-testid="schedule-menu"]');
    await page.click('[data-testid="change-request-link"]');
    
    const requestDate = new Date();
    requestDate.setDate(requestDate.getDate() + 5);
    const formattedDate = requestDate.toISOString().split('T')[0];
    
    await page.fill('[data-testid="request-date-input"]', formattedDate);
    await page.fill('[data-testid="request-time-input"]', '10:30');
    await page.fill('[data-testid="request-reason-input"]', 'Personal appointment');
    await page.click('[data-testid="submit-request-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Navigate to the in-app notification center
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="notification-center-link"]');
    await expect(page.locator('[data-testid="notification-center"]')).toBeVisible();

    // Wait for and verify the notification appears
    const submissionNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Schedule change request submitted' }).first();
    await expect(submissionNotification).toBeVisible({ timeout: 300000 }); // 5 minutes max

    // Record the timestamp when notification is received (T2)
    const notificationReceivedTimestamp = Date.now();

    // Calculate the time difference between submission (T1) and notification receipt (T2)
    const timeDifferenceMs = notificationReceivedTimestamp - submissionTimestamp;
    const timeDifferenceMinutes = timeDifferenceMs / (1000 * 60);

    // Verify notification was delivered within 5 minutes
    expect(timeDifferenceMinutes).toBeLessThanOrEqual(5);

    // Verify the notification timestamp in the notification details
    await submissionNotification.click();
    const notificationTimestamp = await page.locator('[data-testid="notification-timestamp"]').textContent();
    expect(notificationTimestamp).toBeTruthy();

    // Navigate back and prepare for approval notification test
    await page.click('[data-testid="back-button"]');
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Login as approver to trigger approval notification
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    await page.click('[data-testid="approvals-menu"]');
    await page.click('[data-testid="pending-requests-link"]');
    
    const pendingRequest = page.locator('[data-testid="request-item"]').filter({ hasText: 'Personal appointment' }).first();
    await pendingRequest.click();

    // Record timestamp before approval (T3)
    const approvalTimestamp = Date.now();

    // Approve the request
    await page.click('[data-testid="approve-button"]');
    await page.fill('[data-testid="approval-comments-input"]', 'Approved');
    await page.click('[data-testid="confirm-approval-button"]');
    await expect(page.locator('[data-testid="approval-success-message"]')).toBeVisible();

    // Logout and login as employee
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');

    // Check for approval notification
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="notification-center-link"]');
    
    const approvalNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'approved' }).first();
    await expect(approvalNotification).toBeVisible({ timeout: 300000 }); // 5 minutes max

    // Record the timestamp when approval notification is received (T4)
    const approvalNotificationReceivedTimestamp = Date.now();

    // Calculate time difference for approval notification
    const approvalTimeDifferenceMs = approvalNotificationReceivedTimestamp - approvalTimestamp;
    const approvalTimeDifferenceMinutes = approvalTimeDifferenceMs / (1000 * 60);

    // Verify approval notification was delivered within 5 minutes
    expect(approvalTimeDifferenceMinutes).toBeLessThanOrEqual(5);
  });
});