import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Notifications', () => {
  const employeeEmail = 'employee@company.com';
  const employeePassword = 'Employee123!';
  const approverEmail = 'approver@company.com';
  const approverPassword = 'Approver123!';
  const baseURL = 'https://app.example.com';

  test.beforeEach(async ({ page }) => {
    await page.goto(baseURL);
  });

  test('Validate notification sent upon schedule change request submission', async ({ page, context }) => {
    // Step 1: Login as employee
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 2: Navigate to schedule change request form
    await page.click('[data-testid="request-schedule-change"]');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Step 3: Fill in required fields
    await page.fill('[data-testid="start-date-input"]', '2024-02-01');
    await page.fill('[data-testid="end-date-input"]', '2024-02-05');
    await page.fill('[data-testid="reason-input"]', 'Personal appointment');
    
    // Step 4: Submit the request
    const submissionTime = new Date();
    await page.click('[data-testid="submit-request-button"]');
    
    // Step 5: Check for immediate notification delivery
    await expect(page.locator('[data-testid="notification-badge"]')).toBeVisible({ timeout: 5000 });
    const notificationCount = await page.locator('[data-testid="notification-badge"]').textContent();
    expect(parseInt(notificationCount || '0')).toBeGreaterThan(0);

    // Step 6: Open notification center
    await page.click('[data-testid="notification-icon"]');
    await expect(page.locator('[data-testid="notification-center"]')).toBeVisible();

    // Step 7: Verify submission notification is visible with correct details
    const submissionNotification = page.locator('[data-testid="notification-item"]').first();
    await expect(submissionNotification).toBeVisible();
    await expect(submissionNotification.locator('[data-testid="notification-status"]')).toContainText('Submitted');
    await expect(submissionNotification.locator('[data-testid="notification-reason"]')).toContainText('Personal appointment');
    
    // Step 8: Verify notification timestamp
    const notificationTimestamp = await submissionNotification.locator('[data-testid="notification-timestamp"]').textContent();
    expect(notificationTimestamp).toBeTruthy();
  });

  test('Verify notifications sent upon approval and rejection', async ({ page, context }) => {
    // Part 1: Test Approval Notification
    
    // Step 1: Login as approver
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 2: Navigate to approval dashboard
    await page.click('[data-testid="approval-dashboard"]');
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();

    // Step 3: Select first pending request
    const firstRequest = page.locator('[data-testid="pending-request-item"]').first();
    const requestId = await firstRequest.getAttribute('data-request-id');
    await firstRequest.click();
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();

    // Step 4: Approve the request
    await page.click('[data-testid="approve-button"]');
    await page.fill('[data-testid="approval-comments"]', 'Approved as requested');
    await page.click('[data-testid="submit-approval-button"]');
    await expect(page.locator('[data-testid="approval-success-message"]')).toBeVisible();

    // Step 5: Logout from approver account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Step 6: Login as employee
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 7: Check notification icon
    await expect(page.locator('[data-testid="notification-badge"]')).toBeVisible();

    // Step 8: Open notification center
    await page.click('[data-testid="notification-icon"]');
    await expect(page.locator('[data-testid="notification-center"]')).toBeVisible();

    // Step 9: Verify approval notification details
    const approvalNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Approved' }).first();
    await expect(approvalNotification).toBeVisible();
    await expect(approvalNotification.locator('[data-testid="notification-status"]')).toContainText('Approved');
    await expect(approvalNotification.locator('[data-testid="notification-comments"]')).toContainText('Approved as requested');
    await expect(approvalNotification.locator('[data-testid="approver-name"]')).toBeVisible();
    await expect(approvalNotification.locator('[data-testid="notification-timestamp"]')).toBeVisible();

    // Part 2: Test Rejection Notification

    // Step 10: Logout and login as approver again
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');

    // Step 11: Navigate to approval dashboard
    await page.click('[data-testid="approval-dashboard"]');
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();

    // Step 12: Select second pending request
    const secondRequest = page.locator('[data-testid="pending-request-item"]').nth(1);
    await secondRequest.click();
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();

    // Step 13: Reject the request
    await page.click('[data-testid="reject-button"]');
    await page.fill('[data-testid="rejection-comments"]', 'Unable to approve due to staffing constraints during requested period');
    await page.click('[data-testid="submit-rejection-button"]');
    await expect(page.locator('[data-testid="rejection-success-message"]')).toBeVisible();

    // Step 14: Logout and login as employee
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');

    // Step 15: Open notification center
    await page.click('[data-testid="notification-icon"]');
    await expect(page.locator('[data-testid="notification-center"]')).toBeVisible();

    // Step 16: Verify rejection notification details
    const rejectionNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Rejected' }).first();
    await expect(rejectionNotification).toBeVisible();
    await expect(rejectionNotification.locator('[data-testid="notification-status"]')).toContainText('Rejected');
    await expect(rejectionNotification.locator('[data-testid="notification-comments"]')).toContainText('Unable to approve due to staffing constraints');
    await expect(rejectionNotification.locator('[data-testid="approver-name"]')).toBeVisible();
    await expect(rejectionNotification.locator('[data-testid="notification-timestamp"]')).toBeVisible();
  });

  test('Ensure notifications are delivered within 1 minute of status change', async ({ page, context }) => {
    // Step 1: Login as approver
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 2: Open a second page for employee session
    const employeePage = await context.newPage();
    await employeePage.goto(baseURL);
    await employeePage.fill('[data-testid="email-input"]', employeeEmail);
    await employeePage.fill('[data-testid="password-input"]', employeePassword);
    await employeePage.click('[data-testid="login-button"]');
    await expect(employeePage.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 3: Navigate to approval dashboard as approver
    await page.click('[data-testid="approval-dashboard"]');
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();

    // Step 4: Select a pending request
    const pendingRequest = page.locator('[data-testid="pending-request-item"]').first();
    await pendingRequest.click();
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();

    // Step 5: Note the time and approve the request
    const statusChangeTime = Date.now();
    await page.click('[data-testid="approve-button"]');
    await page.fill('[data-testid="approval-comments"]', 'Approved for timing test');
    await page.click('[data-testid="submit-approval-button"]');
    await expect(page.locator('[data-testid="approval-success-message"]')).toBeVisible();

    // Step 6: Immediately check employee notification
    await employeePage.reload();
    
    // Step 7: Wait for notification badge to appear (max 60 seconds)
    await expect(employeePage.locator('[data-testid="notification-badge"]')).toBeVisible({ timeout: 60000 });
    const notificationDeliveryTime = Date.now();

    // Step 8: Calculate time difference
    const timeDifferenceMs = notificationDeliveryTime - statusChangeTime;
    const timeDifferenceSeconds = timeDifferenceMs / 1000;

    // Step 9: Verify notification delivered within 1 minute (60 seconds)
    expect(timeDifferenceSeconds).toBeLessThanOrEqual(60);

    // Step 10: Open notification center and verify notification details
    await employeePage.click('[data-testid="notification-icon"]');
    await expect(employeePage.locator('[data-testid="notification-center"]')).toBeVisible();
    
    const latestNotification = employeePage.locator('[data-testid="notification-item"]').first();
    await expect(latestNotification).toBeVisible();
    await expect(latestNotification.locator('[data-testid="notification-status"]')).toContainText('Approved');
    
    // Step 11: Verify notification timestamp
    const notificationTimestamp = await latestNotification.locator('[data-testid="notification-timestamp"]').textContent();
    expect(notificationTimestamp).toBeTruthy();

    // Step 12: Test rejection timing
    await page.click('[data-testid="approval-dashboard"]');
    const secondRequest = page.locator('[data-testid="pending-request-item"]').first();
    await secondRequest.click();
    
    const rejectionTime = Date.now();
    await page.click('[data-testid="reject-button"]');
    await page.fill('[data-testid="rejection-comments"]', 'Rejected for timing test');
    await page.click('[data-testid="submit-rejection-button"]');
    await expect(page.locator('[data-testid="rejection-success-message"]')).toBeVisible();

    // Step 13: Check employee notification for rejection
    await employeePage.reload();
    await employeePage.click('[data-testid="notification-icon"]');
    
    const rejectionNotification = employeePage.locator('[data-testid="notification-item"]').filter({ hasText: 'Rejected' }).first();
    await expect(rejectionNotification).toBeVisible({ timeout: 60000 });
    const rejectionDeliveryTime = Date.now();
    
    const rejectionTimeDifferenceSeconds = (rejectionDeliveryTime - rejectionTime) / 1000;
    expect(rejectionTimeDifferenceSeconds).toBeLessThanOrEqual(60);

    await employeePage.close();
  });
});