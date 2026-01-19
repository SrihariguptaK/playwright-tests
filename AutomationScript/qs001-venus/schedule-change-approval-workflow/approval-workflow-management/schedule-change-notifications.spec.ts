import { test, expect } from '@playwright/test';

test.describe('Schedule Change Approval Notifications', () => {
  const approverEmail = 'approver@example.com';
  const approverPassword = 'ApproverPass123!';
  const schedulerEmail = 'scheduler@example.com';
  const schedulerPassword = 'SchedulerPass123!';
  const approvalComment = 'Approved as requested - no conflicts identified';
  const rejectionComment = 'Rejected due to insufficient staffing coverage during requested period';

  test.beforeEach(async ({ page }) => {
    // Navigate to the application
    await page.goto('/login');
  });

  test('Receive notification on approval decision', async ({ page, context }) => {
    // Step 1: Approver logs into the system and navigates to the approval dashboard
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    await page.click('[data-testid="approval-dashboard-link"]');
    await expect(page.locator('[data-testid="approval-dashboard-title"]')).toBeVisible();

    // Step 2: Approver selects the schedule change request submitted by the scheduler
    await page.waitForSelector('[data-testid="schedule-change-requests-list"]');
    const scheduleRequest = page.locator('[data-testid="schedule-request-item"]').first();
    await expect(scheduleRequest).toBeVisible();
    await scheduleRequest.click();

    // Step 3: Approver adds comments and clicks the 'Approve' button
    await page.fill('[data-testid="approval-comments-input"]', approvalComment);
    await page.click('[data-testid="approve-button"]');
    
    // Expected Result: Decision recorded
    await expect(page.locator('[data-testid="approval-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-success-message"]')).toContainText('approved');
    
    const approvalTimestamp = Date.now();

    // Step 4: System automatically triggers notification service within 1 minute of approval
    // Log out approver
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Step 5: Scheduler logs into the system and checks in-app notifications
    await page.fill('[data-testid="email-input"]', schedulerEmail);
    await page.fill('[data-testid="password-input"]', schedulerPassword);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);

    // Expected Result: Scheduler receives in-app notification within 1 minute
    await page.waitForSelector('[data-testid="notifications-icon"]', { timeout: 60000 });
    const notificationBadge = page.locator('[data-testid="notification-badge"]');
    await expect(notificationBadge).toBeVisible({ timeout: 60000 });
    
    const notificationReceivedTime = Date.now();
    const timeDifference = (notificationReceivedTime - approvalTimestamp) / 1000;
    expect(timeDifference).toBeLessThan(60);

    // Step 6: Scheduler clicks on the in-app notification to view details
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();
    
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toContainText('approved');
    await notification.click();

    // Expected Result: Notification displays decision and comments
    await expect(page.locator('[data-testid="notification-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-decision"]')).toContainText('Approved');
    await expect(page.locator('[data-testid="notification-comments"]')).toContainText(approvalComment);
    await expect(page.locator('[data-testid="approver-name"]')).toBeVisible();
  });

  test('Receive notification on rejection decision', async ({ page, context }) => {
    // Step 1: Approver logs into the system and navigates to the approval dashboard
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    await page.click('[data-testid="approval-dashboard-link"]');
    await expect(page.locator('[data-testid="approval-dashboard-title"]')).toBeVisible();

    // Step 2: Approver selects the schedule change request submitted by the scheduler
    await page.waitForSelector('[data-testid="schedule-change-requests-list"]');
    const scheduleRequest = page.locator('[data-testid="schedule-request-item"]').first();
    await expect(scheduleRequest).toBeVisible();
    await scheduleRequest.click();

    // Step 3: Approver adds comments and clicks the 'Reject' button
    await page.fill('[data-testid="approval-comments-input"]', rejectionComment);
    await page.click('[data-testid="reject-button"]');
    
    // Expected Result: Decision recorded
    await expect(page.locator('[data-testid="rejection-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="rejection-success-message"]')).toContainText('rejected');
    
    const rejectionTimestamp = Date.now();

    // Step 4: System automatically triggers notification service within 1 minute of rejection
    // Log out approver
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Step 5: Scheduler logs into the system and checks in-app notifications
    await page.fill('[data-testid="email-input"]', schedulerEmail);
    await page.fill('[data-testid="password-input"]', schedulerPassword);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);

    // Expected Result: Scheduler receives in-app notification within 1 minute
    await page.waitForSelector('[data-testid="notifications-icon"]', { timeout: 60000 });
    const notificationBadge = page.locator('[data-testid="notification-badge"]');
    await expect(notificationBadge).toBeVisible({ timeout: 60000 });
    
    const notificationReceivedTime = Date.now();
    const timeDifference = (notificationReceivedTime - rejectionTimestamp) / 1000;
    expect(timeDifference).toBeLessThan(60);

    // Step 6: Scheduler clicks on the in-app notification to view details
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();
    
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toContainText('rejected');
    await notification.click();

    // Expected Result: Notification displays decision and comments
    await expect(page.locator('[data-testid="notification-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-decision"]')).toContainText('Rejected');
    await expect(page.locator('[data-testid="notification-comments"]')).toContainText(rejectionComment);
    await expect(page.locator('[data-testid="approver-name"]')).toBeVisible();
  });
});