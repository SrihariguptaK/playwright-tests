import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Approval', () => {
  const approverEmail = 'approver@company.com';
  const approverPassword = 'ApproverPass123!';
  const schedulerEmail = 'scheduler@company.com';
  const unauthorizedEmail = 'unauthorized@company.com';
  const unauthorizedPassword = 'UnauthorizedPass123!';
  const baseURL = 'https://app.schedulemanager.com';

  test.beforeEach(async ({ page }) => {
    await page.goto(`${baseURL}/login`);
  });

  test('Validate approval decision submission', async ({ page }) => {
    // Step 1: Approver opens approval interface for assigned request
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('**/dashboard');
    await page.click('[data-testid="approval-queue-link"]');
    
    // Select first pending request
    await page.click('[data-testid="request-item"]:first-child');
    
    // Expected Result: Request details and attachments are displayed
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-attachments"]')).toBeVisible();
    await expect(page.locator('[data-testid="requester-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-change-details"]')).toBeVisible();
    
    // Step 2: Approver selects 'Approve' and adds comments
    await page.click('[data-testid="approve-button"]');
    const approvalComments = 'Schedule change approved. All requirements met.';
    await page.fill('[data-testid="approval-comments"]', approvalComments);
    
    // Expected Result: Decision and comments accepted without errors
    await expect(page.locator('[data-testid="approval-comments"]')).toHaveValue(approvalComments);
    await expect(page.locator('[data-testid="submit-decision-button"]')).toBeEnabled();
    
    // Step 3: Approver submits decision
    await page.click('[data-testid="submit-decision-button"]');
    
    // Expected Result: Request status updated, requester notified, and action logged
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Decision submitted successfully');
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Approved');
    
    // Verify notification sent indicator
    await expect(page.locator('[data-testid="notification-sent-indicator"]')).toBeVisible();
    
    // Verify audit log entry
    await page.click('[data-testid="view-audit-log"]');
    await expect(page.locator('[data-testid="audit-log-entry"]:first-child')).toContainText('Approved');
    await expect(page.locator('[data-testid="audit-log-entry"]:first-child')).toContainText(approverEmail);
    await expect(page.locator('[data-testid="audit-log-timestamp"]')).toBeVisible();
  });

  test('Verify rejection with comments', async ({ page }) => {
    // Login as approver
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('**/dashboard');
    await page.click('[data-testid="approval-queue-link"]');
    
    // Select pending request
    await page.click('[data-testid="request-item"]:first-child');
    
    // Step 1: Approver selects 'Reject' and enters comments
    await page.click('[data-testid="reject-button"]');
    const rejectionComments = 'Insufficient justification provided. Please resubmit with detailed reasoning.';
    await page.fill('[data-testid="approval-comments"]', rejectionComments);
    
    // Expected Result: Comments accepted and displayed
    await expect(page.locator('[data-testid="approval-comments"]')).toHaveValue(rejectionComments);
    await expect(page.locator('[data-testid="approval-comments"]')).toBeVisible();
    
    // Step 2: Approver submits rejection
    await page.click('[data-testid="submit-decision-button"]');
    
    // Expected Result: Request status updated to rejected and requester notified
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Decision submitted successfully');
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Rejected');
    await expect(page.locator('[data-testid="notification-sent-indicator"]')).toBeVisible();
    
    // Verify rejection appears in request list with correct status
    await page.click('[data-testid="back-to-queue"]');
    await expect(page.locator('[data-testid="request-item"]:first-child [data-testid="status-badge"]')).toContainText('Rejected');
  });

  test('Test unauthorized approval attempt', async ({ page }) => {
    // Step 1: User not assigned as approver attempts to access approval interface
    await page.fill('[data-testid="email-input"]', unauthorizedEmail);
    await page.fill('[data-testid="password-input"]', unauthorizedPassword);
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('**/dashboard');
    
    // Attempt to navigate to approval queue
    await page.goto(`${baseURL}/approvals/queue`);
    
    // Expected Result: Access denied with appropriate error message
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');
    await expect(page.locator('[data-testid="error-description"]')).toContainText('You do not have permission to access this resource');
    
    // Verify user is redirected or cannot see approval interface
    await expect(page.locator('[data-testid="approval-queue"]')).not.toBeVisible();
    
    // Attempt direct access to specific request
    const requestId = '12345';
    await page.goto(`${baseURL}/approvals/request/${requestId}`);
    
    // Expected Result: Access denied for specific request
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="approve-button"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="reject-button"]')).not.toBeVisible();
  });

  test('Validate notification delivery upon approval decision', async ({ page, context }) => {
    // Approver navigates to the schedule change request approval queue
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('**/dashboard');
    await page.click('[data-testid="approval-queue-link"]');
    
    // Approver selects the scheduler's schedule change request
    await page.click('[data-testid="request-item"]:first-child');
    const requestId = await page.locator('[data-testid="request-id"]').textContent();
    
    // Approver clicks 'Approve' button and confirms the approval
    await page.click('[data-testid="approve-button"]');
    await page.fill('[data-testid="approval-comments"]', 'Approved as requested');
    
    // Note the timestamp of approval action
    const approvalTimestamp = new Date();
    await page.click('[data-testid="submit-decision-button"]');
    
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Open new page as scheduler to check notifications
    const schedulerPage = await context.newPage();
    await schedulerPage.goto(`${baseURL}/login`);
    await schedulerPage.fill('[data-testid="email-input"]', schedulerEmail);
    await schedulerPage.fill('[data-testid="password-input"]', 'SchedulerPass123!');
    await schedulerPage.click('[data-testid="login-button"]');
    
    await schedulerPage.waitForURL('**/dashboard');
    
    // Scheduler checks in-app notification center
    await schedulerPage.click('[data-testid="notification-bell"]');
    await expect(schedulerPage.locator('[data-testid="notification-panel"]')).toBeVisible();
    
    // Verify notification appears within expected timeframe
    await expect(schedulerPage.locator('[data-testid="notification-item"]').first()).toBeVisible({ timeout: 60000 });
    await expect(schedulerPage.locator('[data-testid="notification-item"]').first()).toContainText('Approved');
    await expect(schedulerPage.locator('[data-testid="notification-item"]').first()).toContainText(requestId || '');
    
    // Scheduler opens the notification
    await schedulerPage.click('[data-testid="notification-item"]');
    
    // Click on the dashboard link provided in the notification
    await schedulerPage.click('[data-testid="notification-link"]');
    await expect(schedulerPage.locator('[data-testid="request-details"]')).toBeVisible();
    await expect(schedulerPage.locator('[data-testid="request-status"]')).toContainText('Approved');
  });

  test('Verify notifications are restricted to requestor', async ({ page, context }) => {
    const schedulerAEmail = 'schedulerA@company.com';
    const schedulerBEmail = 'schedulerB@company.com';
    const schedulerBPassword = 'SchedulerBPass123!';
    
    // Log in as Scheduler B (different user from the original requestor)
    await page.fill('[data-testid="email-input"]', schedulerBEmail);
    await page.fill('[data-testid="password-input"]', schedulerBPassword);
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('**/dashboard');
    
    // Navigate to the notification center as Scheduler B
    await page.click('[data-testid="notification-bell"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();
    
    // Search or browse for notifications related to Scheduler A's schedule change request
    const schedulerARequestId = 'REQ-A-12345';
    await page.fill('[data-testid="notification-search"]', schedulerARequestId);
    
    // Verify no results found for Scheduler A's request
    await expect(page.locator('[data-testid="notification-item"]').filter({ hasText: schedulerARequestId })).toHaveCount(0);
    await expect(page.locator('[data-testid="no-notifications-message"]')).toBeVisible();
    
    // Attempt to access Scheduler A's notification directly using URL manipulation
    await page.goto(`${baseURL}/notifications/${schedulerARequestId}`);
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    
    // Check Scheduler B's email inbox - verify no notifications about Scheduler A's request
    await page.goto(`${baseURL}/notifications`);
    const allNotifications = await page.locator('[data-testid="notification-item"]').all();
    for (const notification of allNotifications) {
      const notificationText = await notification.textContent();
      expect(notificationText).not.toContain(schedulerARequestId);
      expect(notificationText).not.toContain(schedulerAEmail);
    }
    
    // Log out and log back in as Scheduler A (original requestor)
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', schedulerAEmail);
    await page.fill('[data-testid="password-input"]', 'SchedulerAPass123!');
    await page.click('[data-testid="login-button"]');
    
    // Navigate to notification center as Scheduler A
    await page.click('[data-testid="notification-bell"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();
    
    // Verify Scheduler A can see their own notifications
    await expect(page.locator('[data-testid="notification-item"]').filter({ hasText: schedulerARequestId })).toBeVisible();
  });

  test('Test notification content accuracy', async ({ page, context }) => {
    // Approver navigates to the schedule change request approval queue
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('**/dashboard');
    await page.click('[data-testid="approval-queue-link"]');
    
    // Approver selects the scheduler's schedule change request
    await page.click('[data-testid="request-item"]:first-child');
    const requestId = await page.locator('[data-testid="request-id"]').textContent();
    
    // Approver clicks 'Request Modifications' button
    await page.click('[data-testid="request-modifications-button"]');
    
    // Approver enters specific modification comments
    const modificationComments = 'Please change shift start time from 8:00 AM to 9:00 AM and provide justification for the change';
    await page.fill('[data-testid="approval-comments"]', modificationComments);
    
    // Approver submits the modification request
    await page.click('[data-testid="submit-decision-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Open new page as scheduler
    const schedulerPage = await context.newPage();
    await schedulerPage.goto(`${baseURL}/login`);
    await schedulerPage.fill('[data-testid="email-input"]', schedulerEmail);
    await schedulerPage.fill('[data-testid="password-input"]', 'SchedulerPass123!');
    await schedulerPage.click('[data-testid="login-button"]');
    
    await schedulerPage.waitForURL('**/dashboard');
    
    // Scheduler checks email and in-app notifications within 1 minute
    await schedulerPage.click('[data-testid="notification-bell"]');
    await expect(schedulerPage.locator('[data-testid="notification-panel"]')).toBeVisible({ timeout: 60000 });
    
    // Scheduler opens the notification and reviews the content
    await schedulerPage.click('[data-testid="notification-item"]');
    await expect(schedulerPage.locator('[data-testid="notification-details"]')).toBeVisible();
    
    // Verify that the modification comments match exactly what the approver entered
    await expect(schedulerPage.locator('[data-testid="notification-message"]')).toContainText(modificationComments);
    await expect(schedulerPage.locator('[data-testid="notification-message"]')).toContainText('8:00 AM to 9:00 AM');
    await expect(schedulerPage.locator('[data-testid="notification-message"]')).toContainText('provide justification');
    
    // Verify that notification includes a link to the schedule change request
    await expect(schedulerPage.locator('[data-testid="notification-link"]')).toBeVisible();
    await expect(schedulerPage.locator('[data-testid="notification-link"]')).toHaveAttribute('href', new RegExp(requestId || ''));
    
    // Click the link in the notification
    await schedulerPage.click('[data-testid="notification-link"]');
    
    // Verify redirected to correct request details page
    await expect(schedulerPage.locator('[data-testid="request-details"]')).toBeVisible();
    await expect(schedulerPage.locator('[data-testid="request-id"]')).toContainText(requestId || '');
    await expect(schedulerPage.locator('[data-testid="request-status"]')).toContainText('Modifications Requested');
    await expect(schedulerPage.locator('[data-testid="approver-comments"]')).toContainText(modificationComments);
  });
});