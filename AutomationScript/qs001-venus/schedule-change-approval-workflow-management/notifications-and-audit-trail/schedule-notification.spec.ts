import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Notifications', () => {
  const APPROVER_EMAIL = 'approver@company.com';
  const APPROVER_PASSWORD = 'ApproverPass123!';
  const EMPLOYEE_EMAIL = 'employee@company.com';
  const NOTIFICATION_TIMEOUT = 300000; // 5 minutes

  test.beforeEach(async ({ page }) => {
    // Navigate to application login page
    await page.goto('/login');
  });

  test('Verify notification sent upon approval (happy-path)', async ({ page }) => {
    // Login as an approver with valid credentials
    await page.fill('[data-testid="email-input"]', APPROVER_EMAIL);
    await page.fill('[data-testid="password-input"]', APPROVER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to pending schedule change requests
    await page.click('[data-testid="schedule-requests-menu"]');
    await page.click('[data-testid="pending-requests-link"]');
    await expect(page.locator('[data-testid="pending-requests-table"]')).toBeVisible();

    // Select the employee's schedule change request
    const firstRequest = page.locator('[data-testid="request-row"]').first();
    const requestId = await firstRequest.getAttribute('data-request-id');
    await firstRequest.click();

    // Click approve button and submit the approval
    await page.click('[data-testid="approve-button"]');
    await page.click('[data-testid="confirm-approval-button"]');
    
    // Verify system triggers notification by checking notification queue or logs
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request approved successfully');
    
    // Navigate to notification logs to verify
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="notification-logs-link"]');
    
    // Access NotificationLogs table or notification history interface
    await page.fill('[data-testid="search-request-id"]', requestId || '');
    await page.click('[data-testid="search-button"]');
    
    // Verify log shows successful delivery
    const logEntry = page.locator('[data-testid="notification-log-entry"]').first();
    await expect(logEntry).toBeVisible();
    await expect(logEntry.locator('[data-testid="notification-status"]')).toContainText('Delivered');
    await expect(logEntry.locator('[data-testid="notification-type"]')).toContainText('Approval');
    await expect(logEntry.locator('[data-testid="recipient-email"]')).toContainText(EMPLOYEE_EMAIL);
    
    // Verify email content includes all required information
    await expect(logEntry.locator('[data-testid="notification-content"]')).toContainText('approved');
  });

  test('Verify notification sent upon rejection with comments (happy-path)', async ({ page }) => {
    const rejectionComment = 'Insufficient staffing coverage during requested period';
    
    // Login as an approver with valid credentials
    await page.fill('[data-testid="email-input"]', APPROVER_EMAIL);
    await page.fill('[data-testid="password-input"]', APPROVER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to pending schedule change requests
    await page.click('[data-testid="schedule-requests-menu"]');
    await page.click('[data-testid="pending-requests-link"]');
    await expect(page.locator('[data-testid="pending-requests-table"]')).toBeVisible();

    // Select the employee's schedule change request
    const firstRequest = page.locator('[data-testid="request-row"]').first();
    const requestId = await firstRequest.getAttribute('data-request-id');
    await firstRequest.click();

    // Click reject button and enter rejection comments
    await page.click('[data-testid="reject-button"]');
    await page.fill('[data-testid="rejection-comments"]', rejectionComment);
    
    // Submit the rejection with comments
    await page.click('[data-testid="confirm-rejection-button"]');
    
    // Verify system triggers notification by checking notification queue or logs
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request rejected successfully');
    
    // Navigate to notification logs
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="notification-logs-link"]');
    
    // Access NotificationLogs table or notification history interface
    await page.fill('[data-testid="search-request-id"]', requestId || '');
    await page.click('[data-testid="search-button"]');
    
    // Verify email content includes rejection comments
    const logEntry = page.locator('[data-testid="notification-log-entry"]').first();
    await expect(logEntry).toBeVisible();
    await expect(logEntry.locator('[data-testid="notification-status"]')).toContainText('Delivered');
    await expect(logEntry.locator('[data-testid="notification-type"]')).toContainText('Rejection');
    await expect(logEntry.locator('[data-testid="recipient-email"]')).toContainText(EMPLOYEE_EMAIL);
    await expect(logEntry.locator('[data-testid="notification-content"]')).toContainText(rejectionComment);
  });

  test('Ensure notifications are sent only to request owners (edge-case)', async ({ page }) => {
    const employeeAEmail = 'employeeA@company.com';
    const employeeBEmail = 'employeeB@company.com';
    
    // Login as approver
    await page.fill('[data-testid="email-input"]', APPROVER_EMAIL);
    await page.fill('[data-testid="password-input"]', APPROVER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the schedule change request submitted by Employee A
    await page.click('[data-testid="schedule-requests-menu"]');
    await page.click('[data-testid="pending-requests-link"]');
    await expect(page.locator('[data-testid="pending-requests-table"]')).toBeVisible();

    // Find and select request from Employee A
    const requestFromEmployeeA = page.locator('[data-testid="request-row"]').filter({ hasText: employeeAEmail }).first();
    const requestId = await requestFromEmployeeA.getAttribute('data-request-id');
    await requestFromEmployeeA.click();
    
    // Verify request owner is Employee A
    await expect(page.locator('[data-testid="request-owner-email"]')).toContainText(employeeAEmail);

    // Approve the schedule change request to trigger notification
    await page.click('[data-testid="approve-button"]');
    await page.click('[data-testid="confirm-approval-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request approved successfully');

    // Check NotificationLogs table for notification entries related to this request
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="notification-logs-link"]');
    await page.fill('[data-testid="search-request-id"]', requestId || '');
    await page.click('[data-testid="search-button"]');

    // Verify Employee A's notification entry exists
    const notificationEntries = page.locator('[data-testid="notification-log-entry"]');
    await expect(notificationEntries).toHaveCount(1);
    
    const employeeANotification = notificationEntries.first();
    await expect(employeeANotification.locator('[data-testid="recipient-email"]')).toContainText(employeeAEmail);
    await expect(employeeANotification.locator('[data-testid="notification-status"]')).toContainText('Delivered');
    
    // Verify Employee B did not receive notification
    await page.fill('[data-testid="search-request-id"]', '');
    await page.fill('[data-testid="search-recipient-email"]', employeeBEmail);
    await page.click('[data-testid="search-button"]');
    
    const employeeBNotifications = page.locator('[data-testid="notification-log-entry"]').filter({ hasText: requestId || '' });
    await expect(employeeBNotifications).toHaveCount(0);
    
    // Verify notification contains correct employee identification
    await page.fill('[data-testid="search-recipient-email"]', '');
    await page.fill('[data-testid="search-request-id"]', requestId || '');
    await page.click('[data-testid="search-button"]');
    
    const finalNotification = page.locator('[data-testid="notification-log-entry"]').first();
    await expect(finalNotification.locator('[data-testid="request-id"]')).toContainText(requestId || '');
    await expect(finalNotification.locator('[data-testid="recipient-email"]')).toContainText(employeeAEmail);
    await expect(finalNotification.locator('[data-testid="recipient-email"]')).not.toContainText(employeeBEmail);
  });
});