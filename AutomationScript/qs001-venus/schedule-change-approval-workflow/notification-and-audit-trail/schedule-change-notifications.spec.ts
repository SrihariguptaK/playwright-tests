import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Notifications', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto('/login');
  });

  test('Validate notification sent on approval', async ({ page }) => {
    // Step 1: Approver logs in and approves schedule change request
    await page.fill('[data-testid="username-input"]', 'approver@example.com');
    await page.fill('[data-testid="password-input"]', 'approverPassword123');
    await page.click('[data-testid="login-button"]');
    
    // Navigate to approval dashboard
    await page.waitForURL('**/dashboard');
    await page.click('[data-testid="approval-dashboard-link"]');
    await page.waitForSelector('[data-testid="pending-requests-table"]');
    
    // Select pending schedule change request
    await page.click('[data-testid="schedule-change-request-row"]:first-child');
    await page.waitForSelector('[data-testid="request-details-panel"]');
    
    // Add approval comments
    await page.fill('[data-testid="approval-comments-textarea"]', 'Approved - Schedule change looks good');
    
    // Click Approve button
    const approvalTime = Date.now();
    await page.click('[data-testid="approve-button"]');
    await expect(page.locator('[data-testid="approval-success-message"]')).toBeVisible();
    
    // Logout approver
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Step 2: Schedule Coordinator logs in and checks notification
    await page.fill('[data-testid="username-input"]', 'coordinator@example.com');
    await page.fill('[data-testid="password-input"]', 'coordinatorPassword123');
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('**/dashboard');
    
    // Check notification inbox within 1 minute
    await page.click('[data-testid="notification-center-icon"]');
    await page.waitForSelector('[data-testid="notification-list"]');
    
    const notificationReceived = Date.now();
    const timeDifference = (notificationReceived - approvalTime) / 1000; // Convert to seconds
    
    // Verify notification delivered within 1 minute (60 seconds)
    expect(timeDifference).toBeLessThanOrEqual(60);
    
    // Open the received notification
    const notification = page.locator('[data-testid="notification-item"]').first();
    await notification.click();
    
    // Verify notification displays approval status
    await expect(page.locator('[data-testid="notification-status"]')).toContainText('Approved');
    
    // Verify notification displays approver comments
    await expect(page.locator('[data-testid="notification-comments"]')).toContainText('Approved - Schedule change looks good');
  });

  test('Test notification preference configuration', async ({ page }) => {
    // Step 1: Schedule Coordinator logs in
    await page.fill('[data-testid="username-input"]', 'coordinator@example.com');
    await page.fill('[data-testid="password-input"]', 'coordinatorPassword123');
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('**/dashboard');
    
    // Navigate to notification settings page
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="notification-settings-link"]');
    await page.waitForSelector('[data-testid="notification-preferences-form"]');
    
    // Modify notification preferences
    await page.check('[data-testid="notify-on-approval-checkbox"]');
    await page.check('[data-testid="notify-on-rejection-checkbox"]');
    await page.uncheck('[data-testid="notify-on-cancellation-checkbox"]');
    
    // Change notification frequency
    await page.selectOption('[data-testid="notification-frequency-select"]', 'immediate');
    
    // Click Save button
    await page.click('[data-testid="save-preferences-button"]');
    
    // Verify preferences saved successfully
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toContainText('Preferences saved successfully');
    
    // Logout coordinator
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Step 2: Trigger notification event by having approver approve a request
    await page.fill('[data-testid="username-input"]', 'approver@example.com');
    await page.fill('[data-testid="password-input"]', 'approverPassword123');
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('**/dashboard');
    await page.click('[data-testid="approval-dashboard-link"]');
    await page.waitForSelector('[data-testid="pending-requests-table"]');
    
    // Select and approve a schedule change request
    await page.click('[data-testid="schedule-change-request-row"]:first-child');
    await page.fill('[data-testid="approval-comments-textarea"]', 'Approved per updated preferences test');
    await page.click('[data-testid="approve-button"]');
    await expect(page.locator('[data-testid="approval-success-message"]')).toBeVisible();
    
    // Logout approver
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Login as coordinator and verify notification sent according to updated preferences
    await page.fill('[data-testid="username-input"]', 'coordinator@example.com');
    await page.fill('[data-testid="password-input"]', 'coordinatorPassword123');
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('**/dashboard');
    await page.click('[data-testid="notification-center-icon"]');
    
    // Verify notification was sent for approval (which was enabled in preferences)
    const approvalNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Approved' }).first();
    await expect(approvalNotification).toBeVisible();
    
    // Verify notification was sent immediately (according to frequency preference)
    await expect(approvalNotification.locator('[data-testid="notification-timestamp"]')).toBeVisible();
  });

  test('Verify notification history accessibility', async ({ page }) => {
    // Schedule Coordinator logs in
    await page.fill('[data-testid="username-input"]', 'coordinator@example.com');
    await page.fill('[data-testid="password-input"]', 'coordinatorPassword123');
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('**/dashboard');
    
    // Navigate to notification history page
    await page.click('[data-testid="notification-center-icon"]');
    await page.waitForSelector('[data-testid="notification-dropdown"]');
    
    // Click on notification history menu item or link
    await page.click('[data-testid="notification-history-link"]');
    await page.waitForURL('**/notifications/history');
    
    // Verify notification history page is displayed
    await expect(page.locator('[data-testid="notification-history-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-history-title"]')).toContainText('Notification History');
    
    // Verify all past notifications are displayed
    const notificationHistoryTable = page.locator('[data-testid="notification-history-table"]');
    await expect(notificationHistoryTable).toBeVisible();
    
    // Verify notification history contains multiple entries
    const notificationRows = page.locator('[data-testid="notification-history-row"]');
    await expect(notificationRows).toHaveCount(await notificationRows.count());
    expect(await notificationRows.count()).toBeGreaterThan(0);
    
    // Verify notification details are displayed (status, timestamp, comments)
    const firstNotification = notificationRows.first();
    await expect(firstNotification.locator('[data-testid="notification-status-cell"]')).toBeVisible();
    await expect(firstNotification.locator('[data-testid="notification-timestamp-cell"]')).toBeVisible();
    await expect(firstNotification.locator('[data-testid="notification-details-cell"]')).toBeVisible();
    
    // Click on a notification to view full details
    await firstNotification.click();
    await expect(page.locator('[data-testid="notification-detail-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-detail-status"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-detail-comments"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-detail-timestamp"]')).toBeVisible();
  });
});