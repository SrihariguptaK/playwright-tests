import { test, expect } from '@playwright/test';

test.describe('Scheduler Notification System', () => {
  let schedulerEmail: string;
  let approverEmail: string;
  let requestId: string;

  test.beforeEach(async ({ page }) => {
    schedulerEmail = 'scheduler@example.com';
    approverEmail = 'approver@example.com';
    requestId = `REQ-${Date.now()}`;
  });

  test('Validate notification delivery upon approval decision', async ({ page, context }) => {
    // Login as approver
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to pending requests
    await page.click('[data-testid="pending-requests-link"]');
    await expect(page.locator('[data-testid="pending-requests-header"]')).toBeVisible();

    // Find and approve the schedule change request
    await page.click(`[data-testid="request-${requestId}"]`);
    await page.click('[data-testid="approve-button"]');
    await page.fill('[data-testid="approval-comments"]', 'Approved - looks good');
    await page.click('[data-testid="confirm-approval-button"]');
    await expect(page.locator('[data-testid="approval-success-message"]')).toBeVisible();

    // Logout approver
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Login as scheduler
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', schedulerEmail);
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Wait for notification to appear (within 1 minute)
    await page.waitForSelector('[data-testid="notification-badge"]', { timeout: 60000 });
    const notificationBadge = page.locator('[data-testid="notification-badge"]');
    await expect(notificationBadge).toBeVisible();

    // Click on notifications icon
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();

    // Verify notification is present
    const notification = page.locator(`[data-testid="notification-${requestId}"]`).first();
    await expect(notification).toBeVisible();

    // Click on notification to view details
    await notification.click();
    await expect(page.locator('[data-testid="notification-details"]')).toBeVisible();

    // Verify notification displays decision details
    await expect(page.locator('[data-testid="notification-decision"]')).toContainText('Approved');
    await expect(page.locator('[data-testid="notification-comments"]')).toContainText('Approved - looks good');

    // Verify link to dashboard is present
    const dashboardLink = page.locator('[data-testid="notification-dashboard-link"]');
    await expect(dashboardLink).toBeVisible();
    await expect(dashboardLink).toHaveAttribute('href', /.*schedule-change-requests/);
  });

  test('Verify notifications are restricted to requestor', async ({ page, context }) => {
    const otherUserEmail = 'otheruser@example.com';

    // Login as scheduler and submit request
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', schedulerEmail);
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Submit schedule change request
    await page.click('[data-testid="new-request-button"]');
    await page.fill('[data-testid="request-title"]', 'Test Schedule Change');
    await page.fill('[data-testid="request-description"]', 'Testing notification restrictions');
    await page.click('[data-testid="submit-request-button"]');
    await expect(page.locator('[data-testid="request-submitted-message"]')).toBeVisible();

    // Get the request ID from the confirmation
    const submittedRequestId = await page.locator('[data-testid="submitted-request-id"]').textContent();

    // Logout scheduler
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Login as approver and approve request
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.click('[data-testid="pending-requests-link"]');
    await page.click(`[data-testid="request-${submittedRequestId}"]`);
    await page.click('[data-testid="approve-button"]');
    await page.click('[data-testid="confirm-approval-button"]');
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Login as another user (not the requestor)
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', otherUserEmail);
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Check notifications
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();

    // Verify the scheduler's notification is not visible to other user
    const schedulerNotification = page.locator(`[data-testid="notification-${submittedRequestId}"]`);
    await expect(schedulerNotification).not.toBeVisible();

    // Attempt to directly access notification via URL
    await page.goto(`/notifications/${submittedRequestId}`);
    
    // Verify access is denied
    const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
    const notFoundMessage = page.locator('[data-testid="not-found-message"]');
    
    await expect(accessDeniedMessage.or(notFoundMessage)).toBeVisible();
  });

  test('Test notification content accuracy', async ({ page }) => {
    // Login as approver
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to pending requests
    await page.click('[data-testid="pending-requests-link"]');
    await expect(page.locator('[data-testid="pending-requests-header"]')).toBeVisible();

    // Find the schedule change request
    await page.click(`[data-testid="request-${requestId}"]`);
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();

    // Request modifications with detailed comments
    await page.click('[data-testid="request-modifications-button"]');
    await expect(page.locator('[data-testid="modifications-form"]')).toBeVisible();

    const modificationComment = 'Please adjust the shift times to start at 9 AM instead of 8 AM and provide coverage details for the afternoon shift.';
    await page.fill('[data-testid="modification-comments"]', modificationComment);
    await page.click('[data-testid="submit-modifications-button"]');
    await expect(page.locator('[data-testid="modifications-submitted-message"]')).toBeVisible();

    // Logout approver
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Login as scheduler
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', schedulerEmail);
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Wait for notification (within 1 minute)
    await page.waitForSelector('[data-testid="notification-badge"]', { timeout: 60000 });
    
    // Open notifications panel
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();

    // Find the modification notification
    const modificationNotification = page.locator(`[data-testid="notification-${requestId}"]`).first();
    await expect(modificationNotification).toBeVisible();

    // Click to view full notification details
    await modificationNotification.click();
    await expect(page.locator('[data-testid="notification-details"]')).toBeVisible();

    // Verify notification includes modification decision
    await expect(page.locator('[data-testid="notification-decision"]')).toContainText('Modifications Requested');

    // Verify notification includes the exact comments from approver
    const notificationComments = page.locator('[data-testid="notification-comments"]');
    await expect(notificationComments).toBeVisible();
    await expect(notificationComments).toContainText(modificationComment);
    await expect(notificationComments).toContainText('9 AM');
    await expect(notificationComments).toContainText('coverage details');

    // Verify modification details are present
    await expect(page.locator('[data-testid="modification-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="modification-type"]')).toContainText('Modification');

    // Verify link to dashboard is included
    const dashboardLink = page.locator('[data-testid="notification-dashboard-link"]');
    await expect(dashboardLink).toBeVisible();
    await expect(dashboardLink).toHaveAttribute('href', /.*schedule-change-requests/);

    // Click dashboard link and verify navigation
    await dashboardLink.click();
    await expect(page).toHaveURL(/.*schedule-change-requests/);
    await expect(page.locator(`[data-testid="request-${requestId}"]`)).toBeVisible();
  });
});