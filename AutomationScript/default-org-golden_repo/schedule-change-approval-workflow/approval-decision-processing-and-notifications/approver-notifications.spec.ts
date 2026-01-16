import { test, expect } from '@playwright/test';

test.describe('Story-15: Approver Notification System', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const APPROVER_EMAIL = 'approver@test.com';
  const APPROVER_PASSWORD = 'Test123!';
  const REQUESTER_EMAIL = 'requester@test.com';
  const REQUESTER_PASSWORD = 'Test123!';
  
  test('TC#1: Validate email notification sent on new request assignment', async ({ page, context }) => {
    // Note the current system time before initiating the test
    const testStartTime = new Date();
    
    // Login as requester to create a new schedule change request
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', REQUESTER_EMAIL);
    await page.fill('[data-testid="password-input"]', REQUESTER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to create schedule change request page
    await page.click('[data-testid="create-request-button"]');
    await expect(page).toHaveURL(/.*request\/create/);
    
    // Fill out schedule change request form
    await page.fill('[data-testid="request-title-input"]', 'Test Schedule Change Request');
    await page.fill('[data-testid="request-description-textarea"]', 'This is a test schedule change request for notification validation');
    await page.selectOption('[data-testid="request-type-select"]', 'shift-swap');
    await page.fill('[data-testid="requested-date-input"]', '2024-12-31');
    
    // Assign to specific approver
    await page.selectOption('[data-testid="approver-select"]', { label: 'Test Approver' });
    
    // Submit the request
    await page.click('[data-testid="submit-request-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request submitted successfully');
    
    // Capture the request ID from the success message or URL
    const requestId = await page.locator('[data-testid="request-id"]').textContent();
    
    // Monitor notification queue - check notification logs
    await page.goto(`${BASE_URL}/admin/notifications`);
    await page.fill('[data-testid="search-request-id"]', requestId || '');
    await page.click('[data-testid="search-button"]');
    
    // Verify notification trigger event is fired
    await expect(page.locator('[data-testid="notification-status"]')).toContainText('sent', { timeout: 65000 });
    
    // Verify notification was sent within 1 minute
    const notificationTimestamp = await page.locator('[data-testid="notification-timestamp"]').textContent();
    const notificationTime = new Date(notificationTimestamp || '');
    const timeDifference = (notificationTime.getTime() - testStartTime.getTime()) / 1000;
    expect(timeDifference).toBeLessThanOrEqual(60);
    
    // Open email client page to check approver's inbox
    const emailPage = await context.newPage();
    await emailPage.goto(`${BASE_URL}/test-email-inbox`);
    await emailPage.fill('[data-testid="email-filter-input"]', APPROVER_EMAIL);
    await emailPage.click('[data-testid="filter-button"]');
    
    // Verify notification email is received
    await expect(emailPage.locator('[data-testid="email-list"]').first()).toBeVisible({ timeout: 65000 });
    
    // Open the notification email
    await emailPage.click('[data-testid="email-list"]').first();
    
    // Verify sender is system notification address
    await expect(emailPage.locator('[data-testid="email-sender"]')).toContainText('noreply@schedulesystem.com');
    
    // Verify email subject line
    await expect(emailPage.locator('[data-testid="email-subject"]')).toContainText('New Schedule Change Request Requires Your Approval');
    
    // Verify email body contains request summary
    await expect(emailPage.locator('[data-testid="email-body"]')).toContainText(requestId || '');
    await expect(emailPage.locator('[data-testid="email-body"]')).toContainText('Test Requester');
    await expect(emailPage.locator('[data-testid="email-body"]')).toContainText('shift-swap');
    
    // Verify direct clickable link exists
    const reviewLink = emailPage.locator('[data-testid="review-request-link"]');
    await expect(reviewLink).toBeVisible();
    
    // Click on the direct link
    await reviewLink.click();
    
    // Verify navigation to request review page
    await expect(emailPage).toHaveURL(new RegExp(`.*request/${requestId}/review`));
    await expect(emailPage.locator('[data-testid="request-details"]')).toBeVisible();
  });
  
  test('TC#2: Verify in-app alert on approver login', async ({ page }) => {
    // Ensure at least one pending approval request exists
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', REQUESTER_EMAIL);
    await page.fill('[data-testid="password-input"]', REQUESTER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Create a new schedule change request
    await page.click('[data-testid="create-request-button"]');
    await page.fill('[data-testid="request-title-input"]', 'Test Request for In-App Alert');
    await page.fill('[data-testid="request-description-textarea"]', 'Testing in-app alert notification');
    await page.selectOption('[data-testid="request-type-select"]', 'time-off');
    await page.fill('[data-testid="requested-date-input"]', '2024-12-25');
    await page.selectOption('[data-testid="approver-select"]', { label: 'Test Approver' });
    await page.click('[data-testid="submit-request-button"]');
    
    const requestId = await page.locator('[data-testid="request-id"]').textContent();
    
    // Logout
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Navigate to login page as approver
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', APPROVER_EMAIL);
    await page.fill('[data-testid="password-input"]', APPROVER_PASSWORD);
    
    // Click Login button
    await page.click('[data-testid="login-button"]');
    
    // Immediately observe for in-app alerts upon page load
    await expect(page.locator('[data-testid="notification-bell"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-badge"]')).toBeVisible();
    
    // Verify alert content includes list of pending requests
    const notificationBadge = page.locator('[data-testid="notification-badge"]');
    const badgeCount = await notificationBadge.textContent();
    expect(parseInt(badgeCount || '0')).toBeGreaterThan(0);
    
    // Click notification bell to expand alert details
    await page.click('[data-testid="notification-bell"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();
    
    // Verify alert shows request IDs and requester names
    const alertItem = page.locator('[data-testid="notification-item"]').first();
    await expect(alertItem).toContainText(requestId || '');
    await expect(alertItem).toContainText('Test Requester');
    
    // Click on the link within the alert
    await alertItem.click();
    
    // Verify navigation to request review page
    await expect(page).toHaveURL(new RegExp(`.*request/${requestId}/review`));
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-id-display"]')).toContainText(requestId || '');
  });
  
  test('TC#3: Test prevention of duplicate notifications', async ({ page, context }) => {
    // Clear or note current state - login as approver to check baseline
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', APPROVER_EMAIL);
    await page.fill('[data-testid="password-input"]', APPROVER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Check email inbox baseline
    const emailPage = await context.newPage();
    await emailPage.goto(`${BASE_URL}/test-email-inbox`);
    await emailPage.fill('[data-testid="email-filter-input"]', APPROVER_EMAIL);
    await emailPage.click('[data-testid="filter-button"]');
    const baselineEmailCount = await emailPage.locator('[data-testid="email-list"]').count();
    
    // Login as requester to create new request
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', REQUESTER_EMAIL);
    await page.fill('[data-testid="password-input"]', REQUESTER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Create a new schedule change request
    await page.click('[data-testid="create-request-button"]');
    await page.fill('[data-testid="request-title-input"]', 'Duplicate Notification Test Request');
    await page.fill('[data-testid="request-description-textarea"]', 'Testing duplicate notification prevention');
    await page.selectOption('[data-testid="request-type-select"]', 'schedule-change');
    await page.fill('[data-testid="requested-date-input"]', '2024-12-20');
    await page.selectOption('[data-testid="approver-select"]', { label: 'Test Approver' });
    await page.click('[data-testid="submit-request-button"]');
    
    const requestId = await page.locator('[data-testid="request-id"]').textContent();
    
    // Verify first notification is sent - check notification logs
    await page.goto(`${BASE_URL}/admin/notifications`);
    await page.fill('[data-testid="search-request-id"]', requestId || '');
    await page.click('[data-testid="search-button"]');
    await expect(page.locator('[data-testid="notification-record"]')).toHaveCount(1);
    
    const firstNotificationId = await page.locator('[data-testid="notification-id"]').first().textContent();
    
    // Simulate same request assignment event again via API
    const apiContext = await context.request;
    await apiContext.post(`${BASE_URL}/api/assignments/process`, {
      data: {
        requestId: requestId,
        approverId: 'approver-123',
        action: 'assign'
      }
    });
    
    // Wait for 2 minutes to allow time for potential duplicate
    await page.waitForTimeout(120000);
    
    // Check notification logs for total count
    await page.reload();
    await page.fill('[data-testid="search-request-id"]', requestId || '');
    await page.click('[data-testid="search-button"]');
    
    // Verify only one notification record exists
    await expect(page.locator('[data-testid="notification-record"]')).toHaveCount(1);
    
    // Check email inbox for duplicate emails
    await emailPage.reload();
    await emailPage.fill('[data-testid="email-filter-input"]', APPROVER_EMAIL);
    await emailPage.click('[data-testid="filter-button"]');
    const currentEmailCount = await emailPage.locator('[data-testid="email-list"]').count();
    
    // Verify only one new email was received
    expect(currentEmailCount - baselineEmailCount).toBe(1);
    
    // Review system logs for duplicate detection messages
    await page.goto(`${BASE_URL}/admin/system-logs`);
    await page.fill('[data-testid="log-search-input"]', `duplicate notification prevented ${requestId}`);
    await page.click('[data-testid="log-search-button"]');
    await expect(page.locator('[data-testid="log-entry"]').first()).toContainText('Duplicate notification prevented');
    
    // Trigger assignment a third time
    await apiContext.post(`${BASE_URL}/api/assignments/process`, {
      data: {
        requestId: requestId,
        approverId: 'approver-123',
        action: 'assign'
      }
    });
    
    // Wait and verify again
    await page.waitForTimeout(120000);
    await page.goto(`${BASE_URL}/admin/notifications`);
    await page.fill('[data-testid="search-request-id"]', requestId || '');
    await page.click('[data-testid="search-button"]');
    
    // Verify still only one notification record
    await expect(page.locator('[data-testid="notification-record"]')).toHaveCount(1);
    
    // Verify email count unchanged
    await emailPage.reload();
    await emailPage.fill('[data-testid="email-filter-input"]', APPROVER_EMAIL);
    await emailPage.click('[data-testid="filter-button"]');
    const finalEmailCount = await emailPage.locator('[data-testid="email-list"]').count();
    expect(finalEmailCount - baselineEmailCount).toBe(1);
  });
});