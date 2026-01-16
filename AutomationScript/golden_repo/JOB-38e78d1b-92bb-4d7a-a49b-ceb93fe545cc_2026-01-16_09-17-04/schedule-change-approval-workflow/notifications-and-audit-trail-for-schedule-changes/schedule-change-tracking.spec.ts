import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Tracking - Story 5', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const scheduleCoordinatorCredentials = {
    username: 'schedule.coordinator@example.com',
    password: 'SecurePass123!'
  };
  const approverCredentials = {
    username: 'approver@example.com',
    password: 'ApproverPass123!'
  };

  test('Validate display of user\'s schedule change requests', async ({ page }) => {
    // Step 1: Log in as Schedule Coordinator
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', scheduleCoordinatorCredentials.username);
    await page.fill('[data-testid="password-input"]', scheduleCoordinatorCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Dashboard with submitted requests is displayed
    await expect(page).toHaveURL(/.*\/dashboard/);
    await expect(page.locator('[data-testid="schedule-changes-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="requests-list"]')).toBeVisible();
    const requestItems = page.locator('[data-testid="request-item"]');
    await expect(requestItems.first()).toBeVisible({ timeout: 5000 });

    // Step 2: Filter requests by status 'Pending'
    await page.locator('[data-testid="status-filter-dropdown"]').click();
    await page.locator('[data-testid="status-option-pending"]').click();
    await page.click('[data-testid="apply-filter-button"]');
    
    // Expected Result: List updates to show only pending requests
    await page.waitForLoadState('networkidle');
    const filteredRequests = page.locator('[data-testid="request-item"]');
    const requestCount = await filteredRequests.count();
    expect(requestCount).toBeGreaterThan(0);
    
    // Verify all displayed requests have 'Pending' status
    for (let i = 0; i < await filteredRequests.count(); i++) {
      const statusBadge = filteredRequests.nth(i).locator('[data-testid="request-status"]');
      await expect(statusBadge).toContainText('Pending');
    }

    // Step 3: Open a request to view approval history and comments
    await filteredRequests.first().click();
    
    // Expected Result: Detailed view is displayed with accurate information
    await expect(page.locator('[data-testid="request-detail-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-history-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="comments-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-status-detail"]')).toContainText('Pending');
  });

  test('Verify notifications on status changes', async ({ page, context }) => {
    // Step 1: Submit a schedule change request
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', scheduleCoordinatorCredentials.username);
    await page.fill('[data-testid="password-input"]', scheduleCoordinatorCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await page.goto(`${baseURL}/schedule-changes/new`);
    await page.fill('[data-testid="change-date-input"]', '2024-06-15');
    await page.fill('[data-testid="change-time-input"]', '14:00');
    await page.fill('[data-testid="change-reason-input"]', 'Staff training session required');
    await page.fill('[data-testid="affected-resources-input"]', 'Conference Room A, Training Materials');
    await page.click('[data-testid="submit-request-button"]');
    
    // Expected Result: Request is created with initial status
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request submitted successfully');
    
    const requestId = await page.locator('[data-testid="request-id"]').textContent();
    expect(requestId).toBeTruthy();
    
    // Log out from Schedule Coordinator
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Step 2: Approver changes status to approved
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', approverCredentials.username);
    await page.fill('[data-testid="password-input"]', approverCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await page.goto(`${baseURL}/approvals/pending`);
    await page.locator(`[data-testid="request-${requestId}"]`).click();
    await page.click('[data-testid="approve-button"]');
    await page.fill('[data-testid="approval-comments"]', 'Approved for staff development');
    await page.click('[data-testid="confirm-approval-button"]');
    
    // Expected Result: Schedule Coordinator receives notification of status update
    await expect(page.locator('[data-testid="approval-confirmation"]')).toBeVisible();
    
    // Log out from Approver
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Step 3: Open dashboard and verify updated status
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', scheduleCoordinatorCredentials.username);
    await page.fill('[data-testid="password-input"]', scheduleCoordinatorCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await page.goto(`${baseURL}/my-schedule-changes`);
    
    // Expected Result: Request status shows as approved
    const updatedRequest = page.locator(`[data-testid="request-${requestId}"]`);
    await expect(updatedRequest).toBeVisible();
    const statusBadge = updatedRequest.locator('[data-testid="request-status"]');
    await expect(statusBadge).toContainText('Approved');
    
    // Verify notification is present
    await page.click('[data-testid="notifications-icon"]');
    const notificationsList = page.locator('[data-testid="notifications-list"]');
    await expect(notificationsList).toBeVisible();
    const latestNotification = notificationsList.locator('[data-testid="notification-item"]').first();
    await expect(latestNotification).toContainText('approved');
  });

  test('Ensure dashboard loads within performance requirements', async ({ page }) => {
    // Step 1: Log in as Schedule Coordinator and measure dashboard load time
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', scheduleCoordinatorCredentials.username);
    await page.fill('[data-testid="password-input"]', scheduleCoordinatorCredentials.password);
    
    const loginStartTime = Date.now();
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Dashboard is displayed
    await expect(page.locator('[data-testid="schedule-changes-dashboard"]')).toBeVisible();
    const loginLoadTime = Date.now() - loginStartTime;
    
    console.log(`Dashboard initial load time: ${loginLoadTime}ms`);
    expect(loginLoadTime).toBeLessThan(3000);

    // Step 2: Load list of submitted requests
    await page.locator('[data-testid="clear-filters-button"]').click({ timeout: 2000 }).catch(() => {});
    
    const listLoadStartTime = Date.now();
    await page.click('[data-testid="refresh-button"]');
    
    // Expected Result: List loads within 3 seconds
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="requests-list"]')).toBeVisible();
    const requestItems = page.locator('[data-testid="request-item"]');
    await expect(requestItems.first()).toBeVisible();
    
    const listLoadTime = Date.now() - listLoadStartTime;
    console.log(`Requests list load time: ${listLoadTime}ms`);
    expect(listLoadTime).toBeLessThan(3000);

    // Step 3: Apply filters and verify response time
    const filterStartTime = Date.now();
    
    await page.locator('[data-testid="status-filter-dropdown"]').click();
    await page.locator('[data-testid="status-option-approved"]').click();
    
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const dateFrom = thirtyDaysAgo.toISOString().split('T')[0];
    const dateTo = new Date().toISOString().split('T')[0];
    
    await page.fill('[data-testid="date-from-input"]', dateFrom);
    await page.fill('[data-testid="date-to-input"]', dateTo);
    await page.click('[data-testid="apply-filter-button"]');
    
    // Expected Result: Filtered list loads within 3 seconds
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="requests-list"]')).toBeVisible();
    
    const filterLoadTime = Date.now() - filterStartTime;
    console.log(`Filtered list load time: ${filterLoadTime}ms`);
    expect(filterLoadTime).toBeLessThan(3000);
    
    // Verify filtered results show only approved requests
    const filteredRequests = page.locator('[data-testid="request-item"]');
    const filteredCount = await filteredRequests.count();
    
    if (filteredCount > 0) {
      for (let i = 0; i < Math.min(filteredCount, 5); i++) {
        const statusBadge = filteredRequests.nth(i).locator('[data-testid="request-status"]');
        await expect(statusBadge).toContainText('Approved');
      }
    }
  });
});