import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Tracking - Story 5', () => {
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
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', scheduleCoordinatorCredentials.username);
    await page.fill('[data-testid="password-input"]', scheduleCoordinatorCredentials.password);
    await page.click('[data-testid="login-button"]');

    // Expected Result: Dashboard with submitted requests is displayed
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="schedule-changes-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="submitted-requests-list"]')).toBeVisible();

    // Step 2: Filter requests by status 'Pending'
    await page.locator('[data-testid="status-filter-dropdown"]').click();
    await page.locator('[data-testid="status-option-pending"]').click();
    await page.click('[data-testid="apply-filter-button"]');

    // Expected Result: List updates to show only pending requests
    await page.waitForSelector('[data-testid="filtered-requests-list"]');
    const requestItems = await page.locator('[data-testid="request-item"]').all();
    for (const item of requestItems) {
      const statusBadge = item.locator('[data-testid="request-status"]');
      await expect(statusBadge).toHaveText('Pending');
    }

    // Step 3: Open a request to view approval history and comments
    await page.locator('[data-testid="request-item"]').first().click();

    // Expected Result: Detailed view is displayed with accurate information
    await expect(page.locator('[data-testid="request-detail-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-history-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="comments-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-status-detail"]')).toContainText('Pending');
  });

  test('Verify notifications on status changes', async ({ page, context }) => {
    // Step 1: Submit a schedule change request
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', scheduleCoordinatorCredentials.username);
    await page.fill('[data-testid="password-input"]', scheduleCoordinatorCredentials.password);
    await page.click('[data-testid="login-button"]');

    await page.goto('/schedule-changes/new');
    await page.fill('[data-testid="change-date-input"]', '2024-02-15');
    await page.fill('[data-testid="change-time-input"]', '14:00');
    await page.fill('[data-testid="change-reason-input"]', 'Staff training session required');
    await page.fill('[data-testid="affected-resources-input"]', 'Conference Room A, Training Staff');
    await page.click('[data-testid="submit-request-button"]');

    // Expected Result: Request is created with initial status
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request submitted successfully');
    const requestId = await page.locator('[data-testid="request-id"]').textContent();

    // Step 2: Approver changes status to approved
    await page.click('[data-testid="logout-button"]');
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', approverCredentials.username);
    await page.fill('[data-testid="password-input"]', approverCredentials.password);
    await page.click('[data-testid="login-button"]');

    await page.goto('/approvals/pending');
    await page.locator(`[data-testid="request-${requestId}"]`).click();
    await page.fill('[data-testid="approval-comments-input"]', 'Approved for training purposes');
    await page.click('[data-testid="approve-button"]');

    // Expected Result: Schedule Coordinator receives notification of status update
    await expect(page.locator('[data-testid="approval-confirmation"]')).toBeVisible();

    // Step 3: Open dashboard and verify updated status
    await page.click('[data-testid="logout-button"]');
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', scheduleCoordinatorCredentials.username);
    await page.fill('[data-testid="password-input"]', scheduleCoordinatorCredentials.password);
    await page.click('[data-testid="login-button"]');

    await page.goto('/my-schedule-changes');

    // Expected Result: Request status shows as approved
    await expect(page.locator('[data-testid="notification-badge"]')).toBeVisible();
    await page.locator(`[data-testid="request-${requestId}"]`).click();
    await expect(page.locator('[data-testid="request-status-detail"]')).toContainText('Approved');
    await expect(page.locator('[data-testid="approval-comments"]')).toContainText('Approved for training purposes');
  });

  test('Ensure dashboard loads within performance requirements', async ({ page }) => {
    // Step 1: Log in as Schedule Coordinator and measure dashboard load time
    const loginStartTime = Date.now();
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', scheduleCoordinatorCredentials.username);
    await page.fill('[data-testid="password-input"]', scheduleCoordinatorCredentials.password);
    await page.click('[data-testid="login-button"]');

    // Expected Result: Dashboard is displayed
    await page.waitForSelector('[data-testid="schedule-changes-dashboard"]');
    const loginEndTime = Date.now();
    const dashboardLoadTime = loginEndTime - loginStartTime;

    await expect(page.locator('[data-testid="schedule-changes-dashboard"]')).toBeVisible();
    expect(dashboardLoadTime).toBeLessThan(3000);

    // Step 2: Load list of submitted requests
    const listLoadStartTime = Date.now();
    await page.click('[data-testid="refresh-requests-button"]');
    await page.waitForSelector('[data-testid="submitted-requests-list"]');
    const listLoadEndTime = Date.now();
    const listLoadTime = listLoadEndTime - listLoadStartTime;

    // Expected Result: List loads within 3 seconds
    await expect(page.locator('[data-testid="submitted-requests-list"]')).toBeVisible();
    expect(listLoadTime).toBeLessThan(3000);

    // Step 3: Apply filters and verify response time
    const filterStartTime = Date.now();
    await page.locator('[data-testid="date-range-filter"]').click();
    await page.locator('[data-testid="date-range-last-30-days"]').click();
    await page.locator('[data-testid="status-filter-dropdown"]').click();
    await page.locator('[data-testid="status-option-pending"]').click();
    await page.click('[data-testid="apply-filter-button"]');
    await page.waitForSelector('[data-testid="filtered-requests-list"]');
    const filterEndTime = Date.now();
    const filterLoadTime = filterEndTime - filterStartTime;

    // Expected Result: Filtered list loads within 3 seconds
    await expect(page.locator('[data-testid="filtered-requests-list"]')).toBeVisible();
    expect(filterLoadTime).toBeLessThan(3000);
  });
});