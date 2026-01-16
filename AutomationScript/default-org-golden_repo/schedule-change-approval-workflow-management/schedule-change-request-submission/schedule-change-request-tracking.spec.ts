import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Tracking - Story 5', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const SCHEDULER_A_EMAIL = 'schedulerA@example.com';
  const SCHEDULER_A_PASSWORD = 'Password123!';
  const SCHEDULER_B_REQUEST_ID = 'SCR-2024-99999';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate scheduler dashboard displays correct requests and statuses (happy-path)', async ({ page }) => {
    // Step 1: Log into the system using valid scheduler credentials
    await page.fill('[data-testid="email-input"]', SCHEDULER_A_EMAIL);
    await page.fill('[data-testid="password-input"]', SCHEDULER_A_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to the schedule change request dashboard from the main menu
    await page.click('[data-testid="schedule-change-requests-menu"]');
    await expect(page).toHaveURL(/.*schedule-change-requests/);

    // Step 3: Verify the dashboard displays request columns
    await expect(page.locator('[data-testid="request-id-column"]')).toBeVisible();
    await expect(page.locator('[data-testid="submission-date-column"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-id-column"]')).toBeVisible();
    await expect(page.locator('[data-testid="status-column"]')).toBeVisible();
    await expect(page.locator('[data-testid="last-updated-column"]')).toBeVisible();

    // Step 4: Review the status indicators for each request in the list
    const statusIndicators = page.locator('[data-testid="status-indicator"]');
    await expect(statusIndicators.first()).toBeVisible();
    const statusCount = await statusIndicators.count();
    expect(statusCount).toBeGreaterThan(0);

    // Step 5: Verify the request count matches the expected number
    const requestRows = page.locator('[data-testid="request-row"]');
    const requestCount = await requestRows.count();
    const displayedCount = await page.locator('[data-testid="total-requests-count"]').textContent();
    expect(requestCount.toString()).toBe(displayedCount?.trim());

    // Step 6: Click on a specific request row to view detailed information
    await requestRows.first().click();
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();

    // Step 7: Scroll down to the approval history section
    await page.locator('[data-testid="approval-history-section"]').scrollIntoViewIfNeeded();
    await expect(page.locator('[data-testid="approval-history-section"]')).toBeVisible();

    // Step 8: Read the comments provided by approvers
    const approverComments = page.locator('[data-testid="approver-comment"]');
    await expect(approverComments.first()).toBeVisible();

    // Step 9: Return to the dashboard main view
    await page.click('[data-testid="back-button"]');
    await expect(page.locator('[data-testid="request-dashboard"]')).toBeVisible();

    // Step 10: Locate the filter section on the dashboard
    await expect(page.locator('[data-testid="filter-section"]')).toBeVisible();

    // Step 11: Select 'Approved' from the Status filter dropdown
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-filter-approved"]');
    await page.waitForLoadState('networkidle');
    const approvedRequests = page.locator('[data-testid="request-row"]');
    const approvedCount = await approvedRequests.count();
    for (let i = 0; i < Math.min(approvedCount, 5); i++) {
      const statusText = await approvedRequests.nth(i).locator('[data-testid="status-indicator"]').textContent();
      expect(statusText?.toLowerCase()).toContain('approved');
    }

    // Step 12: Clear the status filter and enter a specific Request ID
    await page.click('[data-testid="clear-filters-button"]');
    await page.waitForLoadState('networkidle');
    const firstRequestId = await requestRows.first().locator('[data-testid="request-id"]').textContent();
    await page.fill('[data-testid="search-input"]', firstRequestId || '');
    await page.waitForLoadState('networkidle');
    const searchResults = page.locator('[data-testid="request-row"]');
    await expect(searchResults).toHaveCount(1);

    // Step 13: Clear the search box and apply a date range filter
    await page.fill('[data-testid="search-input"]', '');
    await page.waitForLoadState('networkidle');
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const today = new Date();
    await page.fill('[data-testid="date-from-input"]', thirtyDaysAgo.toISOString().split('T')[0]);
    await page.fill('[data-testid="date-to-input"]', today.toISOString().split('T')[0]);
    await page.click('[data-testid="apply-date-filter-button"]');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="request-row"]').first()).toBeVisible();

    // Step 14: Clear all filters to return to the full list view
    await page.click('[data-testid="clear-filters-button"]');
    await page.waitForLoadState('networkidle');
    const allRequests = page.locator('[data-testid="request-row"]');
    const finalCount = await allRequests.count();
    expect(finalCount).toBeGreaterThan(0);
  });

  test('Verify access restriction to own requests (error-case)', async ({ page }) => {
    // Step 1: Log into the system as Scheduler A
    await page.fill('[data-testid="email-input"]', SCHEDULER_A_EMAIL);
    await page.fill('[data-testid="password-input"]', SCHEDULER_A_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to Scheduler A's dashboard and note their own Request IDs
    await page.click('[data-testid="schedule-change-requests-menu"]');
    await expect(page).toHaveURL(/.*schedule-change-requests/);
    const ownRequestId = await page.locator('[data-testid="request-row"]').first().locator('[data-testid="request-id"]').textContent();
    expect(ownRequestId).toBeTruthy();

    // Step 3-5: Manually modify the browser URL to access Scheduler B's request
    await page.goto(`${BASE_URL}/requests/${SCHEDULER_B_REQUEST_ID}`);

    // Step 6: Verify that no request details from Scheduler B are displayed
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/access denied|unauthorized|forbidden/i);

    // Step 7: Attempt to access Scheduler B's request via API endpoint
    const response = await page.request.get(`${BASE_URL}/api/schedule-change-requests/${SCHEDULER_B_REQUEST_ID}`);
    expect(response.status()).toBe(403);

    // Step 8: Verify the response body does not contain any request data
    const responseBody = await response.json();
    expect(responseBody).not.toHaveProperty('requestId', SCHEDULER_B_REQUEST_ID);
    expect(responseBody).toHaveProperty('error');

    // Step 9: Navigate back to Scheduler A's dashboard
    await page.click('[data-testid="schedule-change-requests-menu"]');
    await expect(page).toHaveURL(/.*schedule-change-requests/);

    // Step 10: Verify that Scheduler A can still access their own requests
    const ownRequests = page.locator('[data-testid="request-row"]');
    await expect(ownRequests.first()).toBeVisible();
    await ownRequests.first().click();
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    const displayedRequestId = await page.locator('[data-testid="detail-request-id"]').textContent();
    expect(displayedRequestId).toBe(ownRequestId);
  });

  test('Test dashboard performance under load (boundary)', async ({ page }) => {
    // Step 1-2: Open browser developer tools and clear cache (handled by Playwright context)
    const startTime = Date.now();

    // Step 3: Log into the system using valid scheduler credentials
    await page.fill('[data-testid="email-input"]', SCHEDULER_A_EMAIL);
    await page.fill('[data-testid="password-input"]', SCHEDULER_A_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 4-5: Start performance timer and navigate to dashboard
    const dashboardStartTime = Date.now();
    await page.click('[data-testid="schedule-change-requests-menu"]');

    // Step 6: Monitor the page load progress
    await expect(page.locator('[data-testid="request-dashboard"]')).toBeVisible();

    // Step 7: Wait for the dashboard to fully load
    await page.waitForLoadState('networkidle');
    const dashboardLoadTime = Date.now() - dashboardStartTime;

    // Step 8: Check the total page load time
    expect(dashboardLoadTime).toBeLessThan(3000);

    // Step 9: Verify that all request data is displayed correctly
    const requestRows = page.locator('[data-testid="request-row"]');
    const requestCount = await requestRows.count();
    expect(requestCount).toBeGreaterThanOrEqual(100);

    // Verify columns are present
    await expect(page.locator('[data-testid="request-id-column"]')).toBeVisible();
    await expect(page.locator('[data-testid="submission-date-column"]')).toBeVisible();
    await expect(page.locator('[data-testid="status-column"]')).toBeVisible();

    // Step 10: Scroll through the entire list of requests
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await page.waitForTimeout(500);
    await page.evaluate(() => window.scrollTo(0, 0));

    // Step 11: Check for any JavaScript errors in the browser console
    const consoleErrors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });
    expect(consoleErrors.length).toBe(0);

    // Step 12: Apply a filter to the loaded data
    const filterStartTime = Date.now();
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-filter-pending"]');
    await page.waitForLoadState('networkidle');
    const filterTime = Date.now() - filterStartTime;
    expect(filterTime).toBeLessThan(2000);

    // Step 13: Click on a request to open the detailed view
    const detailStartTime = Date.now();
    await requestRows.first().click();
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    const detailLoadTime = Date.now() - detailStartTime;
    expect(detailLoadTime).toBeLessThan(2000);

    // Step 14: Return to the dashboard and verify the list is still loaded
    await page.click('[data-testid="back-button"]');
    await expect(page.locator('[data-testid="request-dashboard"]')).toBeVisible();
    const reloadedRows = page.locator('[data-testid="request-row"]');
    await expect(reloadedRows.first()).toBeVisible();

    // Step 15: Document the actual load time
    console.log(`Dashboard load time: ${dashboardLoadTime}ms`);
    console.log(`Filter application time: ${filterTime}ms`);
    console.log(`Detail view load time: ${detailLoadTime}ms`);
    console.log(`Total requests displayed: ${requestCount}`);
  });
});