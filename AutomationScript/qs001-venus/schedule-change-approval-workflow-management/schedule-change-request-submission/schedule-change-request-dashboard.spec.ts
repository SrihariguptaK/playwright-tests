import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Dashboard - Story 5', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto('/login');
    
    // Login as scheduler with valid credentials
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and redirect
    await page.waitForURL('/dashboard');
  });

  test('Validate dashboard displays scheduler\'s submitted requests with statuses', async ({ page }) => {
    // Step 1: Scheduler navigates to dashboard
    await page.click('[data-testid="schedule-change-requests-menu"]');
    await page.waitForURL('/schedule-change-requests/dashboard');
    
    // Expected Result: Dashboard displays list of submitted schedule change requests
    await expect(page.locator('[data-testid="request-dashboard-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-list"]')).toBeVisible();
    
    // Verify request items are displayed with status
    const requestItems = page.locator('[data-testid="request-item"]');
    await expect(requestItems).toHaveCount(await requestItems.count());
    expect(await requestItems.count()).toBeGreaterThan(0);
    
    // Verify status indicators are visible
    const firstRequest = requestItems.first();
    await expect(firstRequest.locator('[data-testid="request-status"]')).toBeVisible();
    await expect(firstRequest.locator('[data-testid="request-date"]')).toBeVisible();
    
    // Step 2: Scheduler selects a request
    await firstRequest.click();
    
    // Alternative: Click View Details button if present
    const viewDetailsButton = firstRequest.locator('[data-testid="view-details-button"]');
    if (await viewDetailsButton.isVisible()) {
      await viewDetailsButton.click();
    }
    
    // Expected Result: Detailed approval history with comments and timestamps is displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-history-section"]')).toBeVisible();
    
    // Verify approval history contains comments and timestamps
    const approvalHistoryItems = page.locator('[data-testid="approval-history-item"]');
    await expect(approvalHistoryItems.first()).toBeVisible();
    await expect(approvalHistoryItems.first().locator('[data-testid="approver-comment"]')).toBeVisible();
    await expect(approvalHistoryItems.first().locator('[data-testid="approval-timestamp"]')).toBeVisible();
    
    // Navigate back to dashboard for filtering
    await page.click('[data-testid="back-to-dashboard-button"]');
    await page.waitForSelector('[data-testid="request-list"]');
    
    // Step 3: Scheduler applies filters
    // Apply date range filter (last 30 days)
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="last-30-days-option"]');
    
    // Apply status filter (Approved)
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-approved-option"]');
    
    // Wait for filtered results
    await page.waitForTimeout(1000);
    
    // Expected Result: Filtered list is displayed
    const filteredRequests = page.locator('[data-testid="request-item"]');
    await expect(filteredRequests).toBeVisible();
    
    // Verify filtered requests show only Approved status
    const statusLabels = await filteredRequests.locator('[data-testid="request-status"]').allTextContents();
    statusLabels.forEach(status => {
      expect(status.toLowerCase()).toContain('approved');
    });
    
    // Step 3 continued: Export report
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    
    // Expected Result: CSV report is downloaded
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/.*\.csv$/);
    
    // Verify download completed successfully
    const path = await download.path();
    expect(path).toBeTruthy();
  });

  test('Ensure schedulers cannot view requests submitted by others', async ({ page }) => {
    // Navigate to schedule change request dashboard
    await page.click('[data-testid="schedule-change-requests-menu"]');
    await page.waitForURL('/schedule-change-requests/dashboard');
    
    // Verify dashboard list shows only own requests
    const requestItems = page.locator('[data-testid="request-item"]');
    const requestCount = await requestItems.count();
    
    // Store the current scheduler's requests for verification
    const visibleRequestIds = await requestItems.locator('[data-testid="request-id"]').allTextContents();
    
    // Step 1: Attempt to access request details not submitted by them
    // Try to directly navigate to another scheduler's request using URL manipulation
    const unauthorizedRequestId = '99999'; // Request ID that doesn't belong to this scheduler
    
    await page.goto(`/schedule-change-requests/${unauthorizedRequestId}`);
    
    // Expected Result: Access is denied
    // Check for access denied message or redirect
    const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
    const errorMessage = page.locator('[data-testid="error-message"]');
    const unauthorizedMessage = page.locator('text=/access denied|unauthorized|forbidden/i');
    
    // Verify one of the error indicators is present
    const isAccessDenied = await accessDeniedMessage.isVisible().catch(() => false) ||
                          await errorMessage.isVisible().catch(() => false) ||
                          await unauthorizedMessage.isVisible().catch(() => false);
    
    expect(isAccessDenied).toBeTruthy();
    
    // Alternative: Verify redirect back to dashboard or error page
    await page.waitForTimeout(1000);
    const currentUrl = page.url();
    expect(currentUrl).not.toContain(unauthorizedRequestId);
    
    // Navigate back to dashboard
    await page.goto('/schedule-change-requests/dashboard');
    await page.waitForSelector('[data-testid="request-list"]');
    
    // Step 2: Verify dashboard list confirms only own requests are visible
    const dashboardRequests = page.locator('[data-testid="request-item"]');
    const currentRequestIds = await dashboardRequests.locator('[data-testid="request-id"]').allTextContents();
    
    // Verify the unauthorized request ID is not in the list
    expect(currentRequestIds).not.toContain(unauthorizedRequestId);
    
    // Verify request count hasn't changed (no unauthorized requests added)
    await expect(dashboardRequests).toHaveCount(requestCount);
    
    // Attempt to manipulate filters to access other requests
    // Try to inject request ID through filter manipulation
    await page.evaluate((reqId) => {
      const url = new URL(window.location.href);
      url.searchParams.set('requestId', reqId);
      window.history.pushState({}, '', url);
    }, unauthorizedRequestId);
    
    // Reload page with manipulated URL
    await page.reload();
    await page.waitForSelector('[data-testid="request-list"]');
    
    // Verify still only own requests are visible
    const reloadedRequests = page.locator('[data-testid="request-item"]');
    await expect(reloadedRequests).toHaveCount(requestCount);
    
    // Verify no unauthorized request details are displayed
    const requestDetails = page.locator('[data-testid="request-details-panel"]');
    if (await requestDetails.isVisible()) {
      const displayedRequestId = await requestDetails.locator('[data-testid="request-id"]').textContent();
      expect(displayedRequestId).not.toBe(unauthorizedRequestId);
    }
  });
});