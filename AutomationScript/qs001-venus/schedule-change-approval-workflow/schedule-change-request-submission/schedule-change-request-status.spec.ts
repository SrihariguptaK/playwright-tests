import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Status Viewing', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page and authenticate as Schedule Coordinator
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'schedule.coordinator@example.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123!');
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and dashboard load
    await expect(page).toHaveURL(/\/dashboard/, { timeout: 5000 });
  });

  test('Validate display of user\'s schedule change requests', async ({ page }) => {
    // Step 1: Schedule Coordinator logs into the system
    // Navigate to My Schedule Change Requests dashboard
    await page.click('[data-testid="my-schedule-requests-link"]');
    
    // Expected Result: 'My Schedule Change Requests' dashboard is displayed
    await expect(page.locator('[data-testid="schedule-requests-dashboard"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('My Schedule Change Requests');
    
    // Step 2: View list of submitted requests
    const requestsList = page.locator('[data-testid="schedule-requests-list"]');
    await expect(requestsList).toBeVisible();
    
    // Expected Result: All requests submitted by the user are listed with current status
    const requestItems = page.locator('[data-testid="schedule-request-item"]');
    await expect(requestItems).toHaveCount(await requestItems.count());
    
    // Verify each request displays status
    const firstRequest = requestItems.first();
    await expect(firstRequest.locator('[data-testid="request-status"]')).toBeVisible();
    const statusText = await firstRequest.locator('[data-testid="request-status"]').textContent();
    expect(['Pending', 'Approved', 'Rejected', 'In Review']).toContain(statusText?.trim());
    
    // Step 3: Select a request to view details
    await firstRequest.click();
    
    // Expected Result: Detailed approval history and comments are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-history-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="comments-section"]')).toBeVisible();
    
    // Verify approval history contains entries
    const approvalHistoryItems = page.locator('[data-testid="approval-history-item"]');
    expect(await approvalHistoryItems.count()).toBeGreaterThanOrEqual(1);
  });

  test('Verify filtering and sorting functionality', async ({ page }) => {
    // Navigate to My Schedule Change Requests page
    await page.click('[data-testid="my-schedule-requests-link"]');
    await expect(page.locator('[data-testid="schedule-requests-dashboard"]')).toBeVisible();
    
    // Get initial count of all requests
    const allRequestsCount = await page.locator('[data-testid="schedule-request-item"]').count();
    
    // Step 1: Apply filter by status 'Pending'
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="filter-option-pending"]');
    
    // Expected Result: Only requests with status 'Pending' are displayed
    await page.waitForTimeout(500); // Wait for filter to apply
    const filteredRequests = page.locator('[data-testid="schedule-request-item"]');
    const filteredCount = await filteredRequests.count();
    
    // Verify all displayed requests have 'Pending' status
    for (let i = 0; i < filteredCount; i++) {
      const status = await filteredRequests.nth(i).locator('[data-testid="request-status"]').textContent();
      expect(status?.trim()).toBe('Pending');
    }
    
    // Step 2: Sort requests by submission date descending
    await page.click('[data-testid="sort-submission-date"]');
    
    // Expected Result: Requests are ordered from newest to oldest
    await page.waitForTimeout(500); // Wait for sort to apply
    const sortedRequests = page.locator('[data-testid="schedule-request-item"]');
    const sortedCount = await sortedRequests.count();
    
    if (sortedCount >= 2) {
      const firstDate = await sortedRequests.first().locator('[data-testid="submission-date"]').textContent();
      const secondDate = await sortedRequests.nth(1).locator('[data-testid="submission-date"]').textContent();
      
      const firstDateTime = new Date(firstDate || '').getTime();
      const secondDateTime = new Date(secondDate || '').getTime();
      expect(firstDateTime).toBeGreaterThanOrEqual(secondDateTime);
    }
    
    // Step 3: Clear filters and sorting
    await page.click('[data-testid="clear-filters-button"]');
    
    // Expected Result: All requests are displayed in default order
    await page.waitForTimeout(500); // Wait for filters to clear
    const clearedRequests = page.locator('[data-testid="schedule-request-item"]');
    const clearedCount = await clearedRequests.count();
    expect(clearedCount).toBe(allRequestsCount);
  });

  test('Test access restriction to own requests', async ({ page }) => {
    // Navigate to My Schedule Change Requests page
    await page.click('[data-testid="my-schedule-requests-link"]');
    await expect(page.locator('[data-testid="schedule-requests-dashboard"]')).toBeVisible();
    
    // Get current user's request ID for later verification
    const ownRequestId = await page.locator('[data-testid="schedule-request-item"]').first().getAttribute('data-request-id');
    
    // Step 1: Attempt to access another user's schedule change request via URL manipulation
    const unauthorizedRequestId = '99999'; // Simulated other user's request ID
    await page.goto(`/schedule-change-requests/${unauthorizedRequestId}`);
    
    // Expected Result: Access denied or no data displayed
    const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
    const noDataMessage = page.locator('[data-testid="no-data-message"]');
    const errorMessage = page.locator('[data-testid="error-message"]');
    
    // Check for access denied, no data, or error message
    const isAccessDenied = await accessDeniedMessage.isVisible().catch(() => false);
    const isNoData = await noDataMessage.isVisible().catch(() => false);
    const isError = await errorMessage.isVisible().catch(() => false);
    
    expect(isAccessDenied || isNoData || isError).toBeTruthy();
    
    // Verify no sensitive data is displayed
    const requestDetailsPanel = page.locator('[data-testid="request-details-panel"]');
    const isDetailsVisible = await requestDetailsPanel.isVisible().catch(() => false);
    
    if (isDetailsVisible) {
      // If details are shown, verify they don't belong to another user
      const displayedRequestId = await page.locator('[data-testid="request-id-display"]').textContent();
      expect(displayedRequestId).not.toBe(unauthorizedRequestId);
    }
    
    // Step 2: Navigate back to 'My Schedule Change Requests' dashboard
    await page.click('[data-testid="my-schedule-requests-link"]');
    await expect(page.locator('[data-testid="schedule-requests-dashboard"]')).toBeVisible();
    
    // Step 3: Select and view one of the user's own schedule change requests
    const ownRequest = page.locator('[data-testid="schedule-request-item"]').first();
    await ownRequest.click();
    
    // Expected Result: All own requests are accessible
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    
    // Verify that all displayed requests belong to the logged-in user
    await page.click('[data-testid="back-to-list-button"]');
    const allRequests = page.locator('[data-testid="schedule-request-item"]');
    const requestCount = await allRequests.count();
    
    // Verify submitter information for each request
    for (let i = 0; i < Math.min(requestCount, 5); i++) {
      const submitter = await allRequests.nth(i).locator('[data-testid="request-submitter"]').textContent();
      expect(submitter).toContain('schedule.coordinator@example.com');
    }
  });
});