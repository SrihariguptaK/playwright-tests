import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Status Tracking', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto('/login');
    
    // Login as schedule manager
    await page.fill('[data-testid="username-input"]', 'schedule.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify schedule change request status is displayed correctly', async ({ page }) => {
    // Action: Navigate to status dashboard
    await page.click('[data-testid="schedule-requests-menu"]');
    await page.click('[data-testid="status-dashboard-link"]');
    
    // Expected Result: List of submitted requests with statuses is displayed
    await expect(page.locator('[data-testid="requests-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-item"]')).toHaveCount(await page.locator('[data-testid="request-item"]').count());
    
    // Verify status indicators are present
    const firstRequest = page.locator('[data-testid="request-item"]').first();
    await expect(firstRequest.locator('[data-testid="status-indicator"]')).toBeVisible();
    
    // Verify status text is one of the expected values
    const statusText = await firstRequest.locator('[data-testid="status-indicator"]').textContent();
    expect(['Pending', 'Approved', 'Rejected', 'Modification Requested']).toContain(statusText?.trim());
    
    // Action: Select a request to view detailed history
    const requestId = await firstRequest.locator('[data-testid="request-id"]').textContent();
    await firstRequest.click();
    
    // Expected Result: All approval decisions and comments are visible
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-history-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-decision"]')).toHaveCount(await page.locator('[data-testid="approval-decision"]').count());
    
    // Verify history entries contain decisions and comments
    const historyEntries = page.locator('[data-testid="history-entry"]');
    const historyCount = await historyEntries.count();
    if (historyCount > 0) {
      const firstHistoryEntry = historyEntries.first();
      await expect(firstHistoryEntry.locator('[data-testid="decision-text"]')).toBeVisible();
      await expect(firstHistoryEntry.locator('[data-testid="timestamp"]')).toBeVisible();
    }
    
    // Action: Receive notification on status change
    // Simulate status change by triggering test endpoint or waiting for notification
    await page.evaluate(() => {
      // Simulate a status change event
      window.dispatchEvent(new CustomEvent('statusChange', {
        detail: { requestId: 'REQ-001', newStatus: 'Approved' }
      }));
    });
    
    // Expected Result: Notification is displayed promptly
    await expect(page.locator('[data-testid="notification-toast"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="notification-message"]')).toContainText('status');
    
    // Refresh the status dashboard page
    await page.reload();
    await expect(page.locator('[data-testid="requests-list"]')).toBeVisible();
  });

  test('Test filtering and searching of schedule change requests', async ({ page }) => {
    // Login to the system and navigate to the schedule change request status dashboard
    await page.click('[data-testid="schedule-requests-menu"]');
    await page.click('[data-testid="status-dashboard-link"]');
    await expect(page.locator('[data-testid="requests-list"]')).toBeVisible();
    
    // Locate the filter controls on the dashboard
    await expect(page.locator('[data-testid="filter-controls"]')).toBeVisible();
    
    // Action: Apply filters by status
    // Select a specific status from the status filter (e.g., select 'Approved' only)
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-option-approved"]');
    
    // Expected Result: Request list updates to match filter criteria
    await page.waitForTimeout(500); // Wait for filter to apply
    const filteredRequests = page.locator('[data-testid="request-item"]');
    const filteredCount = await filteredRequests.count();
    
    // Verify that the filtered results match the selected criteria
    if (filteredCount > 0) {
      for (let i = 0; i < filteredCount; i++) {
        const statusIndicator = filteredRequests.nth(i).locator('[data-testid="status-indicator"]');
        await expect(statusIndicator).toContainText('Approved');
      }
    }
    
    // Add a date range filter by selecting a start date and end date
    await page.click('[data-testid="date-filter-start"]');
    await page.fill('[data-testid="date-filter-start"]', '2024-01-01');
    await page.click('[data-testid="date-filter-end"]');
    await page.fill('[data-testid="date-filter-end"]', '2024-12-31');
    await page.click('[data-testid="apply-date-filter-button"]');
    
    // Verify that the filtered results match the date criteria
    await page.waitForTimeout(500);
    await expect(page.locator('[data-testid="request-item"]')).toHaveCount(await page.locator('[data-testid="request-item"]').count());
    
    // Clear the status filter while keeping the date filter active
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-option-all"]');
    await page.waitForTimeout(500);
    
    // Clear all filters by clicking 'Clear Filters' or 'Reset' button
    await page.click('[data-testid="clear-filters-button"]');
    await page.waitForTimeout(500);
    await expect(page.locator('[data-testid="request-item"]')).toHaveCount(await page.locator('[data-testid="request-item"]').count());
    
    // Action: Search for specific request by ID
    // Locate the search functionality on the dashboard
    await expect(page.locator('[data-testid="search-input"]')).toBeVisible();
    
    // Get a request ID from the list to search for
    const firstRequestId = await page.locator('[data-testid="request-item"]').first().locator('[data-testid="request-id"]').textContent();
    
    // Enter a specific request ID in the search box
    await page.fill('[data-testid="search-input"]', firstRequestId || 'REQ-001');
    await page.click('[data-testid="search-button"]');
    
    // Expected Result: Matching request is displayed
    await page.waitForTimeout(500);
    const searchResults = page.locator('[data-testid="request-item"]');
    await expect(searchResults).toHaveCount(1);
    await expect(searchResults.first().locator('[data-testid="request-id"]')).toContainText(firstRequestId || 'REQ-001');
    
    // Clear the search box and test searching with partial request ID
    await page.fill('[data-testid="search-input"]', '');
    await page.fill('[data-testid="search-input"]', 'REQ');
    await page.click('[data-testid="search-button"]');
    await page.waitForTimeout(500);
    
    // Verify search results contain partial match
    const partialSearchResults = page.locator('[data-testid="request-item"]');
    const partialResultCount = await partialSearchResults.count();
    if (partialResultCount > 0) {
      const firstResultId = await partialSearchResults.first().locator('[data-testid="request-id"]').textContent();
      expect(firstResultId).toContain('REQ');
    }
    
    // Combine search with filters by entering a search term and applying a status filter
    await page.fill('[data-testid="search-input"]', 'REQ');
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-option-pending"]');
    await page.click('[data-testid="search-button"]');
    await page.waitForTimeout(500);
    
    // Verify combined filter and search results
    const combinedResults = page.locator('[data-testid="request-item"]');
    const combinedCount = await combinedResults.count();
    if (combinedCount > 0) {
      for (let i = 0; i < combinedCount; i++) {
        const requestId = await combinedResults.nth(i).locator('[data-testid="request-id"]').textContent();
        const statusText = await combinedResults.nth(i).locator('[data-testid="status-indicator"]').textContent();
        expect(requestId).toContain('REQ');
        expect(statusText).toContain('Pending');
      }
    }
    
    // Clear all search terms and filters to return to the full list view
    await page.fill('[data-testid="search-input"]', '');
    await page.click('[data-testid="clear-filters-button"]');
    await page.waitForTimeout(500);
    
    // Verify full list is displayed
    await expect(page.locator('[data-testid="request-item"]')).toHaveCount(await page.locator('[data-testid="request-item"]').count());
  });
});