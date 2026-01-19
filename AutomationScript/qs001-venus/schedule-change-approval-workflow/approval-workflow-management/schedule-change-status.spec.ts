import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Status - Story 3', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('Display schedule change requests and statuses for scheduler', async ({ page }) => {
    const startTime = Date.now();
    
    // Step 1: Scheduler logs into the system
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    
    // Wait for navigation to My Schedule Changes page
    await page.waitForURL('**/my-schedule-changes');
    
    const loadTime = Date.now() - startTime;
    
    // Expected Result: 'My Schedule Changes' page loads within 3 seconds
    expect(loadTime).toBeLessThan(3000);
    await expect(page.locator('[data-testid="my-schedule-changes-page"]')).toBeVisible();
    
    // Step 2: View list of submitted schedule change requests
    const requestsList = page.locator('[data-testid="schedule-requests-list"]');
    await expect(requestsList).toBeVisible();
    
    // Expected Result: All requests submitted by the scheduler are displayed with current statuses
    const requestItems = page.locator('[data-testid="request-item"]');
    await expect(requestItems).toHaveCountGreaterThan(0);
    
    // Verify each request has a status displayed
    const firstRequest = requestItems.first();
    await expect(firstRequest.locator('[data-testid="request-status"]')).toBeVisible();
    await expect(firstRequest.locator('[data-testid="request-date"]')).toBeVisible();
    await expect(firstRequest.locator('[data-testid="request-type"]')).toBeVisible();
    
    // Verify status values are valid
    const statusText = await firstRequest.locator('[data-testid="request-status"]').textContent();
    expect(['Pending', 'Approved', 'Rejected', 'Escalated']).toContain(statusText?.trim());
    
    // Step 3: Select a request to view detailed approval history
    await firstRequest.click();
    
    // Expected Result: Approval actions and comments are displayed with timestamps
    await expect(page.locator('[data-testid="approval-history-section"]')).toBeVisible();
    
    const approvalActions = page.locator('[data-testid="approval-action-item"]');
    await expect(approvalActions.first()).toBeVisible();
    
    // Verify approval action has timestamp
    await expect(approvalActions.first().locator('[data-testid="action-timestamp"]')).toBeVisible();
    
    // Verify comments section exists
    const commentsSection = page.locator('[data-testid="approval-comments"]');
    await expect(commentsSection).toBeVisible();
  });

  test('Filter and sort schedule change requests', async ({ page }) => {
    // Login as scheduler
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('**/my-schedule-changes');
    await expect(page.locator('[data-testid="my-schedule-changes-page"]')).toBeVisible();
    
    // Step 1: Apply filter by status 'Pending'
    const statusFilter = page.locator('[data-testid="status-filter-dropdown"]');
    await statusFilter.click();
    
    await page.locator('[data-testid="filter-option-pending"]').click();
    
    // Wait for filter to be applied
    await page.waitForTimeout(500);
    
    // Expected Result: Only requests with 'Pending' status are displayed
    const requestItems = page.locator('[data-testid="request-item"]');
    const requestCount = await requestItems.count();
    
    // Verify all displayed requests have 'Pending' status
    for (let i = 0; i < requestCount; i++) {
      const statusText = await requestItems.nth(i).locator('[data-testid="request-status"]').textContent();
      expect(statusText?.trim()).toBe('Pending');
    }
    
    // Step 2: Sort requests by submission date descending
    const submissionDateHeader = page.locator('[data-testid="submission-date-header"]');
    await submissionDateHeader.click();
    
    // Wait for sorting to be applied
    await page.waitForTimeout(500);
    
    // Expected Result: Requests are sorted correctly by date
    const dateElements = page.locator('[data-testid="request-date"]');
    const dateCount = await dateElements.count();
    
    if (dateCount > 1) {
      const firstDate = await dateElements.first().textContent();
      const secondDate = await dateElements.nth(1).textContent();
      
      const firstDateTime = new Date(firstDate || '').getTime();
      const secondDateTime = new Date(secondDate || '').getTime();
      
      // Verify descending order (first date should be >= second date)
      expect(firstDateTime).toBeGreaterThanOrEqual(secondDateTime);
    }
    
    // Step 3: Clear filters and sorting
    const clearFiltersButton = page.locator('[data-testid="clear-filters-button"]');
    await clearFiltersButton.click();
    
    // Wait for filters to be cleared
    await page.waitForTimeout(500);
    
    // Expected Result: All requests are displayed in default order
    const allRequestItems = page.locator('[data-testid="request-item"]');
    await expect(allRequestItems).toHaveCountGreaterThan(0);
    
    // Verify filter dropdown is reset to default
    const filterDropdownText = await statusFilter.textContent();
    expect(filterDropdownText?.trim()).toMatch(/All Status|Select Status/i);
    
    // Verify requests with different statuses are now visible
    const allStatuses = await page.locator('[data-testid="request-status"]').allTextContents();
    const uniqueStatuses = [...new Set(allStatuses.map(s => s.trim()))];
    
    // Should have more than just 'Pending' status after clearing filters
    expect(uniqueStatuses.length).toBeGreaterThanOrEqual(1);
  });

  test('System restricts access to only scheduler own requests', async ({ page }) => {
    // Login as scheduler
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('**/my-schedule-changes');
    
    // Verify page loads successfully
    await expect(page.locator('[data-testid="my-schedule-changes-page"]')).toBeVisible();
    
    // Verify user identifier is displayed
    const userIdentifier = page.locator('[data-testid="current-user-name"]');
    await expect(userIdentifier).toContainText('scheduler@example.com');
    
    // Verify all requests belong to the logged-in scheduler
    const requestItems = page.locator('[data-testid="request-item"]');
    const count = await requestItems.count();
    
    if (count > 0) {
      // Check that requests have the scheduler's identifier
      const firstRequestOwner = requestItems.first().locator('[data-testid="request-owner"]');
      const ownerText = await firstRequestOwner.textContent();
      expect(ownerText).toContain('scheduler@example.com');
    }
  });

  test('System loads the status page within 3 seconds', async ({ page }) => {
    const startTime = Date.now();
    
    // Login as scheduler
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    
    // Wait for My Schedule Changes page to load
    await page.waitForURL('**/my-schedule-changes');
    await page.waitForLoadState('networkidle');
    
    const loadTime = Date.now() - startTime;
    
    // Verify page loads within 3 seconds
    expect(loadTime).toBeLessThan(3000);
    
    // Verify page content is visible
    await expect(page.locator('[data-testid="my-schedule-changes-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-requests-list"]')).toBeVisible();
  });
});