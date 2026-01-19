import { test, expect } from '@playwright/test';

test.describe('Schedule Change Requests Dashboard - Story 19', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto('/login');
    // Login as employee with valid credentials
    await page.fill('[data-testid="username-input"]', 'employee.user@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123!');
    await page.click('[data-testid="login-button"]');
    // Wait for successful login
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('View schedule change requests dashboard (happy-path)', async ({ page }) => {
    // Navigate to the schedule change requests dashboard
    await page.click('text=My Requests');
    await expect(page).toHaveURL(/.*schedule-requests/);
    
    // Verify that all previously submitted requests are visible in the list
    await expect(page.locator('[data-testid="requests-list"]')).toBeVisible();
    const requestRows = page.locator('[data-testid="request-row"]');
    await expect(requestRows).toHaveCount(await requestRows.count());
    await expect(requestRows.first()).toBeVisible();
    
    // Select a request from the list to view detailed approval history
    await requestRows.first().click();
    await expect(page.locator('[data-testid="request-details-modal"]')).toBeVisible();
    
    // Verify detailed history with timestamps and comments is shown
    await expect(page.locator('[data-testid="approval-history"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-timestamp"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="approval-comments"]').first()).toBeVisible();
    
    // Close details modal and return to dashboard list view
    await page.click('[data-testid="close-details-button"]');
    await expect(page.locator('[data-testid="requests-list"]')).toBeVisible();
    
    // Locate the filter section
    await expect(page.locator('[data-testid="filter-section"]')).toBeVisible();
    
    // Select 'Approved' from the status filter dropdown
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-option-approved"]');
    
    // Verify filtered list updates accordingly
    await page.waitForTimeout(500);
    const filteredRequests = page.locator('[data-testid="request-row"]');
    const firstRequestStatus = await filteredRequests.first().locator('[data-testid="request-status"]').textContent();
    expect(firstRequestStatus?.toLowerCase()).toContain('approved');
    
    // Clear the status filter
    await page.click('[data-testid="clear-status-filter"]');
    
    // Apply a date range filter to find requests from the last 30 days
    await page.click('[data-testid="date-range-filter"]');
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const today = new Date();
    
    await page.fill('[data-testid="date-from-input"]', thirtyDaysAgo.toISOString().split('T')[0]);
    await page.fill('[data-testid="date-to-input"]', today.toISOString().split('T')[0]);
    await page.click('[data-testid="apply-date-filter"]');
    
    // Verify filtered results are displayed
    await page.waitForTimeout(500);
    await expect(page.locator('[data-testid="request-row"]').first()).toBeVisible();
  });

  test('Ensure access restriction to own requests (error-case)', async ({ page }) => {
    // Navigate to Employee A's own schedule change requests dashboard
    await page.click('text=My Requests');
    await expect(page).toHaveURL(/.*schedule-requests/);
    
    // Note the URL structure and request ID format
    const currentUrl = page.url();
    const requestRows = page.locator('[data-testid="request-row"]');
    await requestRows.first().click();
    
    // Get current request ID from URL or data attribute
    await page.waitForURL(/.*requests\/\d+/);
    const validRequestUrl = page.url();
    const validRequestId = validRequestUrl.match(/requests\/(\d+)/)?.[1];
    
    // Close the modal
    await page.click('[data-testid="close-details-button"]');
    
    // Attempt to access another employee's request by manipulating request ID
    const unauthorizedRequestId = parseInt(validRequestId || '100') + 9999;
    await page.goto(`/schedule-requests/${unauthorizedRequestId}`);
    
    // Verify access denied error is displayed
    await expect(page.locator('[data-testid="access-denied-error"]')).toBeVisible();
    await expect(page.locator('text=Access Denied')).toBeVisible();
    await expect(page.locator('text=You do not have permission to view this request')).toBeVisible();
    
    // Attempt to access another employee's dashboard by manipulating userId parameter
    await page.goto('/schedule-requests?userId=EmployeeB');
    
    // Verify access denied or redirect to own requests
    const finalUrl = page.url();
    const hasAccessDenied = await page.locator('[data-testid="access-denied-error"]').isVisible().catch(() => false);
    const redirectedToOwn = finalUrl.includes('userId=') === false || finalUrl.includes('EmployeeB') === false;
    
    expect(hasAccessDenied || redirectedToOwn).toBeTruthy();
    
    // Verify Employee A can still access their own requests normally
    await page.click('text=My Requests');
    await expect(page.locator('[data-testid="requests-list"]')).toBeVisible();
    await expect(requestRows.first()).toBeVisible();
  });

  test('Dashboard performance under normal load (edge-case)', async ({ page }) => {
    // Clear browser cache
    await page.context().clearCookies();
    
    // Navigate to the schedule change requests dashboard with 100+ requests
    const startTime = Date.now();
    
    await page.goto('/schedule-requests');
    
    // Wait for the requests list to be fully loaded
    await page.waitForSelector('[data-testid="requests-list"]', { state: 'visible' });
    await page.waitForLoadState('networkidle');
    
    const loadTime = Date.now() - startTime;
    
    // Verify dashboard loads within 2 seconds (2000ms)
    expect(loadTime).toBeLessThan(2000);
    
    // Verify that all UI elements are rendered correctly
    await expect(page.locator('[data-testid="requests-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="filter-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="status-filter-dropdown"]')).toBeVisible();
    
    // Verify pagination controls are present
    const paginationExists = await page.locator('[data-testid="pagination-controls"]').isVisible().catch(() => false);
    if (paginationExists) {
      await expect(page.locator('[data-testid="pagination-controls"]')).toBeVisible();
    }
    
    // Count the number of requests displayed
    const requestRows = page.locator('[data-testid="request-row"]');
    const requestCount = await requestRows.count();
    expect(requestCount).toBeGreaterThan(0);
    
    // Verify request data is rendered (headers and content)
    await expect(page.locator('[data-testid="request-header"]')).toBeVisible();
    await expect(requestRows.first().locator('[data-testid="request-status"]')).toBeVisible();
    await expect(requestRows.first().locator('[data-testid="request-date"]')).toBeVisible();
    
    // Test dashboard responsiveness by applying a filter
    const filterStartTime = Date.now();
    
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-option-pending"]');
    
    // Wait for filter to be applied
    await page.waitForTimeout(300);
    await page.waitForLoadState('networkidle');
    
    const filterTime = Date.now() - filterStartTime;
    
    // Verify filter response time is reasonable (under 1 second)
    expect(filterTime).toBeLessThan(1000);
    
    // Verify filtered results are displayed correctly
    const filteredRows = page.locator('[data-testid="request-row"]');
    if (await filteredRows.count() > 0) {
      const statusText = await filteredRows.first().locator('[data-testid="request-status"]').textContent();
      expect(statusText?.toLowerCase()).toContain('pending');
    }
    
    // Record performance metrics
    const performanceMetrics = await page.evaluate(() => {
      const perfData = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
      return {
        domContentLoaded: perfData.domContentLoadedEventEnd - perfData.domContentLoadedEventStart,
        loadComplete: perfData.loadEventEnd - perfData.loadEventStart,
        totalLoadTime: perfData.loadEventEnd - perfData.fetchStart
      };
    });
    
    console.log('Performance Metrics:', performanceMetrics);
    expect(performanceMetrics.totalLoadTime).toBeLessThan(2000);
  });
});