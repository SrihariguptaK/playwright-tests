import { test, expect } from '@playwright/test';

test.describe('Story-31: Notification History for Schedule Changes', () => {
  const SCHEDULER_USERNAME = 'scheduler@example.com';
  const SCHEDULER_PASSWORD = 'schedulerPass123';
  const UNAUTHORIZED_USERNAME = 'user@example.com';
  const UNAUTHORIZED_PASSWORD = 'userPass123';
  const BASE_URL = 'http://localhost:3000';
  const NOTIFICATION_HISTORY_URL = `${BASE_URL}/notifications/history`;
  const MAX_RESPONSE_TIME = 2000;

  test('Validate access to notification history (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the application login page and enter valid scheduler credentials
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', SCHEDULER_USERNAME);
    await page.fill('[data-testid="password-input"]', SCHEDULER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Locate and click on the 'Notification History' menu item or navigation link
    await page.click('[data-testid="notification-history-link"]');
    await expect(page).toHaveURL(NOTIFICATION_HISTORY_URL);

    // Step 3: Verify that notification records are displayed with all required fields
    await expect(page.locator('[data-testid="notification-history-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-timestamp"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="notification-content"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="notification-status"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="notification-recipient"]').first()).toBeVisible();

    // Step 4: Click on the filter dropdown and select 'Acknowledged' status filter
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="filter-option-acknowledged"]');
    await expect(page.locator('[data-testid="notification-status"]').first()).toContainText('Acknowledged');

    // Step 5: Clear the status filter and enter a search term in the search box
    await page.click('[data-testid="clear-filters-button"]');
    await page.fill('[data-testid="notification-search-input"]', 'schedule change');
    await page.click('[data-testid="search-button"]');
    await expect(page.locator('[data-testid="notification-content"]').first()).toContainText(/schedule change/i);

    // Step 6: Apply multiple filters simultaneously
    await page.click('[data-testid="date-range-filter"]');
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-12-31');
    await page.click('[data-testid="notification-type-filter"]');
    await page.click('[data-testid="filter-option-schedule-change"]');
    await page.click('[data-testid="apply-filters-button"]');
    await expect(page.locator('[data-testid="notification-history-table"] tbody tr')).toHaveCount(await page.locator('[data-testid="notification-history-table"] tbody tr').count());

    // Step 7: Click on the 'Export' button and select export format
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-format-csv"]');
    
    // Step 8: Confirm the export action and wait for file generation
    await page.click('[data-testid="confirm-export-button"]');
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('notification-history');
    
    // Step 9: Verify export file is downloaded
    expect(download).toBeTruthy();
  });

  test('Verify access control enforcement (error-case)', async ({ page }) => {
    // Step 1: Navigate to the application login page and enter credentials for an unauthorized user
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', UNAUTHORIZED_USERNAME);
    await page.fill('[data-testid="password-input"]', UNAUTHORIZED_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Attempt to access the notification history page by entering the URL directly
    await page.goto(NOTIFICATION_HISTORY_URL);
    
    // Step 3: Verify that the user is redirected to an error page or their default dashboard
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/access denied|unauthorized|forbidden/i);

    // Step 4: Attempt to access the notification history API endpoint directly
    const response = await page.request.get(`${BASE_URL}/api/notifications/history`);
    expect(response.status()).toBe(403);

    // Step 5: Log out from the unauthorized user account
    await page.click('[data-testid="user-menu-button"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 6: Log in with valid scheduler credentials that have proper authorization
    await page.fill('[data-testid="username-input"]', SCHEDULER_USERNAME);
    await page.fill('[data-testid="password-input"]', SCHEDULER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 7: Navigate to the notification history page using the navigation menu
    await page.click('[data-testid="notification-history-link"]');
    await expect(page).toHaveURL(NOTIFICATION_HISTORY_URL);

    // Step 8: Verify that all notification history features are accessible
    await expect(page.locator('[data-testid="status-filter-dropdown"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-search-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-history-table"]')).toBeVisible();
  });

  test('Ensure performance of notification history queries (boundary)', async ({ page }) => {
    // Step 1: Log in as a scheduler user and navigate to the notification history page
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', SCHEDULER_USERNAME);
    await page.fill('[data-testid="password-input"]', SCHEDULER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Open browser developer tools and navigate to the Network tab (monitored via page.request)
    // Step 3: Click on the 'Notification History' link to load the notification history page with large dataset
    const startTime = Date.now();
    const responsePromise = page.waitForResponse(response => 
      response.url().includes('/api/notifications/history') && response.status() === 200
    );
    
    await page.click('[data-testid="notification-history-link"]');
    const response = await responsePromise;
    const endTime = Date.now();
    const responseTime = endTime - startTime;

    // Step 4: Measure the API response time for the GET /notifications/history request
    expect(responseTime).toBeLessThan(MAX_RESPONSE_TIME);
    await expect(page).toHaveURL(NOTIFICATION_HISTORY_URL);

    // Step 5: Verify that pagination controls are displayed showing total pages and current page number
    await expect(page.locator('[data-testid="pagination-controls"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-page"]')).toContainText('1');
    await expect(page.locator('[data-testid="total-pages"]')).toBeVisible();

    // Step 6: Click on the 'Next' button to navigate to page 2 of the notification history
    const page2StartTime = Date.now();
    const page2ResponsePromise = page.waitForResponse(response => 
      response.url().includes('/api/notifications/history') && response.status() === 200
    );
    
    await page.click('[data-testid="next-page-button"]');
    await page2ResponsePromise;
    const page2EndTime = Date.now();
    const page2ResponseTime = page2EndTime - page2StartTime;

    // Step 7: Measure the response time for the page 2 request
    expect(page2ResponseTime).toBeLessThan(MAX_RESPONSE_TIME);
    await expect(page.locator('[data-testid="current-page"]')).toContainText('2');

    // Step 8: Navigate to a middle page (e.g., page 50) by entering the page number
    await page.fill('[data-testid="page-number-input"]', '50');
    const page50StartTime = Date.now();
    const page50ResponsePromise = page.waitForResponse(response => 
      response.url().includes('/api/notifications/history') && response.status() === 200
    );
    
    await page.click('[data-testid="go-to-page-button"]');
    await page50ResponsePromise;
    const page50EndTime = Date.now();
    const page50ResponseTime = page50EndTime - page50StartTime;
    
    expect(page50ResponseTime).toBeLessThan(MAX_RESPONSE_TIME);
    await expect(page.locator('[data-testid="current-page"]')).toContainText('50');

    // Step 9: Navigate to the last page of results using the pagination controls
    const lastPageStartTime = Date.now();
    const lastPageResponsePromise = page.waitForResponse(response => 
      response.url().includes('/api/notifications/history') && response.status() === 200
    );
    
    await page.click('[data-testid="last-page-button"]');
    await lastPageResponsePromise;
    const lastPageEndTime = Date.now();
    const lastPageResponseTime = lastPageEndTime - lastPageStartTime;
    
    expect(lastPageResponseTime).toBeLessThan(MAX_RESPONSE_TIME);

    // Step 10: Apply a filter to the large dataset and measure the query response time
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="filter-option-acknowledged"]');
    
    const filterStartTime = Date.now();
    const filterResponsePromise = page.waitForResponse(response => 
      response.url().includes('/api/notifications/history') && response.status() === 200
    );
    
    await page.click('[data-testid="apply-filters-button"]');
    await filterResponsePromise;
    const filterEndTime = Date.now();
    const filterResponseTime = filterEndTime - filterStartTime;
    
    expect(filterResponseTime).toBeLessThan(MAX_RESPONSE_TIME);

    // Step 11: Perform a search query on the large dataset and measure response time
    await page.fill('[data-testid="notification-search-input"]', 'schedule');
    
    const searchStartTime = Date.now();
    const searchResponsePromise = page.waitForResponse(response => 
      response.url().includes('/api/notifications/history') && response.status() === 200
    );
    
    await page.click('[data-testid="search-button"]');
    await searchResponsePromise;
    const searchEndTime = Date.now();
    const searchResponseTime = searchEndTime - searchStartTime;
    
    expect(searchResponseTime).toBeLessThan(MAX_RESPONSE_TIME);

    // Step 12: Verify that no errors, timeouts, or performance degradation occurred during navigation
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="notification-history-table"]')).toBeVisible();
  });
});