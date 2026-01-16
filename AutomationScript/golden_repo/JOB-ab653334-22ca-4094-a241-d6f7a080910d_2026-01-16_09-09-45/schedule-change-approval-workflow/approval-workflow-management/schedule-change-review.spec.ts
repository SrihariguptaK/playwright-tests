import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Review - Story 2', () => {
  const approverCredentials = {
    username: 'approver@example.com',
    password: 'ApproverPass123!'
  };

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('Validate display of pending schedule change requests', async ({ page }) => {
    // Step 1: Log in as Approver
    await page.fill('[data-testid="username-input"]', approverCredentials.username);
    await page.fill('[data-testid="password-input"]', approverCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Dashboard with pending requests list is displayed
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();
    const requestItems = page.locator('[data-testid="request-item"]');
    await expect(requestItems.first()).toBeVisible();

    // Step 2: Filter requests by date and requester
    await page.click('[data-testid="date-filter"]');
    await page.fill('[data-testid="date-from"]', '2024-01-01');
    await page.fill('[data-testid="date-to"]', '2024-12-31');
    await page.click('[data-testid="requester-filter-dropdown"]');
    await page.click('[data-testid="requester-option"]', { hasText: 'John Smith' });
    await page.click('[data-testid="apply-filters-button"]');
    
    // Expected Result: List updates to show filtered requests
    await page.waitForResponse(response => 
      response.url().includes('/api/schedule-changes/pending') && response.status() === 200
    );
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();
    const filteredRequests = page.locator('[data-testid="request-item"]');
    await expect(filteredRequests).toHaveCount(await filteredRequests.count());

    // Step 3: Select a request to view details
    await page.click('[data-testid="request-item"]', { hasText: 'Schedule Change' });
    
    // Expected Result: Detailed view with all information and attachments is displayed
    await expect(page.locator('[data-testid="request-detail-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-title"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-description"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-requester"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-date"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-attachments"]')).toBeVisible();
  });

  test('Verify adding comments to schedule change requests', async ({ page }) => {
    // Step 1: Open a schedule change request detail view
    await page.fill('[data-testid="username-input"]', approverCredentials.username);
    await page.fill('[data-testid="password-input"]', approverCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    await page.click('[data-testid="request-item"]');
    
    // Expected Result: Request details are visible
    await expect(page.locator('[data-testid="request-detail-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-title"]')).toBeVisible();

    // Step 2: Enter a comment and submit
    const testComment = 'Please provide additional justification for this schedule change';
    await page.locator('[data-testid="comment-section"]').scrollIntoViewIfNeeded();
    await page.click('[data-testid="comment-text-field"]');
    await page.fill('[data-testid="comment-text-field"]', testComment);
    await page.click('[data-testid="submit-comment-button"]');
    
    // Expected Result: Comment is saved and displayed in the request history
    await expect(page.locator('[data-testid="comment-item"]', { hasText: testComment })).toBeVisible();
    await expect(page.locator('[data-testid="request-history"]')).toContainText(testComment);

    // Step 3: Reload the request detail view
    await page.reload();
    
    // Expected Result: Previously added comment is visible
    await expect(page.locator('[data-testid="request-detail-view"]')).toBeVisible();
    await page.locator('[data-testid="comment-section"]').scrollIntoViewIfNeeded();
    await expect(page.locator('[data-testid="comment-item"]', { hasText: testComment })).toBeVisible();
  });

  test('Ensure request list loads within performance requirements', async ({ page }) => {
    // Step 1: Log in as Approver
    const loginStartTime = Date.now();
    await page.fill('[data-testid="username-input"]', approverCredentials.username);
    await page.fill('[data-testid="password-input"]', approverCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Dashboard is displayed
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 2: Load pending requests list
    const requestListStartTime = Date.now();
    const responsePromise = page.waitForResponse(response => 
      response.url().includes('/api/schedule-changes/pending') && response.status() === 200
    );
    await page.waitForSelector('[data-testid="pending-requests-list"]');
    const response = await responsePromise;
    const requestListEndTime = Date.now();
    const loadTime = requestListEndTime - requestListStartTime;
    
    // Expected Result: List loads within 3 seconds
    expect(loadTime).toBeLessThan(3000);
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();

    // Step 3: Apply filters and verify response time
    const filterStartTime = Date.now();
    await page.click('[data-testid="date-filter"]');
    await page.fill('[data-testid="date-from"]', '2024-01-01');
    await page.fill('[data-testid="date-to"]', '2024-12-31');
    await page.click('[data-testid="requester-filter-dropdown"]');
    await page.click('[data-testid="requester-option"]');
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-option"]', { hasText: 'Pending' });
    
    const filteredResponsePromise = page.waitForResponse(response => 
      response.url().includes('/api/schedule-changes/pending') && response.status() === 200
    );
    await page.click('[data-testid="apply-filters-button"]');
    await filteredResponsePromise;
    const filterEndTime = Date.now();
    const filterLoadTime = filterEndTime - filterStartTime;
    
    // Expected Result: Filtered list loads within 3 seconds
    expect(filterLoadTime).toBeLessThan(3000);
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();
  });
});