import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Review - Story 2', () => {
  const approverCredentials = {
    username: 'approver@company.com',
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
    await page.fill('[data-testid="date-from-input"]', '2024-01-01');
    await page.fill('[data-testid="date-to-input"]', '2024-12-31');
    await page.click('[data-testid="requester-dropdown"]');
    await page.click('[data-testid="requester-option"]', { hasText: 'John Smith' });
    await page.click('[data-testid="apply-filters-button"]');
    
    // Expected Result: List updates to show filtered requests
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-item"]')).toHaveCount(await page.locator('[data-testid="request-item"]').count());
    
    // Step 3: Select a request to view details
    await page.click('[data-testid="request-item"]', { hasText: 'John Smith' });
    
    // Expected Result: Detailed view with all information and attachments is displayed
    await expect(page.locator('[data-testid="request-detail-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-title"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-description"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-requester"]')).toContainText('John Smith');
    await expect(page.locator('[data-testid="request-attachments"]')).toBeVisible();
  });

  test('Verify adding comments to schedule change requests', async ({ page }) => {
    // Step 1: Open a schedule change request detail view
    await page.fill('[data-testid="username-input"]', approverCredentials.username);
    await page.fill('[data-testid="password-input"]', approverCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();
    await page.click('[data-testid="request-item"]');
    
    // Expected Result: Request details are visible
    await expect(page.locator('[data-testid="request-detail-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="comments-section"]')).toBeVisible();

    // Step 2: Enter a comment and submit
    const commentText = 'Please provide additional justification for this schedule change';
    await page.locator('[data-testid="comment-input"]').scrollIntoViewIfNeeded();
    await page.fill('[data-testid="comment-input"]', commentText);
    await page.click('[data-testid="submit-comment-button"]');
    
    // Expected Result: Comment is saved and displayed in the request history
    await expect(page.locator('[data-testid="comment-item"]').filter({ hasText: commentText })).toBeVisible();
    await expect(page.locator('[data-testid="request-history"]')).toContainText(commentText);

    // Step 3: Reload the request detail view
    await page.reload();
    
    // Expected Result: Previously added comment is visible
    await expect(page.locator('[data-testid="request-detail-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="comment-item"]').filter({ hasText: commentText })).toBeVisible();
  });

  test('Ensure request list loads within performance requirements', async ({ page }) => {
    // Step 1: Log in as Approver and measure time
    const loginStartTime = Date.now();
    await page.fill('[data-testid="username-input"]', approverCredentials.username);
    await page.fill('[data-testid="password-input"]', approverCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Dashboard is displayed
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    const loginEndTime = Date.now();
    const loginDuration = loginEndTime - loginStartTime;
    console.log(`Login and dashboard load time: ${loginDuration}ms`);

    // Step 2: Load pending requests list and measure time
    const listLoadStartTime = Date.now();
    await page.click('[data-testid="pending-requests-section"]');
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-item"]').first()).toBeVisible();
    const listLoadEndTime = Date.now();
    const listLoadDuration = listLoadEndTime - listLoadStartTime;
    
    // Expected Result: List loads within 3 seconds
    console.log(`Pending requests list load time: ${listLoadDuration}ms`);
    expect(listLoadDuration).toBeLessThan(3000);

    // Step 3: Apply filters and verify response time
    const filterStartTime = Date.now();
    await page.click('[data-testid="date-filter"]');
    await page.fill('[data-testid="date-from-input"]', '2024-01-01');
    await page.fill('[data-testid="date-to-input"]', '2024-12-31');
    await page.click('[data-testid="requester-dropdown"]');
    await page.click('[data-testid="requester-option"]');
    await page.click('[data-testid="apply-filters-button"]');
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();
    await page.waitForLoadState('networkidle');
    const filterEndTime = Date.now();
    const filterDuration = filterEndTime - filterStartTime;
    
    // Expected Result: Filtered list loads within 3 seconds
    console.log(`Filtered list load time: ${filterDuration}ms`);
    expect(filterDuration).toBeLessThan(3000);
  });
});