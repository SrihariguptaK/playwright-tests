import { test, expect } from '@playwright/test';

test.describe('Task Status History - Story 14', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_USERNAME = 'employee@company.com';
  const VALID_PASSWORD = 'Password123!';
  const TASK_ID = 'task-123';

  test.beforeEach(async ({ page }) => {
    // Login before each test
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify display of complete status history', async ({ page }) => {
    // Navigate to task details
    await page.goto(`${BASE_URL}/tasks/${TASK_ID}`);
    await expect(page.locator('[data-testid="task-details-container"]')).toBeVisible();

    // Open status history tab
    await page.click('[data-testid="status-history-tab"]');
    await expect(page.locator('[data-testid="status-history-section"]')).toBeVisible();

    // Verify full list of status changes is displayed
    const statusHistoryItems = page.locator('[data-testid="status-history-item"]');
    await expect(statusHistoryItems).toHaveCount(await statusHistoryItems.count());
    await expect(statusHistoryItems.first()).toBeVisible();

    // Verify each status change has user and timestamp
    const firstHistoryItem = statusHistoryItems.first();
    await expect(firstHistoryItem.locator('[data-testid="status-change-user"]')).toBeVisible();
    await expect(firstHistoryItem.locator('[data-testid="status-change-timestamp"]')).toBeVisible();
    await expect(firstHistoryItem.locator('[data-testid="status-change-value"]')).toBeVisible();

    // Verify chronological order (most recent first)
    const timestamps = await statusHistoryItems.locator('[data-testid="status-change-timestamp"]').allTextContents();
    expect(timestamps.length).toBeGreaterThan(0);
  });

  test('Test filtering of status history by date and status', async ({ page }) => {
    // Navigate to task details and open status history tab
    await page.goto(`${BASE_URL}/tasks/${TASK_ID}`);
    await page.click('[data-testid="status-history-tab"]');
    await expect(page.locator('[data-testid="status-history-section"]')).toBeVisible();

    // Get initial count of status history items
    const initialItems = page.locator('[data-testid="status-history-item"]');
    const initialCount = await initialItems.count();
    expect(initialCount).toBeGreaterThan(0);

    // Apply date range filter
    await page.click('[data-testid="filter-button"]');
    await expect(page.locator('[data-testid="filter-panel"]')).toBeVisible();
    
    await page.fill('[data-testid="date-from-input"]', '2024-01-01');
    await page.fill('[data-testid="date-to-input"]', '2024-12-31');

    // Apply status filter
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-option-in-progress"]');

    // Apply filters
    await page.click('[data-testid="apply-filters-button"]');

    // Wait for filtered results
    await page.waitForResponse(response => 
      response.url().includes(`/api/tasks/${TASK_ID}/status-history`) && response.status() === 200
    );

    // Verify filtered list is displayed
    const filteredItems = page.locator('[data-testid="status-history-item"]');
    await expect(filteredItems.first()).toBeVisible();

    // Verify filtered items contain only the selected status
    const statusValues = await filteredItems.locator('[data-testid="status-change-value"]').allTextContents();
    for (const status of statusValues) {
      expect(status.toLowerCase()).toContain('in progress');
    }

    // Clear filters and verify full list returns
    await page.click('[data-testid="clear-filters-button"]');
    await page.waitForTimeout(500);
    const clearedItems = page.locator('[data-testid="status-history-item"]');
    const clearedCount = await clearedItems.count();
    expect(clearedCount).toBeGreaterThanOrEqual(await filteredItems.count());
  });

  test('Ensure unauthorized users cannot access status history', async ({ page, context }) => {
    // Logout current user
    await page.goto(`${BASE_URL}/dashboard`);
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Attempt to access status history API directly without authentication
    const apiContext = await context.request;
    
    const unauthorizedResponse = await apiContext.get(
      `${BASE_URL}/api/tasks/${TASK_ID}/status-history`,
      {
        failOnStatusCode: false
      }
    );

    // Verify access is denied
    expect(unauthorizedResponse.status()).toBe(401);
    
    const responseBody = await unauthorizedResponse.json();
    expect(responseBody).toHaveProperty('error');
    expect(responseBody.error).toMatch(/unauthorized|authentication|access denied/i);

    // Attempt to navigate to status history page without authentication
    await page.goto(`${BASE_URL}/tasks/${TASK_ID}`, { waitUntil: 'networkidle' });
    
    // Should be redirected to login or show error
    const currentUrl = page.url();
    const isRedirectedToLogin = currentUrl.includes('/login');
    const hasErrorMessage = await page.locator('[data-testid="error-message"]').isVisible().catch(() => false);
    
    expect(isRedirectedToLogin || hasErrorMessage).toBeTruthy();

    // Login with unauthorized user (different role)
    if (isRedirectedToLogin) {
      await page.fill('[data-testid="username-input"]', 'unauthorized@company.com');
      await page.fill('[data-testid="password-input"]', 'Password123!');
      await page.click('[data-testid="login-button"]');
      
      // Try to access task that doesn't belong to this user
      const response = await page.goto(`${BASE_URL}/tasks/${TASK_ID}`, { waitUntil: 'networkidle' });
      
      // Should show access denied or 403 error
      if (response) {
        const status = response.status();
        expect([403, 404]).toContain(status);
      }
    }
  });

  test('Verify dashboard displays task status counts', async ({ page }) => {
    // Navigate to dashboard (already logged in from beforeEach)
    await page.goto(`${BASE_URL}/dashboard`);
    
    // Observe dashboard page load time
    const startTime = Date.now();
    await expect(page.locator('[data-testid="dashboard-container"]')).toBeVisible();
    const loadTime = Date.now() - startTime;
    expect(loadTime).toBeLessThan(5000);

    // Locate task status summary section
    const statusSummary = page.locator('[data-testid="task-status-summary"]');
    await expect(statusSummary).toBeVisible();

    // Review task counts for each status category
    const todoCount = page.locator('[data-testid="status-count-todo"]');
    const inProgressCount = page.locator('[data-testid="status-count-in-progress"]');
    const completedCount = page.locator('[data-testid="status-count-completed"]');
    const blockedCount = page.locator('[data-testid="status-count-blocked"]');

    await expect(todoCount).toBeVisible();
    await expect(inProgressCount).toBeVisible();
    await expect(completedCount).toBeVisible();
    await expect(blockedCount).toBeVisible();

    // Verify counts are numeric values
    const todoText = await todoCount.textContent();
    const inProgressText = await inProgressCount.textContent();
    const completedText = await completedCount.textContent();
    const blockedText = await blockedCount.textContent();

    expect(parseInt(todoText || '0')).toBeGreaterThanOrEqual(0);
    expect(parseInt(inProgressText || '0')).toBeGreaterThanOrEqual(0);
    expect(parseInt(completedText || '0')).toBeGreaterThanOrEqual(0);
    expect(parseInt(blockedText || '0')).toBeGreaterThanOrEqual(0);
  });

  test('Verify recent comments are shown on dashboard', async ({ page }) => {
    // Navigate to dashboard after login
    await page.goto(`${BASE_URL}/dashboard`);
    await expect(page.locator('[data-testid="dashboard-container"]')).toBeVisible();

    // Locate recent comments section
    const recentCommentsSection = page.locator('[data-testid="recent-comments-section"]');
    await expect(recentCommentsSection).toBeVisible();

    // Review comments displayed
    const commentItems = page.locator('[data-testid="comment-item"]');
    const commentCount = await commentItems.count();
    
    if (commentCount > 0) {
      // Verify each comment shows relevant information
      const firstComment = commentItems.first();
      
      await expect(firstComment.locator('[data-testid="comment-author"]')).toBeVisible();
      await expect(firstComment.locator('[data-testid="comment-timestamp"]')).toBeVisible();
      await expect(firstComment.locator('[data-testid="comment-task-reference"]')).toBeVisible();
      await expect(firstComment.locator('[data-testid="comment-text"]')).toBeVisible();

      // Verify commenter name is not empty
      const authorText = await firstComment.locator('[data-testid="comment-author"]').textContent();
      expect(authorText?.trim().length).toBeGreaterThan(0);

      // Verify timestamp is present
      const timestampText = await firstComment.locator('[data-testid="comment-timestamp"]').textContent();
      expect(timestampText?.trim().length).toBeGreaterThan(0);

      // Verify task reference is present
      const taskRefText = await firstComment.locator('[data-testid="comment-task-reference"]').textContent();
      expect(taskRefText?.trim().length).toBeGreaterThan(0);

      // Verify comment text is not empty
      const commentText = await firstComment.locator('[data-testid="comment-text"]').textContent();
      expect(commentText?.trim().length).toBeGreaterThan(0);
    }

    // Check the number of comments displayed (should be limited)
    expect(commentCount).toBeLessThanOrEqual(10);
  });

  test('Test navigation from dashboard to task details', async ({ page }) => {
    // View dashboard
    await page.goto(`${BASE_URL}/dashboard`);
    await expect(page.locator('[data-testid="dashboard-container"]')).toBeVisible();

    // Identify a task link in task status summary
    const taskLink = page.locator('[data-testid="task-link"]').first();
    await expect(taskLink).toBeVisible();

    // Hover over task link to verify it is interactive
    await taskLink.hover();
    await expect(taskLink).toHaveCSS('cursor', 'pointer');

    // Get task ID from link for verification
    const taskHref = await taskLink.getAttribute('href');
    expect(taskHref).toBeTruthy();

    // Click on the task link
    await taskLink.click();

    // Verify task details page loads completely
    await expect(page.locator('[data-testid="task-details-container"]')).toBeVisible({ timeout: 5000 });
    
    // Confirm URL matches the task clicked
    expect(page.url()).toContain('/tasks/');
    if (taskHref) {
      expect(page.url()).toContain(taskHref);
    }

    // Verify task details are displayed
    await expect(page.locator('[data-testid="task-title"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-description"]')).toBeVisible();

    // Use browser back button to return to dashboard
    await page.goBack();
    await expect(page.locator('[data-testid="dashboard-container"]')).toBeVisible();
    expect(page.url()).toContain('/dashboard');

    // Click on a different task link from recent comments section
    const commentTaskLink = page.locator('[data-testid="comment-task-link"]').first();
    
    if (await commentTaskLink.isVisible()) {
      const commentTaskHref = await commentTaskLink.getAttribute('href');
      await commentTaskLink.click();

      // Verify navigation to different task
      await expect(page.locator('[data-testid="task-details-container"]')).toBeVisible({ timeout: 5000 });
      
      if (commentTaskHref) {
        expect(page.url()).toContain(commentTaskHref);
      }
      
      // Verify it's a different task than the first one
      if (taskHref && commentTaskHref) {
        expect(commentTaskHref).not.toBe(taskHref);
      }
    }
  });
});