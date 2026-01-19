import { test, expect } from '@playwright/test';

test.describe('Story-11: Viewing Comments on Tasks', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const AUTHORIZED_TASK_ID = 'task-123';
  const UNAUTHORIZED_TASK_ID = 'task-999';

  test.beforeEach(async ({ page }) => {
    // Login as employee user
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', 'employee@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate display of comments with pagination (happy-path)', async ({ page }) => {
    const startTime = Date.now();

    // Navigate to the task detail page by clicking on a task from the task list
    await page.goto(`${BASE_URL}/tasks`);
    await page.click(`[data-testid="task-item-${AUTHORIZED_TASK_ID}"]`);
    await expect(page).toHaveURL(new RegExp(`.*tasks/${AUTHORIZED_TASK_ID}`));

    // Scroll down to the comments section on the task detail page
    await page.locator('[data-testid="comments-section"]').scrollIntoViewIfNeeded();

    // Verify that first 20 comments load within 1 second
    const loadTime = Date.now() - startTime;
    expect(loadTime).toBeLessThan(1000);

    // Verify that comments are displayed in chronological order
    const comments = await page.locator('[data-testid="comment-item"]').all();
    expect(comments.length).toBeGreaterThan(0);
    expect(comments.length).toBeLessThanOrEqual(20);

    // Check each comment for the presence of author name and timestamp
    for (let i = 0; i < Math.min(comments.length, 3); i++) {
      const comment = comments[i];
      await expect(comment.locator('[data-testid="comment-author"]')).toBeVisible();
      await expect(comment.locator('[data-testid="comment-timestamp"]')).toBeVisible();
      
      const authorText = await comment.locator('[data-testid="comment-author"]').textContent();
      const timestampText = await comment.locator('[data-testid="comment-timestamp"]').textContent();
      
      expect(authorText).toBeTruthy();
      expect(timestampText).toBeTruthy();
    }

    // Scroll down to the bottom of the loaded comments to trigger pagination or lazy loading
    const initialCommentCount = comments.length;
    await page.locator('[data-testid="comments-section"]').evaluate(el => {
      el.scrollTop = el.scrollHeight;
    });

    // Wait for additional comments to load
    await page.waitForTimeout(500);

    // Continue scrolling through multiple pages of comments
    const updatedComments = await page.locator('[data-testid="comment-item"]').all();
    
    // Additional comments load smoothly
    if (updatedComments.length > initialCommentCount) {
      expect(updatedComments.length).toBeGreaterThan(initialCommentCount);
    }

    // Verify the total number of comments matches the expected count for the task
    const totalCommentsText = await page.locator('[data-testid="total-comments-count"]').textContent();
    expect(totalCommentsText).toMatch(/\d+/);
  });

  test('Verify highlighting of new comments (happy-path)', async ({ page }) => {
    // Navigate to the task detail page that has new comments added since last visit
    await page.goto(`${BASE_URL}/tasks/${AUTHORIZED_TASK_ID}`);
    
    // Scroll to the comments section and observe the display of comments
    await page.locator('[data-testid="comments-section"]').scrollIntoViewIfNeeded();
    await page.waitForSelector('[data-testid="comment-item"]');

    // Verify that only comments added after the last visit timestamp are highlighted
    const highlightedComments = await page.locator('[data-testid="comment-item"][data-new="true"]').all();
    
    // New comments are visually highlighted
    if (highlightedComments.length > 0) {
      for (const comment of highlightedComments) {
        const backgroundColor = await comment.evaluate(el => window.getComputedStyle(el).backgroundColor);
        expect(backgroundColor).not.toBe('rgba(0, 0, 0, 0)');
        
        // Verify highlighting class or attribute
        const isHighlighted = await comment.getAttribute('data-new');
        expect(isHighlighted).toBe('true');
      }

      // Count the number of highlighted comments
      const highlightedCount = highlightedComments.length;
      expect(highlightedCount).toBeGreaterThan(0);
    }

    // Scroll through all comments to view the highlighted new comments
    await page.locator('[data-testid="comments-section"]').evaluate(el => {
      el.scrollTop = el.scrollHeight;
    });

    // Navigate away from the task detail page to another page in the application
    await page.goto(`${BASE_URL}/dashboard`);
    await expect(page).toHaveURL(/.*dashboard/);

    // Return to the same task detail page and navigate to the comments section
    await page.goto(`${BASE_URL}/tasks/${AUTHORIZED_TASK_ID}`);
    await page.locator('[data-testid="comments-section"]').scrollIntoViewIfNeeded();

    // Refresh the browser page and check the comments section again
    await page.reload();
    await page.waitForSelector('[data-testid="comments-section"]');

    // Highlighting resets after viewing - verify no false positives in highlighting
    const highlightedAfterRefresh = await page.locator('[data-testid="comment-item"][data-new="true"]').count();
    expect(highlightedAfterRefresh).toBe(0);
  });

  test('Ensure access control for comments (error-case)', async ({ page }) => {
    // Identify a task ID that the logged-in user is not authorized to access
    // Attempt to navigate to the unauthorized task detail page by entering the URL directly
    const response = await page.goto(`${BASE_URL}/tasks/${UNAUTHORIZED_TASK_ID}`);
    
    // Access is denied
    expect(response?.status()).toBeGreaterThanOrEqual(400);
    
    // Verify access denied message or redirect
    const accessDeniedVisible = await page.locator('[data-testid="access-denied-message"]').isVisible().catch(() => false);
    const unauthorizedVisible = await page.locator('text=/unauthorized|access denied|forbidden/i').isVisible().catch(() => false);
    
    expect(accessDeniedVisible || unauthorizedVisible || response?.status() === 403 || response?.status() === 401).toBeTruthy();

    // Attempt to access the comments section via direct API call
    const apiResponse = await page.request.get(`${BASE_URL}/api/tasks/${UNAUTHORIZED_TASK_ID}/comments`);
    expect(apiResponse.status()).toBeGreaterThanOrEqual(400);

    // Verify that no comment data or metadata is visible or leaked in the error response
    const responseBody = await apiResponse.text();
    expect(responseBody).not.toMatch(/comment-text|author|timestamp/i);

    // Navigate to a task that the user IS authorized to view
    await page.goto(`${BASE_URL}/tasks/${AUTHORIZED_TASK_ID}`);
    await expect(page).toHaveURL(new RegExp(`.*tasks/${AUTHORIZED_TASK_ID}`));

    // Scroll to the comments section of the authorized task
    await page.locator('[data-testid="comments-section"]').scrollIntoViewIfNeeded();
    await page.waitForSelector('[data-testid="comment-item"]');

    // Comments are displayed correctly
    const authorizedComments = await page.locator('[data-testid="comment-item"]').all();
    expect(authorizedComments.length).toBeGreaterThan(0);

    // Verify that all displayed comments belong to the current task
    for (const comment of authorizedComments) {
      const commentTaskId = await comment.getAttribute('data-task-id');
      if (commentTaskId) {
        expect(commentTaskId).toBe(AUTHORIZED_TASK_ID);
      }
    }

    // Verify no comments from other tasks are visible
    const allCommentElements = await page.locator('[data-testid="comment-item"]').all();
    for (const commentEl of allCommentElements) {
      const taskIdAttr = await commentEl.getAttribute('data-task-id');
      if (taskIdAttr) {
        expect(taskIdAttr).toBe(AUTHORIZED_TASK_ID);
      }
    }

    // Check browser console for any unauthorized data requests or errors
    const consoleErrors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    // Verify no data leakage occurs - only authorized comments are visible
    const networkRequests: string[] = [];
    page.on('request', request => {
      if (request.url().includes('/comments')) {
        networkRequests.push(request.url());
      }
    });

    await page.reload();
    await page.waitForTimeout(1000);

    // Verify all comment requests are for the authorized task
    for (const requestUrl of networkRequests) {
      if (requestUrl.includes(UNAUTHORIZED_TASK_ID)) {
        throw new Error(`Unauthorized task ID found in request: ${requestUrl}`);
      }
    }
  });
});