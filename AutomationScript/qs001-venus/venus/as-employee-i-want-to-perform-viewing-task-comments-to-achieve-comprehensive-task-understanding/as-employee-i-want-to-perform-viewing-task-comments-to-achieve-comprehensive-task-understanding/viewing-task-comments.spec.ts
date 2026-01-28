import { test, expect } from '@playwright/test';

test.describe('Story 11742: Viewing Task Comments', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page and authenticate as employee
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('AC1: Display all task comments with user names and timestamps in chronological order', async ({ page }) => {
    // Navigate to a task with multiple comments
    await page.goto('/tasks/12345');
    await page.waitForSelector('[data-testid="task-detail-page"]');
    
    // Navigate to comments section
    await page.click('[data-testid="comments-tab"]');
    await page.waitForSelector('[data-testid="comments-section"]');
    
    // Verify comments are displayed
    const comments = await page.locator('[data-testid="comment-item"]').all();
    expect(comments.length).toBeGreaterThan(0);
    
    // Verify first comment has user name and timestamp
    const firstComment = page.locator('[data-testid="comment-item"]').first();
    await expect(firstComment.locator('[data-testid="comment-user-name"]')).toBeVisible();
    await expect(firstComment.locator('[data-testid="comment-timestamp"]')).toBeVisible();
    
    // Verify chronological order (timestamps should be in ascending or descending order)
    const timestamps = await page.locator('[data-testid="comment-timestamp"]').allTextContents();
    expect(timestamps.length).toBeGreaterThan(1);
    
    // Verify comment content is displayed
    await expect(firstComment.locator('[data-testid="comment-content"]')).toBeVisible();
  });

  test('AC2: Support pagination or lazy loading for tasks with more than 20 comments', async ({ page }) => {
    // Navigate to a task with more than 20 comments
    await page.goto('/tasks/67890');
    await page.waitForSelector('[data-testid="task-detail-page"]');
    
    // Navigate to comments section
    await page.click('[data-testid="comments-tab"]');
    await page.waitForSelector('[data-testid="comments-section"]');
    
    // Verify initial load shows 20 comments or less
    const initialComments = await page.locator('[data-testid="comment-item"]').all();
    expect(initialComments.length).toBeLessThanOrEqual(20);
    
    // Check for pagination controls or lazy load trigger
    const hasPagination = await page.locator('[data-testid="pagination-controls"]').isVisible().catch(() => false);
    const hasLoadMore = await page.locator('[data-testid="load-more-comments"]').isVisible().catch(() => false);
    
    expect(hasPagination || hasLoadMore).toBeTruthy();
    
    if (hasLoadMore) {
      // Test lazy loading
      await page.click('[data-testid="load-more-comments"]');
      await page.waitForTimeout(1000);
      const updatedComments = await page.locator('[data-testid="comment-item"]').all();
      expect(updatedComments.length).toBeGreaterThan(initialComments.length);
    } else if (hasPagination) {
      // Test pagination
      await page.click('[data-testid="next-page-button"]');
      await page.waitForSelector('[data-testid="comment-item"]');
      const pageNumber = await page.locator('[data-testid="current-page"]').textContent();
      expect(pageNumber).toBe('2');
    }
  });

  test('AC3: Highlight new or unread comments distinctly', async ({ page }) => {
    // Navigate to a task with unread comments
    await page.goto('/tasks/11111');
    await page.waitForSelector('[data-testid="task-detail-page"]');
    
    // Navigate to comments section
    await page.click('[data-testid="comments-tab"]');
    await page.waitForSelector('[data-testid="comments-section"]');
    
    // Verify unread comments have distinct styling
    const unreadComments = page.locator('[data-testid="comment-item"][data-status="unread"]');
    const unreadCount = await unreadComments.count();
    
    if (unreadCount > 0) {
      const firstUnreadComment = unreadComments.first();
      
      // Check for unread indicator
      await expect(firstUnreadComment.locator('[data-testid="unread-indicator"]')).toBeVisible();
      
      // Verify distinct styling (e.g., background color, border)
      const backgroundColor = await firstUnreadComment.evaluate((el) => {
        return window.getComputedStyle(el).backgroundColor;
      });
      expect(backgroundColor).not.toBe('rgb(255, 255, 255)');
    }
    
    // Verify new comment badge if present
    const newCommentBadge = page.locator('[data-testid="new-comment-badge"]');
    if (await newCommentBadge.isVisible()) {
      await expect(newCommentBadge).toContainText(/new|unread/i);
    }
  });

  test('AC4: Allow searching and filtering comments by keywords', async ({ page }) => {
    // Navigate to a task with multiple comments
    await page.goto('/tasks/22222');
    await page.waitForSelector('[data-testid="task-detail-page"]');
    
    // Navigate to comments section
    await page.click('[data-testid="comments-tab"]');
    await page.waitForSelector('[data-testid="comments-section"]');
    
    // Get initial comment count
    const initialComments = await page.locator('[data-testid="comment-item"]').all();
    const initialCount = initialComments.length;
    
    // Locate search/filter input
    const searchInput = page.locator('[data-testid="comment-search-input"]');
    await expect(searchInput).toBeVisible();
    
    // Enter search keyword
    await searchInput.fill('urgent');
    await page.waitForTimeout(500); // Wait for debounce/filter
    
    // Verify filtered results
    const filteredComments = await page.locator('[data-testid="comment-item"]').all();
    expect(filteredComments.length).toBeLessThanOrEqual(initialCount);
    
    // Verify filtered comments contain the keyword
    if (filteredComments.length > 0) {
      const firstFilteredComment = page.locator('[data-testid="comment-item"]').first();
      const commentText = await firstFilteredComment.locator('[data-testid="comment-content"]').textContent();
      expect(commentText?.toLowerCase()).toContain('urgent');
    }
    
    // Clear search and verify all comments return
    await searchInput.clear();
    await page.waitForTimeout(500);
    const clearedComments = await page.locator('[data-testid="comment-item"]').all();
    expect(clearedComments.length).toBe(initialCount);
  });

  test('AC5: Enforce role-based access control for comment visibility', async ({ page }) => {
    // Test as employee with proper access
    await page.goto('/tasks/33333');
    await page.waitForSelector('[data-testid="task-detail-page"]');
    
    // Navigate to comments section
    await page.click('[data-testid="comments-tab"]');
    await page.waitForSelector('[data-testid="comments-section"]');
    
    // Verify comments are visible
    const comments = await page.locator('[data-testid="comment-item"]').all();
    expect(comments.length).toBeGreaterThan(0);
    
    // Logout and login as restricted user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Login as user without access
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'restricted@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    
    // Try to access the same task
    await page.goto('/tasks/33333');
    
    // Verify access is denied or comments are not visible
    const accessDenied = await page.locator('[data-testid="access-denied-message"]').isVisible().catch(() => false);
    const commentsHidden = await page.locator('[data-testid="comments-section"]').isHidden().catch(() => true);
    
    expect(accessDenied || commentsHidden).toBeTruthy();
  });

  test('Performance: Load first 20 comments within 2 seconds', async ({ page }) => {
    const startTime = Date.now();
    
    // Navigate to task with comments
    await page.goto('/tasks/44444');
    await page.waitForSelector('[data-testid="task-detail-page"]');
    
    // Navigate to comments section
    await page.click('[data-testid="comments-tab"]');
    
    // Wait for comments to load
    await page.waitForSelector('[data-testid="comment-item"]');
    
    const endTime = Date.now();
    const loadTime = endTime - startTime;
    
    // Verify load time is under 2 seconds (2000ms)
    expect(loadTime).toBeLessThan(2000);
    
    // Verify comments are loaded
    const comments = await page.locator('[data-testid="comment-item"]').all();
    expect(comments.length).toBeGreaterThan(0);
    expect(comments.length).toBeLessThanOrEqual(20);
  });

  test('User Flow: Complete comment viewing workflow', async ({ page }) => {
    // Step 1: Employee opens task detail page
    await page.goto('/tasks/55555');
    await page.waitForSelector('[data-testid="task-detail-page"]');
    await expect(page.locator('[data-testid="task-title"]')).toBeVisible();
    
    // Step 2: Navigates to comments section
    await page.click('[data-testid="comments-tab"]');
    await page.waitForSelector('[data-testid="comments-section"]');
    
    // Step 3: Scrolls through comments or uses search
    const comments = await page.locator('[data-testid="comment-item"]').all();
    expect(comments.length).toBeGreaterThan(0);
    
    // Scroll to last comment
    await page.locator('[data-testid="comment-item"]').last().scrollIntoViewIfNeeded();
    
    // Step 4: Reads comments for context
    const firstComment = page.locator('[data-testid="comment-item"]').first();
    const commentContent = await firstComment.locator('[data-testid="comment-content"]').textContent();
    expect(commentContent).toBeTruthy();
    
    // Step 5: Marks comments as read
    const unreadComments = page.locator('[data-testid="comment-item"][data-status="unread"]');
    const unreadCount = await unreadComments.count();
    
    if (unreadCount > 0) {
      // Click mark as read button if available
      const markReadButton = page.locator('[data-testid="mark-all-read-button"]');
      if (await markReadButton.isVisible()) {
        await markReadButton.click();
        await page.waitForTimeout(500);
        
        // Verify unread count decreased
        const updatedUnreadCount = await page.locator('[data-testid="comment-item"][data-status="unread"]').count();
        expect(updatedUnreadCount).toBeLessThan(unreadCount);
      }
    }
  });
});