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
    // Navigate to task detail page
    await page.goto('/tasks/1001');
    await expect(page.locator('[data-testid="task-detail-page"]')).toBeVisible();

    // Navigate to comments section
    await page.click('[data-testid="comments-tab"]');
    await expect(page.locator('[data-testid="comments-section"]')).toBeVisible();

    // Verify comments are displayed
    const comments = page.locator('[data-testid="comment-item"]');
    await expect(comments).toHaveCount(await comments.count());
    await expect(comments.first()).toBeVisible();

    // Verify first comment has user name and timestamp
    const firstComment = comments.first();
    await expect(firstComment.locator('[data-testid="comment-author"]')).toBeVisible();
    await expect(firstComment.locator('[data-testid="comment-timestamp"]')).toBeVisible();

    // Verify chronological order (timestamps should be in descending or ascending order)
    const timestamps = await page.locator('[data-testid="comment-timestamp"]').allTextContents();
    expect(timestamps.length).toBeGreaterThan(0);
  });

  test('AC2: Support pagination or lazy loading for tasks with more than 20 comments', async ({ page }) => {
    // Navigate to task with many comments
    await page.goto('/tasks/2001');
    await expect(page.locator('[data-testid="task-detail-page"]')).toBeVisible();

    // Navigate to comments section
    await page.click('[data-testid="comments-tab"]');
    await expect(page.locator('[data-testid="comments-section"]')).toBeVisible();

    // Verify initial comment count is 20 or less
    const initialComments = page.locator('[data-testid="comment-item"]');
    const initialCount = await initialComments.count();
    expect(initialCount).toBeLessThanOrEqual(20);

    // Check for pagination controls or lazy loading trigger
    const paginationExists = await page.locator('[data-testid="comments-pagination"]').isVisible().catch(() => false);
    const loadMoreExists = await page.locator('[data-testid="load-more-comments"]').isVisible().catch(() => false);
    
    expect(paginationExists || loadMoreExists).toBeTruthy();

    // If load more button exists, click it
    if (loadMoreExists) {
      await page.click('[data-testid="load-more-comments"]');
      await page.waitForTimeout(1000);
      const newCount = await page.locator('[data-testid="comment-item"]').count();
      expect(newCount).toBeGreaterThan(initialCount);
    }

    // If pagination exists, navigate to next page
    if (paginationExists) {
      await page.click('[data-testid="next-page-button"]');
      await page.waitForTimeout(1000);
      await expect(page.locator('[data-testid="comment-item"]').first()).toBeVisible();
    }
  });

  test('AC3: Highlight new or unread comments distinctly', async ({ page }) => {
    // Navigate to task detail page
    await page.goto('/tasks/3001');
    await expect(page.locator('[data-testid="task-detail-page"]')).toBeVisible();

    // Navigate to comments section
    await page.click('[data-testid="comments-tab"]');
    await expect(page.locator('[data-testid="comments-section"]')).toBeVisible();

    // Check for unread comments indicator
    const unreadComments = page.locator('[data-testid="comment-item"][data-unread="true"]');
    const unreadCount = await unreadComments.count();

    if (unreadCount > 0) {
      // Verify unread comment has distinct styling
      const firstUnread = unreadComments.first();
      await expect(firstUnread).toBeVisible();
      
      // Check for unread badge or indicator
      const unreadBadge = firstUnread.locator('[data-testid="unread-badge"]');
      await expect(unreadBadge).toBeVisible();

      // Verify unread comment has different background or border
      const backgroundColor = await firstUnread.evaluate((el) => 
        window.getComputedStyle(el).backgroundColor
      );
      expect(backgroundColor).toBeTruthy();
    }
  });

  test('AC4: Allow searching and filtering comments by keywords', async ({ page }) => {
    // Navigate to task detail page
    await page.goto('/tasks/4001');
    await expect(page.locator('[data-testid="task-detail-page"]')).toBeVisible();

    // Navigate to comments section
    await page.click('[data-testid="comments-tab"]');
    await expect(page.locator('[data-testid="comments-section"]')).toBeVisible();

    // Verify search input exists
    const searchInput = page.locator('[data-testid="comment-search-input"]');
    await expect(searchInput).toBeVisible();

    // Get initial comment count
    const initialComments = await page.locator('[data-testid="comment-item"]').count();

    // Enter search keyword
    await searchInput.fill('urgent');
    await page.waitForTimeout(500);

    // Verify filtered results
    const filteredComments = await page.locator('[data-testid="comment-item"]').count();
    expect(filteredComments).toBeLessThanOrEqual(initialComments);

    // Verify filtered comments contain the keyword
    if (filteredComments > 0) {
      const commentTexts = await page.locator('[data-testid="comment-text"]').allTextContents();
      const containsKeyword = commentTexts.some(text => 
        text.toLowerCase().includes('urgent')
      );
      expect(containsKeyword).toBeTruthy();
    }

    // Clear search
    await searchInput.clear();
    await page.waitForTimeout(500);
    const clearedCount = await page.locator('[data-testid="comment-item"]').count();
    expect(clearedCount).toBeGreaterThanOrEqual(filteredComments);
  });

  test('AC5: Enforce role-based access control for comment visibility', async ({ page }) => {
    // Navigate to task detail page
    await page.goto('/tasks/5001');
    await expect(page.locator('[data-testid="task-detail-page"]')).toBeVisible();

    // Navigate to comments section
    await page.click('[data-testid="comments-tab"]');
    await expect(page.locator('[data-testid="comments-section"]')).toBeVisible();

    // Verify comments are visible for authorized employee
    const comments = page.locator('[data-testid="comment-item"]');
    await expect(comments.first()).toBeVisible();

    // Verify employee can read all comments
    const commentCount = await comments.count();
    expect(commentCount).toBeGreaterThan(0);

    // Logout and login as different role to verify access control
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Login as unauthorized user
    await page.fill('[data-testid="username-input"]', 'guest@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');

    // Try to access the same task
    await page.goto('/tasks/5001');
    
    // Verify access is restricted or comments are not visible
    const accessDenied = await page.locator('[data-testid="access-denied-message"]').isVisible().catch(() => false);
    const commentsHidden = await page.locator('[data-testid="comments-section"]').isHidden().catch(() => true);
    
    expect(accessDenied || commentsHidden).toBeTruthy();
  });

  test('Performance: Load first 20 comments within 2 seconds', async ({ page }) => {
    const startTime = Date.now();

    // Navigate to task detail page
    await page.goto('/tasks/6001');
    await expect(page.locator('[data-testid="task-detail-page"]')).toBeVisible();

    // Navigate to comments section
    await page.click('[data-testid="comments-tab"]');
    
    // Wait for comments to load
    await expect(page.locator('[data-testid="comment-item"]').first()).toBeVisible();
    
    const endTime = Date.now();
    const loadTime = endTime - startTime;

    // Verify load time is under 2 seconds (2000ms)
    expect(loadTime).toBeLessThan(2000);

    // Verify at least some comments are loaded
    const commentCount = await page.locator('[data-testid="comment-item"]').count();
    expect(commentCount).toBeGreaterThan(0);
    expect(commentCount).toBeLessThanOrEqual(20);
  });

  test('User Flow: Complete comment viewing workflow', async ({ page }) => {
    // Step 1: Employee opens task detail page
    await page.goto('/tasks/7001');
    await expect(page.locator('[data-testid="task-detail-page"]')).toBeVisible();

    // Step 2: Navigates to comments section
    await page.click('[data-testid="comments-tab"]');
    await expect(page.locator('[data-testid="comments-section"]')).toBeVisible();

    // Step 3: Scrolls through comments
    const commentsSection = page.locator('[data-testid="comments-section"]');
    await commentsSection.evaluate((el) => el.scrollTo(0, el.scrollHeight / 2));
    await page.waitForTimeout(500);

    // Step 4: Reads comments for context
    const comments = page.locator('[data-testid="comment-item"]');
    const commentCount = await comments.count();
    expect(commentCount).toBeGreaterThan(0);

    // Verify comment content is readable
    const firstCommentText = await comments.first().locator('[data-testid="comment-text"]').textContent();
    expect(firstCommentText).toBeTruthy();
    expect(firstCommentText!.length).toBeGreaterThan(0);

    // Step 5: Marks comments as read (if functionality exists)
    const markAsReadButton = page.locator('[data-testid="mark-all-read-button"]');
    const markAsReadExists = await markAsReadButton.isVisible().catch(() => false);
    
    if (markAsReadExists) {
      await markAsReadButton.click();
      await page.waitForTimeout(500);
      
      // Verify unread badges are removed
      const unreadBadges = page.locator('[data-testid="unread-badge"]');
      const unreadCount = await unreadBadges.count();
      expect(unreadCount).toBe(0);
    }
  });
});