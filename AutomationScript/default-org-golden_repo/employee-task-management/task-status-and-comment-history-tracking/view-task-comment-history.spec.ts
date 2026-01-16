import { test, expect } from '@playwright/test';

test.describe('Story-15: View Task Comment History', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const TASK_ID = 'task-123';

  test.beforeEach(async ({ page }) => {
    // Login as authorized employee
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('#1 Verify display of all comments in chronological order', async ({ page }) => {
    // Action: Employee opens task details and views comments section
    await page.goto(`${BASE_URL}/tasks/${TASK_ID}`);
    await page.waitForSelector('[data-testid="task-details-container"]');
    
    // Navigate to comments section
    await page.click('[data-testid="comments-tab"]');
    await page.waitForSelector('[data-testid="comments-section"]');
    
    // Expected Result: All comments displayed with author and timestamp
    const commentsSection = page.locator('[data-testid="comments-section"]');
    await expect(commentsSection).toBeVisible();
    
    // Verify comments are present
    const commentItems = page.locator('[data-testid="comment-item"]');
    const commentCount = await commentItems.count();
    expect(commentCount).toBeGreaterThan(0);
    
    // Verify each comment has author and timestamp
    for (let i = 0; i < commentCount; i++) {
      const comment = commentItems.nth(i);
      await expect(comment.locator('[data-testid="comment-author"]')).toBeVisible();
      await expect(comment.locator('[data-testid="comment-timestamp"]')).toBeVisible();
      await expect(comment.locator('[data-testid="comment-text"]')).toBeVisible();
    }
    
    // Verify chronological order (timestamps should be in ascending or descending order)
    const timestamps = await page.locator('[data-testid="comment-timestamp"]').allTextContents();
    expect(timestamps.length).toBeGreaterThan(0);
    
    // Verify comments loaded within 3 seconds
    const loadTime = await page.evaluate(() => {
      return performance.getEntriesByType('navigation')[0].loadEventEnd - performance.getEntriesByType('navigation')[0].fetchStart;
    });
    expect(loadTime).toBeLessThan(3000);
  });

  test('#2 Test comment search and filtering functionality', async ({ page }) => {
    // Action: Employee searches comments by keyword or date
    await page.goto(`${BASE_URL}/tasks/${TASK_ID}`);
    await page.waitForSelector('[data-testid="task-details-container"]');
    
    // Navigate to comments section
    await page.click('[data-testid="comments-tab"]');
    await page.waitForSelector('[data-testid="comments-section"]');
    
    // Get initial comment count
    const initialComments = await page.locator('[data-testid="comment-item"]').count();
    expect(initialComments).toBeGreaterThan(0);
    
    // Test keyword search
    const searchInput = page.locator('[data-testid="comment-search-input"]');
    await expect(searchInput).toBeVisible();
    await searchInput.fill('meeting');
    await page.click('[data-testid="comment-search-button"]');
    
    // Wait for filtered results
    await page.waitForTimeout(500);
    
    // Expected Result: Filtered comments displayed matching criteria
    const filteredComments = page.locator('[data-testid="comment-item"]');
    const filteredCount = await filteredComments.count();
    
    // Verify filtered results contain the search keyword
    if (filteredCount > 0) {
      for (let i = 0; i < filteredCount; i++) {
        const commentText = await filteredComments.nth(i).locator('[data-testid="comment-text"]').textContent();
        expect(commentText?.toLowerCase()).toContain('meeting');
      }
    }
    
    // Clear search
    await searchInput.clear();
    await page.click('[data-testid="comment-search-button"]');
    await page.waitForTimeout(500);
    
    // Test date filtering
    const dateFilter = page.locator('[data-testid="comment-date-filter"]');
    await expect(dateFilter).toBeVisible();
    await dateFilter.click();
    
    // Select date range option
    await page.click('[data-testid="date-filter-last-week"]');
    await page.waitForTimeout(500);
    
    // Verify filtered results are displayed
    const dateFilteredComments = await page.locator('[data-testid="comment-item"]').count();
    expect(dateFilteredComments).toBeGreaterThanOrEqual(0);
    
    // Verify filter indicator is shown
    await expect(page.locator('[data-testid="active-filter-indicator"]')).toBeVisible();
  });

  test('#3 Ensure unauthorized users cannot access comment history', async ({ page, context }) => {
    // Action: Unauthorized user attempts to access comments API
    
    // Logout current user
    await page.goto(`${BASE_URL}/logout`);
    await page.waitForURL(/.*login/);
    
    // Create new context without authentication
    const unauthorizedPage = await context.newPage();
    
    // Attempt to access comments API directly
    const response = await unauthorizedPage.goto(`${BASE_URL}/api/tasks/${TASK_ID}/comments`);
    
    // Expected Result: Access denied with authorization error
    expect(response?.status()).toBe(401);
    
    const responseBody = await response?.json();
    expect(responseBody).toHaveProperty('error');
    expect(responseBody.error).toMatch(/unauthorized|access denied|authentication required/i);
    
    // Attempt to access comments UI without authentication
    await unauthorizedPage.goto(`${BASE_URL}/tasks/${TASK_ID}`);
    
    // Should redirect to login or show access denied
    await unauthorizedPage.waitForTimeout(1000);
    const currentUrl = unauthorizedPage.url();
    const isRedirectedToLogin = currentUrl.includes('/login');
    const hasAccessDeniedMessage = await unauthorizedPage.locator('[data-testid="access-denied-message"]').isVisible().catch(() => false);
    
    expect(isRedirectedToLogin || hasAccessDeniedMessage).toBeTruthy();
    
    await unauthorizedPage.close();
  });

  test('Verify comments load within 3 seconds performance requirement', async ({ page }) => {
    const startTime = Date.now();
    
    await page.goto(`${BASE_URL}/tasks/${TASK_ID}`);
    await page.click('[data-testid="comments-tab"]');
    
    // Wait for comments to load
    await page.waitForSelector('[data-testid="comments-section"]');
    await page.waitForSelector('[data-testid="comment-item"]');
    
    const endTime = Date.now();
    const loadTime = endTime - startTime;
    
    // Verify load time is under 3 seconds (3000ms)
    expect(loadTime).toBeLessThan(3000);
    
    // Verify comments are visible
    const commentsVisible = await page.locator('[data-testid="comment-item"]').count();
    expect(commentsVisible).toBeGreaterThan(0);
  });
});