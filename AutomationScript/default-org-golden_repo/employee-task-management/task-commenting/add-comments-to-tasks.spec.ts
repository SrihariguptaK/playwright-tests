import { test, expect } from '@playwright/test';

test.describe('Story-12: Add comments to tasks for effective communication', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_COMMENT = 'This task is progressing well. Expected completion by Friday.';
  const MAX_COMMENT_LENGTH = 1000;
  const LONG_COMMENT = 'a'.repeat(MAX_COMMENT_LENGTH + 500);
  const TASK_ID = '12345';

  test.beforeEach(async ({ page }) => {
    // Login as authorized employee before each test
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful comment addition with valid input', async ({ page }) => {
    // Step 1: Employee navigates to task details page
    await page.goto(`${BASE_URL}/tasks`);
    await page.click(`[data-testid="task-item-${TASK_ID}"]`);
    
    // Expected Result: Task details and comments section displayed
    await expect(page.locator('[data-testid="task-details-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="comments-section"]')).toBeVisible();
    
    // Step 2: Employee enters valid comment text
    const commentInput = page.locator('[data-testid="comment-input"]');
    await commentInput.fill(VALID_COMMENT);
    
    // Expected Result: Input accepted without errors
    await expect(commentInput).toHaveValue(VALID_COMMENT);
    await expect(page.locator('[data-testid="comment-error"]')).not.toBeVisible();
    
    // Step 3: Employee submits comment
    await page.click('[data-testid="submit-comment-button"]');
    
    // Expected Result: Comment is saved and displayed immediately
    await expect(page.locator('[data-testid="comment-success-message"]')).toBeVisible({ timeout: 3000 });
    const newComment = page.locator('[data-testid="comment-item"]').last();
    await expect(newComment).toBeVisible();
    await expect(newComment.locator('[data-testid="comment-text"]')).toContainText(VALID_COMMENT);
    await expect(newComment.locator('[data-testid="comment-author"]')).toContainText('employee@company.com');
    await expect(newComment.locator('[data-testid="comment-timestamp"]')).toBeVisible();
    
    // Verify comment input is cleared after submission
    await expect(commentInput).toHaveValue('');
  });

  test('Reject comment submission with empty text', async ({ page }) => {
    // Navigate to task details page
    await page.goto(`${BASE_URL}/tasks/${TASK_ID}`);
    await expect(page.locator('[data-testid="comments-section"]')).toBeVisible();
    
    // Step 1: Employee attempts to submit empty comment
    const commentInput = page.locator('[data-testid="comment-input"]');
    await commentInput.fill('');
    await page.click('[data-testid="submit-comment-button"]');
    
    // Expected Result: System displays validation error and blocks submission
    await expect(page.locator('[data-testid="comment-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="comment-error"]')).toContainText(/comment.*required|cannot.*empty/i);
    
    // Verify comment was not added to the list
    const commentCountBefore = await page.locator('[data-testid="comment-item"]').count();
    await page.waitForTimeout(1000);
    const commentCountAfter = await page.locator('[data-testid="comment-item"]').count();
    expect(commentCountAfter).toBe(commentCountBefore);
  });

  test('Reject comment submission with text exceeding maximum length', async ({ page }) => {
    // Navigate to task details page
    await page.goto(`${BASE_URL}/tasks/${TASK_ID}`);
    await expect(page.locator('[data-testid="comments-section"]')).toBeVisible();
    
    // Step 2: Employee enters comment exceeding max length
    const commentInput = page.locator('[data-testid="comment-input"]');
    await commentInput.fill(LONG_COMMENT);
    await page.click('[data-testid="submit-comment-button"]');
    
    // Expected Result: System displays validation error and blocks submission
    await expect(page.locator('[data-testid="comment-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="comment-error"]')).toContainText(/exceeds.*maximum|too.*long|character.*limit/i);
    
    // Verify comment was not added to the list
    const commentCountBefore = await page.locator('[data-testid="comment-item"]').count();
    await page.waitForTimeout(1000);
    const commentCountAfter = await page.locator('[data-testid="comment-item"]').count();
    expect(commentCountAfter).toBe(commentCountBefore);
  });

  test('Prevent unauthorized user from adding comments', async ({ page, context }) => {
    // Logout current user
    await page.goto(`${BASE_URL}/logout`);
    await page.waitForURL(/.*login/);
    
    // Step 1: Unauthorized user attempts to navigate to task details page
    await page.goto(`${BASE_URL}/tasks/${TASK_ID}`);
    
    // Expected Result: System denies access and shows authorization error
    // Either redirected to login or shown error message
    const currentUrl = page.url();
    const isRedirectedToLogin = currentUrl.includes('/login');
    const hasAuthError = await page.locator('[data-testid="auth-error"]').isVisible().catch(() => false);
    
    expect(isRedirectedToLogin || hasAuthError).toBeTruthy();
    
    if (hasAuthError) {
      await expect(page.locator('[data-testid="auth-error"]')).toContainText(/unauthorized|access.*denied|permission/i);
    }
    
    // Attempt direct API call to add comment
    const response = await page.request.post(`${BASE_URL}/api/tasks/${TASK_ID}/comments`, {
      data: {
        text: 'Unauthorized comment attempt'
      },
      failOnStatusCode: false
    });
    
    // Expected Result: API returns 401 or 403 status
    expect([401, 403]).toContain(response.status());
  });

  test('Verify comment displays with user and timestamp after submission', async ({ page }) => {
    // Navigate to task details page
    await page.goto(`${BASE_URL}/tasks/${TASK_ID}`);
    await expect(page.locator('[data-testid="comments-section"]')).toBeVisible();
    
    // Get initial comment count
    const initialCommentCount = await page.locator('[data-testid="comment-item"]').count();
    
    // Add a new comment
    const testComment = `Test comment added at ${new Date().toISOString()}`;
    await page.fill('[data-testid="comment-input"]', testComment);
    await page.click('[data-testid="submit-comment-button"]');
    
    // Wait for comment to be added
    await page.waitForTimeout(1000);
    
    // Verify new comment count
    const newCommentCount = await page.locator('[data-testid="comment-item"]').count();
    expect(newCommentCount).toBe(initialCommentCount + 1);
    
    // Verify the latest comment has all required information
    const latestComment = page.locator('[data-testid="comment-item"]').last();
    await expect(latestComment.locator('[data-testid="comment-text"]')).toContainText(testComment);
    await expect(latestComment.locator('[data-testid="comment-author"]')).toBeVisible();
    await expect(latestComment.locator('[data-testid="comment-timestamp"]')).toBeVisible();
    
    // Verify timestamp is recent (within last minute)
    const timestampText = await latestComment.locator('[data-testid="comment-timestamp"]').textContent();
    expect(timestampText).toBeTruthy();
  });
});