import { test, expect } from '@playwright/test';

test.describe('Edit Comments - Story 13', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const TASK_ID = 'task-123';
  const EMPLOYEE_EMAIL = 'employee@company.com';
  const EMPLOYEE_PASSWORD = 'password123';
  const OTHER_USER_EMAIL = 'otheruser@company.com';
  
  test.beforeEach(async ({ page }) => {
    // Login as employee
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful comment edit within allowed time', async ({ page }) => {
    // Navigate to task details page with recent comment
    await page.goto(`${BASE_URL}/tasks/${TASK_ID}`);
    await page.waitForLoadState('networkidle');
    
    // Post a new comment to ensure it's within 15 minutes
    const originalCommentText = 'This is my original coment with a typo';
    await page.fill('[data-testid="comment-input"]', originalCommentText);
    await page.click('[data-testid="submit-comment-button"]');
    
    // Wait for comment to appear
    await expect(page.locator('[data-testid="comment-text"]').last()).toContainText(originalCommentText);
    
    // Verify edit option is available for recent comment
    const editButton = page.locator('[data-testid="edit-comment-button"]').last();
    await expect(editButton).toBeVisible();
    await expect(editButton).toBeEnabled();
    
    // Click edit button
    await editButton.click();
    
    // Verify edit mode is activated
    const editTextarea = page.locator('[data-testid="edit-comment-textarea"]').last();
    await expect(editTextarea).toBeVisible();
    await expect(editTextarea).toHaveValue(originalCommentText);
    
    // Modify comment text to correct the typo
    const updatedCommentText = 'This is my original comment with a typo fixed';
    await editTextarea.clear();
    await editTextarea.fill(updatedCommentText);
    
    // Submit the changes
    await page.click('[data-testid="save-comment-button"]');
    
    // Wait for update to complete
    await page.waitForResponse(response => 
      response.url().includes('/api/comments/') && response.request().method() === 'PUT'
    );
    
    // Verify comment is updated
    await expect(page.locator('[data-testid="comment-text"]').last()).toContainText(updatedCommentText);
    
    // Verify edit indicator is shown
    const editIndicator = page.locator('[data-testid="comment-edited-indicator"]').last();
    await expect(editIndicator).toBeVisible();
    await expect(editIndicator).toContainText(/edited/i);
  });

  test('Reject comment edit outside allowed time window', async ({ page }) => {
    // Navigate to task details page
    await page.goto(`${BASE_URL}/tasks/${TASK_ID}`);
    await page.waitForLoadState('networkidle');
    
    // Locate a comment that is older than 15 minutes
    // This assumes the page has test data with old comments
    const oldComment = page.locator('[data-testid="comment-item"]').first();
    await expect(oldComment).toBeVisible();
    
    // Check if edit button is disabled or not present
    const editButton = oldComment.locator('[data-testid="edit-comment-button"]');
    
    // Verify edit option is disabled or shows appropriate message
    const editButtonCount = await editButton.count();
    
    if (editButtonCount > 0) {
      // If button exists, it should be disabled
      await expect(editButton).toBeDisabled();
      
      // Hover over disabled button to see tooltip/message
      await editButton.hover();
      
      // Verify message about edit time window expired
      const tooltip = page.locator('[data-testid="edit-disabled-tooltip"]');
      await expect(tooltip).toBeVisible();
      await expect(tooltip).toContainText(/edit window expired|15 minutes/i);
    } else {
      // Edit button should not be present for old comments
      await expect(editButton).not.toBeVisible();
      
      // Verify message is displayed
      const message = oldComment.locator('[data-testid="edit-not-allowed-message"]');
      await expect(message).toBeVisible();
      await expect(message).toContainText(/cannot edit|time window/i);
    }
    
    // Attempt to directly call edit API for old comment (if comment ID is available)
    const commentId = await oldComment.getAttribute('data-comment-id');
    
    if (commentId) {
      const response = await page.request.put(`${BASE_URL}/api/comments/${commentId}`, {
        data: {
          text: 'Attempting to edit old comment'
        }
      });
      
      // Verify API rejects the edit
      expect(response.status()).toBe(403);
      const responseBody = await response.json();
      expect(responseBody.error).toMatch(/edit window expired|not allowed/i);
    }
  });

  test('Prevent editing of others\' comments', async ({ page }) => {
    // Navigate to task details page
    await page.goto(`${BASE_URL}/tasks/${TASK_ID}`);
    await page.waitForLoadState('networkidle');
    
    // Locate a comment posted by another user
    const otherUserComment = page.locator('[data-testid="comment-item"]').filter({
      has: page.locator('[data-testid="comment-author"]', { hasText: OTHER_USER_EMAIL })
    }).first();
    
    // Verify the comment exists
    await expect(otherUserComment).toBeVisible();
    
    // Verify edit button is not available for other user's comment
    const editButton = otherUserComment.locator('[data-testid="edit-comment-button"]');
    await expect(editButton).not.toBeVisible();
    
    // Attempt to directly access edit API endpoint for another user's comment
    const commentId = await otherUserComment.getAttribute('data-comment-id');
    
    if (commentId) {
      const response = await page.request.put(`${BASE_URL}/api/comments/${commentId}`, {
        data: {
          text: 'Attempting to edit another user\'s comment'
        }
      });
      
      // Verify system denies access with authorization error
      expect(response.status()).toBe(403);
      const responseBody = await response.json();
      expect(responseBody.error).toMatch(/unauthorized|not authorized|permission denied/i);
    }
    
    // Verify no edit functionality is exposed in UI for other user's comments
    const commentActions = otherUserComment.locator('[data-testid="comment-actions"]');
    if (await commentActions.isVisible()) {
      await expect(commentActions.locator('[data-testid="edit-comment-button"]')).not.toBeVisible();
    }
  });
});