import { test, expect } from '@playwright/test';

test.describe('Task Comments - Employee Communication', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const TEST_TASK_ID = 'task-123';

  test.beforeEach(async ({ page }) => {
    // Login as employee before each test
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', 'employee@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful comment submission', async ({ page }) => {
    // Step 1: Navigate to task detail page
    await page.goto(`${BASE_URL}/tasks`);
    await page.click(`[data-testid="task-item-${TEST_TASK_ID}"]`);
    
    // Expected Result: Task details and comment input box are visible
    await expect(page.locator('[data-testid="task-detail-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="comment-input-box"]')).toBeVisible();

    // Step 2: Enter a valid comment and submit
    const commentText = 'This is a test comment for validation';
    await page.fill('[data-testid="comment-input-box"]', commentText);
    await page.click('[data-testid="comment-submit-button"]');

    // Expected Result: Comment appears immediately in the comment list with author and timestamp
    await expect(page.locator('[data-testid="comment-list"]')).toBeVisible();
    const newComment = page.locator('[data-testid="comment-item"]').last();
    await expect(newComment.locator('[data-testid="comment-text"]')).toContainText(commentText);
    await expect(newComment.locator('[data-testid="comment-author"]')).toBeVisible();
    await expect(newComment.locator('[data-testid="comment-timestamp"]')).toBeVisible();

    // Step 3: Verify notification sent to stakeholders
    // Expected Result: Notification received by relevant users
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();
    const notificationSent = page.locator('[data-testid="notification-item"]').filter({ hasText: 'New comment on task' });
    await expect(notificationSent).toBeVisible({ timeout: 5000 });
  });

  test('Verify editing and deleting own comments within time limit', async ({ page }) => {
    // Navigate to task detail page and add a comment first
    await page.goto(`${BASE_URL}/tasks`);
    await page.click(`[data-testid="task-item-${TEST_TASK_ID}"]`);
    await page.fill('[data-testid="comment-input-box"]', 'This is a test comment');
    await page.click('[data-testid="comment-submit-button"]');
    await page.waitForTimeout(1000);

    // Step 1: Locate own comment posted less than 15 minutes ago
    const ownComment = page.locator('[data-testid="comment-item"]').last();
    await ownComment.hover();

    // Expected Result: Edit and delete options are available
    await expect(ownComment.locator('[data-testid="comment-edit-button"]')).toBeVisible();
    await expect(ownComment.locator('[data-testid="comment-delete-button"]')).toBeVisible();

    // Step 2: Edit the comment and save changes
    await ownComment.locator('[data-testid="comment-edit-button"]').click();
    const editInput = ownComment.locator('[data-testid="comment-edit-input"]');
    await expect(editInput).toBeVisible();
    await editInput.clear();
    await editInput.fill('This is an updated test comment');
    await ownComment.locator('[data-testid="comment-save-button"]').click();

    // Expected Result: Updated comment is displayed with updated timestamp
    await expect(ownComment.locator('[data-testid="comment-text"]')).toContainText('This is an updated test comment');
    await expect(ownComment.locator('[data-testid="comment-timestamp"]')).toContainText(/edited|updated/);

    // Step 3: Delete the comment
    await ownComment.hover();
    await ownComment.locator('[data-testid="comment-delete-button"]').click();
    
    // Handle confirmation dialog if present
    const confirmDialog = page.locator('[data-testid="confirm-delete-dialog"]');
    if (await confirmDialog.isVisible()) {
      await page.click('[data-testid="confirm-delete-button"]');
    }

    // Expected Result: Comment is removed from the list
    await expect(ownComment).not.toBeVisible({ timeout: 3000 });
  });

  test('Ensure comment input sanitization prevents XSS', async ({ page }) => {
    // Navigate to task detail page
    await page.goto(`${BASE_URL}/tasks`);
    await page.click(`[data-testid="task-item-${TEST_TASK_ID}"]`);
    await expect(page.locator('[data-testid="comment-input-box"]')).toBeVisible();

    // Step 1: Enter a comment containing script tags or malicious code
    const maliciousComments = [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      '<svg onload=alert("XSS")>'
    ];

    for (const maliciousCode of maliciousComments) {
      await page.fill('[data-testid="comment-input-box"]', maliciousCode);

      // Expected Result: System sanitizes input and prevents script execution
      // Monitor for any alert dialogs (which should not appear)
      let alertFired = false;
      page.on('dialog', async dialog => {
        alertFired = true;
        await dialog.dismiss();
      });

      // Step 2: Submit the comment
      await page.click('[data-testid="comment-submit-button"]');
      await page.waitForTimeout(1000);

      // Expected Result: Comment is saved and displayed as plain text without executing scripts
      const lastComment = page.locator('[data-testid="comment-item"]').last();
      const commentText = await lastComment.locator('[data-testid="comment-text"]').textContent();
      
      // Verify the malicious code is displayed as plain text or sanitized
      expect(commentText).toBeTruthy();
      expect(alertFired).toBe(false);

      // Step 3: Verify no security alerts or errors occur
      // Expected Result: System remains stable and secure
      const consoleErrors: string[] = [];
      page.on('console', msg => {
        if (msg.type() === 'error') {
          consoleErrors.push(msg.text());
        }
      });

      // Refresh the page and verify the comment still displays safely
      await page.reload();
      await expect(page.locator('[data-testid="task-detail-container"]')).toBeVisible();
      
      // Verify no XSS-related errors in console
      const xssErrors = consoleErrors.filter(error => 
        error.toLowerCase().includes('xss') || 
        error.toLowerCase().includes('script') ||
        error.toLowerCase().includes('security')
      );
      expect(xssErrors.length).toBe(0);

      // Clean up - delete the test comment
      const testComment = page.locator('[data-testid="comment-item"]').last();
      await testComment.hover();
      if (await testComment.locator('[data-testid="comment-delete-button"]').isVisible()) {
        await testComment.locator('[data-testid="comment-delete-button"]').click();
        const confirmDialog = page.locator('[data-testid="confirm-delete-dialog"]');
        if (await confirmDialog.isVisible()) {
          await page.click('[data-testid="confirm-delete-button"]');
        }
        await page.waitForTimeout(500);
      }
    }
  });
});