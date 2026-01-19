import { test, expect } from '@playwright/test';

test.describe('Delete Own Comments Within Allowed Time', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const TEST_TASK_ID = 'task-123';
  const TEST_EMPLOYEE_EMAIL = 'employee@test.com';
  const TEST_EMPLOYEE_PASSWORD = 'password123';

  test.beforeEach(async ({ page }) => {
    // Login as employee
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', TEST_EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', TEST_EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful deletion of own comment within time window', async ({ page }) => {
    // Navigate to the task details page containing the employee's own comment
    await page.goto(`${BASE_URL}/tasks/${TEST_TASK_ID}`);
    await page.waitForLoadState('networkidle');

    // Post a new comment to ensure it's less than 15 minutes old
    await page.fill('[data-testid="comment-input"]', 'Test comment for deletion');
    await page.click('[data-testid="submit-comment-button"]');
    await page.waitForSelector('[data-testid="comment-item"]');

    // Locate the comment posted by the logged-in employee that is less than 15 minutes old
    const ownComments = page.locator('[data-testid="comment-item"][data-own-comment="true"]');
    const latestComment = ownComments.last();
    await expect(latestComment).toBeVisible();

    // Verify delete option is visible
    const deleteButton = latestComment.locator('[data-testid="delete-comment-button"]');
    await expect(deleteButton).toBeVisible();
    await expect(deleteButton).toBeEnabled();

    // Click the delete button/icon on the eligible comment
    await deleteButton.click();

    // Click the 'Confirm' or 'Yes' button in the confirmation dialog
    const confirmDialog = page.locator('[data-testid="confirmation-dialog"]');
    await expect(confirmDialog).toBeVisible();
    await expect(confirmDialog.locator('text=Are you sure')).toBeVisible();
    await page.click('[data-testid="confirm-delete-button"]');

    // Verify comment is removed from UI
    await expect(latestComment).not.toBeVisible({ timeout: 5000 });

    // Refresh the page to verify comment removal from database
    await page.reload();
    await page.waitForLoadState('networkidle');
    const commentText = page.locator('text=Test comment for deletion');
    await expect(commentText).not.toBeVisible();

    // Access the audit log system and search for deletion events
    await page.goto(`${BASE_URL}/audit-logs`);
    await page.fill('[data-testid="audit-search-input"]', 'comment_deleted');
    await page.click('[data-testid="audit-search-button"]');
    
    // Verify deletion event is logged
    const auditLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditLogEntry).toBeVisible();
    await expect(auditLogEntry).toContainText('comment_deleted');
    await expect(auditLogEntry).toContainText(TEST_EMPLOYEE_EMAIL);
  });

  test('Verify rejection of deletion after time window', async ({ page }) => {
    // Navigate to the task details page containing the employee's own comment posted more than 15 minutes ago
    await page.goto(`${BASE_URL}/tasks/${TEST_TASK_ID}`);
    await page.waitForLoadState('networkidle');

    // Locate the comment posted by the logged-in employee that is older than 15 minutes
    // This assumes there's a test comment that was created more than 15 minutes ago
    const oldComment = page.locator('[data-testid="comment-item"][data-own-comment="true"][data-expired="true"]').first();
    
    // Attempt to access the delete functionality
    const deleteButton = oldComment.locator('[data-testid="delete-comment-button"]');
    
    // Verify delete option is disabled or not visible
    const isVisible = await deleteButton.isVisible();
    if (isVisible) {
      await expect(deleteButton).toBeDisabled();
    } else {
      await expect(deleteButton).not.toBeVisible();
    }

    // Try to submit a DELETE request via API endpoint if button is disabled
    const commentId = await oldComment.getAttribute('data-comment-id');
    const response = await page.request.delete(`${BASE_URL}/api/tasks/${TEST_TASK_ID}/comments/${commentId}`);
    
    // Verify the system rejects with appropriate message
    expect(response.status()).toBe(403);
    const responseBody = await response.json();
    expect(responseBody.message).toContain('Deletion window expired');

    // Refresh the page and verify the comment status
    await page.reload();
    await page.waitForLoadState('networkidle');
    
    // Confirm comment remains unchanged
    const commentStillExists = page.locator(`[data-testid="comment-item"][data-comment-id="${commentId}"]`);
    await expect(commentStillExists).toBeVisible();

    // Check audit logs for any deletion attempt records
    await page.goto(`${BASE_URL}/audit-logs`);
    await page.fill('[data-testid="audit-search-input"]', 'comment_deletion_rejected');
    await page.click('[data-testid="audit-search-button"]');
    
    const rejectionLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(rejectionLogEntry).toBeVisible();
    await expect(rejectionLogEntry).toContainText('deletion_rejected');
  });

  test('Ensure confirmation prompt appears before deletion', async ({ page }) => {
    // Navigate to the task details page containing the employee's own eligible comment
    await page.goto(`${BASE_URL}/tasks/${TEST_TASK_ID}`);
    await page.waitForLoadState('networkidle');

    // Post a new comment to ensure it's eligible (less than 15 minutes old)
    await page.fill('[data-testid="comment-input"]', 'Test comment for confirmation prompt');
    await page.click('[data-testid="submit-comment-button"]');
    await page.waitForSelector('[data-testid="comment-item"]');

    // Locate an eligible comment and click the delete button
    const eligibleComment = page.locator('[data-testid="comment-item"][data-own-comment="true"]').last();
    await expect(eligibleComment).toBeVisible();
    const deleteButton = eligibleComment.locator('[data-testid="delete-comment-button"]');
    await deleteButton.click();

    // Verify confirmation dialog appears
    const confirmDialog = page.locator('[data-testid="confirmation-dialog"]');
    await expect(confirmDialog).toBeVisible();
    await expect(confirmDialog.locator('text=Are you sure')).toBeVisible();
    await expect(page.locator('[data-testid="confirm-delete-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="cancel-delete-button"]')).toBeVisible();

    // Click the 'Cancel' or 'No' button in the confirmation dialog
    await page.click('[data-testid="cancel-delete-button"]');

    // Verify the confirmation dialog is closed
    await expect(confirmDialog).not.toBeVisible();

    // Verify the comment is still present in the UI
    await expect(eligibleComment).toBeVisible();
    await expect(eligibleComment.locator('text=Test comment for confirmation prompt')).toBeVisible();

    // Click the delete button again on the same comment
    await deleteButton.click();
    await expect(confirmDialog).toBeVisible();

    // Click the 'Confirm' or 'Yes' button in the confirmation dialog
    await page.click('[data-testid="confirm-delete-button"]');

    // Verify the comment is removed from UI
    await expect(eligibleComment).not.toBeVisible({ timeout: 5000 });

    // Verify the deletion was processed in the database
    await page.reload();
    await page.waitForLoadState('networkidle');
    const deletedCommentText = page.locator('text=Test comment for confirmation prompt');
    await expect(deletedCommentText).not.toBeVisible();
  });
});