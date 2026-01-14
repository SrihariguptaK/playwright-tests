import { test, expect } from '@playwright/test';

test.describe('Approver Comments on Schedule Change Requests', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as approver
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'approver@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate adding and saving comments during approval (happy-path)', async ({ page }) => {
    // Navigate to the pending schedule change requests dashboard
    await page.goto('/schedule-change-requests/pending');
    await expect(page.locator('[data-testid="pending-requests-dashboard"]')).toBeVisible();

    // Select and open a specific schedule change request for review
    await page.click('[data-testid="schedule-request-item"]:first-child');
    await expect(page.locator('[data-testid="request-details-page"]')).toBeVisible();

    // Verify the comment input field is visible on the approval form
    const commentField = page.locator('[data-testid="comment-input-field"]');
    await expect(commentField).toBeVisible();

    // Enter a valid comment in the comment field
    const validComment = 'Approved due to valid business justification and adequate coverage';
    await commentField.fill(validComment);
    await expect(commentField).toHaveValue(validComment);

    // Click the 'Approve' button to submit the approval decision with the comment
    await page.click('[data-testid="approve-button"]');
    
    // Wait for success confirmation
    await expect(page.locator('[data-testid="approval-success-message"]')).toBeVisible({ timeout: 5000 });

    // Navigate to the schedule change request history or details page
    await page.click('[data-testid="view-history-link"]');
    await expect(page.locator('[data-testid="request-history-section"]')).toBeVisible();

    // Locate the approval action entry in the request history
    const approvalEntry = page.locator('[data-testid="approval-action-entry"]').first();
    await expect(approvalEntry).toBeVisible();

    // Verify the comment is properly linked to the approval action
    const displayedComment = approvalEntry.locator('[data-testid="action-comment"]');
    await expect(displayedComment).toBeVisible();
    await expect(displayedComment).toContainText(validComment);

    // Verify the approval action is marked as approved
    await expect(approvalEntry.locator('[data-testid="action-status"]')).toContainText('Approved');
  });

  test('Validate comment length validation (boundary)', async ({ page }) => {
    // Navigate to the pending schedule change requests dashboard
    await page.goto('/schedule-change-requests/pending');
    await expect(page.locator('[data-testid="pending-requests-dashboard"]')).toBeVisible();

    // Select and open a schedule change request for approval
    await page.click('[data-testid="schedule-request-item"]:first-child');
    await expect(page.locator('[data-testid="request-details-page"]')).toBeVisible();

    // Generate and enter a comment text that exceeds 500 characters (501 characters)
    const oversizedComment = 'A'.repeat(501);
    const commentField = page.locator('[data-testid="comment-input-field"]');
    await commentField.fill(oversizedComment);

    // Attempt to submit the approval decision with the oversized comment
    await page.click('[data-testid="approve-button"]');

    // Verify that the approval submission is blocked
    const errorMessage = page.locator('[data-testid="comment-validation-error"]');
    await expect(errorMessage).toBeVisible();

    // Verify the error message clearly indicates the character limit and current character count
    await expect(errorMessage).toContainText('500');
    await expect(errorMessage).toContainText(/character limit|maximum length|exceeds/i);

    // Verify that the request was not approved (still on the same page)
    await expect(page.locator('[data-testid="request-details-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-success-message"]')).not.toBeVisible();

    // Reduce the comment text to exactly 500 characters
    const validComment = 'A'.repeat(500);
    await commentField.clear();
    await commentField.fill(validComment);

    // Verify character count indicator if present
    const charCount = page.locator('[data-testid="character-count"]');
    if (await charCount.isVisible()) {
      await expect(charCount).toContainText('500');
    }

    // Submit the approval decision with the valid-length comment
    await page.click('[data-testid="approve-button"]');

    // Verify successful submission
    await expect(page.locator('[data-testid="approval-success-message"]')).toBeVisible({ timeout: 5000 });

    // Verify no validation error is displayed
    await expect(errorMessage).not.toBeVisible();
  });

  test('Validate adding comments during rejection', async ({ page }) => {
    // Navigate to the pending schedule change requests dashboard
    await page.goto('/schedule-change-requests/pending');
    await expect(page.locator('[data-testid="pending-requests-dashboard"]')).toBeVisible();

    // Select and open a schedule change request for review
    await page.click('[data-testid="schedule-request-item"]:first-child');
    await expect(page.locator('[data-testid="request-details-page"]')).toBeVisible();

    // Verify comment input field is visible
    const commentField = page.locator('[data-testid="comment-input-field"]');
    await expect(commentField).toBeVisible();

    // Enter rejection comment
    const rejectionComment = 'Rejected due to insufficient coverage during the requested period';
    await commentField.fill(rejectionComment);

    // Click reject button
    await page.click('[data-testid="reject-button"]');

    // Wait for success confirmation
    await expect(page.locator('[data-testid="rejection-success-message"]')).toBeVisible({ timeout: 5000 });

    // Navigate to request history
    await page.click('[data-testid="view-history-link"]');
    await expect(page.locator('[data-testid="request-history-section"]')).toBeVisible();

    // Verify rejection action with comment is displayed
    const rejectionEntry = page.locator('[data-testid="approval-action-entry"]').first();
    await expect(rejectionEntry).toBeVisible();
    await expect(rejectionEntry.locator('[data-testid="action-comment"]')).toContainText(rejectionComment);
    await expect(rejectionEntry.locator('[data-testid="action-status"]')).toContainText('Rejected');
  });

  test('Validate comment input sanitization', async ({ page }) => {
    // Navigate to the pending schedule change requests dashboard
    await page.goto('/schedule-change-requests/pending');
    await expect(page.locator('[data-testid="pending-requests-dashboard"]')).toBeVisible();

    // Select and open a schedule change request
    await page.click('[data-testid="schedule-request-item"]:first-child');
    await expect(page.locator('[data-testid="request-details-page"]')).toBeVisible();

    // Enter comment with special characters that should be sanitized
    const commentWithSpecialChars = 'Approved with conditions: <script>alert("test")</script> & special chars';
    const commentField = page.locator('[data-testid="comment-input-field"]');
    await commentField.fill(commentWithSpecialChars);

    // Submit approval
    await page.click('[data-testid="approve-button"]');
    await expect(page.locator('[data-testid="approval-success-message"]')).toBeVisible({ timeout: 5000 });

    // Navigate to history and verify comment is sanitized
    await page.click('[data-testid="view-history-link"]');
    const displayedComment = page.locator('[data-testid="approval-action-entry"]').first().locator('[data-testid="action-comment"]');
    await expect(displayedComment).toBeVisible();
    
    // Verify script tags are not executed/rendered
    const commentText = await displayedComment.textContent();
    expect(commentText).not.toContain('<script>');
  });
});