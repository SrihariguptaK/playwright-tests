import { test, expect } from '@playwright/test';

test.describe('Story-8: Approver Request Modifications on Schedule Change Requests', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page and authenticate as approver
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'approver@company.com');
    await page.fill('[data-testid="password-input"]', 'ApproverPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to pending approvals
    await page.click('[data-testid="pending-approvals-link"]');
    await expect(page.locator('[data-testid="approvals-page-title"]')).toBeVisible();
  });

  test('TC#1: Validate approver can request modifications with comments', async ({ page }) => {
    // Step 1: Approver selects 'Request Modifications' on a schedule change request
    await page.click('[data-testid="schedule-change-request-item"]:first-child');
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    
    await page.click('[data-testid="request-modifications-button"]');
    
    // Expected Result: Comment input is displayed and required
    await expect(page.locator('[data-testid="modification-comment-input"]')).toBeVisible();
    const commentInput = page.locator('[data-testid="modification-comment-input"]');
    await expect(commentInput).toHaveAttribute('required', '');
    
    // Step 2: Approver enters comments and submits request
    await commentInput.fill('Please update the shift start time to 9:00 AM instead of 8:00 AM. Also verify the employee availability for the requested date.');
    await page.click('[data-testid="submit-modification-request-button"]');
    
    // Expected Result: Modification request saved and scheduler notified
    await expect(page.locator('[data-testid="success-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-notification"]')).toContainText('Modification request sent to scheduler');
    
    // Verify request status updated
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Modifications Requested');
  });

  test('TC#2: Verify scheduler receives notification and can edit request', async ({ page }) => {
    // Logout as approver and login as scheduler
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@company.com');
    await page.fill('[data-testid="password-input"]', 'SchedulerPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Step 1: Scheduler receives modification request notification
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();
    
    const modificationNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Modification Requested' }).first();
    await expect(modificationNotification).toBeVisible();
    
    // Expected Result: Notification contains comments and link to edit request
    await expect(modificationNotification).toContainText('Please update the shift start time');
    await expect(modificationNotification.locator('[data-testid="edit-request-link"]')).toBeVisible();
    
    await modificationNotification.locator('[data-testid="edit-request-link"]').click();
    
    // Step 2: Scheduler edits and resubmits request
    await expect(page.locator('[data-testid="edit-request-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="modification-comments-display"]')).toContainText('Please update the shift start time to 9:00 AM');
    
    // Edit the schedule change request
    await page.selectOption('[data-testid="shift-start-time-select"]', '09:00');
    await page.fill('[data-testid="revision-notes-input"]', 'Updated shift start time to 9:00 AM as requested. Employee availability confirmed.');
    
    await page.click('[data-testid="resubmit-request-button"]');
    
    // Expected Result: Updated request saved and workflow resumes
    await expect(page.locator('[data-testid="success-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-notification"]')).toContainText('Request resubmitted successfully');
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Pending Approval');
  });

  test('TC#3: Test validation prevents empty comments on modification request', async ({ page }) => {
    // Step 1: Approver attempts to submit modification request without comments
    await page.click('[data-testid="schedule-change-request-item"]:first-child');
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    
    await page.click('[data-testid="request-modifications-button"]');
    await expect(page.locator('[data-testid="modification-comment-input"]')).toBeVisible();
    
    // Leave comment field empty and attempt to submit
    const submitButton = page.locator('[data-testid="submit-modification-request-button"]');
    await submitButton.click();
    
    // Expected Result: System blocks submission and displays error
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Comments are required for modification requests');
    
    // Verify request was not submitted
    await expect(page.locator('[data-testid="request-status"]')).not.toContainText('Modifications Requested');
    
    // Verify form validation styling
    const commentInput = page.locator('[data-testid="modification-comment-input"]');
    await expect(commentInput).toHaveClass(/error|invalid/);
    
    // Verify submit button remains enabled for retry
    await expect(submitButton).toBeEnabled();
  });
});