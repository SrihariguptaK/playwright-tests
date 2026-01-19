import { test, expect } from '@playwright/test';

test.describe('Schedule Change Approval Comments', () => {
  test.beforeEach(async ({ page }) => {
    // Login as approver
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'approver@company.com');
    await page.fill('[data-testid="password-input"]', 'approver123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Reject request with mandatory comment - error case', async ({ page }) => {
    // Navigate to the schedule change approval dashboard
    await page.goto('/approvals/schedule-changes');
    await expect(page.locator('[data-testid="approval-dashboard"]')).toBeVisible();

    // Select a pending schedule change request to review
    await page.click('[data-testid="pending-request-item"]:first-child');
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();

    // Click on the 'Reject' button without entering any comment in the comment field
    await page.click('[data-testid="reject-button"]');

    // Verify that the system prevents submission and displays error
    await expect(page.locator('[data-testid="comment-error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="comment-error-message"]')).toContainText('Comment is required when rejecting a request');

    // Verify that the request status has not changed
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Pending');

    // Enter a comment in the comment field explaining the reason for rejection
    await page.fill('[data-testid="approval-comment-input"]', 'Insufficient coverage during requested time period');

    // Click on the 'Reject' button with the comment entered
    await page.click('[data-testid="reject-button"]');

    // Verify request is rejected and comment saved
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request rejected successfully');

    // Navigate to the request history or details page
    await page.click('[data-testid="view-history-link"]');
    await expect(page.locator('[data-testid="request-history"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-comment"]')).toContainText('Insufficient coverage during requested time period');
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Rejected');
  });

  test('Approve request with optional comment - happy path', async ({ page }) => {
    // Navigate to the schedule change approval dashboard
    await page.goto('/approvals/schedule-changes');
    await expect(page.locator('[data-testid="approval-dashboard"]')).toBeVisible();

    // Select a pending schedule change request to review
    await page.click('[data-testid="pending-request-item"]:first-child');
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();

    // Click on the 'Approve' button without entering any comment in the comment field
    await page.click('[data-testid="approve-button"]');

    // Verify the request status has been updated
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request approved successfully');
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Approved');

    // Navigate back to dashboard
    await page.goto('/approvals/schedule-changes');

    // Select another pending schedule change request to review
    await page.click('[data-testid="pending-request-item"]:first-child');
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();

    // Enter a comment in the comment field
    await page.fill('[data-testid="approval-comment-input"]', 'Approved. Please ensure handover notes are updated');

    // Click on the 'Approve' button with the comment entered
    await page.click('[data-testid="approve-button"]');

    // Verify comment is saved and displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Navigate to the request history or details page for the second request
    await page.click('[data-testid="view-history-link"]');
    await expect(page.locator('[data-testid="request-history"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-comment"]')).toContainText('Approved. Please ensure handover notes are updated');
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Approved');
  });

  test('Display comments in request history and notifications - happy path', async ({ page }) => {
    // First, create an approved request with comment as approver
    await page.goto('/approvals/schedule-changes');
    await page.click('[data-testid="pending-request-item"]:first-child');
    const requestId = await page.locator('[data-testid="request-id"]').textContent();
    await page.fill('[data-testid="approval-comment-input"]', 'Approved with conditions. Please coordinate with team lead.');
    await page.click('[data-testid="approve-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Logout as approver
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Log in as the requester who submitted the schedule change request
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'requester@company.com');
    await page.fill('[data-testid="password-input"]', 'requester123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to 'My Requests' or 'Request History' section
    await page.goto('/my-requests');
    await expect(page.locator('[data-testid="my-requests-page"]')).toBeVisible();

    // Select the schedule change request that was processed by the approver
    await page.click(`[data-testid="request-item-${requestId}"]`);
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();

    // Scroll to the approval history or comments section
    await page.locator('[data-testid="approval-history-section"]').scrollIntoViewIfNeeded();

    // Verify the comment content matches what the approver entered
    await expect(page.locator('[data-testid="approval-comment"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-comment"]')).toContainText('Approved with conditions. Please coordinate with team lead.');

    // Navigate to the notifications section or check email notifications
    await page.goto('/notifications');
    await expect(page.locator('[data-testid="notifications-page"]')).toBeVisible();

    // Open the notification related to the schedule change request decision
    await page.click(`[data-testid="notification-${requestId}"]`);
    await expect(page.locator('[data-testid="notification-details"]')).toBeVisible();

    // Verify the notification includes all relevant information
    await expect(page.locator('[data-testid="notification-request-id"]')).toContainText(requestId || '');
    await expect(page.locator('[data-testid="notification-decision"]')).toContainText('Approved');
    await expect(page.locator('[data-testid="notification-approver-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-comments"]')).toContainText('Approved with conditions. Please coordinate with team lead.');
    await expect(page.locator('[data-testid="notification-timestamp"]')).toBeVisible();
  });
});