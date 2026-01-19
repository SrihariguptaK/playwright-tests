import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Approval', () => {
  const approverCredentials = {
    username: 'approver@company.com',
    password: 'ApproverPass123!'
  };

  const unauthorizedCredentials = {
    username: 'regular.user@company.com',
    password: 'UserPass123!'
  };

  test.beforeEach(async ({ page }) => {
    await page.goto('/login');
  });

  test('Approve a schedule change request successfully', async ({ page }) => {
    // Step 1: Approver logs in and navigates to pending approvals
    await page.fill('[data-testid="username-input"]', approverCredentials.username);
    await page.fill('[data-testid="password-input"]', approverCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Verify login successful and dashboard loaded
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to pending approvals section
    await page.click('[data-testid="pending-approvals-menu"]');
    await expect(page.locator('[data-testid="pending-approvals-dashboard"]')).toBeVisible();
    
    // Expected Result: List of pending requests is displayed
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();
    const requestCount = await page.locator('[data-testid="pending-request-item"]').count();
    expect(requestCount).toBeGreaterThan(0);
    
    // Step 2: Selects a request and approves it with optional comment
    const firstRequest = page.locator('[data-testid="pending-request-item"]').first();
    const requestId = await firstRequest.getAttribute('data-request-id');
    await firstRequest.click();
    
    // Verify request details are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    
    // Click approve button
    await page.click('[data-testid="approve-button"]');
    
    // Optionally enter comment
    await page.fill('[data-testid="approval-comment-input"]', 'Approved - meets all requirements');
    await page.click('[data-testid="confirm-approval-button"]');
    
    // Expected Result: Request status updates to approved
    await expect(page.locator('[data-testid="approval-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-success-message"]')).toContainText('approved');
    
    // Verify status update within 1 second
    await page.waitForResponse(
      response => response.url().includes(`/api/schedule-change-requests/${requestId}/approval`) && response.status() === 200,
      { timeout: 1000 }
    );
    
    // Step 3: Requester receives notification of approval
    // Navigate to notification system to verify
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();
    
    // Expected Result: Notification is received and visible
    const notification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'approved' }).first();
    await expect(notification).toBeVisible();
    
    // Navigate to approval history
    await page.click('[data-testid="approval-history-menu"]');
    await expect(page.locator('[data-testid="approval-history-list"]')).toBeVisible();
    
    // Verify approval is logged in history
    const historyEntry = page.locator(`[data-testid="history-entry-${requestId}"]`);
    await expect(historyEntry).toBeVisible();
    await expect(historyEntry).toContainText('Approved');
    await expect(historyEntry).toContainText(approverCredentials.username);
  });

  test('Reject a schedule change request with mandatory comment', async ({ page }) => {
    // Login as approver
    await page.fill('[data-testid="username-input"]', approverCredentials.username);
    await page.fill('[data-testid="password-input"]', approverCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Step 1: Navigate to pending approvals and select a request to reject
    await page.click('[data-testid="pending-approvals-menu"]');
    await expect(page.locator('[data-testid="pending-approvals-dashboard"]')).toBeVisible();
    
    const requestToReject = page.locator('[data-testid="pending-request-item"]').first();
    const requestId = await requestToReject.getAttribute('data-request-id');
    await requestToReject.click();
    
    // Click reject button
    await page.click('[data-testid="reject-button"]');
    
    // Expected Result: Rejection form with comment input is displayed
    await expect(page.locator('[data-testid="rejection-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="rejection-comment-input"]')).toBeVisible();
    
    // Step 2: Attempts to reject without comment
    await page.click('[data-testid="confirm-rejection-button"]');
    
    // Expected Result: Validation error prevents rejection
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('comment');
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('required');
    
    // Verify request status has not changed
    const currentStatus = await page.locator('[data-testid="request-status"]').textContent();
    expect(currentStatus).toContain('Pending');
    
    // Step 3: Enters rejection comment and submits
    await page.fill('[data-testid="rejection-comment-input"]', 'Request conflicts with operational requirements');
    await page.click('[data-testid="confirm-rejection-button"]');
    
    // Expected Result: Request status updates to rejected
    await expect(page.locator('[data-testid="rejection-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="rejection-success-message"]')).toContainText('rejected');
    
    // Verify API response
    await page.waitForResponse(
      response => response.url().includes(`/api/schedule-change-requests/${requestId}/approval`) && response.status() === 200,
      { timeout: 1000 }
    );
    
    // Expected Result: Notification sent to requester
    await page.click('[data-testid="notifications-icon"]');
    const rejectionNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'rejected' }).first();
    await expect(rejectionNotification).toBeVisible();
    
    // Navigate to approval history and verify logging
    await page.click('[data-testid="approval-history-menu"]');
    await expect(page.locator('[data-testid="approval-history-list"]')).toBeVisible();
    
    const historyEntry = page.locator(`[data-testid="history-entry-${requestId}"]`);
    await expect(historyEntry).toBeVisible();
    await expect(historyEntry).toContainText('Rejected');
    await expect(historyEntry).toContainText('Request conflicts with operational requirements');
    await expect(historyEntry).toContainText(approverCredentials.username);
    
    // Verify timestamp is present
    const timestamp = historyEntry.locator('[data-testid="action-timestamp"]');
    await expect(timestamp).toBeVisible();
  });

  test('Prevent unauthorized approval actions', async ({ page }) => {
    // Step 1: Log in to the system using unauthorized user credentials
    await page.fill('[data-testid="username-input"]', unauthorizedCredentials.username);
    await page.fill('[data-testid="password-input"]', unauthorizedCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Step 2: Attempt to navigate to the pending approvals dashboard
    const approvalMenuVisible = await page.locator('[data-testid="pending-approvals-menu"]').isVisible();
    
    if (approvalMenuVisible) {
      await page.click('[data-testid="pending-approvals-menu"]');
      // Expected Result: Access denied error is displayed
      await expect(page.locator('[data-testid="access-denied-error"]')).toBeVisible();
      await expect(page.locator('[data-testid="access-denied-error"]')).toContainText('Access denied');
    }
    
    // Attempt direct URL access
    await page.goto('/approvals/pending');
    await expect(page.locator('[data-testid="access-denied-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-error"]')).toContainText('unauthorized');
    
    // Step 3: Attempt to call the approval API endpoint directly
    const testRequestId = '12345';
    const apiResponse = await page.request.put(`/api/schedule-change-requests/${testRequestId}/approval`, {
      data: {
        action: 'approve',
        comment: 'Unauthorized approval attempt'
      }
    });
    
    // Expected Result: API returns 401 or 403 status
    expect([401, 403]).toContain(apiResponse.status());
    
    // Step 4: Log out the unauthorized user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);
    
    // Step 5: Log in using authorized approver credentials
    await page.fill('[data-testid="username-input"]', approverCredentials.username);
    await page.fill('[data-testid="password-input"]', approverCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Step 6: Navigate to pending approvals dashboard
    await page.click('[data-testid="pending-approvals-menu"]');
    await expect(page.locator('[data-testid="pending-approvals-dashboard"]')).toBeVisible();
    
    // Select a pending request and approve
    const pendingRequest = page.locator('[data-testid="pending-request-item"]').first();
    const requestId = await pendingRequest.getAttribute('data-request-id');
    await pendingRequest.click();
    
    await page.click('[data-testid="approve-button"]');
    await page.fill('[data-testid="approval-comment-input"]', 'Authorized approval');
    await page.click('[data-testid="confirm-approval-button"]');
    
    // Expected Result: Approval succeeds with status update
    await expect(page.locator('[data-testid="approval-success-message"]')).toBeVisible();
    
    // Verify API response is successful
    const successResponse = await page.waitForResponse(
      response => response.url().includes(`/api/schedule-change-requests/${requestId}/approval`) && response.status() === 200
    );
    expect(successResponse.status()).toBe(200);
    
    // Step 7: Verify the approval action in the audit log
    await page.click('[data-testid="approval-history-menu"]');
    await expect(page.locator('[data-testid="approval-history-list"]')).toBeVisible();
    
    const auditEntry = page.locator(`[data-testid="history-entry-${requestId}"]`);
    await expect(auditEntry).toBeVisible();
    await expect(auditEntry).toContainText('Approved');
    await expect(auditEntry).toContainText(approverCredentials.username);
    
    // Verify timestamp and user details are logged
    const userDetails = auditEntry.locator('[data-testid="action-user"]');
    await expect(userDetails).toContainText(approverCredentials.username);
    
    const actionTimestamp = auditEntry.locator('[data-testid="action-timestamp"]');
    await expect(actionTimestamp).toBeVisible();
  });
});