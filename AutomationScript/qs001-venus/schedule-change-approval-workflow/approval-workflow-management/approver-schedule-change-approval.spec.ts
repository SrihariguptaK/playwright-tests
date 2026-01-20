import { test, expect } from '@playwright/test';

test.describe('Approver Schedule Change Request Approval', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const approverCredentials = {
    username: 'approver@company.com',
    password: 'ApproverPass123!'
  };
  const firstLevelApprover = {
    username: 'approver.level1@company.com',
    password: 'Level1Pass123!'
  };
  const secondLevelApprover = {
    username: 'approver.level2@company.com',
    password: 'Level2Pass123!'
  };

  test.beforeEach(async ({ page }) => {
    await page.goto(`${baseURL}/login`);
  });

  test('Validate display of pending schedule change requests (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the system login page and enter valid approver credentials
    await page.fill('[data-testid="username-input"]', approverCredentials.username);
    await page.fill('[data-testid="password-input"]', approverCredentials.password);
    await page.click('[data-testid="login-button"]');

    // Expected Result: Dashboard with pending approvals is displayed
    await expect(page).toHaveURL(/.*\/dashboard/);
    await expect(page.locator('[data-testid="pending-approvals-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="pending-requests-header"]')).toContainText('Pending Approvals');

    // Step 2: Review the pending approvals dashboard and select a pending schedule change request
    const pendingRequestsList = page.locator('[data-testid="pending-requests-list"]');
    await expect(pendingRequestsList).toBeVisible();
    
    const firstRequest = pendingRequestsList.locator('[data-testid="request-item"]').first();
    await expect(firstRequest).toBeVisible();
    await firstRequest.click();

    // Expected Result: Request details and attachments are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-details-header"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-attachments-section"]')).toBeVisible();

    // Step 3: Review the request details and attachments, enter approval comments, and click Approve
    const commentsField = page.locator('[data-testid="approval-comments-input"]');
    await expect(commentsField).toBeVisible();
    await commentsField.fill('Approved - Schedule change is reasonable and does not conflict with existing commitments.');

    const approveButton = page.locator('[data-testid="approve-button"]');
    await expect(approveButton).toBeEnabled();
    await approveButton.click();

    // Expected Result: Request status updates to approved and confirmation shown
    await expect(page.locator('[data-testid="approval-confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-confirmation-message"]')).toContainText('approved');
    
    // Verify status update
    const statusBadge = page.locator('[data-testid="request-status-badge"]');
    await expect(statusBadge).toContainText('Approved');
  });

  test('Verify rejection requires mandatory comments (error-case)', async ({ page }) => {
    // Step 1: Login as approver
    await page.fill('[data-testid="username-input"]', approverCredentials.username);
    await page.fill('[data-testid="password-input"]', approverCredentials.password);
    await page.click('[data-testid="login-button"]');

    await expect(page.locator('[data-testid="pending-approvals-dashboard"]')).toBeVisible();

    // Step 2: From the pending approvals dashboard, select a schedule change request
    const pendingRequestsList = page.locator('[data-testid="pending-requests-list"]');
    const requestToReject = pendingRequestsList.locator('[data-testid="request-item"]').first();
    await requestToReject.click();

    // Expected Result: Rejection form displayed with comment field
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    
    const rejectButton = page.locator('[data-testid="reject-button"]');
    await expect(rejectButton).toBeVisible();
    await rejectButton.click();

    await expect(page.locator('[data-testid="rejection-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="rejection-comments-input"]')).toBeVisible();

    // Step 3: Attempt to submit rejection without comments
    const submitRejectionButton = page.locator('[data-testid="submit-rejection-button"]');
    await submitRejectionButton.click();

    // Expected Result: Validation error displayed, submission blocked
    await expect(page.locator('[data-testid="validation-error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-message"]')).toContainText('Comments are required for rejection');
    
    // Verify request status has not changed
    const statusBadge = page.locator('[data-testid="request-status-badge"]');
    await expect(statusBadge).not.toContainText('Rejected');

    // Step 4: Enter detailed rejection comments and submit
    const rejectionCommentsField = page.locator('[data-testid="rejection-comments-input"]');
    await rejectionCommentsField.fill('Rejected - The proposed schedule change conflicts with critical project milestones and resource allocation. Please revise the request with alternative dates.');

    await submitRejectionButton.click();

    // Expected Result: Request status updates to rejected and confirmation shown
    await expect(page.locator('[data-testid="rejection-confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="rejection-confirmation-message"]')).toContainText('rejected');
    
    // Verify status update
    await expect(page.locator('[data-testid="request-status-badge"]')).toContainText('Rejected');
  });

  test('Test multi-level approval routing (happy-path)', async ({ page, context }) => {
    // Step 1: Submit a schedule change request that requires multi-level approval
    // Note: Assuming request is already submitted and in the system
    // For this test, we'll verify the multi-level routing process

    // First-level approver login
    await page.fill('[data-testid="username-input"]', firstLevelApprover.username);
    await page.fill('[data-testid="password-input"]', firstLevelApprover.password);
    await page.click('[data-testid="login-button"]');

    // Expected Result: Request routed to first-level approver
    await expect(page.locator('[data-testid="pending-approvals-dashboard"]')).toBeVisible();
    
    const pendingRequestsList = page.locator('[data-testid="pending-requests-list"]');
    const multiLevelRequest = pendingRequestsList.locator('[data-testid="request-item"]').filter({ hasText: 'Multi-level' }).first();
    
    // If no specific multi-level indicator, use first request
    const requestToApprove = await multiLevelRequest.count() > 0 ? multiLevelRequest : pendingRequestsList.locator('[data-testid="request-item"]').first();
    await requestToApprove.click();

    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    
    // Verify multi-level approval indicator
    const approvalLevelIndicator = page.locator('[data-testid="approval-level-indicator"]');
    await expect(approvalLevelIndicator).toContainText('Level 1');

    // Step 2: First-level approver approves request
    await page.fill('[data-testid="approval-comments-input"]', 'First-level approval granted - request meets initial criteria and resource availability.');
    await page.click('[data-testid="approve-button"]');

    // Expected Result: Request routed to second-level approver
    await expect(page.locator('[data-testid="approval-confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-confirmation-message"]')).toContainText('approved');
    
    // Verify status shows pending second-level approval
    const statusAfterFirstApproval = page.locator('[data-testid="request-status-badge"]');
    await expect(statusAfterFirstApproval).toContainText('Pending Level 2 Approval');

    // Logout first-level approver
    await page.click('[data-testid="user-menu-button"]');
    await page.click('[data-testid="logout-button"]');

    // Step 3: Log in as second-level approver
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', secondLevelApprover.username);
    await page.fill('[data-testid="password-input"]', secondLevelApprover.password);
    await page.click('[data-testid="login-button"]');

    await expect(page.locator('[data-testid="pending-approvals-dashboard"]')).toBeVisible();

    // Navigate to pending approvals and select the request
    const level2PendingList = page.locator('[data-testid="pending-requests-list"]');
    const level2Request = level2PendingList.locator('[data-testid="request-item"]').first();
    await level2Request.click();

    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    
    // Verify approval level indicator shows Level 2
    await expect(page.locator('[data-testid="approval-level-indicator"]')).toContainText('Level 2');
    
    // Review first-level approval details
    const approvalHistorySection = page.locator('[data-testid="approval-history-section"]');
    await expect(approvalHistorySection).toBeVisible();
    await expect(approvalHistorySection).toContainText('Level 1');
    await expect(approvalHistorySection).toContainText(firstLevelApprover.username);

    // Enter approval comments and approve
    await page.fill('[data-testid="approval-comments-input"]', 'Second-level approval granted - final authorization confirmed after reviewing all details and first-level approval.');
    await page.click('[data-testid="approve-button"]');

    // Expected Result: Request status updated to approved
    await expect(page.locator('[data-testid="approval-confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-confirmation-message"]')).toContainText('approved');
    
    // Verify final status is Approved
    const finalStatus = page.locator('[data-testid="request-status-badge"]');
    await expect(finalStatus).toContainText('Approved');
    await expect(finalStatus).not.toContainText('Pending');
    
    // Verify audit trail shows both approvals
    await expect(approvalHistorySection).toContainText('Level 2');
    await expect(approvalHistorySection).toContainText(secondLevelApprover.username);
  });
});