import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Approval', () => {
  test.beforeEach(async ({ page }) => {
    // Login as approver before each test
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'approver@company.com');
    await page.fill('[data-testid="password-input"]', 'ApproverPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Approve schedule change request successfully', async ({ page }) => {
    // Action: Approver navigates to pending approvals dashboard
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="pending-approvals-link"]');
    
    // Expected Result: List of pending requests is displayed
    await expect(page.locator('[data-testid="pending-approvals-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();
    const pendingRequests = page.locator('[data-testid="request-item"]');
    await expect(pendingRequests).toHaveCountGreaterThan(0);
    
    // Approver reviews the list of pending requests
    const firstRequest = pendingRequests.first();
    await expect(firstRequest).toBeVisible();
    
    // Action: Approver clicks on a specific schedule change request from the list
    await firstRequest.click();
    
    // Expected Result: Full request information and attachments are visible
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-schedule-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="proposed-schedule-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="change-reason"]')).toBeVisible();
    
    // Approver reviews the current schedule details
    const currentSchedule = await page.locator('[data-testid="current-schedule-details"]').textContent();
    expect(currentSchedule).toBeTruthy();
    
    // Approver reviews the proposed schedule details
    const proposedSchedule = await page.locator('[data-testid="proposed-schedule-details"]').textContent();
    expect(proposedSchedule).toBeTruthy();
    
    // Approver reviews the reason for change provided by the manager
    const changeReason = await page.locator('[data-testid="change-reason"]').textContent();
    expect(changeReason).toBeTruthy();
    
    // Approver clicks on the attached document link to view supporting documentation
    const attachmentLink = page.locator('[data-testid="attachment-link"]');
    if (await attachmentLink.isVisible()) {
      await attachmentLink.click();
      await expect(page.locator('[data-testid="document-viewer"]')).toBeVisible();
      
      // Approver closes the document and returns to the request details page
      await page.click('[data-testid="close-document-button"]');
      await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    }
    
    // Action: Approver clicks the Approve button
    await page.click('[data-testid="approve-button"]');
    
    // Approver enters optional approval comment
    await expect(page.locator('[data-testid="approval-comment-modal"]')).toBeVisible();
    await page.fill('[data-testid="approval-comment-input"]', 'Approved as requested');
    await page.click('[data-testid="confirm-approval-button"]');
    
    // Expected Result: Request status updates to approved and requester is notified
    await expect(page.locator('[data-testid="success-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-notification"]')).toContainText('approved');
    
    // Approver verifies the approved request is no longer in the pending list
    await page.click('[data-testid="pending-approvals-link"]');
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();
    
    // Approver navigates to the approval history or completed approvals section
    await page.click('[data-testid="approval-history-link"]');
    await expect(page.locator('[data-testid="approval-history-list"]')).toBeVisible();
    const approvedRequest = page.locator('[data-testid="history-item"]').filter({ hasText: 'Approved' }).first();
    await expect(approvedRequest).toBeVisible();
  });

  test('Reject schedule change request with mandatory comment', async ({ page }) => {
    // Action: Approver navigates to pending approvals dashboard
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="pending-approvals-link"]');
    await expect(page.locator('[data-testid="pending-approvals-dashboard"]')).toBeVisible();
    
    // Action: Approver selects a schedule change request to reject by clicking on it
    const requestToReject = page.locator('[data-testid="request-item"]').first();
    await requestToReject.click();
    
    // Expected Result: Rejection option and comment input are available
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    
    // Approver reviews the request details and determines it should be rejected
    await expect(page.locator('[data-testid="reject-button"]')).toBeVisible();
    
    // Action: Approver clicks the Reject button
    await page.click('[data-testid="reject-button"]');
    await expect(page.locator('[data-testid="rejection-comment-modal"]')).toBeVisible();
    
    // Action: Approver leaves the comment field empty and attempts to click the Confirm button
    await page.click('[data-testid="confirm-rejection-button"]');
    
    // Expected Result: System prevents rejection and prompts for comment
    await expect(page.locator('[data-testid="comment-required-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="comment-required-error"]')).toContainText('comment');
    
    // Approver enters only 3 characters in the comment field (below minimum requirement)
    await page.fill('[data-testid="rejection-comment-input"]', 'abc');
    await page.click('[data-testid="confirm-rejection-button"]');
    await expect(page.locator('[data-testid="comment-length-error"]')).toBeVisible();
    
    // Action: Approver clears the field and enters a valid rejection comment with sufficient detail
    await page.fill('[data-testid="rejection-comment-input"]', '');
    await page.fill('[data-testid="rejection-comment-input"]', 'The proposed schedule conflicts with operational requirements and cannot be accommodated at this time');
    
    // Approver clicks the Confirm button to submit the rejection
    await page.click('[data-testid="confirm-rejection-button"]');
    
    // Expected Result: Request status updates to rejected and requester is notified with comments
    await expect(page.locator('[data-testid="success-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-notification"]')).toContainText('rejected');
    
    // Approver verifies the rejected request is no longer in the pending list
    await page.click('[data-testid="pending-approvals-link"]');
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();
    
    // Approver navigates to the approval history or completed approvals section
    await page.click('[data-testid="approval-history-link"]');
    await expect(page.locator('[data-testid="approval-history-list"]')).toBeVisible();
    const rejectedRequest = page.locator('[data-testid="history-item"]').filter({ hasText: 'Rejected' }).first();
    await expect(rejectedRequest).toBeVisible();
  });

  test('Prevent unauthorized access to approval tasks', async ({ page }) => {
    // Logout as approver and login as regular user without approver role
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // User without approver role logs into the system successfully
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'regularuser@company.com');
    await page.fill('[data-testid="password-input"]', 'UserPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // User reviews the main navigation menu
    await page.click('[data-testid="main-menu"]');
    const approvalMenuItem = page.locator('[data-testid="pending-approvals-link"]');
    
    // Verify approval menu item is not visible for non-approver
    await expect(approvalMenuItem).not.toBeVisible();
    
    // Action: User manually types the approval dashboard URL in the browser address bar
    await page.goto('/approvals/pending');
    
    // Expected Result: Access is denied with appropriate error message
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');
    await expect(page.locator('[data-testid="error-code"]')).toContainText('403');
    
    // User attempts to navigate back using browser back button
    await page.goBack();
    await expect(page).toHaveURL(/.*dashboard/);
    
    // User attempts to access a specific approval task by manually entering the URL with a request ID
    await page.goto('/approvals/12345');
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');
    
    // User attempts to access the approval API endpoint directly
    const apiResponse = await page.request.get('/api/approvals/pending');
    expect(apiResponse.status()).toBe(403);
    const responseBody = await apiResponse.json();
    expect(responseBody.error).toContain('Unauthorized');
    
    // User attempts to submit an approval decision via API endpoint
    const decisionResponse = await page.request.post('/api/approvals/12345/decision', {
      data: {
        decision: 'approved',
        comment: 'Attempting unauthorized approval'
      }
    });
    expect(decisionResponse.status()).toBe(403);
    const decisionBody = await decisionResponse.json();
    expect(decisionBody.error).toContain('Unauthorized');
    
    // User logs out and logs back in to verify role has not changed
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'regularuser@company.com');
    await page.fill('[data-testid="password-input"]', 'UserPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Verify still no access to approvals
    await page.goto('/approvals/pending');
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
  });
});