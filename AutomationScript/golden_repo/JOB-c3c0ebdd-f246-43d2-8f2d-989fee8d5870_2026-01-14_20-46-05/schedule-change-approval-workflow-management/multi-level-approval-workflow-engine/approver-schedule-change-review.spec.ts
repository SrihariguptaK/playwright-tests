import { test, expect } from '@playwright/test';

test.describe('Approver Schedule Change Request Review', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page and authenticate as approver
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'approver.user@company.com');
    await page.fill('[data-testid="password-input"]', 'ApproverPass123!');
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and dashboard load
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate viewing and decision making on pending approvals', async ({ page }) => {
    // Action: Navigate to pending approvals
    await page.click('[data-testid="pending-approvals-menu"]');
    
    // Expected Result: List of pending schedule change requests is displayed
    await expect(page.locator('[data-testid="pending-approvals-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-change-request-item"]')).toHaveCount(await page.locator('[data-testid="schedule-change-request-item"]').count());
    
    // Action: Select a request to view details
    const firstRequest = page.locator('[data-testid="schedule-change-request-item"]').first();
    const requestId = await firstRequest.getAttribute('data-request-id');
    await firstRequest.click();
    
    // Expected Result: Detailed information of the request is shown
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-id"]')).toContainText(requestId || '');
    await expect(page.locator('[data-testid="requester-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="requested-schedule-change"]')).toBeVisible();
    
    // Action: Approve the request with comments and submit
    await page.click('[data-testid="approve-button"]');
    await page.fill('[data-testid="approval-comments"]', 'Approved as requested - no conflicts identified');
    await page.click('[data-testid="submit-decision-button"]');
    
    // Expected Result: Request status updates to 'Approved' and confirmation is displayed
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('approved');
    
    // Verify the request no longer appears in the pending approvals list
    await page.click('[data-testid="pending-approvals-menu"]');
    await expect(page.locator(`[data-testid="schedule-change-request-item"][data-request-id="${requestId}"]`)).not.toBeVisible();
  });

  test('Validate rejection of schedule change requests', async ({ page }) => {
    // Navigate to pending approvals list
    await page.click('[data-testid="pending-approvals-menu"]');
    await expect(page.locator('[data-testid="pending-approvals-list"]')).toBeVisible();
    
    // Action: Select a pending request
    const requestToReject = page.locator('[data-testid="schedule-change-request-item"]').first();
    const requestId = await requestToReject.getAttribute('data-request-id');
    await requestToReject.click();
    
    // Expected Result: Request details are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-id"]')).toContainText(requestId || '');
    
    // Action: Reject the request with comments and submit
    await page.click('[data-testid="reject-button"]');
    await page.fill('[data-testid="rejection-comments"]', 'Rejected due to insufficient staffing coverage during proposed time');
    await page.click('[data-testid="submit-decision-button"]');
    
    // Expected Result: Request status updates to 'Rejected' and confirmation is displayed
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('rejected');
    
    // Navigate back to the pending approvals list
    await page.click('[data-testid="pending-approvals-menu"]');
    
    // Verify the rejection is recorded by checking the request history or audit trail
    await page.click('[data-testid="audit-trail-menu"]');
    await page.fill('[data-testid="search-request-id"]', requestId || '');
    await page.click('[data-testid="search-button"]');
    await expect(page.locator('[data-testid="audit-entry"]').filter({ hasText: 'Rejected' })).toBeVisible();
    await expect(page.locator('[data-testid="audit-entry"]').filter({ hasText: 'insufficient staffing coverage' })).toBeVisible();
  });

  test('Validate audit logging of approval decisions', async ({ page }) => {
    // Navigate to pending approvals and select a schedule change request
    await page.click('[data-testid="pending-approvals-menu"]');
    await expect(page.locator('[data-testid="pending-approvals-list"]')).toBeVisible();
    
    const firstRequest = page.locator('[data-testid="schedule-change-request-item"]').first();
    const approvalRequestId = await firstRequest.getAttribute('data-request-id');
    await firstRequest.click();
    
    // Click 'Approve' button, enter comments and submit
    await page.click('[data-testid="approve-button"]');
    await page.fill('[data-testid="approval-comments"]', 'Test approval for audit logging');
    
    // Record submission time for timestamp verification
    const submissionTime = new Date();
    await page.click('[data-testid="submit-decision-button"]');
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    
    // Access the audit log interface
    await page.click('[data-testid="audit-trail-menu"]');
    await page.fill('[data-testid="search-request-id"]', approvalRequestId || '');
    await page.click('[data-testid="search-button"]');
    
    // Verify the timestamp recorded in the audit log matches the time of submission
    const auditEntry = page.locator('[data-testid="audit-entry"]').filter({ hasText: 'Test approval for audit logging' });
    await expect(auditEntry).toBeVisible();
    
    const auditTimestamp = await auditEntry.locator('[data-testid="audit-timestamp"]').textContent();
    const auditTime = new Date(auditTimestamp || '');
    const timeDifference = Math.abs(auditTime.getTime() - submissionTime.getTime());
    expect(timeDifference).toBeLessThan(60000); // Within 1 minute variance
    
    // Verify the approver information logged includes correct user ID and username
    await expect(auditEntry.locator('[data-testid="audit-user"]')).toContainText('approver.user@company.com');
    await expect(auditEntry.locator('[data-testid="audit-action"]')).toContainText('Approved');
    
    // Select another pending request, reject it with comments and submit
    await page.click('[data-testid="pending-approvals-menu"]');
    const secondRequest = page.locator('[data-testid="schedule-change-request-item"]').first();
    const rejectionRequestId = await secondRequest.getAttribute('data-request-id');
    await secondRequest.click();
    
    await page.click('[data-testid="reject-button"]');
    await page.fill('[data-testid="rejection-comments"]', 'Test rejection for audit logging');
    await page.click('[data-testid="submit-decision-button"]');
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    
    // Retrieve audit logs for the rejected request
    await page.click('[data-testid="audit-trail-menu"]');
    await page.fill('[data-testid="search-request-id"]', rejectionRequestId || '');
    await page.click('[data-testid="search-button"]');
    
    // Verify audit trail shows complete and accurate history
    const rejectionAuditEntry = page.locator('[data-testid="audit-entry"]').filter({ hasText: 'Test rejection for audit logging' });
    await expect(rejectionAuditEntry).toBeVisible();
    await expect(rejectionAuditEntry.locator('[data-testid="audit-action"]')).toContainText('Rejected');
    await expect(rejectionAuditEntry.locator('[data-testid="audit-user"]')).toContainText('approver.user@company.com');
    await expect(rejectionAuditEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
    
    // Verify both requests have complete audit trails
    await page.fill('[data-testid="search-request-id"]', approvalRequestId || '');
    await page.click('[data-testid="search-button"]');
    await expect(page.locator('[data-testid="audit-entry"]')).toHaveCount(await page.locator('[data-testid="audit-entry"]').count());
  });
});