import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Approval', () => {
  let requestId: string;

  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as approver
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'approver@example.com');
    await page.fill('[data-testid="password-input"]', 'approver123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Approve schedule change request successfully', async ({ page }) => {
    // Step 1: Navigate to the pending requests dashboard and select a specific pending schedule change request to view
    await page.goto('/pending-requests');
    await page.waitForSelector('[data-testid="pending-requests-table"]');
    
    // Select the first pending request
    const firstRequest = page.locator('[data-testid="request-row"]').first();
    requestId = await firstRequest.getAttribute('data-request-id') || 'REQ-001';
    await firstRequest.click();
    
    // Expected Result: Request details and attachments are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-id"]')).toContainText(requestId);
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Pending');
    
    // Verify attachments section is present
    const attachmentsSection = page.locator('[data-testid="attachments-section"]');
    await expect(attachmentsSection).toBeVisible();
    
    // Step 2: Review the request details and click the 'Approve' button
    await page.click('[data-testid="approve-button"]');
    
    // Wait for the approval to be processed
    await page.waitForResponse(response => 
      response.url().includes(`/api/schedule-change-requests/${requestId}/approve`) && 
      response.status() === 200
    );
    
    // Expected Result: Request status updated to 'Approved', confirmation displayed
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('approved successfully');
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Approved');
    
    // Step 3: Navigate to the audit logs section to verify the approval action was logged
    await page.goto('/audit-logs');
    await page.waitForSelector('[data-testid="audit-logs-table"]');
    
    // Filter by request ID
    await page.fill('[data-testid="search-request-id"]', requestId);
    await page.click('[data-testid="search-button"]');
    
    // Expected Result: Audit log contains approval action with timestamp and approver info
    const auditLogEntry = page.locator(`[data-testid="audit-log-entry"][data-request-id="${requestId}"]`).first();
    await expect(auditLogEntry).toBeVisible();
    await expect(auditLogEntry.locator('[data-testid="action-type"]')).toContainText('Approved');
    await expect(auditLogEntry.locator('[data-testid="approver-name"]')).toContainText('approver@example.com');
    await expect(auditLogEntry.locator('[data-testid="timestamp"]')).not.toBeEmpty();
  });

  test('Reject schedule change request with mandatory comments', async ({ page }) => {
    // Step 1: Navigate to the pending requests dashboard and select a specific pending schedule change request to view
    await page.goto('/pending-requests');
    await page.waitForSelector('[data-testid="pending-requests-table"]');
    
    // Select the first pending request
    const firstRequest = page.locator('[data-testid="request-row"]').first();
    requestId = await firstRequest.getAttribute('data-request-id') || 'REQ-002';
    await firstRequest.click();
    
    // Expected Result: Request details and attachments are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-id"]')).toContainText(requestId);
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Pending');
    
    // Step 2: Click the 'Reject' button without entering any comments in the rejection comments field
    await page.click('[data-testid="reject-button"]');
    
    // Wait for rejection modal or form to appear
    await expect(page.locator('[data-testid="rejection-modal"]')).toBeVisible();
    
    // Attempt to submit without comments
    await page.click('[data-testid="submit-rejection-button"]');
    
    // Expected Result: Validation error prompts for mandatory comments
    await expect(page.locator('[data-testid="comments-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="comments-error"]')).toContainText('mandatory');
    
    // Step 3: Enter meaningful rejection comments and click the 'Reject' or 'Submit' button
    await page.fill('[data-testid="rejection-comments"]', 'Request conflicts with operational requirements');
    await page.click('[data-testid="submit-rejection-button"]');
    
    // Wait for the rejection to be processed
    await page.waitForResponse(response => 
      response.url().includes(`/api/schedule-change-requests/${requestId}/reject`) && 
      response.status() === 200
    );
    
    // Expected Result: Request status updated to 'Rejected', confirmation displayed
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('rejected successfully');
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Rejected');
  });

  test('Verify audit logging of approval actions', async ({ page }) => {
    // Step 1: Select a pending schedule change request and approve it
    await page.goto('/pending-requests');
    await page.waitForSelector('[data-testid="pending-requests-table"]');
    
    const firstRequest = page.locator('[data-testid="request-row"]').first();
    requestId = await firstRequest.getAttribute('data-request-id') || 'REQ-003';
    await firstRequest.click();
    
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    
    // Approve the request
    await page.click('[data-testid="approve-button"]');
    
    // Wait for approval to be processed
    await page.waitForResponse(response => 
      response.url().includes(`/api/schedule-change-requests/${requestId}/approve`) && 
      response.status() === 200
    );
    
    // Expected Result: Action is processed successfully
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    
    // Step 2: Navigate to the audit logs interface to retrieve audit records
    await page.goto('/audit-logs');
    await page.waitForSelector('[data-testid="audit-logs-table"]');
    
    // Query the audit logs using the request ID
    await page.fill('[data-testid="search-request-id"]', requestId);
    await page.click('[data-testid="search-button"]');
    
    await page.waitForTimeout(1000); // Allow search to complete
    
    // Expected Result: Audit log contains accurate record of the action
    const auditLogEntry = page.locator(`[data-testid="audit-log-entry"][data-request-id="${requestId}"]`).first();
    await expect(auditLogEntry).toBeVisible();
    
    // Verify audit log details
    await expect(auditLogEntry.locator('[data-testid="request-id"]')).toContainText(requestId);
    await expect(auditLogEntry.locator('[data-testid="action-type"]')).toContainText('Approved');
    await expect(auditLogEntry.locator('[data-testid="approver-name"]')).toContainText('approver@example.com');
    
    // Verify timestamp is present and recent
    const timestamp = await auditLogEntry.locator('[data-testid="timestamp"]').textContent();
    expect(timestamp).toBeTruthy();
    expect(timestamp?.length).toBeGreaterThan(0);
    
    // Verify action was logged within the last few minutes
    const loggedTime = new Date(timestamp || '');
    const currentTime = new Date();
    const timeDifferenceMinutes = (currentTime.getTime() - loggedTime.getTime()) / (1000 * 60);
    expect(timeDifferenceMinutes).toBeLessThan(5);
  });
});