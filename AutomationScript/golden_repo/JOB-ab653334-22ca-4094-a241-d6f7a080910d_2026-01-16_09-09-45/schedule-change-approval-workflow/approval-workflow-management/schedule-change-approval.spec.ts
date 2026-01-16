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

  test('Validate approval of schedule change request', async ({ page }) => {
    // Step 1: Open a pending schedule change request as Approver
    await page.goto('/approver/dashboard');
    await page.waitForSelector('[data-testid="schedule-change-requests-list"]');
    
    const firstPendingRequest = page.locator('[data-testid="schedule-change-request-item"]').filter({ hasText: 'Pending' }).first();
    await expect(firstPendingRequest).toBeVisible();
    
    const requestId = await firstPendingRequest.getAttribute('data-request-id');
    await firstPendingRequest.click();
    
    // Expected Result: Request details are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Pending');
    
    // Step 2: Click approve and submit
    await page.click('[data-testid="approve-button"]');
    
    // Handle confirmation dialog if present
    const confirmDialog = page.locator('[data-testid="confirmation-dialog"]');
    if (await confirmDialog.isVisible()) {
      await page.click('[data-testid="confirm-button"]');
    }
    
    // Expected Result: Request status updates to approved and confirmation is shown
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('approved');
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Approved');
    
    // Step 3: Verify audit log entry for approval action
    await page.goto('/admin/audit-log');
    await page.fill('[data-testid="audit-search-input"]', requestId || '');
    await page.click('[data-testid="audit-search-button"]');
    
    // Expected Result: Audit log contains user, timestamp, and action details
    const auditEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditEntry).toBeVisible();
    await expect(auditEntry).toContainText('approver@company.com');
    await expect(auditEntry).toContainText('Approved');
    await expect(auditEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
  });

  test('Verify rejection requires comments', async ({ page }) => {
    // Step 1: Open a pending schedule change request as Approver
    await page.goto('/approver/dashboard');
    await page.waitForSelector('[data-testid="schedule-change-requests-list"]');
    
    const firstPendingRequest = page.locator('[data-testid="schedule-change-request-item"]').filter({ hasText: 'Pending' }).first();
    await expect(firstPendingRequest).toBeVisible();
    await firstPendingRequest.click();
    
    // Expected Result: Request details are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    
    // Step 2: Click reject without entering comments
    await page.click('[data-testid="reject-button"]');
    
    // Attempt to submit without comments
    const submitButton = page.locator('[data-testid="submit-rejection-button"]');
    if (await submitButton.isVisible()) {
      await submitButton.click();
    }
    
    // Expected Result: System prevents submission and displays error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/comment|required/i);
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Pending');
    
    // Step 3: Enter rejection comments and submit
    await page.fill('[data-testid="comments-input"]', 'This schedule change conflicts with project deadlines and resource availability');
    await page.click('[data-testid="submit-rejection-button"]');
    
    // Handle confirmation if present
    const confirmDialog = page.locator('[data-testid="confirmation-dialog"]');
    if (await confirmDialog.isVisible()) {
      await page.click('[data-testid="confirm-button"]');
    }
    
    // Expected Result: Request status updates to rejected and audit log is created
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Rejected');
  });

  test('Ensure unauthorized users cannot approve requests', async ({ page, request }) => {
    // Logout approver and login as unauthorized user
    await page.goto('/logout');
    
    // Step 1: Log in as a user without approval permissions
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to a schedule change request
    await page.goto('/schedule-changes');
    
    // Expected Result: Approval actions are not visible or accessible
    const approveButton = page.locator('[data-testid="approve-button"]');
    const rejectButton = page.locator('[data-testid="reject-button"]');
    
    await expect(approveButton).not.toBeVisible();
    await expect(rejectButton).not.toBeVisible();
    
    // Step 2: Attempt to access approval API endpoint directly
    const validRequestId = '12345';
    const apiResponse = await request.post(`/api/schedule-changes/${validRequestId}/approval`, {
      data: {
        action: 'approve',
        comments: 'Unauthorized approval attempt'
      },
      failOnStatusCode: false
    });
    
    // Expected Result: Access is denied with appropriate error
    expect(apiResponse.status()).toBe(403);
    const responseBody = await apiResponse.json();
    expect(responseBody.error).toMatch(/unauthorized|forbidden|access denied/i);
    
    // Step 3: Verify no approval actions are logged for unauthorized attempts
    // Logout and login as admin to check audit logs
    await page.goto('/logout');
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123');
    await page.click('[data-testid="login-button"]');
    
    await page.goto('/admin/audit-log');
    await page.fill('[data-testid="audit-search-input"]', 'employee@company.com');
    await page.click('[data-testid="audit-search-button"]');
    
    // Expected Result: No audit entries exist for unauthorized actions
    const approvalAuditEntries = page.locator('[data-testid="audit-log-entry"]').filter({ hasText: /approve|reject/i });
    await expect(approvalAuditEntries).toHaveCount(0);
  });
});