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
    await page.goto('/schedule-changes/pending');
    await page.click('[data-testid="pending-requests-list"] >> text=Pending Request');
    
    // Expected Result: Request details are displayed
    await expect(page.locator('[data-testid="request-details-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Pending');
    
    // Step 2: Click approve and submit
    await page.fill('[data-testid="approval-comments"]', 'Approved - schedule change is justified');
    await page.click('[data-testid="approve-button"]');
    
    // Handle confirmation dialog if present
    page.on('dialog', dialog => dialog.accept());
    
    // Expected Result: Request status updates to approved and confirmation is shown
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Approved', { timeout: 10000 });
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('successfully approved');
    
    // Step 3: Verify audit log entry for approval action
    await page.goto('/admin/audit-logs');
    await page.fill('[data-testid="audit-search-input"]', 'schedule change approval');
    await page.click('[data-testid="audit-search-button"]');
    
    // Expected Result: Audit log contains user, timestamp, and action details
    const auditEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditEntry).toBeVisible();
    await expect(auditEntry.locator('[data-testid="audit-user"]')).toContainText('approver@company.com');
    await expect(auditEntry.locator('[data-testid="audit-action"]')).toContainText('Approved');
    await expect(auditEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
  });

  test('Verify rejection requires comments', async ({ page }) => {
    // Step 1: Open a pending schedule change request as Approver
    await page.goto('/schedule-changes/pending');
    await page.click('[data-testid="pending-requests-list"] >> text=Pending Request');
    
    // Expected Result: Request details are displayed
    await expect(page.locator('[data-testid="request-details-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Pending');
    
    // Step 2: Click reject without entering comments
    await page.click('[data-testid="reject-button"]');
    
    // Expected Result: System prevents submission and displays error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Comments are required');
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Pending');
    
    // Step 3: Enter rejection comments and submit
    await page.fill('[data-testid="approval-comments"]', 'Insufficient justification provided for schedule change');
    await page.click('[data-testid="reject-button"]');
    
    // Handle confirmation dialog if present
    page.on('dialog', dialog => dialog.accept());
    
    // Expected Result: Request status updates to rejected and audit log is created
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Rejected', { timeout: 10000 });
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('rejected');
    
    // Verify audit log entry
    await page.goto('/admin/audit-logs');
    await page.fill('[data-testid="audit-search-input"]', 'schedule change rejection');
    await page.click('[data-testid="audit-search-button"]');
    
    const auditEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditEntry).toBeVisible();
    await expect(auditEntry.locator('[data-testid="audit-action"]')).toContainText('Rejected');
    await expect(auditEntry.locator('[data-testid="audit-comments"]')).toContainText('Insufficient justification');
  });

  test('Ensure unauthorized users cannot approve requests', async ({ page, request }) => {
    // Logout approver and login as regular employee
    await page.goto('/logout');
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Step 1: Log in as a user without approval permissions
    await page.goto('/schedule-changes/pending');
    
    // Expected Result: Approval actions are not visible or accessible
    const requestDetails = page.locator('[data-testid="request-details-container"]');
    if (await requestDetails.isVisible()) {
      await expect(page.locator('[data-testid="approve-button"]')).not.toBeVisible();
      await expect(page.locator('[data-testid="reject-button"]')).not.toBeVisible();
    } else {
      await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    }
    
    // Step 2: Attempt to access approval API endpoint directly
    const response = await request.post('/api/schedule-changes/123/approval', {
      data: {
        action: 'approve',
        comments: 'Unauthorized approval attempt'
      }
    });
    
    // Expected Result: Access is denied with appropriate error
    expect(response.status()).toBe(403);
    const responseBody = await response.json();
    expect(responseBody.error).toContain('Unauthorized');
    
    // Step 3: Verify no approval actions are logged for unauthorized attempts
    // Login back as approver to check audit logs
    await page.goto('/logout');
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'approver@company.com');
    await page.fill('[data-testid="password-input"]', 'ApproverPass123');
    await page.click('[data-testid="login-button"]');
    
    await page.goto('/admin/audit-logs');
    await page.fill('[data-testid="audit-search-input"]', 'employee@company.com approval');
    await page.click('[data-testid="audit-search-button"]');
    
    // Expected Result: No audit entries exist for unauthorized actions
    const noResultsMessage = page.locator('[data-testid="no-audit-results"]');
    const auditEntries = page.locator('[data-testid="audit-log-entry"]');
    
    const hasNoResults = await noResultsMessage.isVisible();
    const entryCount = await auditEntries.count();
    
    if (!hasNoResults && entryCount > 0) {
      // If entries exist, verify none are approval actions from unauthorized user
      for (let i = 0; i < entryCount; i++) {
        const entry = auditEntries.nth(i);
        const action = await entry.locator('[data-testid="audit-action"]').textContent();
        expect(action).not.toContain('Approved');
        expect(action).not.toContain('Rejected');
      }
    } else {
      await expect(noResultsMessage).toBeVisible();
    }
  });
});