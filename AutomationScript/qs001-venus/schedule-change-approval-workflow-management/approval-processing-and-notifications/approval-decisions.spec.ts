import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Approval Decisions', () => {
  test.beforeEach(async ({ page }) => {
    // Login as approver user
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'approver@hospital.com');
    await page.fill('[data-testid="password-input"]', 'ApproverPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate approval decision submission with comments', async ({ page }) => {
    // Step 1: Approver navigates to pending approval request
    await page.click('[data-testid="pending-approvals-menu"]');
    await expect(page).toHaveURL(/.*pending-approvals/);
    
    // Locate and click on specific schedule change request
    await page.click('[data-testid="request-item-12345"]');
    await expect(page.locator('[data-testid="request-details-container"]')).toBeVisible();
    
    // Verify request details are displayed
    await expect(page.locator('[data-testid="request-id"]')).toContainText('12345');
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Pending');
    await expect(page.locator('[data-testid="requester-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="requested-changes"]')).toBeVisible();
    
    // Step 2: Approver selects reject and enters comments
    await page.click('[data-testid="reject-button"]');
    await expect(page.locator('[data-testid="comment-input"]')).toBeVisible();
    
    const rejectionComment = 'Request conflicts with existing coverage requirements for the emergency department. Please coordinate with shift supervisor before resubmitting.';
    await page.fill('[data-testid="comment-input"]', rejectionComment);
    
    // Verify comment input accepts text
    await expect(page.locator('[data-testid="comment-input"]')).toHaveValue(rejectionComment);
    
    // Review entered comments
    const enteredComment = await page.locator('[data-testid="comment-input"]').inputValue();
    expect(enteredComment).toBe(rejectionComment);
    
    // Step 3: Approver submits decision
    await page.click('[data-testid="submit-decision-button"]');
    
    // Confirm decision in confirmation dialog
    await expect(page.locator('[data-testid="confirmation-dialog"]')).toBeVisible();
    await page.click('[data-testid="confirm-decision-button"]');
    
    // Wait for submission to complete
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });
    
    // Verify request status updates to rejected
    await page.click('[data-testid="pending-approvals-menu"]');
    await page.reload();
    
    // Check that request is no longer in pending list or status is updated
    await page.click('[data-testid="rejected-requests-tab"]');
    await expect(page.locator('[data-testid="request-item-12345"]')).toBeVisible();
    await page.click('[data-testid="request-item-12345"]');
    
    // Verify status is rejected
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Rejected');
    
    // Navigate to history/audit trail
    await page.click('[data-testid="audit-trail-tab"]');
    await expect(page.locator('[data-testid="audit-entry"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="audit-entry"]').first()).toContainText('Rejected');
    await expect(page.locator('[data-testid="audit-entry"]').first()).toContainText(rejectionComment);
    await expect(page.locator('[data-testid="audit-entry"]').first()).toContainText('approver@hospital.com');
  });

  test('Verify rejection is blocked without comments', async ({ page }) => {
    // Navigate to pending schedule change request details page
    await page.click('[data-testid="pending-approvals-menu"]');
    await page.click('[data-testid="request-item-12346"]');
    await expect(page.locator('[data-testid="request-details-container"]')).toBeVisible();
    
    // Step 1: Approver clicks reject button
    await page.click('[data-testid="reject-button"]');
    await expect(page.locator('[data-testid="comment-input"]')).toBeVisible();
    
    // Step 2: Leave comment field empty and attempt to submit
    await page.locator('[data-testid="comment-input"]').clear();
    await page.click('[data-testid="submit-decision-button"]');
    
    // Verify validation error prevents submission
    await expect(page.locator('[data-testid="comment-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="comment-error"]')).toContainText('Comment is required');
    
    // Verify comment field is highlighted
    await expect(page.locator('[data-testid="comment-input"]')).toHaveClass(/error|invalid/);
    
    // Verify request status has not changed
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Pending');
    
    // Test with whitespace only
    await page.fill('[data-testid="comment-input"]', '   \t  ');
    await page.click('[data-testid="submit-decision-button"]');
    
    // Verify validation error still appears
    await expect(page.locator('[data-testid="comment-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="comment-error"]')).toContainText(/Comment is required|Comment cannot be empty/);
    
    // Test with very short comment (1-2 characters)
    await page.fill('[data-testid="comment-input"]', 'No');
    await page.click('[data-testid="submit-decision-button"]');
    
    // Verify validation error for minimum length
    await expect(page.locator('[data-testid="comment-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="comment-error"]')).toContainText(/minimum|at least/);
    
    // Verify status still pending
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Pending');
    
    // Verify no audit trail entry was created
    await page.click('[data-testid="audit-trail-tab"]');
    const auditEntries = await page.locator('[data-testid="audit-entry"]').count();
    // Should have no new entries or only original creation entry
    expect(auditEntries).toBeLessThanOrEqual(1);
  });

  test('Ensure unauthorized users cannot approve or reject requests', async ({ page }) => {
    // Logout as approver and login as non-approver user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Login as viewer role user
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'viewer@hospital.com');
    await page.fill('[data-testid="password-input"]', 'ViewerPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Step 1: Verify Pending Approvals menu is not visible or disabled
    const pendingApprovalsMenu = page.locator('[data-testid="pending-approvals-menu"]');
    await expect(pendingApprovalsMenu).not.toBeVisible().catch(async () => {
      // If visible, check if disabled
      await expect(pendingApprovalsMenu).toBeDisabled();
    });
    
    // Step 2: Attempt to access approval request details page via direct URL
    await page.goto('/approvals/request/12345');
    
    // Verify access is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/Access Denied|Unauthorized|403/);
    
    // Verify user is redirected or shown error page
    const currentUrl = page.url();
    expect(currentUrl).toMatch(/access-denied|unauthorized|403|dashboard/);
    
    // Step 3: Attempt to access approval decision UI directly
    await page.goto('/approvals/decision/12345');
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    
    // Step 4: Attempt API call with unauthorized token
    const response = await page.request.put('/api/approval-decisions', {
      data: {
        requestId: '12345',
        decision: 'rejected',
        comments: 'Unauthorized rejection attempt'
      },
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('authToken'))}`
      }
    });
    
    // Verify API returns 403 Forbidden
    expect(response.status()).toBe(403);
    
    const responseBody = await response.json();
    expect(responseBody.error).toMatch(/unauthorized|forbidden|access denied/i);
    
    // Verify request payload is rejected
    expect(responseBody.success).toBe(false);
    
    // Navigate back to check request status unchanged
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'approver@hospital.com');
    await page.fill('[data-testid="password-input"]', 'ApproverPass123!');
    await page.click('[data-testid="login-button"]');
    
    await page.click('[data-testid="pending-approvals-menu"]');
    await page.click('[data-testid="request-item-12345"]');
    
    // Verify status is still pending (unchanged)
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Pending');
    
    // Verify no unauthorized audit trail entry exists
    await page.click('[data-testid="audit-trail-tab"]');
    const auditEntries = page.locator('[data-testid="audit-entry"]');
    const auditCount = await auditEntries.count();
    
    for (let i = 0; i < auditCount; i++) {
      const entryText = await auditEntries.nth(i).textContent();
      expect(entryText).not.toContain('viewer@hospital.com');
      expect(entryText).not.toContain('Unauthorized rejection attempt');
    }
  });
});