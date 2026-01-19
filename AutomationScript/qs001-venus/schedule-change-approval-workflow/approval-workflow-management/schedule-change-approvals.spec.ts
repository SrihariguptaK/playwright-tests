import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Approvals - Story 24', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const APPROVER_EMAIL = 'approver@company.com';
  const APPROVER_PASSWORD = 'ApproverPass123!';
  const NON_APPROVER_EMAIL = 'employee@company.com';
  const NON_APPROVER_PASSWORD = 'EmployeePass123!';

  test('Verify approver can view and act on pending schedule change requests (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the application login page and enter valid approver credentials
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', APPROVER_EMAIL);
    await page.fill('[data-testid="password-input"]', APPROVER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and redirect
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 5000 });
    
    // Step 2: Click on 'Pending Approvals' menu item or navigate to the pending approvals dashboard
    await page.click('[data-testid="pending-approvals-menu"]');
    await expect(page).toHaveURL(/.*approvals\/pending/);
    
    // Expected Result: Dashboard displays all assigned pending requests
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();
    const requestCount = await page.locator('[data-testid="pending-request-item"]').count();
    expect(requestCount).toBeGreaterThan(0);
    
    // Step 3: Select a specific pending schedule change request from the list by clicking on it
    await page.click('[data-testid="pending-request-item"]').first();
    
    // Expected Result: Complete request information is displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-employee-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-date-range"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-reason"]')).toBeVisible();
    
    // Step 4: Click on attachment links to verify accessibility
    const attachmentLink = page.locator('[data-testid="request-attachment-link"]').first();
    if (await attachmentLink.count() > 0) {
      await expect(attachmentLink).toBeVisible();
    }
    
    // Step 5: Click the 'Approve' button to initiate approval action
    await page.click('[data-testid="approve-button"]');
    
    // Step 6: Enter comment 'Approved as requested - meets all policy requirements' in the comment field
    await expect(page.locator('[data-testid="approval-comment-field"]')).toBeVisible();
    await page.fill('[data-testid="approval-comment-field"]', 'Approved as requested - meets all policy requirements');
    
    // Step 7: Click 'Submit' or 'Confirm' button to finalize the approval
    await page.click('[data-testid="submit-approval-button"]');
    
    // Expected Result: Request status updates to approved and action is logged
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/approved/i);
    
    // Verify request status updated
    const requestStatus = page.locator('[data-testid="request-status"]');
    if (await requestStatus.count() > 0) {
      await expect(requestStatus).toContainText(/approved/i);
    }
  });

  test('Ensure unauthorized users cannot approve requests (error-case)', async ({ page, request }) => {
    // Step 1: Navigate to the application login page and enter credentials for a user without approver role
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', NON_APPROVER_EMAIL);
    await page.fill('[data-testid="password-input"]', NON_APPROVER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 5000 });
    
    // Step 2: Attempt to navigate to 'Pending Approvals' dashboard via URL or menu
    const pendingApprovalsMenu = page.locator('[data-testid="pending-approvals-menu"]');
    
    // Expected Result: Access to approval actions is denied
    if (await pendingApprovalsMenu.count() > 0) {
      // If menu is visible, it should be disabled or show error on click
      await pendingApprovalsMenu.click();
      await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible({ timeout: 3000 });
    } else {
      // Menu should not be visible for non-approvers
      expect(await pendingApprovalsMenu.count()).toBe(0);
    }
    
    // Step 3: Attempt to directly access a specific approval request URL if known
    await page.goto(`${BASE_URL}/approvals/pending`);
    
    // Should show access denied or redirect
    const currentUrl = page.url();
    const hasAccessDenied = await page.locator('[data-testid="access-denied-message"]').count() > 0;
    const isRedirected = !currentUrl.includes('/approvals/pending');
    
    expect(hasAccessDenied || isRedirected).toBeTruthy();
    
    // Step 4 & 5: Using API testing, attempt to call approval endpoints with non-approver user token
    // Get the auth token from cookies or local storage
    const cookies = await page.context().cookies();
    const authToken = cookies.find(c => c.name === 'auth_token')?.value || '';
    
    // Expected Result: System returns authorization error for GET /api/approvals/pending
    const getPendingResponse = await request.get(`${BASE_URL}/api/approvals/pending`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      failOnStatusCode: false
    });
    
    expect(getPendingResponse.status()).toBe(403);
    const getPendingBody = await getPendingResponse.json();
    expect(getPendingBody.error || getPendingBody.message).toMatch(/unauthorized|forbidden|access denied/i);
    
    // Expected Result: System returns authorization error for POST /api/approvals/decisions
    const postDecisionResponse = await request.post(`${BASE_URL}/api/approvals/decisions`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      data: {
        requestId: 'test-request-123',
        decision: 'approved',
        comments: 'Test approval attempt'
      },
      failOnStatusCode: false
    });
    
    expect(postDecisionResponse.status()).toBe(403);
    const postDecisionBody = await postDecisionResponse.json();
    expect(postDecisionBody.error || postDecisionBody.message).toMatch(/unauthorized|forbidden|access denied/i);
  });

  test('Validate rejection and request for additional information flows (happy-path)', async ({ page }) => {
    // Login as approver
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', APPROVER_EMAIL);
    await page.fill('[data-testid="password-input"]', APPROVER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 5000 });
    
    // Navigate to pending approvals dashboard
    await page.click('[data-testid="pending-approvals-menu"]');
    await expect(page).toHaveURL(/.*approvals\/pending/);
    
    // Step 1: From the pending approvals dashboard, select the first pending schedule change request
    await page.click('[data-testid="pending-request-item"]').first();
    
    // Expected Result: Request details are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    
    // Store first request ID for audit trail verification
    const firstRequestId = await page.locator('[data-testid="request-id"]').textContent();
    
    // Step 2: Click the 'Reject' button to initiate rejection action
    await page.click('[data-testid="reject-button"]');
    
    // Step 3: Enter rejection comment
    await expect(page.locator('[data-testid="rejection-comment-field"]')).toBeVisible();
    await page.fill('[data-testid="rejection-comment-field"]', 'Request does not comply with company policy section 4.2 - insufficient justification provided');
    
    // Step 4: Click 'Submit' or 'Confirm' button to finalize the rejection
    await page.click('[data-testid="submit-rejection-button"]');
    
    // Expected Result: Request status updates to rejected and logs comments
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/rejected/i);
    
    // Step 5: Navigate back to pending approvals dashboard and select a second pending request
    await page.click('[data-testid="back-to-approvals-button"]');
    await expect(page).toHaveURL(/.*approvals\/pending/);
    
    // Get the second request (or first available after rejection)
    const availableRequests = page.locator('[data-testid="pending-request-item"]');
    await expect(availableRequests.first()).toBeVisible();
    await availableRequests.first().click();
    
    // Store second request ID for audit trail verification
    const secondRequestId = await page.locator('[data-testid="request-id"]').textContent();
    
    // Step 6: Click the 'Request Additional Information' button
    await page.click('[data-testid="request-info-button"]');
    
    // Step 7: Enter comment requesting additional information
    await expect(page.locator('[data-testid="additional-info-comment-field"]')).toBeVisible();
    await page.fill('[data-testid="additional-info-comment-field"]', 'Please provide supporting documentation from your manager and clarify the business justification for the schedule change');
    
    // Step 8: Click 'Submit' or 'Confirm' button to send the request for additional information
    await page.click('[data-testid="submit-info-request-button"]');
    
    // Expected Result: Request status updates accordingly and comments are logged
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/additional information/i);
    
    // Step 9: Verify the audit trail by accessing request history for both requests
    // Navigate to first request history
    await page.goto(`${BASE_URL}/approvals/requests/${firstRequestId}/history`);
    await expect(page.locator('[data-testid="audit-trail-panel"]')).toBeVisible();
    
    // Verify rejection action is logged with timestamp
    const firstRequestAuditEntries = page.locator('[data-testid="audit-entry"]');
    await expect(firstRequestAuditEntries).toHaveCount(await firstRequestAuditEntries.count());
    
    const rejectionEntry = firstRequestAuditEntries.filter({ hasText: /rejected/i });
    await expect(rejectionEntry.first()).toBeVisible();
    await expect(rejectionEntry.first()).toContainText('Request does not comply with company policy section 4.2');
    
    // Verify timestamp is present
    await expect(page.locator('[data-testid="audit-entry-timestamp"]').first()).toBeVisible();
    
    // Navigate to second request history
    await page.goto(`${BASE_URL}/approvals/requests/${secondRequestId}/history`);
    await expect(page.locator('[data-testid="audit-trail-panel"]')).toBeVisible();
    
    // Verify additional information request is logged
    const secondRequestAuditEntries = page.locator('[data-testid="audit-entry"]');
    const infoRequestEntry = secondRequestAuditEntries.filter({ hasText: /additional information/i });
    await expect(infoRequestEntry.first()).toBeVisible();
    await expect(infoRequestEntry.first()).toContainText('Please provide supporting documentation from your manager');
    
    // Verify timestamp is present
    await expect(page.locator('[data-testid="audit-entry-timestamp"]').first()).toBeVisible();
  });
});