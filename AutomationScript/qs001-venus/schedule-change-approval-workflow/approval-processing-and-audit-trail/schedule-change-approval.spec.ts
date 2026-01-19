import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Approval - Story 10', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const APPROVER_EMAIL = 'approver@company.com';
  const APPROVER_PASSWORD = 'ApproverPass123!';
  const UNAUTHORIZED_EMAIL = 'employee@company.com';
  const UNAUTHORIZED_PASSWORD = 'EmployeePass123!';

  test('Validate approver can view and approve schedule change request', async ({ page }) => {
    // Step 1: Navigate to the system login page and enter valid approver credentials
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', APPROVER_EMAIL);
    await page.fill('[data-testid="password-input"]', APPROVER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and redirect
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Step 2: Navigate to the approval queue section from the main menu
    await page.click('[data-testid="approval-queue-menu"]');
    await expect(page).toHaveURL(/.*approvals/);
    
    // Expected Result: List of pending schedule change requests is displayed
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();
    const requestCount = await page.locator('[data-testid="request-item"]').count();
    expect(requestCount).toBeGreaterThan(0);
    
    // Step 3: Select a specific schedule change request from the list by clicking on it
    const firstRequest = page.locator('[data-testid="request-item"]').first();
    const requestId = await firstRequest.getAttribute('data-request-id');
    await firstRequest.click();
    
    // Step 4: Review all details and attachments displayed on the request details page
    // Expected Result: All relevant information is visible
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-id"]')).toContainText(requestId || '');
    await expect(page.locator('[data-testid="requester-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-change-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-timestamp"]')).toBeVisible();
    
    // Check for attachments section
    const attachmentsSection = page.locator('[data-testid="attachments-section"]');
    if (await attachmentsSection.isVisible()) {
      await expect(attachmentsSection).toBeVisible();
    }
    
    // Step 5: Click the 'Approve' button and enter comments in the comments field
    await page.click('[data-testid="approve-button"]');
    await expect(page.locator('[data-testid="comments-field"]')).toBeVisible();
    await page.fill('[data-testid="comments-field"]', 'Approved - request meets all requirements');
    
    // Step 6: Click the 'Submit Decision' button to finalize the approval
    await page.click('[data-testid="submit-decision-button"]');
    
    // Expected Result: Decision is recorded and confirmation displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/approved|success/i);
    
    // Verify the request is no longer in pending queue
    await page.click('[data-testid="approval-queue-menu"]');
    const updatedRequests = page.locator(`[data-testid="request-item"][data-request-id="${requestId}"]`);
    await expect(updatedRequests).toHaveCount(0);
  });

  test('Verify rejection with comments is recorded and notified', async ({ page }) => {
    // Step 1: Navigate to the approval queue and select a schedule change request to reject
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', APPROVER_EMAIL);
    await page.fill('[data-testid="password-input"]', APPROVER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    await page.click('[data-testid="approval-queue-menu"]');
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();
    
    // Expected Result: Request details are displayed
    const requestToReject = page.locator('[data-testid="request-item"]').first();
    const requestId = await requestToReject.getAttribute('data-request-id');
    await requestToReject.click();
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    
    // Step 2: Click the 'Reject' button on the request details page
    await page.click('[data-testid="reject-button"]');
    await expect(page.locator('[data-testid="comments-field"]')).toBeVisible();
    
    // Step 3: Enter detailed rejection comments in the comments field
    const rejectionComment = 'Request rejected - insufficient justification provided for schedule change';
    await page.fill('[data-testid="comments-field"]', rejectionComment);
    
    // Step 4: Click the 'Submit Decision' button to finalize the rejection
    await page.click('[data-testid="submit-decision-button"]');
    
    // Expected Result: Rejection is recorded and notification sent to requester
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/rejected|recorded/i);
    
    // Step 5: Verify the rejection is recorded by checking the audit trail or decision history
    await page.click('[data-testid="audit-trail-link"]');
    await expect(page.locator('[data-testid="audit-trail-panel"]')).toBeVisible();
    
    const auditEntry = page.locator(`[data-testid="audit-entry"][data-request-id="${requestId}"]`).first();
    await expect(auditEntry).toBeVisible();
    await expect(auditEntry).toContainText(/rejected/i);
    await expect(auditEntry).toContainText(rejectionComment);
    await expect(auditEntry.locator('[data-testid="approver-name"]')).toBeVisible();
    await expect(auditEntry.locator('[data-testid="decision-timestamp"]')).toBeVisible();
    
    // Step 6: Verify notification was sent by checking notification logs
    await page.click('[data-testid="notifications-menu"]');
    await expect(page.locator('[data-testid="notification-logs"]')).toBeVisible();
    
    const notificationEntry = page.locator(`[data-testid="notification-item"][data-request-id="${requestId}"]`).first();
    await expect(notificationEntry).toBeVisible();
    await expect(notificationEntry).toContainText(/rejected|notification sent/i);
  });

  test('Ensure unauthorized users cannot access approval actions', async ({ page, request }) => {
    // Step 1: Login to the system using credentials of a user without approver role
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', UNAUTHORIZED_EMAIL);
    await page.fill('[data-testid="password-input"]', UNAUTHORIZED_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Step 2: Attempt to navigate to the approval queue section from the main menu or by direct URL
    // Expected Result: Approval queue and actions are not accessible
    const approvalQueueMenu = page.locator('[data-testid="approval-queue-menu"]');
    
    // Check if menu item is hidden or not present
    const isMenuVisible = await approvalQueueMenu.isVisible().catch(() => false);
    expect(isMenuVisible).toBe(false);
    
    // Step 3: Attempt to access approval queue by direct URL
    await page.goto(`${BASE_URL}/approvals`);
    
    // Should be redirected or see access denied message
    const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
    const unauthorizedMessage = page.locator('text=/unauthorized|access denied|forbidden/i');
    
    const isDenied = await accessDeniedMessage.isVisible().catch(() => false) || 
                     await unauthorizedMessage.isVisible().catch(() => false);
    expect(isDenied).toBe(true);
    
    // Step 4: Attempt to access approval actions through the UI
    // Verify no approve/reject buttons are accessible
    const approveButton = page.locator('[data-testid="approve-button"]');
    const rejectButton = page.locator('[data-testid="reject-button"]');
    
    await expect(approveButton).not.toBeVisible();
    await expect(rejectButton).not.toBeVisible();
    
    // Step 5: Using API testing, attempt to directly call GET /api/approvals endpoint
    // Get authentication token from cookies or local storage
    const cookies = await page.context().cookies();
    const authToken = cookies.find(c => c.name === 'auth_token')?.value || 
                     await page.evaluate(() => localStorage.getItem('authToken'));
    
    const getApprovalsResponse = await request.get(`${BASE_URL}/api/approvals`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      failOnStatusCode: false
    });
    
    // Expected Result: Access is denied with appropriate error messages
    expect([401, 403]).toContain(getApprovalsResponse.status());
    const getResponseBody = await getApprovalsResponse.json().catch(() => ({}));
    expect(JSON.stringify(getResponseBody).toLowerCase()).toMatch(/unauthorized|forbidden|access denied/i);
    
    // Step 6: Using API testing, attempt to directly call POST /api/approvals/{id}/decision endpoint
    const testRequestId = '12345';
    const postDecisionResponse = await request.post(`${BASE_URL}/api/approvals/${testRequestId}/decision`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      data: {
        decision: 'approved',
        comments: 'Unauthorized approval attempt'
      },
      failOnStatusCode: false
    });
    
    // Expected Result: Access is denied
    expect([401, 403]).toContain(postDecisionResponse.status());
    const postResponseBody = await postDecisionResponse.json().catch(() => ({}));
    expect(JSON.stringify(postResponseBody).toLowerCase()).toMatch(/unauthorized|forbidden|access denied/i);
    
    // Step 7: Verify that no approval decision was recorded in the system
    // Login as approver to check audit logs
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', APPROVER_EMAIL);
    await page.fill('[data-testid="password-input"]', APPROVER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    await page.click('[data-testid="audit-trail-link"]');
    await expect(page.locator('[data-testid="audit-trail-panel"]')).toBeVisible();
    
    // Search for any decisions made by unauthorized user
    const unauthorizedDecisions = page.locator(`[data-testid="audit-entry"][data-approver-email="${UNAUTHORIZED_EMAIL}"]`);
    await expect(unauthorizedDecisions).toHaveCount(0);
  });
});