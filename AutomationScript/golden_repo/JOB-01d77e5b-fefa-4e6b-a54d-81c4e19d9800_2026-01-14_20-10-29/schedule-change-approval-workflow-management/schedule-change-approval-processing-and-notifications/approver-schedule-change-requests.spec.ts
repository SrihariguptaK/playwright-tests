import { test, expect } from '@playwright/test';

test.describe('Approver Schedule Change Request Management', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('Validate approver can view and act on pending requests', async ({ page }) => {
    // Step 1: Approver logs into the system and navigates to approval dashboard
    await page.fill('[data-testid="username-input"]', 'approver.user@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePassword123!');
    await page.click('[data-testid="login-button"]');
    
    // Wait for navigation and verify login success
    await page.waitForURL('**/dashboard');
    
    // Navigate to approval dashboard
    await page.click('[data-testid="approval-dashboard-menu"]');
    await page.waitForURL('**/approvals/dashboard');
    
    // Expected Result: Dashboard displays list of pending schedule change requests
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();
    const pendingRequests = page.locator('[data-testid="pending-request-item"]');
    await expect(pendingRequests).toHaveCountGreaterThan(0);
    
    // Step 2: Approver selects a request and reviews details
    const firstRequest = pendingRequests.first();
    await firstRequest.click();
    
    // Expected Result: Request details and attachments are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-employee-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-date-range"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-reason"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-attachments"]')).toBeVisible();
    
    // Step 3: Approver approves the request with comments
    await page.click('[data-testid="approve-button"]');
    await page.fill('[data-testid="approval-comments-input"]', 'Approved as requested. Schedule change is justified.');
    await page.click('[data-testid="submit-approval-button"]');
    
    // Expected Result: Request status updates to approved and confirmation is shown
    await expect(page.locator('[data-testid="approval-confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-confirmation-message"]')).toContainText('approved');
    
    // Verify the approved request no longer appears in the pending requests list
    await page.click('[data-testid="approval-dashboard-menu"]');
    await page.waitForURL('**/approvals/dashboard');
    const updatedPendingRequests = page.locator('[data-testid="pending-request-item"]');
    const initialCount = await pendingRequests.count();
    const updatedCount = await updatedPendingRequests.count();
    expect(updatedCount).toBeLessThan(initialCount);
  });

  test('Verify rejection and request for additional information actions', async ({ page }) => {
    // Login as approver
    await page.fill('[data-testid="username-input"]', 'approver.user@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePassword123!');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');
    
    // Navigate to approval dashboard
    await page.click('[data-testid="approval-dashboard-menu"]');
    await page.waitForURL('**/approvals/dashboard');
    
    // Step 1: Approver selects a pending request
    const pendingRequests = page.locator('[data-testid="pending-request-item"]');
    await expect(pendingRequests.first()).toBeVisible();
    await pendingRequests.first().click();
    
    // Expected Result: Request details are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    
    // Step 2: Approver rejects the request with comments
    await page.click('[data-testid="reject-button"]');
    await page.fill('[data-testid="rejection-comments-input"]', 'Request denied due to insufficient staffing coverage during requested period.');
    await page.click('[data-testid="submit-rejection-button"]');
    
    // Expected Result: Request status updates to rejected and requester is notified
    await expect(page.locator('[data-testid="rejection-confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="rejection-confirmation-message"]')).toContainText('rejected');
    
    // Verify the rejection notification was sent by checking the notification log
    await page.click('[data-testid="notification-log-menu"]');
    await expect(page.locator('[data-testid="notification-log-list"]')).toBeVisible();
    const latestNotification = page.locator('[data-testid="notification-item"]').first();
    await expect(latestNotification).toContainText('rejected');
    
    // Step 3: Navigate back to approval dashboard and select another pending request
    await page.click('[data-testid="approval-dashboard-menu"]');
    await page.waitForURL('**/approvals/dashboard');
    const secondRequest = page.locator('[data-testid="pending-request-item"]').first();
    await secondRequest.click();
    
    // Approver requests additional information
    await page.click('[data-testid="request-info-button"]');
    await page.fill('[data-testid="info-request-comments-input"]', 'Please provide manager approval and detailed justification for the extended leave period.');
    await page.click('[data-testid="submit-info-request-button"]');
    
    // Expected Result: Request status updates accordingly and requester receives notification
    await expect(page.locator('[data-testid="info-request-confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="info-request-confirmation-message"]')).toContainText('additional information');
    
    // Verify the requester receives notification with the information request
    await page.click('[data-testid="notification-log-menu"]');
    const infoRequestNotification = page.locator('[data-testid="notification-item"]').first();
    await expect(infoRequestNotification).toContainText('additional information');
  });

  test('Ensure unauthorized users cannot perform approval actions', async ({ page }) => {
    // Login as non-approver user
    await page.fill('[data-testid="username-input"]', 'regular.employee@company.com');
    await page.fill('[data-testid="password-input"]', 'RegularPassword123!');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');
    
    // Step 1: Attempt to navigate to the approval dashboard by entering the URL directly
    const approvalDashboardResponse = page.goto('/approvals/dashboard');
    
    // Expected Result: System denies access with appropriate error message
    await page.waitForLoadState('networkidle');
    const currentUrl = page.url();
    
    // Check if redirected or access denied message shown
    const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
    const unauthorizedMessage = page.locator('text=/unauthorized|access denied|forbidden/i');
    
    const isAccessDenied = await accessDeniedMessage.isVisible().catch(() => false) || 
                          await unauthorizedMessage.isVisible().catch(() => false) ||
                          !currentUrl.includes('/approvals/dashboard');
    
    expect(isAccessDenied).toBeTruthy();
    
    // Step 2: Attempt to access the API endpoint directly
    const apiResponse = await page.request.get('/api/approvals/pending');
    
    // Expected Result: API returns 401 or 403 status code
    expect([401, 403]).toContain(apiResponse.status());
    
    // Step 3: Obtain a valid schedule change request ID and attempt approval action
    const requestId = 'test-request-123';
    const approvalActionResponse = await page.request.post(`/api/approvals/${requestId}/action`, {
      data: {
        action: 'approve',
        comments: 'Unauthorized approval attempt'
      }
    });
    
    // Expected Result: Action is rejected
    expect([401, 403]).toContain(approvalActionResponse.status());
    
    // Step 4: Verify the unauthorized access attempt is logged
    // Login as admin to check security logs
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'admin.user@company.com');
    await page.fill('[data-testid="password-input"]', 'AdminPassword123!');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');
    
    await page.click('[data-testid="security-log-menu"]');
    await expect(page.locator('[data-testid="security-log-list"]')).toBeVisible();
    
    const unauthorizedAttemptLog = page.locator('[data-testid="security-log-item"]').filter({
      hasText: 'unauthorized'
    }).first();
    
    await expect(unauthorizedAttemptLog).toBeVisible();
    await expect(unauthorizedAttemptLog).toContainText('regular.employee@company.com');
    
    // Step 5: Check the schedule change request status in the database remains unchanged
    await page.click('[data-testid="approval-dashboard-menu"]');
    await page.waitForURL('**/approvals/dashboard');
    
    const requestStatus = page.locator(`[data-testid="request-${requestId}-status"]`);
    if (await requestStatus.isVisible()) {
      await expect(requestStatus).not.toContainText('approved');
    }
  });
});