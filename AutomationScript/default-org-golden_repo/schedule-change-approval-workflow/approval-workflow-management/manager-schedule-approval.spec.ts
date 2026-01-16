import { test, expect } from '@playwright/test';

test.describe('Manager Schedule Change Request Approval', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('Verify manager can view and approve schedule change requests (happy-path)', async ({ page }) => {
    // Step 1: Manager logs into the system and navigates to approval dashboard
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'ManagerPass123!');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Dashboard displays list of pending requests
    await expect(page).toHaveURL(/.*dashboard/);
    await page.click('[data-testid="approvals-menu"]');
    await expect(page.locator('[data-testid="approval-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();
    
    // Step 2: Manager selects a request to view details
    const firstRequest = page.locator('[data-testid="request-item"]').first();
    await expect(firstRequest).toBeVisible();
    await firstRequest.click();
    
    // Expected Result: Detailed information and attachments are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-information"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-attachments"]')).toBeVisible();
    
    // Step 3: Manager approves the request with a comment
    await page.click('[data-testid="approve-button"]');
    await page.fill('[data-testid="approval-comment-input"]', 'Approved due to valid business reason');
    await page.click('[data-testid="confirm-approval-button"]');
    
    // Expected Result: Request status updates to approved and requester is notified
    await expect(page.locator('[data-testid="success-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-notification"]')).toContainText('approved');
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Approved');
  });

  test('Verify rejection with mandatory comment (error-case)', async ({ page }) => {
    // Login as manager
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'ManagerPass123!');
    await page.click('[data-testid="login-button"]');
    
    // Navigate to approval dashboard
    await page.click('[data-testid="approvals-menu"]');
    await expect(page.locator('[data-testid="approval-dashboard"]')).toBeVisible();
    
    // Step 1: Click on a pending request to open its details
    const firstRequest = page.locator('[data-testid="request-item"]').first();
    await firstRequest.click();
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    
    // Step 2: Click the Reject button without entering any comment
    await page.click('[data-testid="reject-button"]');
    await page.click('[data-testid="confirm-rejection-button"]');
    
    // Expected Result: System prevents rejection and prompts for mandatory comment
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('comment');
    await expect(page.locator('[data-testid="comment-validation-error"]')).toBeVisible();
    
    // Step 3: Enter a detailed rejection comment
    await page.fill('[data-testid="rejection-comment-input"]', 'Rejected due to insufficient staffing coverage during requested period');
    
    // Step 4: Click the Submit Rejection button
    await page.click('[data-testid="confirm-rejection-button"]');
    
    // Expected Result: Request status updates to rejected and requester is notified
    await expect(page.locator('[data-testid="success-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-notification"]')).toContainText('rejected');
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Rejected');
  });

  test('Ensure unauthorized users cannot access approval actions (error-case)', async ({ page, request }) => {
    // Step 1: Log into the system using non-manager user credentials
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Step 2: Attempt to manually navigate to the approval dashboard URL
    await page.goto('/approvals');
    
    // Expected Result: System denies access with appropriate error message
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/access denied|unauthorized|forbidden/i);
    
    // Alternative: Check if redirected away from approvals page
    await expect(page).not.toHaveURL(/.*approvals/);
    
    // Step 3: Attempt to directly call the approval API endpoint GET /api/approvals/pending
    const authToken = await page.evaluate(() => localStorage.getItem('authToken'));
    
    const pendingRequestsResponse = await request.get('/api/approvals/pending', {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    // Expected Result: API returns 403 Forbidden or 401 Unauthorized
    expect(pendingRequestsResponse.status()).toBeGreaterThanOrEqual(401);
    expect(pendingRequestsResponse.status()).toBeLessThanOrEqual(403);
    
    // Step 4: Attempt to call the approval action API endpoint POST /api/approvals/actions
    const approvalActionResponse = await request.post('/api/approvals/actions', {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      data: {
        requestId: 'test-request-123',
        action: 'approve',
        comment: 'Attempting unauthorized approval'
      }
    });
    
    // Expected Result: API returns 403 Forbidden or 401 Unauthorized
    expect(approvalActionResponse.status()).toBeGreaterThanOrEqual(401);
    expect(approvalActionResponse.status()).toBeLessThanOrEqual(403);
    
    const responseBody = await approvalActionResponse.json();
    expect(responseBody.error || responseBody.message).toMatch(/unauthorized|forbidden|access denied/i);
  });
});