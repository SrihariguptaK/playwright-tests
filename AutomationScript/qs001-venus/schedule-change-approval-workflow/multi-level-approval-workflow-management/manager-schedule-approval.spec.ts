import { test, expect } from '@playwright/test';

test.describe('Manager Schedule Change Request Approval', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const MANAGER_USERNAME = 'manager@company.com';
  const MANAGER_PASSWORD = 'Manager@123';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate manager can view and approve pending requests (happy-path)', async ({ page }) => {
    // Step 1: Manager logs into the system
    await page.fill('[data-testid="username-input"]', MANAGER_USERNAME);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Expected Result: Approval dashboard displays pending requests
    await expect(page).toHaveURL(/.*\/approvals/);
    await expect(page.locator('[data-testid="approval-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();
    
    // Verify at least one pending request is displayed
    const pendingRequests = page.locator('[data-testid="pending-request-row"]');
    await expect(pendingRequests.first()).toBeVisible();

    // Step 2: Select a pending request and review details
    await pendingRequests.first().click();

    // Expected Result: Request details and history are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-history"]')).toBeVisible();
    await expect(page.locator('[data-testid="requester-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="requested-date"]')).toBeVisible();

    // Step 3: Approve the request with a comment
    await page.fill('[data-testid="approval-comment-input"]', 'Approved - adequate coverage available');
    await page.click('[data-testid="approve-button"]');

    // Expected Result: Request status updates to approved and confirmation shown
    await expect(page.locator('[data-testid="approval-confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-confirmation-message"]')).toContainText('approved');
    
    // Verify request status is updated
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Approved');
  });

  test('Verify rejection with mandatory comment enforcement (error-case)', async ({ page }) => {
    // Login as manager
    await page.fill('[data-testid="username-input"]', MANAGER_USERNAME);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');

    await expect(page).toHaveURL(/.*\/approvals/);

    // Step 1: Manager selects a pending request
    const pendingRequests = page.locator('[data-testid="pending-request-row"]');
    await pendingRequests.first().click();

    // Expected Result: Request details displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();

    // Step 2: Attempt to reject request without comment
    await page.click('[data-testid="reject-button"]');

    // Expected Result: System blocks rejection and prompts for comment
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('comment');
    await expect(page.locator('[data-testid="approval-comment-input"]')).toHaveAttribute('aria-invalid', 'true');
    
    // Verify request status has not changed
    await expect(page.locator('[data-testid="request-status"]')).not.toContainText('Rejected');

    // Step 3: Enter comment and reject request
    await page.fill('[data-testid="approval-comment-input"]', 'Rejected - insufficient coverage during requested period');
    await page.click('[data-testid="reject-button"]');

    // Expected Result: Request status updates to rejected and notification sent
    await expect(page.locator('[data-testid="rejection-confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="rejection-confirmation-message"]')).toContainText('rejected');
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Rejected');
    
    // Verify notification indicator
    await expect(page.locator('[data-testid="notification-sent-indicator"]')).toBeVisible();
  });

  test('Ensure escalation triggers after SLA breach (edge-case)', async ({ page }) => {
    // Step 1: Simulate pending approval exceeding SLA time
    // Navigate to admin/test utilities to simulate SLA breach
    await page.goto(`${BASE_URL}/admin/test-utilities`);
    await page.fill('[data-testid="admin-username"]', 'admin@company.com');
    await page.fill('[data-testid="admin-password"]', 'Admin@123');
    await page.click('[data-testid="admin-login-button"]');

    // Simulate SLA breach for a specific request
    await page.click('[data-testid="simulate-sla-breach-button"]');
    await page.fill('[data-testid="request-id-input"]', 'REQ-12345');
    await page.fill('[data-testid="sla-hours-input"]', '25');
    await page.click('[data-testid="trigger-escalation-button"]');

    // Expected Result: System triggers escalation notification to next approver
    await expect(page.locator('[data-testid="escalation-triggered-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="escalation-triggered-message"]')).toContainText('Escalation triggered');

    // Logout from admin
    await page.click('[data-testid="logout-button"]');

    // Step 2: Verify escalation notification received
    // Login as next level approver
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'senior.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SeniorManager@123');
    await page.click('[data-testid="login-button"]');

    // Navigate to notifications
    await page.click('[data-testid="notifications-icon"]');

    // Expected Result: Notification is delivered successfully
    await expect(page.locator('[data-testid="notification-list"]')).toBeVisible();
    const escalationNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'escalated' });
    await expect(escalationNotification).toBeVisible();
    await expect(escalationNotification).toContainText('REQ-12345');

    // Navigate to approval dashboard
    await page.goto(`${BASE_URL}/approvals`);
    await expect(page.locator('[data-testid="approval-dashboard"]')).toBeVisible();

    // Step 3: Next approver acts on escalated request
    const escalatedRequest = page.locator('[data-testid="pending-request-row"]').filter({ hasText: 'REQ-12345' });
    await expect(escalatedRequest).toBeVisible();
    await expect(escalatedRequest.locator('[data-testid="escalation-badge"]')).toBeVisible();
    
    await escalatedRequest.click();
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="escalation-indicator"]')).toBeVisible();

    // Approve the escalated request
    await page.fill('[data-testid="approval-comment-input"]', 'Approved after escalation - coverage confirmed');
    await page.click('[data-testid="approve-button"]');

    // Expected Result: Request status updates accordingly
    await expect(page.locator('[data-testid="approval-confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Approved');
    await expect(page.locator('[data-testid="approved-by"]')).toContainText('senior.manager@company.com');
  });
});