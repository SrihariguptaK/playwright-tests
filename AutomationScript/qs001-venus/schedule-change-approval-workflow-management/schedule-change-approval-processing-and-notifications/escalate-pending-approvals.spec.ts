import { test, expect } from '@playwright/test';

test.describe('Story-18: Escalate Pending Schedule Change Approvals', () => {
  let baseURL: string;

  test.beforeEach(async ({ page }) => {
    baseURL = process.env.BASE_URL || 'http://localhost:3000';
    await page.goto(`${baseURL}/login`);
    // Login as approver for most tests
    await page.fill('[data-testid="username-input"]', 'approver@company.com');
    await page.fill('[data-testid="password-input"]', 'ApproverPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Automatic escalation of overdue approvals (happy-path)', async ({ page }) => {
    // Step 1: Create a schedule change request and submit it for approval
    await page.goto(`${baseURL}/schedule-changes/new`);
    await page.fill('[data-testid="employee-select"]', 'John Doe');
    await page.fill('[data-testid="shift-date-input"]', '2024-02-15');
    await page.fill('[data-testid="new-shift-time"]', '09:00-17:00');
    await page.fill('[data-testid="reason-textarea"]', 'Personal appointment');
    await page.click('[data-testid="submit-for-approval-button"]');
    
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule change request submitted');
    
    const requestId = await page.locator('[data-testid="request-id"]').textContent();
    
    // Step 2: Wait for the configured threshold period to elapse (simulate time passage)
    // In test environment, trigger escalation via API or time simulation
    await page.goto(`${baseURL}/admin/test-controls`);
    await page.fill('[data-testid="request-id-input"]', requestId || '');
    await page.click('[data-testid="simulate-threshold-breach-button"]');
    
    await expect(page.locator('[data-testid="simulation-status"]')).toContainText('Threshold breach simulated');
    
    // Step 3: System automatically triggers escalation process
    await page.waitForTimeout(2000); // Wait for escalation processing
    
    // Step 4: Higher-level approver logs in and views the escalated request
    await page.goto(`${baseURL}/logout`);
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', 'senior.approver@company.com');
    await page.fill('[data-testid="password-input"]', 'SeniorPass123');
    await page.click('[data-testid="login-button"]');
    
    await page.goto(`${baseURL}/approvals/queue`);
    await expect(page.locator('[data-testid="escalated-badge"]').first()).toBeVisible();
    
    const escalatedRequest = page.locator(`[data-testid="approval-request-${requestId}"]`);
    await expect(escalatedRequest).toContainText('ESCALATED');
    
    // Step 5: Escalated approver reviews and approves the schedule change request
    await escalatedRequest.click();
    await page.click('[data-testid="approve-button"]');
    await page.fill('[data-testid="approval-comments"]', 'Approved after escalation');
    await page.click('[data-testid="confirm-approval-button"]');
    
    await expect(page.locator('[data-testid="approval-success-message"]')).toContainText('Request approved successfully');
    
    // Step 6: Verify escalation history log for the request
    await page.goto(`${baseURL}/approvals/${requestId}/history`);
    const escalationLog = page.locator('[data-testid="escalation-history"]');
    await expect(escalationLog).toContainText('Automatic Escalation');
    await expect(escalationLog).toContainText('senior.approver@company.com');
    await expect(escalationLog).toContainText('Threshold breach detected');
  });

  test('Manual escalation by approver (happy-path)', async ({ page }) => {
    // Step 1: Approver navigates to their pending approvals queue
    await page.goto(`${baseURL}/approvals/pending`);
    await expect(page.locator('[data-testid="pending-approvals-header"]')).toBeVisible();
    
    // Step 2: Approver selects a specific pending request that requires urgent attention
    const pendingRequest = page.locator('[data-testid="pending-request-item"]').first();
    await pendingRequest.click();
    
    const requestId = await page.locator('[data-testid="request-id-display"]').textContent();
    
    // Step 3: Approver clicks on 'Escalate' button or selects 'Manual Escalation' option
    await page.click('[data-testid="actions-menu-button"]');
    await page.click('[data-testid="manual-escalation-option"]');
    
    // Step 4: Approver enters escalation reason and confirms the escalation
    await expect(page.locator('[data-testid="escalation-dialog"]')).toBeVisible();
    await page.fill('[data-testid="escalation-reason-input"]', 'Requires senior management review');
    await page.click('[data-testid="confirm-escalation-button"]');
    
    await expect(page.locator('[data-testid="escalation-success-message"]')).toContainText('Request escalated successfully');
    
    // Step 5: Navigate to escalation history or audit log for the request
    await page.goto(`${baseURL}/approvals/${requestId}/history`);
    
    const escalationHistory = page.locator('[data-testid="escalation-history-list"]');
    await expect(escalationHistory).toContainText('Manual Escalation');
    await expect(escalationHistory).toContainText('Requires senior management review');
    await expect(escalationHistory).toContainText('approver@company.com');
    
    // Verify timestamp is present
    const timestamp = page.locator('[data-testid="escalation-timestamp"]').first();
    await expect(timestamp).toBeVisible();
    
    // Step 6: Verify the designated higher-level approver receives the escalation notification
    await page.goto(`${baseURL}/logout`);
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', 'senior.approver@company.com');
    await page.fill('[data-testid="password-input"]', 'SeniorPass123');
    await page.click('[data-testid="login-button"]');
    
    await page.goto(`${baseURL}/notifications`);
    const escalationNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: requestId || '' });
    await expect(escalationNotification).toContainText('Escalated');
    await expect(escalationNotification).toContainText('Requires senior management review');
  });

  test('Prevent unauthorized manual escalation (error-case)', async ({ page }) => {
    // Logout and login as unauthorized user
    await page.goto(`${baseURL}/logout`);
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', 'regular.employee@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123');
    await page.click('[data-testid="login-button"]');
    
    // Step 1: Unauthorized user attempts to access a schedule change request details page
    const testRequestId = 'REQ-12345';
    await page.goto(`${baseURL}/approvals/${testRequestId}`);
    
    // Step 2: Unauthorized user attempts to locate and click on 'Escalate' button
    const actionsMenu = page.locator('[data-testid="actions-menu-button"]');
    
    // Check if actions menu is visible, if so, try to access escalation option
    if (await actionsMenu.isVisible()) {
      await actionsMenu.click();
      const escalationOption = page.locator('[data-testid="manual-escalation-option"]');
      
      // Escalation option should not be visible for unauthorized users
      await expect(escalationOption).not.toBeVisible();
    }
    
    // Step 3: Unauthorized user attempts to access escalation API endpoint directly
    const response = await page.request.post(`${baseURL}/api/approvals/escalate`, {
      data: {
        requestId: testRequestId,
        reason: 'Unauthorized escalation attempt'
      }
    });
    
    // Verify access denied response
    expect(response.status()).toBe(403);
    const responseBody = await response.json();
    expect(responseBody.error).toContain('Access denied');
    
    // Step 4: Verify system security logs for the unauthorized escalation attempt
    // Login as admin to check security logs
    await page.goto(`${baseURL}/logout`);
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123');
    await page.click('[data-testid="login-button"]');
    
    await page.goto(`${baseURL}/admin/security-logs`);
    await page.fill('[data-testid="search-logs-input"]', 'regular.employee@company.com');
    await page.click('[data-testid="search-button"]');
    
    const securityLog = page.locator('[data-testid="security-log-entry"]').filter({ hasText: 'escalate' });
    await expect(securityLog).toContainText('Unauthorized escalation attempt');
    await expect(securityLog).toContainText('Access denied');
    
    // Step 5: Verify that no escalation notification was sent and escalation history remains unchanged
    await page.goto(`${baseURL}/approvals/${testRequestId}/history`);
    const escalationHistory = page.locator('[data-testid="escalation-history-list"]');
    
    // Check that no new escalation entry exists from unauthorized user
    const unauthorizedEscalation = escalationHistory.locator('text=regular.employee@company.com');
    await expect(unauthorizedEscalation).not.toBeVisible();
  });
});