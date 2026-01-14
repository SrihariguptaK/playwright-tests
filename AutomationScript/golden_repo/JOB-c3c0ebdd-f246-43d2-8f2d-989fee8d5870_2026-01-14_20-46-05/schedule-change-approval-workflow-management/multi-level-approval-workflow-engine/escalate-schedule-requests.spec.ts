import { test, expect } from '@playwright/test';

test.describe('Escalate Pending Schedule Change Requests', () => {
  const approverEmail = 'approver@example.com';
  const approverPassword = 'ApproverPass123!';
  const higherLevelApproverEmail = 'senior.approver@example.com';
  const higherLevelApproverPassword = 'SeniorPass123!';
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';

  test.beforeEach(async ({ page }) => {
    await page.goto(`${baseURL}/login`);
  });

  test('Validate manual escalation by approver', async ({ page }) => {
    // Login as approver
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    
    // Wait for dashboard to load
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to the pending schedule change requests dashboard
    await page.click('[data-testid="pending-requests-menu"]');
    await expect(page.locator('[data-testid="pending-requests-dashboard"]')).toBeVisible();
    
    // Select a specific pending schedule change request from the list
    const requestRow = page.locator('[data-testid="request-row"]').first();
    await expect(requestRow).toBeVisible();
    const requestId = await requestRow.getAttribute('data-request-id');
    await requestRow.click();
    
    // Click on the 'Escalate' button or option for the selected request
    await page.click('[data-testid="escalate-button"]');
    await expect(page.locator('[data-testid="escalation-dialog"]')).toBeVisible();
    
    // Enter escalation reason and confirm the escalation action
    await page.fill('[data-testid="escalation-reason-input"]', 'Requires urgent attention from senior management due to complexity');
    await page.click('[data-testid="confirm-escalation-button"]');
    
    // Verify confirmation displayed
    await expect(page.locator('[data-testid="escalation-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="escalation-success-message"]')).toContainText('Request is routed to higher-level approver');
    
    // Verify the request status has been updated to 'Escalated'
    await page.reload();
    const escalatedRequest = page.locator(`[data-request-id="${requestId}"]`);
    await expect(escalatedRequest.locator('[data-testid="request-status"]')).toContainText('Escalated');
    
    // Logout current approver
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Log in as the escalated higher-level approver and check notifications
    await page.fill('[data-testid="email-input"]', higherLevelApproverEmail);
    await page.fill('[data-testid="password-input"]', higherLevelApproverPassword);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Check notifications
    await page.click('[data-testid="notifications-icon"]');
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toBeVisible();
    await expect(notification).toContainText('escalation');
    await expect(notification).toContainText(requestId || '');
    await expect(notification).toContainText('Requires urgent attention');
    
    // Verify the escalated request appears in the higher-level approver's pending queue
    await page.click('[data-testid="pending-requests-menu"]');
    const escalatedRequestInQueue = page.locator(`[data-request-id="${requestId}"]`);
    await expect(escalatedRequestInQueue).toBeVisible();
    await expect(escalatedRequestInQueue.locator('[data-testid="request-status"]')).toContainText('Escalated');
  });

  test('Validate automatic escalation of overdue requests', async ({ page, context }) => {
    // Login as approver to create/identify a pending request
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to pending requests
    await page.click('[data-testid="pending-requests-menu"]');
    await expect(page.locator('[data-testid="pending-requests-dashboard"]')).toBeVisible();
    
    // Create or identify a pending schedule change request in the system
    const pendingRequest = page.locator('[data-testid="request-row"]').first();
    await expect(pendingRequest).toBeVisible();
    const requestId = await pendingRequest.getAttribute('data-request-id');
    const requestCreatedTime = await pendingRequest.getAttribute('data-created-time');
    
    // Simulate or wait for the request to exceed the configured SLA threshold
    // In test environment, trigger automatic escalation via admin panel or API
    await page.goto(`${baseURL}/admin/escalation-simulator`);
    await page.fill('[data-testid="request-id-input"]', requestId || '');
    await page.click('[data-testid="simulate-sla-exceeded-button"]');
    
    // Trigger the automatic escalation process
    await page.click('[data-testid="trigger-auto-escalation-button"]');
    await expect(page.locator('[data-testid="escalation-triggered-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="escalation-triggered-message"]')).toContainText('Automatic escalation completed');
    
    // Verify the request has been automatically escalated to the designated higher-level approver
    await page.goto(`${baseURL}/requests/${requestId}`);
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Escalated');
    await expect(page.locator('[data-testid="escalation-type"]')).toContainText('Automatic');
    
    // Check the escalation logs in the system audit trail
    await page.click('[data-testid="audit-trail-tab"]');
    const escalationLog = page.locator('[data-testid="audit-entry"]').filter({ hasText: 'Automatic escalation' }).first();
    await expect(escalationLog).toBeVisible();
    await expect(escalationLog).toContainText('SLA exceeded');
    await expect(escalationLog).toContainText('System');
    
    // Verify timestamp is present in escalation log
    const timestamp = escalationLog.locator('[data-testid="audit-timestamp"]');
    await expect(timestamp).toBeVisible();
    
    // Logout current user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Log in as the escalated approver and verify the request appears in their queue
    await page.fill('[data-testid="email-input"]', higherLevelApproverEmail);
    await page.fill('[data-testid="password-input"]', higherLevelApproverPassword);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Verify notifications were sent to the escalated approver
    await page.click('[data-testid="notifications-icon"]');
    const autoEscalationNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'automatically escalated' }).first();
    await expect(autoEscalationNotification).toBeVisible();
    await expect(autoEscalationNotification).toContainText(requestId || '');
    await expect(autoEscalationNotification).toContainText('SLA');
    
    // Verify the request appears in escalated approver's queue
    await page.click('[data-testid="pending-requests-menu"]');
    const escalatedRequestInQueue = page.locator(`[data-request-id="${requestId}"]`);
    await expect(escalatedRequestInQueue).toBeVisible();
    await expect(escalatedRequestInQueue.locator('[data-testid="request-status"]')).toContainText('Escalated');
    
    // Logout and verify the original approver is notified about the automatic escalation
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Check original approver received notification about automatic escalation
    await page.click('[data-testid="notifications-icon"]');
    const originalApproverNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'has been automatically escalated' }).first();
    await expect(originalApproverNotification).toBeVisible();
    await expect(originalApproverNotification).toContainText(requestId || '');
  });
});