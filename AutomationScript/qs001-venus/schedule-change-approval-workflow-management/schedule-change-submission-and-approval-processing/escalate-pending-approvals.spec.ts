import { test, expect } from '@playwright/test';

test.describe('Escalate Pending Schedule Change Approvals', () => {
  test.beforeEach(async ({ page }) => {
    // Login as approver
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'approver@example.com');
    await page.fill('[data-testid="password-input"]', 'ApproverPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Manual escalation of pending approval (happy-path)', async ({ page }) => {
    // Navigate to the 'Pending Approvals' section from the approver dashboard
    await page.click('[data-testid="pending-approvals-link"]');
    await expect(page).toHaveURL(/.*pending-approvals/);
    await expect(page.locator('[data-testid="pending-approvals-header"]')).toBeVisible();

    // Observe the list of pending approvals for escalation indicators or flags
    const pendingApprovalsList = page.locator('[data-testid="pending-approvals-list"]');
    await expect(pendingApprovalsList).toBeVisible();
    
    // Verify the escalation indicator shows time information (e.g., 'Pending for 3 days')
    const flaggedRequest = page.locator('[data-testid="approval-item"]').filter({ hasText: 'Pending for' }).first();
    await expect(flaggedRequest).toBeVisible();
    const escalationIndicator = flaggedRequest.locator('[data-testid="escalation-indicator"]');
    await expect(escalationIndicator).toContainText(/Pending for \d+ day/);

    // Select a flagged request by clicking on it to view details
    await flaggedRequest.click();
    await expect(page.locator('[data-testid="approval-details-panel"]')).toBeVisible();

    // Click the 'Escalate' button or select 'Escalate to Higher Authority' option
    await page.click('[data-testid="escalate-button"]');
    await expect(page.locator('[data-testid="escalation-dialog"]')).toBeVisible();

    // Enter optional escalation comments and click 'Confirm Escalation'
    await page.fill('[data-testid="escalation-comments-input"]', 'Requires urgent attention');
    await page.click('[data-testid="confirm-escalation-button"]');

    // Verify the request status updates to 'Escalated' in the pending approvals list
    await expect(page.locator('[data-testid="escalation-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="escalation-success-message"]')).toContainText('Request escalated successfully');
    
    const escalatedRequest = page.locator('[data-testid="approval-item"]').first();
    await expect(escalatedRequest.locator('[data-testid="approval-status"]')).toContainText('Escalated');

    // Check that the higher-level approver receives notification
    // Verify through notification panel
    await page.click('[data-testid="notifications-icon"]');
    const notificationPanel = page.locator('[data-testid="notifications-panel"]');
    await expect(notificationPanel).toBeVisible();
  });

  test('Automatic escalation after time threshold (happy-path)', async ({ page }) => {
    // Navigate to pending approvals
    await page.goto('/pending-approvals');
    
    // Wait for or simulate the system's scheduled escalation check process to run
    // Trigger the escalation check via API or wait for scheduled job
    await page.evaluate(() => {
      return fetch('/api/escalation/trigger-check', { method: 'POST' });
    });

    // Wait for system to process automatic escalation
    await page.waitForTimeout(2000);

    // Verify the system detects the request that has been pending beyond the configured time threshold
    await page.reload();
    const autoEscalatedRequest = page.locator('[data-testid="approval-item"]').filter({ hasText: 'Escalated' }).first();
    await expect(autoEscalatedRequest).toBeVisible();

    // Observe the system automatically escalating the request without manual intervention
    await expect(autoEscalatedRequest.locator('[data-testid="escalation-type"]')).toContainText('Automatic');

    // Check the higher-level approver's pending approvals queue
    // Logout and login as higher-level approver
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'senior.approver@example.com');
    await page.fill('[data-testid="password-input"]', 'SeniorPass123');
    await page.click('[data-testid="login-button"]');
    
    await page.click('[data-testid="pending-approvals-link"]');
    const higherLevelQueue = page.locator('[data-testid="pending-approvals-list"]');
    await expect(higherLevelQueue).toBeVisible();

    // Verify that the higher-level approver receives an escalation notification
    await page.click('[data-testid="notifications-icon"]');
    const notificationPanel = page.locator('[data-testid="notifications-panel"]');
    await expect(notificationPanel).toBeVisible();
    
    const escalationNotification = notificationPanel.locator('[data-testid="notification-item"]').filter({ hasText: 'escalated' }).first();
    await expect(escalationNotification).toBeVisible();

    // Check the notification content for completeness
    await escalationNotification.click();
    const notificationDetails = page.locator('[data-testid="notification-details"]');
    await expect(notificationDetails).toContainText('Request ID');
    await expect(notificationDetails).toContainText('Escalated from');
    await expect(notificationDetails).toContainText('Reason');

    // Verify the original approver is notified that the request has been escalated
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'approver@example.com');
    await page.fill('[data-testid="password-input"]', 'ApproverPass123');
    await page.click('[data-testid="login-button"]');
    
    await page.click('[data-testid="notifications-icon"]');
    const originalApproverNotifications = page.locator('[data-testid="notifications-panel"]');
    const escalationConfirmation = originalApproverNotifications.locator('[data-testid="notification-item"]').filter({ hasText: 'has been escalated' }).first();
    await expect(escalationConfirmation).toBeVisible();
  });

  test('Audit trail records escalation actions (happy-path)', async ({ page }) => {
    // Trigger an escalation event by performing manual escalation
    await page.goto('/pending-approvals');
    
    const flaggedRequest = page.locator('[data-testid="approval-item"]').filter({ hasText: 'Pending for' }).first();
    await flaggedRequest.click();
    
    // Store request ID for later verification
    const requestId = await page.locator('[data-testid="request-id"]').textContent();
    
    await page.click('[data-testid="escalate-button"]');
    await page.fill('[data-testid="escalation-comments-input"]', 'Test escalation for audit trail');
    await page.click('[data-testid="confirm-escalation-button"]');

    // Verify the escalation completes and request status is updated
    await expect(page.locator('[data-testid="escalation-success-message"]')).toBeVisible();

    // Log in as an administrator or user with audit log access permissions
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'admin@example.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123');
    await page.click('[data-testid="login-button"]');

    // Navigate to the 'Audit Logs' or 'System Logs' section
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-logs-link"]');
    await expect(page).toHaveURL(/.*audit-logs/);
    await expect(page.locator('[data-testid="audit-logs-header"]')).toBeVisible();

    // Search or filter audit logs for escalation-related events
    await page.fill('[data-testid="audit-log-search-input"]', requestId || 'escalation');
    await page.click('[data-testid="search-button"]');
    await page.waitForTimeout(1000);

    // Locate the specific escalation entry in the audit logs
    const auditLogsList = page.locator('[data-testid="audit-logs-list"]');
    await expect(auditLogsList).toBeVisible();
    
    const escalationLogEntry = auditLogsList.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'escalation' }).first();
    await expect(escalationLogEntry).toBeVisible();

    // Verify the audit log entry contains complete escalation details
    await escalationLogEntry.click();
    const auditLogDetails = page.locator('[data-testid="audit-log-details"]');
    await expect(auditLogDetails).toBeVisible();
    
    // Verify timestamp
    await expect(auditLogDetails.locator('[data-testid="log-timestamp"]')).toBeVisible();
    const timestamp = await auditLogDetails.locator('[data-testid="log-timestamp"]').textContent();
    expect(timestamp).toBeTruthy();
    
    // Verify request ID
    await expect(auditLogDetails.locator('[data-testid="log-request-id"]')).toContainText(requestId || '');
    
    // Verify escalation type (manual/automatic)
    const escalationType = auditLogDetails.locator('[data-testid="log-escalation-type"]');
    await expect(escalationType).toBeVisible();
    await expect(escalationType).toContainText(/Manual|Automatic/);
    
    // Verify original approver
    await expect(auditLogDetails.locator('[data-testid="log-original-approver"]')).toBeVisible();
    
    // Verify target approver
    await expect(auditLogDetails.locator('[data-testid="log-target-approver"]')).toBeVisible();
    
    // Verify reason
    await expect(auditLogDetails.locator('[data-testid="log-reason"]')).toBeVisible();

    // Check that the audit log entry includes the user who initiated the escalation
    const initiatedBy = auditLogDetails.locator('[data-testid="log-initiated-by"]');
    await expect(initiatedBy).toBeVisible();
    const initiatorText = await initiatedBy.textContent();
    expect(initiatorText).toMatch(/approver@example.com|SYSTEM/);

    // Verify the audit log is immutable by attempting to edit or delete the entry
    const editButton = page.locator('[data-testid="edit-audit-log-button"]');
    const deleteButton = page.locator('[data-testid="delete-audit-log-button"]');
    
    // These buttons should not exist or be disabled
    await expect(editButton).toHaveCount(0);
    await expect(deleteButton).toHaveCount(0);

    // Export or view the complete audit trail for the escalated request
    await page.click('[data-testid="view-complete-trail-button"]');
    const completeTrail = page.locator('[data-testid="complete-audit-trail"]');
    await expect(completeTrail).toBeVisible();
    
    // Verify all actions from submission to escalation are visible
    await expect(completeTrail.locator('[data-testid="trail-entry"]').filter({ hasText: 'Submitted' })).toBeVisible();
    await expect(completeTrail.locator('[data-testid="trail-entry"]').filter({ hasText: 'Escalated' })).toBeVisible();
  });
});