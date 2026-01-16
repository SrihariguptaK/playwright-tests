import { test, expect } from '@playwright/test';

test.describe('Approver Schedule Change Request Review and Decision', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('Validate approval decision submission with comments', async ({ page }) => {
    // Step 1: Login as approver
    await page.fill('[data-testid="username-input"]', 'approver@company.com');
    await page.fill('[data-testid="password-input"]', 'ApproverPass123!');
    await page.click('[data-testid="login-button"]');
    
    // Verify successful login by checking for dashboard or user menu
    await expect(page.locator('[data-testid="user-menu"]')).toBeVisible();

    // Step 2: Navigate to pending approvals dashboard
    await page.click('[data-testid="pending-approvals-menu"]');
    await page.waitForURL('**/pending-approvals');
    
    // Expected Result: List of pending requests is displayed
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();
    const requestRows = page.locator('[data-testid="request-row"]');
    await expect(requestRows).toHaveCountGreaterThan(0);

    // Step 3: Select a request and review details
    const firstRequest = requestRows.first();
    const requestId = await firstRequest.getAttribute('data-request-id');
    await firstRequest.click();
    
    // Expected Result: Request details and documents are visible
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-id"]')).toContainText(requestId || '');
    
    // Review attachments
    const attachmentLinks = page.locator('[data-testid="attachment-link"]');
    if (await attachmentLinks.count() > 0) {
      await expect(attachmentLinks.first()).toBeVisible();
    }

    // Step 4: Select 'Approve' decision
    await page.click('[data-testid="decision-approve"]');
    await expect(page.locator('[data-testid="decision-approve"]')).toBeChecked();

    // Step 5: Add comments
    const commentsText = 'Request approved as justification is valid and no conflicts identified';
    await page.fill('[data-testid="comments-textarea"]', commentsText);
    await expect(page.locator('[data-testid="comments-textarea"]')).toHaveValue(commentsText);

    // Step 6: Submit decision
    await page.click('[data-testid="submit-decision-button"]');
    
    // Expected Result: Decision is saved, status updated, and confirmation shown
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Decision submitted successfully');
    
    // Verify request no longer appears in pending list
    await page.click('[data-testid="pending-approvals-menu"]');
    await page.waitForURL('**/pending-approvals');
    const updatedRequestRows = page.locator(`[data-testid="request-row"][data-request-id="${requestId}"]`);
    await expect(updatedRequestRows).toHaveCount(0);
  });

  test('Verify rejection of decision submission without selection', async ({ page }) => {
    // Step 1: Login as approver
    await page.fill('[data-testid="username-input"]', 'approver@company.com');
    await page.fill('[data-testid="password-input"]', 'ApproverPass123!');
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="user-menu"]')).toBeVisible();

    // Step 2: Navigate to pending approvals
    await page.click('[data-testid="pending-approvals-menu"]');
    await page.waitForURL('**/pending-approvals');

    // Step 3: Open a pending request
    const requestRows = page.locator('[data-testid="request-row"]');
    await expect(requestRows.first()).toBeVisible();
    const requestId = await requestRows.first().getAttribute('data-request-id');
    await requestRows.first().click();
    
    // Expected Result: Request details are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();

    // Step 4: Optionally enter comments without selecting decision
    await page.fill('[data-testid="comments-textarea"]', 'Some comments without decision');

    // Step 5: Attempt to submit without selecting a decision
    await page.click('[data-testid="submit-decision-button"]');
    
    // Expected Result: System blocks submission and displays validation error
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Please select a decision');
    
    // Verify decision options are highlighted or marked as required
    const decisionSection = page.locator('[data-testid="decision-section"]');
    await expect(decisionSection).toHaveClass(/error|required|invalid/);
    
    // Verify request status remains unchanged and page remains on details view
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-id"]')).toContainText(requestId || '');
  });

  test('Test audit logging of approval decisions', async ({ page }) => {
    let requestId: string | null = '';
    let approverUserId = 'approver@company.com';
    let submissionTimestamp: string;

    // Step 1: Login as approver
    await page.fill('[data-testid="username-input"]', approverUserId);
    await page.fill('[data-testid="password-input"]', 'ApproverPass123!');
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="user-menu"]')).toBeVisible();

    // Step 2: Navigate to pending approvals and select a request
    await page.click('[data-testid="pending-approvals-menu"]');
    await page.waitForURL('**/pending-approvals');
    
    const requestRows = page.locator('[data-testid="request-row"]');
    await expect(requestRows.first()).toBeVisible();
    requestId = await requestRows.first().getAttribute('data-request-id');
    await requestRows.first().click();
    
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();

    // Step 3: Select decision and enter comments
    await page.click('[data-testid="decision-approve"]');
    const commentsText = 'Approved based on valid business justification and resource availability';
    await page.fill('[data-testid="comments-textarea"]', commentsText);
    
    // Note current timestamp before submission
    const beforeSubmitTime = new Date();

    // Step 4: Submit decision
    await page.click('[data-testid="submit-decision-button"]');
    
    // Expected Result: Decision and comments are logged with timestamp and approver ID
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    
    // Extract timestamp from confirmation if available
    const confirmationText = await page.locator('[data-testid="confirmation-message"]').textContent();
    submissionTimestamp = beforeSubmitTime.toISOString();

    // Step 5: Logout from approver account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-button"]')).toBeVisible();

    // Step 6: Login as administrator
    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="user-menu"]')).toBeVisible();

    // Step 7: Navigate to audit logs
    await page.click('[data-testid="audit-logs-menu"]');
    await page.waitForURL('**/audit-logs');
    
    // Expected Result: Decision entry is present and accurate
    await expect(page.locator('[data-testid="audit-logs-table"]')).toBeVisible();

    // Step 8: Search or filter by request ID
    await page.fill('[data-testid="audit-search-input"]', requestId || '');
    await page.click('[data-testid="audit-search-button"]');
    
    // Locate the audit log entry
    const auditLogEntry = page.locator(`[data-testid="audit-log-row"][data-request-id="${requestId}"]`).first();
    await expect(auditLogEntry).toBeVisible();

    // Step 9: Verify audit log contains all required information
    await expect(auditLogEntry.locator('[data-testid="log-request-id"]')).toContainText(requestId || '');
    await expect(auditLogEntry.locator('[data-testid="log-decision-type"]')).toContainText('Approved');
    await expect(auditLogEntry.locator('[data-testid="log-approver-id"]')).toContainText(approverUserId);
    await expect(auditLogEntry.locator('[data-testid="log-comments"]')).toContainText(commentsText);
    
    // Verify timestamp is present and reasonable
    const logTimestamp = await auditLogEntry.locator('[data-testid="log-timestamp"]').textContent();
    expect(logTimestamp).toBeTruthy();
    
    // Verify audit log entry is immutable and displays creation metadata
    await expect(auditLogEntry.locator('[data-testid="log-created-by"]')).toBeVisible();
    await expect(auditLogEntry.locator('[data-testid="log-created-date"]')).toBeVisible();
    
    // Verify no edit or delete buttons are present for audit log entry
    await expect(auditLogEntry.locator('[data-testid="edit-log-button"]')).toHaveCount(0);
    await expect(auditLogEntry.locator('[data-testid="delete-log-button"]')).toHaveCount(0);
  });
});