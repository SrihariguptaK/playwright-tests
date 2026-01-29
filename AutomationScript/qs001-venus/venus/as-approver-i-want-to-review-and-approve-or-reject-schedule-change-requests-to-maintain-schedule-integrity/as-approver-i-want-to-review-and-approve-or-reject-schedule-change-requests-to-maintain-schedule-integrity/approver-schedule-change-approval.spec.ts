import { test, expect } from '@playwright/test';

test.describe('Approver Schedule Change Request Review and Approval', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const approverEmail = 'approver@company.com';
  const approverPassword = 'ApproverPass123!';

  test.beforeEach(async ({ page }) => {
    // Login as approver
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Happy Path - Approver successfully reviews and approves schedule change request', async ({ page }) => {
    // Navigate to approval requests page
    await page.click('[data-testid="approvals-menu"]');
    await expect(page).toHaveURL(/.*approvals/);

    // Verify pending requests are displayed
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();

    // Click on first pending request
    const firstRequest = page.locator('[data-testid="request-item"]').first();
    await expect(firstRequest).toBeVisible();
    await firstRequest.click();

    // Verify schedule change details are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-schedule"]')).toBeVisible();
    await expect(page.locator('[data-testid="requested-schedule"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-reason"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-date"]')).toBeVisible();

    // Select approve decision
    await page.click('[data-testid="approve-button"]');

    // Add optional comments
    await page.fill('[data-testid="approval-comments"]', 'Approved due to valid business reason and adequate coverage.');

    // Submit decision
    await page.click('[data-testid="submit-decision-button"]');

    // Verify confirmation message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Decision submitted successfully');

    // Verify request status updated
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Approved');

    // Verify decision is logged in approval history
    await page.click('[data-testid="approval-history-tab"]');
    await expect(page.locator('[data-testid="approval-history-list"]')).toBeVisible();
    const latestApproval = page.locator('[data-testid="approval-record"]').first();
    await expect(latestApproval).toContainText('Approved');
    await expect(latestApproval).toContainText(approverEmail);
    await expect(latestApproval).toContainText('Approved due to valid business reason and adequate coverage.');
  });

  test('Happy Path - Approver successfully reviews and rejects schedule change request', async ({ page }) => {
    // Navigate to approval requests page
    await page.click('[data-testid="approvals-menu"]');
    await expect(page).toHaveURL(/.*approvals/);

    // Click on pending request
    const requestItem = page.locator('[data-testid="request-item"]').first();
    await requestItem.click();

    // Verify schedule change details are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-schedule"]')).toBeVisible();
    await expect(page.locator('[data-testid="requested-schedule"]')).toBeVisible();

    // Select reject decision
    await page.click('[data-testid="reject-button"]');

    // Add rejection comments
    await page.fill('[data-testid="approval-comments"]', 'Rejected due to insufficient coverage during requested time period.');

    // Submit decision
    await page.click('[data-testid="submit-decision-button"]');

    // Verify confirmation message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Decision submitted successfully');

    // Verify request status updated to rejected
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Rejected');

    // Verify rejection is logged with timestamp and user identity
    await page.click('[data-testid="approval-history-tab"]');
    const latestApproval = page.locator('[data-testid="approval-record"]').first();
    await expect(latestApproval).toContainText('Rejected');
    await expect(latestApproval).toContainText(approverEmail);
    await expect(latestApproval).toContainText('Rejected due to insufficient coverage');
  });

  test('Approver can view complete schedule change details before making decision', async ({ page }) => {
    // Navigate to approvals page
    await page.goto(`${baseURL}/approvals`);

    // Select a pending request
    await page.click('[data-testid="request-item"]');

    // Verify all required details are displayed
    await expect(page.locator('[data-testid="employee-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-id"]')).toBeVisible();
    await expect(page.locator('[data-testid="department"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-schedule"]')).toBeVisible();
    await expect(page.locator('[data-testid="requested-schedule"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-reason"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-date"]')).toBeVisible();
    await expect(page.locator('[data-testid="effective-date"]')).toBeVisible();

    // Verify action buttons are available
    await expect(page.locator('[data-testid="approve-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="reject-button"]')).toBeVisible();
  });

  test('System records decision with timestamp and user identity', async ({ page }) => {
    // Navigate to approvals and select request
    await page.goto(`${baseURL}/approvals`);
    await page.click('[data-testid="request-item"]');

    // Approve the request
    await page.click('[data-testid="approve-button"]');
    await page.fill('[data-testid="approval-comments"]', 'Test approval with timestamp verification');
    
    // Capture time before submission
    const beforeSubmission = new Date();
    await page.click('[data-testid="submit-decision-button"]');

    // Wait for confirmation
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Navigate to approval history
    await page.click('[data-testid="approval-history-tab"]');
    
    // Verify decision record contains timestamp
    const approvalRecord = page.locator('[data-testid="approval-record"]').first();
    await expect(approvalRecord).toBeVisible();
    await expect(approvalRecord.locator('[data-testid="approval-timestamp"]')).toBeVisible();
    
    // Verify user identity is recorded
    await expect(approvalRecord.locator('[data-testid="approver-name"]')).toContainText(approverEmail);
    
    // Verify decision type is recorded
    await expect(approvalRecord.locator('[data-testid="decision-type"]')).toContainText('Approved');
    
    // Verify comments are recorded
    await expect(approvalRecord.locator('[data-testid="approval-comments-text"]')).toContainText('Test approval with timestamp verification');
  });

  test('Approver can submit decision without comments', async ({ page }) => {
    // Navigate to approvals
    await page.goto(`${baseURL}/approvals`);
    await page.click('[data-testid="request-item"]');

    // Select approve without adding comments
    await page.click('[data-testid="approve-button"]');
    
    // Submit decision without filling comments field
    await page.click('[data-testid="submit-decision-button"]');

    // Verify successful submission
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Approved');
  });

  test('System updates schedule change status based on approval decision', async ({ page }) => {
    // Navigate to approvals
    await page.goto(`${baseURL}/approvals`);
    
    // Get request ID before approval
    const requestItem = page.locator('[data-testid="request-item"]').first();
    const requestId = await requestItem.getAttribute('data-request-id');
    await requestItem.click();

    // Verify initial status is pending
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Pending');

    // Approve the request
    await page.click('[data-testid="approve-button"]');
    await page.click('[data-testid="submit-decision-button"]');

    // Verify status updated to approved
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Approved');

    // Navigate back to approvals list
    await page.goto(`${baseURL}/approvals`);
    
    // Verify request moved from pending to approved list
    await page.click('[data-testid="approved-tab"]');
    await expect(page.locator(`[data-request-id="${requestId}"]`)).toBeVisible();
  });

  test('System validates approver authorization before allowing decision submission', async ({ page }) => {
    // Logout as approver
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Login as regular employee (non-approver)
    await page.fill('[data-testid="email-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123!');
    await page.click('[data-testid="login-button"]');

    // Attempt to access approvals page
    await page.goto(`${baseURL}/approvals`);

    // Verify access denied or redirect
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    // OR verify redirect to dashboard
    // await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Decision submission completes within 2 seconds performance requirement', async ({ page }) => {
    // Navigate to approvals
    await page.goto(`${baseURL}/approvals`);
    await page.click('[data-testid="request-item"]');

    // Select approve
    await page.click('[data-testid="approve-button"]');
    await page.fill('[data-testid="approval-comments"]', 'Performance test approval');

    // Measure submission time
    const startTime = Date.now();
    await page.click('[data-testid="submit-decision-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    const endTime = Date.now();

    const submissionTime = endTime - startTime;
    
    // Verify submission completed within 2 seconds (2000ms)
    expect(submissionTime).toBeLessThan(2000);
  });

  test('Approver can view approval history for previous decisions', async ({ page }) => {
    // Navigate to approvals
    await page.goto(`${baseURL}/approvals`);

    // Click on approval history tab
    await page.click('[data-testid="approval-history-tab"]');

    // Verify approval history is displayed
    await expect(page.locator('[data-testid="approval-history-list"]')).toBeVisible();

    // Verify history records contain required information
    const historyRecords = page.locator('[data-testid="approval-record"]');
    await expect(historyRecords.first()).toBeVisible();

    // Verify each record shows decision, timestamp, and approver
    const firstRecord = historyRecords.first();
    await expect(firstRecord.locator('[data-testid="decision-type"]')).toBeVisible();
    await expect(firstRecord.locator('[data-testid="approval-timestamp"]')).toBeVisible();
    await expect(firstRecord.locator('[data-testid="approver-name"]')).toBeVisible();
  });

  test('Approver receives notification for pending approval requests', async ({ page }) => {
    // Navigate to dashboard
    await page.goto(`${baseURL}/dashboard`);

    // Verify notification indicator is present
    await expect(page.locator('[data-testid="notification-badge"]')).toBeVisible();

    // Click on notifications
    await page.click('[data-testid="notifications-icon"]');

    // Verify pending approval notifications are displayed
    await expect(page.locator('[data-testid="notification-list"]')).toBeVisible();
    const pendingApprovalNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'pending approval' });
    await expect(pendingApprovalNotification).toBeVisible();

    // Click on notification to navigate to approval page
    await pendingApprovalNotification.click();
    await expect(page).toHaveURL(/.*approvals/);
  });
});