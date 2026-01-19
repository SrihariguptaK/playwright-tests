import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Approval', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('Approve schedule change request successfully', async ({ page }) => {
    // Step 1: Approver logs into the system and navigates to approval dashboard
    await page.fill('[data-testid="username-input"]', 'approver@company.com');
    await page.fill('[data-testid="password-input"]', 'ApproverPass123!');
    await page.click('[data-testid="login-button"]');
    
    // Wait for navigation and verify login success
    await page.waitForURL('**/dashboard');
    
    // Navigate to approval dashboard
    await page.click('[data-testid="approvals-menu"]');
    await page.waitForSelector('[data-testid="pending-requests-list"]');
    
    // Expected Result: Dashboard displays list of pending requests
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();
    const requestCount = await page.locator('[data-testid="request-item"]').count();
    expect(requestCount).toBeGreaterThan(0);
    
    // Step 2: Approver selects a request and reviews details and attachments
    await page.click('[data-testid="request-item"]:first-child');
    await page.waitForSelector('[data-testid="request-details"]');
    
    // Expected Result: Request details and attachments are displayed correctly
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-employee-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-date-range"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-reason"]')).toBeVisible();
    
    // Check if attachments are present
    const attachmentExists = await page.locator('[data-testid="attachment-link"]').count();
    if (attachmentExists > 0) {
      await expect(page.locator('[data-testid="attachment-link"]').first()).toBeVisible();
    }
    
    // Step 3: Approver approves the request with optional comments and submits
    await page.click('[data-testid="approve-button"]');
    await page.waitForSelector('[data-testid="approval-comment-field"]');
    await page.fill('[data-testid="approval-comment-field"]', 'Approved as requested. Schedule updated.');
    await page.click('[data-testid="submit-approval-button"]');
    
    // Expected Result: Request status updates to approved and requester is notified
    await page.waitForSelector('[data-testid="success-message"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('approved');
    
    // Navigate back to dashboard to verify status update
    await page.click('[data-testid="approvals-menu"]');
    await page.waitForSelector('[data-testid="pending-requests-list"]');
    
    // Verify the approved request is no longer in pending list or status is updated
    const updatedRequestStatus = await page.locator('[data-testid="request-status"]').first().textContent();
    expect(updatedRequestStatus).not.toBe('Pending');
  });

  test('Reject schedule change request with comments', async ({ page }) => {
    // Step 1: Approver accesses a pending request
    await page.fill('[data-testid="username-input"]', 'approver@company.com');
    await page.fill('[data-testid="password-input"]', 'ApproverPass123!');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');
    
    await page.click('[data-testid="approvals-menu"]');
    await page.waitForSelector('[data-testid="pending-requests-list"]');
    await page.click('[data-testid="request-item"]:first-child');
    await page.waitForSelector('[data-testid="request-details"]');
    
    // Expected Result: Request details are shown
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-employee-name"]')).toBeVisible();
    
    // Step 2: Approver rejects the request and adds rejection reason
    await page.click('[data-testid="reject-button"]');
    await page.waitForSelector('[data-testid="rejection-comment-field"]');
    await page.fill('[data-testid="rejection-comment-field"]', 'Request conflicts with operational requirements. Insufficient staffing coverage during requested period.');
    await page.click('[data-testid="submit-rejection-button"]');
    
    // Expected Result: Request status updates to rejected and comments are saved
    await page.waitForSelector('[data-testid="success-message"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('rejected');
    
    // Verify status update in dashboard
    await page.click('[data-testid="approvals-menu"]');
    await page.waitForSelector('[data-testid="pending-requests-list"]');
    
    // Step 3: Requester receives notification of rejection
    // Verify notification was sent by checking notification log or system records
    await page.click('[data-testid="notifications-menu"]');
    await page.waitForSelector('[data-testid="notification-list"]');
    
    // Expected Result: Notification contains rejection reason
    const notificationText = await page.locator('[data-testid="notification-item"]').first().textContent();
    expect(notificationText).toContain('rejected');
  });

  test('Request additional information for schedule change request', async ({ page }) => {
    // Step 1: Approver reviews request and determines more info is needed
    await page.fill('[data-testid="username-input"]', 'approver@company.com');
    await page.fill('[data-testid="password-input"]', 'ApproverPass123!');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');
    
    await page.click('[data-testid="approvals-menu"]');
    await page.waitForSelector('[data-testid="pending-requests-list"]');
    await page.click('[data-testid="request-item"]:first-child');
    await page.waitForSelector('[data-testid="request-details"]');
    
    // Expected Result: Approver selects 'request more information' option
    await expect(page.locator('[data-testid="request-more-info-button"]')).toBeVisible();
    
    // Step 2: Approver adds comments specifying required details and submits
    await page.click('[data-testid="request-more-info-button"]');
    await page.waitForSelector('[data-testid="additional-info-comment-field"]');
    await page.fill('[data-testid="additional-info-comment-field"]', 'Please provide: 1) Coverage plan for your current shift, 2) Manager approval from your department, 3) Justification for urgency of this change');
    await page.click('[data-testid="submit-info-request-button"]');
    
    // Expected Result: Request status updates accordingly and requester is notified
    await page.waitForSelector('[data-testid="success-message"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('information requested');
    
    // Verify status update
    await page.click('[data-testid="approvals-menu"]');
    await page.waitForSelector('[data-testid="pending-requests-list"]');
    const requestStatus = await page.locator('[data-testid="request-status"]').first().textContent();
    expect(requestStatus).toContain('Additional Info Requested');
    
    // Step 3: Requester receives notification and updates the request
    // Log out approver and log in as requester
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.waitForURL('**/login');
    
    // Expected Result: Requester can resubmit with additional information
    await page.fill('[data-testid="username-input"]', 'requester@company.com');
    await page.fill('[data-testid="password-input"]', 'RequesterPass123!');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');
    
    // Navigate to My Requests
    await page.click('[data-testid="my-requests-menu"]');
    await page.waitForSelector('[data-testid="my-requests-list"]');
    
    // Find the request with additional info needed
    await page.click('[data-testid="request-item"]:has-text("Additional Info Requested")');
    await page.waitForSelector('[data-testid="request-details"]');
    
    // Verify the approver's comments are visible
    await expect(page.locator('[data-testid="approver-comments"]')).toContainText('Coverage plan');
    
    // Add additional information
    await page.click('[data-testid="edit-request-button"]');
    await page.waitForSelector('[data-testid="additional-info-field"]');
    await page.fill('[data-testid="additional-info-field"]', '1) Coverage arranged with John Doe for my shift, 2) Manager approval attached, 3) Family emergency requiring immediate schedule change');
    
    // Upload attachment if needed
    const fileInput = page.locator('[data-testid="file-upload-input"]');
    if (await fileInput.count() > 0) {
      await fileInput.setInputFiles('test-files/manager-approval.pdf');
    }
    
    // Resubmit the request
    await page.click('[data-testid="resubmit-request-button"]');
    await page.waitForSelector('[data-testid="success-message"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('resubmitted');
    
    // Verify the request is back in pending status
    await page.click('[data-testid="my-requests-menu"]');
    await page.waitForSelector('[data-testid="my-requests-list"]');
    const updatedStatus = await page.locator('[data-testid="request-status"]').first().textContent();
    expect(updatedStatus).toContain('Pending');
  });
});