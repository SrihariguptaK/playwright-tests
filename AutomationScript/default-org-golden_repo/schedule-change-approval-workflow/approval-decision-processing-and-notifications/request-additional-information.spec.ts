import { test, expect } from '@playwright/test';

test.describe('Story-18: Request Additional Information on Schedule Change Requests', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const approverEmail = 'approver@example.com';
  const approverPassword = 'ApproverPass123!';
  const schedulerEmail = 'scheduler@example.com';
  const schedulerPassword = 'SchedulerPass123!';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto(`${baseURL}/login`);
  });

  test('#1 Validate submission of additional information request by approver', async ({ page }) => {
    // Login as approver
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 1: Approver opens a schedule change request
    await page.click('[data-testid="approval-requests-menu"]');
    await page.waitForSelector('[data-testid="approval-requests-list"]');
    
    // Select first pending request
    const firstRequest = page.locator('[data-testid="request-item"]').first();
    await firstRequest.click();
    
    // Expected Result: Request details are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-title"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-description"]')).toBeVisible();

    // Step 2: Approver selects 'Request More Info' and enters comments
    await page.click('[data-testid="request-more-info-button"]');
    await expect(page.locator('[data-testid="info-request-modal"]')).toBeVisible();
    
    const infoRequestComment = 'Please provide more details about the resource allocation and justification for this schedule change.';
    await page.fill('[data-testid="info-request-comment-input"]', infoRequestComment);
    
    // Expected Result: Comments accepted and submission enabled
    await expect(page.locator('[data-testid="info-request-comment-input"]')).toHaveValue(infoRequestComment);
    await expect(page.locator('[data-testid="submit-info-request-button"]')).toBeEnabled();

    // Step 3: Approver submits info request
    await page.click('[data-testid="submit-info-request-button"]');
    
    // Expected Result: Request status updated and scheduler notified
    await expect(page.locator('[data-testid="success-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-notification"]')).toContainText('Information request submitted successfully');
    
    await page.waitForTimeout(1000); // Wait for status update
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Info Requested');
    await expect(page.locator('[data-testid="info-request-status-badge"]')).toBeVisible();
    await expect(page.locator('[data-testid="info-request-status-badge"]')).toContainText('Pending Information');
  });

  test('#2 Verify prevention of approval before info is provided', async ({ page }) => {
    // Login as approver
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to approval requests
    await page.click('[data-testid="approval-requests-menu"]');
    await page.waitForSelector('[data-testid="approval-requests-list"]');
    
    // Find and open a request with pending info request
    const requestWithInfoPending = page.locator('[data-testid="request-item"]').filter({ hasText: 'Info Requested' }).first();
    await requestWithInfoPending.click();
    
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="info-request-status-badge"]')).toContainText('Pending Information');

    // Step 1: Approver attempts to approve request with pending info request
    await page.click('[data-testid="approve-button"]');
    
    // Expected Result: System blocks approval and displays warning
    await expect(page.locator('[data-testid="warning-dialog"]')).toBeVisible();
    await expect(page.locator('[data-testid="warning-dialog"]')).toContainText('Cannot approve request');
    await expect(page.locator('[data-testid="warning-dialog"]')).toContainText('pending information request');
    
    // Verify approve button is disabled or action is blocked
    const approveButtonState = await page.locator('[data-testid="approve-button"]').isDisabled();
    expect(approveButtonState).toBeTruthy();
    
    // Close warning dialog
    await page.click('[data-testid="close-warning-button"]');
    await expect(page.locator('[data-testid="warning-dialog"]')).not.toBeVisible();
    
    // Verify request status remains unchanged
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Info Requested');
  });

  test('#3 Test tracking and display of info request status', async ({ page, context }) => {
    // Login as scheduler
    await page.fill('[data-testid="email-input"]', schedulerEmail);
    await page.fill('[data-testid="password-input"]', schedulerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 1: Scheduler views request with pending info request
    await page.click('[data-testid="my-requests-menu"]');
    await page.waitForSelector('[data-testid="requests-list"]');
    
    // Find request with info request status
    const requestWithInfoRequest = page.locator('[data-testid="request-item"]').filter({ hasText: 'Info Requested' }).first();
    await requestWithInfoRequest.click();
    
    // Expected Result: Info request status and comments are visible
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="info-request-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="info-request-status"]')).toContainText('Pending');
    await expect(page.locator('[data-testid="info-request-comments"]')).toBeVisible();
    await expect(page.locator('[data-testid="info-request-comments"]')).toContainText('Please provide more details');
    
    // Verify request history shows info request
    await page.click('[data-testid="request-history-tab"]');
    await expect(page.locator('[data-testid="history-entry"]').filter({ hasText: 'Information Requested' })).toBeVisible();
    
    // Step 2: Scheduler responds with required information
    await page.click('[data-testid="request-details-tab"]');
    await page.click('[data-testid="respond-to-info-request-button"]');
    await expect(page.locator('[data-testid="info-response-modal"]')).toBeVisible();
    
    const responseText = 'The resource allocation has been updated based on team availability. Justification: Critical project deadline requires additional support for 2 weeks.';
    await page.fill('[data-testid="info-response-input"]', responseText);
    
    // Optionally attach documents
    await page.click('[data-testid="submit-info-response-button"]');
    
    // Expected Result: Info request marked as resolved and approver notified
    await expect(page.locator('[data-testid="success-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-notification"]')).toContainText('Response submitted successfully');
    
    await page.waitForTimeout(1000); // Wait for status update
    await expect(page.locator('[data-testid="info-request-status"]')).toContainText('Resolved');
    await expect(page.locator('[data-testid="info-request-status-badge"]')).toContainText('Information Provided');
    
    // Verify request status changed back to pending approval
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Pending Approval');
    
    // Verify history updated
    await page.click('[data-testid="request-history-tab"]');
    await expect(page.locator('[data-testid="history-entry"]').filter({ hasText: 'Information Provided' })).toBeVisible();
    
    // Verify response is visible
    await page.click('[data-testid="request-details-tab"]');
    await expect(page.locator('[data-testid="info-response-text"]')).toContainText(responseText);
  });
});