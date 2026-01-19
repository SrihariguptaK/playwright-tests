import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Approval', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto('/login');
  });

  test('Display pending schedule change requests to approver', async ({ page }) => {
    // Step 1: Approver logs into the system using valid credentials
    await page.fill('[data-testid="username-input"]', 'approver@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Dashboard loads within 3 seconds
    const startTime = Date.now();
    await page.waitForSelector('[data-testid="approval-dashboard"]', { timeout: 3000 });
    const loadTime = Date.now() - startTime;
    expect(loadTime).toBeLessThan(3000);
    
    // Step 2: Navigate to approval dashboard by clicking on the approval dashboard menu option
    await page.click('[data-testid="approval-dashboard-menu"]');
    
    // Expected Result: List of pending schedule change requests is displayed
    await page.waitForSelector('[data-testid="pending-requests-list"]');
    const requestsList = page.locator('[data-testid="pending-requests-list"]');
    await expect(requestsList).toBeVisible();
    
    const requestRows = page.locator('[data-testid="request-row"]');
    await expect(requestRows.first()).toBeVisible();
    
    // Step 3: Select a request from the list to view details by clicking on the request row
    await requestRows.first().click();
    
    // Expected Result: Detailed information and attachments are displayed
    await page.waitForSelector('[data-testid="request-details-panel"]');
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-information"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-attachments"]')).toBeVisible();
  });

  test('Approve a schedule change request', async ({ page }) => {
    // Login as approver
    await page.fill('[data-testid="username-input"]', 'approver@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    await page.waitForSelector('[data-testid="approval-dashboard"]');
    
    // Navigate to approval dashboard
    await page.click('[data-testid="approval-dashboard-menu"]');
    await page.waitForSelector('[data-testid="pending-requests-list"]');
    
    // Step 1: Select a pending schedule change request from the list by clicking on it
    const requestRow = page.locator('[data-testid="request-row"]').first();
    const requestId = await requestRow.getAttribute('data-request-id');
    await requestRow.click();
    
    // Expected Result: Request details are displayed
    await page.waitForSelector('[data-testid="request-details-panel"]');
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-information"]')).toBeVisible();
    
    // Step 2: Click the 'Approve' button and add optional comments in the comments text field
    await page.click('[data-testid="approve-button"]');
    await page.waitForSelector('[data-testid="comments-field"]');
    await page.fill('[data-testid="comments-field"]', 'Approved - schedule change aligns with operational requirements');
    
    // Expected Result: Decision is accepted
    await expect(page.locator('[data-testid="comments-field"]')).toHaveValue('Approved - schedule change aligns with operational requirements');
    
    // Step 3: Click the 'Submit' button to confirm the approval decision
    await page.click('[data-testid="submit-decision-button"]');
    
    // Expected Result: Request status updated to approved and notification sent to requester
    await page.waitForSelector('[data-testid="success-notification"]', { timeout: 5000 });
    await expect(page.locator('[data-testid="success-notification"]')).toContainText('approved');
    
    // Verify request status is updated
    await page.waitForTimeout(1000);
    const statusBadge = page.locator(`[data-request-id="${requestId}"] [data-testid="request-status"]`);
    await expect(statusBadge).toContainText('Approved');
    
    // Verify notification was sent
    await expect(page.locator('[data-testid="notification-sent-indicator"]')).toBeVisible();
  });

  test('Reject a schedule change request with comments', async ({ page }) => {
    // Login as approver
    await page.fill('[data-testid="username-input"]', 'approver@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    await page.waitForSelector('[data-testid="approval-dashboard"]');
    
    // Navigate to approval dashboard
    await page.click('[data-testid="approval-dashboard-menu"]');
    await page.waitForSelector('[data-testid="pending-requests-list"]');
    
    // Step 1: Select a pending schedule change request from the list by clicking on it
    const requestRow = page.locator('[data-testid="request-row"]').first();
    const requestId = await requestRow.getAttribute('data-request-id');
    await requestRow.click();
    
    // Expected Result: Request details are displayed
    await page.waitForSelector('[data-testid="request-details-panel"]');
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-information"]')).toBeVisible();
    
    // Step 2: Click the 'Reject' button and enter a rejection reason in the mandatory comments field
    await page.click('[data-testid="reject-button"]');
    await page.waitForSelector('[data-testid="comments-field"]');
    await page.fill('[data-testid="comments-field"]', 'Rejected - conflicts with existing operational schedule and staffing constraints');
    
    // Expected Result: Decision is accepted
    await expect(page.locator('[data-testid="comments-field"]')).toHaveValue('Rejected - conflicts with existing operational schedule and staffing constraints');
    
    // Step 3: Click the 'Submit' button to confirm the rejection decision
    await page.click('[data-testid="submit-decision-button"]');
    
    // Expected Result: Request status updated to rejected and notification sent to requester
    await page.waitForSelector('[data-testid="success-notification"]', { timeout: 5000 });
    await expect(page.locator('[data-testid="success-notification"]')).toContainText('rejected');
    
    // Verify request status is updated
    await page.waitForTimeout(1000);
    const statusBadge = page.locator(`[data-request-id="${requestId}"] [data-testid="request-status"]`);
    await expect(statusBadge).toContainText('Rejected');
    
    // Verify notification was sent
    await expect(page.locator('[data-testid="notification-sent-indicator"]')).toBeVisible();
  });
});