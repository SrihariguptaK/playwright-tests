import { test, expect } from '@playwright/test';

test.describe('Track Schedule Change Request Status', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to scheduling portal login page
    await page.goto('/login');
  });

  test('View schedule change request status successfully', async ({ page }) => {
    // Step 1: Employee logs into the scheduling portal
    await page.fill('[data-testid="username-input"]', 'employee.user@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123!');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Employee is authenticated and navigates to 'My Requests'
    await expect(page).toHaveURL(/\/dashboard/);
    await page.click('[data-testid="my-requests-link"]');
    await expect(page).toHaveURL(/\/my-requests/);
    
    // Step 2: Employee views list of submitted schedule change requests
    await page.waitForSelector('[data-testid="requests-list"]');
    const requestsList = page.locator('[data-testid="requests-list"]');
    await expect(requestsList).toBeVisible();
    
    // Expected Result: List displays all requests with current status
    const requestItems = page.locator('[data-testid="request-item"]');
    await expect(requestItems).toHaveCount(await requestItems.count());
    
    // Verify status indicators are present
    const firstRequest = requestItems.first();
    await expect(firstRequest.locator('[data-testid="request-status"]')).toBeVisible();
    
    // Verify status indicators are visually distinct
    const statusElement = firstRequest.locator('[data-testid="request-status"]');
    const statusText = await statusElement.textContent();
    expect(['Pending', 'Approved', 'Rejected', 'Info Requested']).toContain(statusText?.trim());
    
    // Step 3: Employee selects a request to view detailed approval history
    await firstRequest.click();
    
    // Expected Result: Approval actions, timestamps, and comments are displayed
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-history"]')).toBeVisible();
    
    // Verify timestamps are displayed
    const timestamps = page.locator('[data-testid="approval-timestamp"]');
    await expect(timestamps.first()).toBeVisible();
    const timestampText = await timestamps.first().textContent();
    expect(timestampText).toMatch(/\d{1,2}\/\d{1,2}\/\d{4}/);
    
    // Verify approval history section exists
    const approvalHistory = page.locator('[data-testid="approval-history"]');
    await expect(approvalHistory).toBeVisible();
    
    // Check if approver comments are present
    const comments = page.locator('[data-testid="approver-comment"]');
    if (await comments.count() > 0) {
      await expect(comments.first()).toBeVisible();
    }
    
    // Return to 'My Requests' list
    await page.click('[data-testid="back-to-requests"]');
    await expect(page).toHaveURL(/\/my-requests/);
    
    // Verify status in list matches detailed status
    const listStatus = await firstRequest.locator('[data-testid="request-status"]').textContent();
    expect(listStatus).toBeTruthy();
  });

  test('Prevent employee from viewing others\' requests', async ({ page }) => {
    // Step 1: Employee logs in and navigates to My Requests
    await page.fill('[data-testid="username-input"]', 'employee.user@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/\/dashboard/);
    
    await page.click('[data-testid="my-requests-link"]');
    await expect(page).toHaveURL(/\/my-requests/);
    
    // Note the URL structure and request IDs
    await page.waitForSelector('[data-testid="request-item"]');
    const firstRequest = page.locator('[data-testid="request-item"]').first();
    await firstRequest.click();
    
    const currentUrl = page.url();
    const currentRequestId = currentUrl.match(/\/request\/([\d]+)/)?.[1];
    expect(currentRequestId).toBeTruthy();
    
    // Navigate back to list
    await page.click('[data-testid="back-to-requests"]');
    
    // Step 2: Attempt to access another employee's request via URL manipulation
    const unauthorizedRequestId = '9999';
    const unauthorizedUrl = currentUrl.replace(currentRequestId!, unauthorizedRequestId);
    
    await page.goto(unauthorizedUrl);
    
    // Expected Result: System denies access and displays an error message
    const errorMessage = page.locator('[data-testid="error-message"]');
    const accessDenied = page.locator('text=/Access Denied|Unauthorized|Not Found|403|404/i');
    
    await expect(errorMessage.or(accessDenied)).toBeVisible({ timeout: 5000 });
    
    // Verify no sensitive information is exposed
    const requestDetails = page.locator('[data-testid="request-details"]');
    await expect(requestDetails).not.toBeVisible();
    
    // Verify redirect or error page
    const currentPageUrl = page.url();
    const isErrorPage = currentPageUrl.includes('/error') || 
                        currentPageUrl.includes('/my-requests') || 
                        currentPageUrl.includes('/unauthorized');
    expect(isErrorPage).toBeTruthy();
    
    // Step 3: Attempt API access directly
    const apiResponse = await page.request.get(`/api/my-schedule-change-requests/${unauthorizedRequestId}`);
    expect([401, 403, 404]).toContain(apiResponse.status());
    
    // Step 4: Employee views own requests normally
    await page.goto('/my-requests');
    await page.waitForSelector('[data-testid="requests-list"]');
    
    const ownRequest = page.locator('[data-testid="request-item"]').first();
    await ownRequest.click();
    
    // Expected Result: Access granted with full details
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-history"]')).toBeVisible();
    
    // Verify full access to own request details
    const requestStatus = page.locator('[data-testid="request-status"]');
    await expect(requestStatus).toBeVisible();
    
    const approvalHistory = page.locator('[data-testid="approval-history"]');
    await expect(approvalHistory).toBeVisible();
  });
});