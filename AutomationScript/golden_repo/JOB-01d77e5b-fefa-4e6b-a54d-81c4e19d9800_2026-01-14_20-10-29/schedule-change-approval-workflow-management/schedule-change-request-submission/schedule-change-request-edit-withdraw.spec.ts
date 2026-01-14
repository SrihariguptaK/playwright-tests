import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request - Edit and Withdraw', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const EMPLOYEE_A_EMAIL = 'employeeA@company.com';
  const EMPLOYEE_A_PASSWORD = 'password123';
  const EMPLOYEE_B_EMAIL = 'employeeB@company.com';
  const EMPLOYEE_B_PASSWORD = 'password123';

  test.beforeEach(async ({ page }) => {
    // Login as Employee A for most tests
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', EMPLOYEE_A_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_A_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate editing of pending schedule change requests - happy path', async ({ page }) => {
    // Navigate to the list of submitted schedule change requests
    await page.goto(`${BASE_URL}/schedule-change-requests`);
    await expect(page.locator('[data-testid="schedule-requests-list"]')).toBeVisible();

    // Filter or identify pending schedule change requests in the list
    await page.click('[data-testid="filter-status"]');
    await page.click('[data-testid="filter-pending"]');
    await expect(page.locator('[data-testid="request-status"]').first()).toContainText('Pending');

    // Select a pending request and click the Edit button
    const pendingRequestId = await page.locator('[data-testid="request-row"]').first().getAttribute('data-request-id');
    await page.click(`[data-testid="edit-request-${pendingRequestId}"]`);
    await expect(page.locator('[data-testid="edit-request-form"]')).toBeVisible();

    // Modify the requested schedule field with a new valid date and time
    const newDate = '2024-03-15';
    const newTime = '09:00';
    await page.fill('[data-testid="requested-date-input"]', newDate);
    await page.fill('[data-testid="requested-time-input"]', newTime);

    // Modify the reason field with updated text
    const updatedReason = 'Updated reason: Need to attend important family event';
    await page.fill('[data-testid="reason-input"]', '');
    await page.fill('[data-testid="reason-input"]', updatedReason);

    // Click the Save button to save the edited request
    await page.click('[data-testid="save-request-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request updated successfully');

    // Verify the updated request in the submitted requests list
    await page.goto(`${BASE_URL}/schedule-change-requests`);
    await page.click('[data-testid="filter-status"]');
    await page.click('[data-testid="filter-pending"]');
    const updatedRequest = page.locator(`[data-request-id="${pendingRequestId}"]`);
    await expect(updatedRequest.locator('[data-testid="request-reason"]')).toContainText(updatedReason);

    // Select an approved request from the list and attempt to click Edit
    await page.click('[data-testid="filter-status"]');
    await page.click('[data-testid="filter-approved"]');
    await page.waitForSelector('[data-testid="request-row"]');
    const approvedRequestId = await page.locator('[data-testid="request-row"]').first().getAttribute('data-request-id');
    
    // Attempt to click edit on approved request
    const editButton = page.locator(`[data-testid="edit-request-${approvedRequestId}"]`);
    if (await editButton.isVisible()) {
      await editButton.click();
      await expect(page.locator('[data-testid="error-message"]')).toContainText('Cannot edit approved request');
    } else {
      // Edit button should not be visible for approved requests
      await expect(editButton).not.toBeVisible();
    }

    // Attempt to access the edit endpoint directly for an approved request
    await page.goto(`${BASE_URL}/schedule-change-requests/${approvedRequestId}/edit`);
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Cannot edit non-pending request');
  });

  test('Verify withdrawal of pending schedule change requests - happy path', async ({ page }) => {
    // Navigate to the list of submitted schedule change requests
    await page.goto(`${BASE_URL}/schedule-change-requests`);
    await expect(page.locator('[data-testid="schedule-requests-list"]')).toBeVisible();

    // Select a pending request from the list
    await page.click('[data-testid="filter-status"]');
    await page.click('[data-testid="filter-pending"]');
    await page.waitForSelector('[data-testid="request-row"]');
    const pendingRequestId = await page.locator('[data-testid="request-row"]').first().getAttribute('data-request-id');

    // Click the Withdraw button for the selected pending request
    await page.click(`[data-testid="withdraw-request-${pendingRequestId}"]`);

    // System prompts for confirmation
    await expect(page.locator('[data-testid="confirmation-dialog"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Are you sure you want to withdraw this request?');

    // Click the Confirm button in the confirmation dialog
    await page.click('[data-testid="confirm-withdrawal-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request withdrawn successfully');

    // Verify the withdrawn request in the submitted requests list
    await page.goto(`${BASE_URL}/schedule-change-requests`);
    await page.click('[data-testid="filter-status"]');
    await page.click('[data-testid="filter-withdrawn"]');
    const withdrawnRequest = page.locator(`[data-request-id="${pendingRequestId}"]`);
    await expect(withdrawnRequest).toBeVisible();
    await expect(withdrawnRequest.locator('[data-testid="request-status"]')).toContainText('Withdrawn');

    // Verify that approvers received notification of the withdrawal
    // This would typically be verified through API or database check
    const response = await page.request.get(`${BASE_URL}/api/notifications?requestId=${pendingRequestId}`);
    expect(response.ok()).toBeTruthy();
    const notifications = await response.json();
    expect(notifications.some((n: any) => n.type === 'REQUEST_WITHDRAWN')).toBeTruthy();

    // Select an approved request from the list and attempt to click Withdraw
    await page.click('[data-testid="filter-status"]');
    await page.click('[data-testid="filter-approved"]');
    await page.waitForSelector('[data-testid="request-row"]');
    const approvedRequestId = await page.locator('[data-testid="request-row"]').first().getAttribute('data-request-id');
    
    const withdrawButton = page.locator(`[data-testid="withdraw-request-${approvedRequestId}"]`);
    if (await withdrawButton.isVisible()) {
      await withdrawButton.click();
      await expect(page.locator('[data-testid="error-message"]')).toContainText('Cannot withdraw approved request');
    } else {
      // Withdraw button should not be visible for approved requests
      await expect(withdrawButton).not.toBeVisible();
    }

    // Attempt to access the withdraw endpoint directly for an approved request
    const apiResponse = await page.request.delete(`${BASE_URL}/api/schedule-change-requests/${approvedRequestId}`);
    expect(apiResponse.status()).toBe(403);
    const errorData = await apiResponse.json();
    expect(errorData.message).toContain('Cannot withdraw non-pending request');
  });

  test('Ensure only request owner can edit or withdraw requests - error case', async ({ page, context }) => {
    // First, get Employee A's pending request ID while logged in as Employee A
    await page.goto(`${BASE_URL}/schedule-change-requests`);
    await page.click('[data-testid="filter-status"]');
    await page.click('[data-testid="filter-pending"]');
    await page.waitForSelector('[data-testid="request-row"]');
    const employeeARequestId = await page.locator('[data-testid="request-row"]').first().getAttribute('data-request-id');

    // Log out Employee A
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Log in as Employee B
    await page.fill('[data-testid="email-input"]', EMPLOYEE_B_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_B_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Attempt to navigate to Employee A's pending schedule change request using direct URL
    await page.goto(`${BASE_URL}/schedule-change-requests/${employeeARequestId}/edit`);
    await expect(page.locator('[data-testid="error-message"]')).toContainText('You do not have permission to edit this request');

    // Attempt to call PUT endpoint directly for Employee A's request with modified data
    const putResponse = await page.request.put(`${BASE_URL}/api/schedule-change-requests/${employeeARequestId}`, {
      data: {
        requestedDate: '2024-04-01',
        requestedTime: '10:00',
        reason: 'Unauthorized modification attempt'
      }
    });
    expect(putResponse.status()).toBe(403);
    const putError = await putResponse.json();
    expect(putError.message).toContain('not authorized');

    // Attempt to call DELETE endpoint directly for Employee A's request
    const deleteResponse = await page.request.delete(`${BASE_URL}/api/schedule-change-requests/${employeeARequestId}`);
    expect(deleteResponse.status()).toBe(403);
    const deleteError = await deleteResponse.json();
    expect(deleteError.message).toContain('not authorized');

    // Verify that Employee A's request remains unchanged in the database
    const getResponse = await page.request.get(`${BASE_URL}/api/schedule-change-requests/${employeeARequestId}`);
    expect(getResponse.ok()).toBeTruthy();
    const requestData = await getResponse.json();
    expect(requestData.reason).not.toBe('Unauthorized modification attempt');
    expect(requestData.status).toBe('Pending');

    // Log out Employee B
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Log in as Employee A
    await page.fill('[data-testid="email-input"]', EMPLOYEE_A_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_A_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to Employee A's pending schedule change request and click Edit
    await page.goto(`${BASE_URL}/schedule-change-requests`);
    await page.click('[data-testid="filter-status"]');
    await page.click('[data-testid="filter-pending"]');
    await page.click(`[data-testid="edit-request-${employeeARequestId}"]`);
    await expect(page.locator('[data-testid="edit-request-form"]')).toBeVisible();
    
    // Verify Employee A can edit their own request
    await page.fill('[data-testid="reason-input"]', 'Employee A authorized edit');
    await page.click('[data-testid="save-request-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request updated successfully');

    // Navigate to Employee A's pending schedule change request and click Withdraw
    await page.goto(`${BASE_URL}/schedule-change-requests`);
    await page.click('[data-testid="filter-status"]');
    await page.click('[data-testid="filter-pending"]');
    await page.click(`[data-testid="withdraw-request-${employeeARequestId}"]`);
    await expect(page.locator('[data-testid="confirmation-dialog"]')).toBeVisible();
    
    // Verify Employee A can withdraw their own request
    await page.click('[data-testid="confirm-withdrawal-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request withdrawn successfully');
  });
});