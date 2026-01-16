import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request - Edit and Withdraw Pending Requests', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const DASHBOARD_URL = `${BASE_URL}/schedule-change-requests`;

  test.beforeEach(async ({ page }) => {
    // Login as scheduler
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate editing of pending schedule change request (happy-path)', async ({ page }) => {
    // Navigate to the schedule change requests dashboard
    await page.goto(DASHBOARD_URL);
    await expect(page.locator('[data-testid="requests-dashboard"]')).toBeVisible();

    // Filter or locate a request with 'Pending' status
    await page.selectOption('[data-testid="status-filter"]', 'Pending');
    await page.waitForTimeout(500);
    const pendingRequests = page.locator('[data-testid="request-row"][data-status="Pending"]');
    await expect(pendingRequests.first()).toBeVisible();

    // Click on the pending request to view details
    await pendingRequests.first().click();
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();

    // Verify request details are displayed with edit options
    await expect(page.locator('[data-testid="edit-request-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="edit-request-button"]')).toBeEnabled();

    // Click the 'Edit' button or icon
    await page.click('[data-testid="edit-request-button"]');
    await expect(page.locator('[data-testid="edit-request-form"]')).toBeVisible();

    // Modify request details such as schedule date, time, or reason text
    await page.fill('[data-testid="schedule-date-input"]', '2024-06-15');
    await page.fill('[data-testid="schedule-time-input"]', '14:30');
    await page.fill('[data-testid="reason-textarea"]', 'Updated schedule due to team availability changes');

    // Remove an existing attachment from the request
    const existingAttachment = page.locator('[data-testid="attachment-item"]').first();
    if (await existingAttachment.isVisible()) {
      await existingAttachment.locator('[data-testid="remove-attachment-button"]').click();
      await expect(page.locator('[data-testid="attachment-removed-message"]')).toBeVisible();
    }

    // Add a new attachment to the request
    const fileInput = page.locator('[data-testid="attachment-upload-input"]');
    await fileInput.setInputFiles({
      name: 'updated-schedule.pdf',
      mimeType: 'application/pdf',
      buffer: Buffer.from('Mock PDF content for testing')
    });
    await expect(page.locator('[data-testid="attachment-item"]', { hasText: 'updated-schedule.pdf' })).toBeVisible();

    // Click 'Submit' or 'Save Changes' button
    await page.click('[data-testid="submit-changes-button"]');

    // Verify the confirmation message content
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request updated successfully');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Approvers have been notified');

    // Check the request details page after update
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-date-display"]')).toContainText('2024-06-15');
    await expect(page.locator('[data-testid="schedule-time-display"]')).toContainText('14:30');
    await expect(page.locator('[data-testid="reason-display"]')).toContainText('Updated schedule due to team availability changes');

    // Verify notification was sent to assigned approvers
    await expect(page.locator('[data-testid="notification-status"]')).toContainText('Approvers notified');
  });

  test('Verify withdrawal of pending request with reason (happy-path)', async ({ page }) => {
    // Navigate to the schedule change requests dashboard
    await page.goto(DASHBOARD_URL);
    await expect(page.locator('[data-testid="requests-dashboard"]')).toBeVisible();

    // Locate and select a pending request to withdraw
    await page.selectOption('[data-testid="status-filter"]', 'Pending');
    await page.waitForTimeout(500);
    const pendingRequest = page.locator('[data-testid="request-row"][data-status="Pending"]').first();
    await pendingRequest.click();
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();

    // Click the 'Withdraw' button or option
    await page.click('[data-testid="withdraw-request-button"]');

    // Verify the withdrawal dialog content
    const withdrawalDialog = page.locator('[data-testid="withdrawal-dialog"]');
    await expect(withdrawalDialog).toBeVisible();
    await expect(withdrawalDialog.locator('[data-testid="dialog-title"]')).toContainText('Withdraw Request');
    await expect(withdrawalDialog.locator('[data-testid="withdrawal-reason-label"]')).toBeVisible();

    // Attempt to confirm withdrawal without providing a reason
    await page.click('[data-testid="confirm-withdrawal-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Withdrawal reason is required');

    // Enter a valid withdrawal reason in the text field
    await page.fill('[data-testid="withdrawal-reason-textarea"]', 'Schedule conflict resolved, request no longer needed');

    // Click 'Confirm Withdrawal' button
    await page.click('[data-testid="confirm-withdrawal-button"]');

    // Verify the confirmation message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request withdrawn successfully');

    // Check the request status in the dashboard
    await page.goto(DASHBOARD_URL);
    await page.selectOption('[data-testid="status-filter"]', 'Withdrawn');
    await page.waitForTimeout(500);
    const withdrawnRequest = page.locator('[data-testid="request-row"][data-status="Withdrawn"]').first();
    await expect(withdrawnRequest).toBeVisible();

    // Open the withdrawn request details
    await withdrawnRequest.click();
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Withdrawn');
    await expect(page.locator('[data-testid="withdrawal-reason-display"]')).toContainText('Schedule conflict resolved, request no longer needed');

    // Verify approvers received withdrawal notification
    await expect(page.locator('[data-testid="notification-status"]')).toContainText('Approvers notified of withdrawal');
  });

  test('Test prevention of edits after approval (error-case)', async ({ page }) => {
    // Navigate to the schedule change requests dashboard
    await page.goto(DASHBOARD_URL);
    await expect(page.locator('[data-testid="requests-dashboard"]')).toBeVisible();

    // Filter or locate a request with 'Approved' status
    await page.selectOption('[data-testid="status-filter"]', 'Approved');
    await page.waitForTimeout(500);
    const approvedRequest = page.locator('[data-testid="request-row"][data-status="Approved"]').first();
    await expect(approvedRequest).toBeVisible();

    // Click on the approved request to view details
    await approvedRequest.click();
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Approved');

    // Verify the availability of edit controls
    const editButton = page.locator('[data-testid="edit-request-button"]');
    if (await editButton.isVisible()) {
      // Attempt to click the edit button if visible but disabled
      await expect(editButton).toBeDisabled();
    } else {
      // Edit button should not be visible for approved requests
      await expect(editButton).not.toBeVisible();
    }

    // Get the request ID for URL manipulation
    const requestUrl = page.url();
    const requestId = requestUrl.split('/').pop();

    // Attempt to directly access the edit endpoint via URL manipulation
    await page.goto(`${DASHBOARD_URL}/${requestId}/edit`);

    // Verify the error message content
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Cannot edit approved request');

    // Navigate back to request details
    await page.goto(`${DASHBOARD_URL}/${requestId}`);
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();

    // Attempt to withdraw the approved request
    const withdrawButton = page.locator('[data-testid="withdraw-request-button"]');
    if (await withdrawButton.isVisible()) {
      await withdrawButton.click();
      // Verify withdrawal prevention message if applicable
      await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
      await expect(page.locator('[data-testid="error-message"]')).toContainText('Cannot withdraw approved request');
    } else {
      // Withdraw button should not be visible for approved requests
      await expect(withdrawButton).not.toBeVisible();
    }

    // Attempt to modify request via API call using PUT
    const response = await page.request.put(`${BASE_URL}/api/schedule-change-requests/${requestId}`, {
      data: {
        scheduleDate: '2024-07-01',
        scheduleTime: '10:00',
        reason: 'Attempting to modify approved request'
      }
    });

    // Verify API returns error for approved request modification
    expect(response.status()).toBe(403);
    const responseBody = await response.json();
    expect(responseBody.error).toContain('Cannot modify approved request');
  });
});