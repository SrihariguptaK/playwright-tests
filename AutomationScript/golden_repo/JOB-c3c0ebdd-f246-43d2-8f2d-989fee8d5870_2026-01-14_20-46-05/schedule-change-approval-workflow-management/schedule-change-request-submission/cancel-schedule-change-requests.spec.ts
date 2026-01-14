import { test, expect } from '@playwright/test';

test.describe('Cancel Schedule Change Requests - Story 9', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful cancellation of pending requests', async ({ page }) => {
    // Navigate to the list of submitted schedule change requests
    await page.goto('/schedule-change-requests');
    await expect(page.locator('[data-testid="requests-list"]')).toBeVisible();

    // Locate and select a schedule change request with status 'Pending Approval'
    const pendingRequest = page.locator('[data-testid="request-row"]').filter({ hasText: 'Pending Approval' }).first();
    await expect(pendingRequest).toBeVisible();
    
    // Store request ID for verification
    const requestId = await pendingRequest.getAttribute('data-request-id');
    
    // Click on the request to view details
    await pendingRequest.click();
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();

    // Verify that cancellation option is available
    const cancelButton = page.locator('[data-testid="cancel-request-button"]');
    await expect(cancelButton).toBeVisible();
    await expect(cancelButton).toBeEnabled();

    // Click 'Cancel Request' button
    await cancelButton.click();

    // Confirm the cancellation action
    const confirmDialog = page.locator('[data-testid="cancel-confirmation-dialog"]');
    await expect(confirmDialog).toBeVisible();
    await expect(confirmDialog.locator('text=Are you sure you want to cancel this request?')).toBeVisible();
    await page.click('[data-testid="confirm-cancel-button"]');

    // Verify the request status is updated
    await expect(page.locator('[data-testid="request-status"]')).toHaveText('Cancelled', { timeout: 5000 });

    // Check for confirmation message
    const confirmationMessage = page.locator('[data-testid="success-message"]');
    await expect(confirmationMessage).toBeVisible();
    await expect(confirmationMessage).toContainText('Request cancelled successfully');

    // Navigate back to requests list
    await page.goto('/schedule-change-requests');

    // Verify the cancelled request appears in the requests list with updated status
    const cancelledRequest = page.locator(`[data-testid="request-row"][data-request-id="${requestId}"]`);
    await expect(cancelledRequest).toBeVisible();
    await expect(cancelledRequest.locator('[data-testid="status-badge"]')).toHaveText('Cancelled');

    // Verify notification sent to approvers
    await page.goto('/notifications');
    const notificationSent = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Cancellation notification sent to approvers' });
    await expect(notificationSent).toBeVisible();

    // Navigate back to the cancelled request
    await page.goto('/schedule-change-requests');
    await page.locator(`[data-testid="request-row"][data-request-id="${requestId}"]`).click();

    // Attempt to edit or resubmit the cancelled request
    const editButton = page.locator('[data-testid="edit-request-button"]');
    const resubmitButton = page.locator('[data-testid="resubmit-request-button"]');
    
    // Verify edit/resubmit options are not available or disabled for cancelled requests
    if (await editButton.isVisible()) {
      await expect(editButton).toBeDisabled();
    }
    if (await resubmitButton.isVisible()) {
      await expect(resubmitButton).toBeDisabled();
    }
  });

  test('Validate cancellation prevention for approved requests', async ({ page }) => {
    // Navigate to the list of submitted schedule change requests
    await page.goto('/schedule-change-requests');
    await expect(page.locator('[data-testid="requests-list"]')).toBeVisible();

    // Locate and select a schedule change request with status 'Approved'
    const approvedRequest = page.locator('[data-testid="request-row"]').filter({ hasText: 'Approved' }).first();
    await expect(approvedRequest).toBeVisible();
    
    // Store request ID and initial status
    const requestId = await approvedRequest.getAttribute('data-request-id');
    const initialStatus = await approvedRequest.locator('[data-testid="status-badge"]').textContent();
    
    // Click on the approved request to view details
    await approvedRequest.click();
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();

    // Check for cancellation option availability
    const cancelButton = page.locator('[data-testid="cancel-request-button"]');
    
    // If cancel button is visible, verify it is disabled
    if (await cancelButton.isVisible()) {
      await expect(cancelButton).toBeDisabled();
      
      // Hover over the disabled button to check for tooltip
      await cancelButton.hover();
      const tooltip = page.locator('[data-testid="cancel-disabled-tooltip"]');
      await expect(tooltip).toBeVisible();
      await expect(tooltip).toContainText('Cannot cancel approved requests');
    } else {
      // Verify cancel button is not present for approved requests
      await expect(cancelButton).not.toBeVisible();
    }

    // Attempt to cancel the request through any available means (if technically possible)
    // Try clicking disabled button
    if (await cancelButton.isVisible()) {
      await cancelButton.click({ force: true });
      
      // Verify error message is displayed
      const errorMessage = page.locator('[data-testid="error-message"]');
      if (await errorMessage.isVisible()) {
        await expect(errorMessage).toContainText('Cannot cancel approved or rejected requests');
      }
    }

    // Verify the request status remains unchanged
    await expect(page.locator('[data-testid="request-status"]')).toHaveText('Approved');

    // Navigate back to requests list and verify status unchanged
    await page.goto('/schedule-change-requests');
    const unchangedRequest = page.locator(`[data-testid="request-row"][data-request-id="${requestId}"]`);
    await expect(unchangedRequest.locator('[data-testid="status-badge"]')).toHaveText(initialStatus);

    // Repeat steps for a request with status 'Rejected'
    const rejectedRequest = page.locator('[data-testid="request-row"]').filter({ hasText: 'Rejected' }).first();
    
    if (await rejectedRequest.isVisible()) {
      const rejectedRequestId = await rejectedRequest.getAttribute('data-request-id');
      const rejectedInitialStatus = await rejectedRequest.locator('[data-testid="status-badge"]').textContent();
      
      // Click on the rejected request
      await rejectedRequest.click();
      await expect(page.locator('[data-testid="request-details"]')).toBeVisible();

      // Check for cancellation option availability
      const cancelButtonRejected = page.locator('[data-testid="cancel-request-button"]');
      
      if (await cancelButtonRejected.isVisible()) {
        await expect(cancelButtonRejected).toBeDisabled();
        
        // Hover over the disabled button
        await cancelButtonRejected.hover();
        const tooltipRejected = page.locator('[data-testid="cancel-disabled-tooltip"]');
        await expect(tooltipRejected).toBeVisible();
        await expect(tooltipRejected).toContainText('Cannot cancel approved or rejected requests');
      } else {
        await expect(cancelButtonRejected).not.toBeVisible();
      }

      // Verify the request status remains unchanged
      await expect(page.locator('[data-testid="request-status"]')).toHaveText('Rejected');

      // Navigate back and verify status unchanged
      await page.goto('/schedule-change-requests');
      const unchangedRejectedRequest = page.locator(`[data-testid="request-row"][data-request-id="${rejectedRequestId}"]`);
      await expect(unchangedRejectedRequest.locator('[data-testid="status-badge"]')).toHaveText(rejectedInitialStatus);
    }
  });
});