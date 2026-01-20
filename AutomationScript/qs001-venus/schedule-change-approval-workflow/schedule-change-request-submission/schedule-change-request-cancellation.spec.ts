import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Cancellation', () => {
  test.beforeEach(async ({ page }) => {
    // Login as Schedule Coordinator
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'schedule.coordinator@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate cancellation of pending schedule change request (happy-path)', async ({ page }) => {
    // Navigate to 'My Schedule Change Requests' page
    await page.goto('/schedule-change-requests/my-requests');
    await expect(page.locator('[data-testid="my-requests-page"]')).toBeVisible();

    // Locate and select a pending schedule change request from the list
    const pendingRequest = page.locator('[data-testid="request-row"]').filter({ hasText: 'Pending' }).first();
    await expect(pendingRequest).toBeVisible();
    const requestId = await pendingRequest.getAttribute('data-request-id');
    await pendingRequest.click();

    // Request details displayed with cancel option
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-status"]')).toHaveText('Pending');
    const cancelButton = page.locator('[data-testid="cancel-request-button"]');
    await expect(cancelButton).toBeVisible();
    await expect(cancelButton).toBeEnabled();

    // Click cancel button
    await cancelButton.click();

    // Confirmation dialog appears
    const confirmDialog = page.locator('[data-testid="cancel-confirmation-dialog"]');
    await expect(confirmDialog).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Are you sure you want to cancel this schedule change request?');

    // Record start time for performance verification
    const startTime = Date.now();

    // Click confirm button in the confirmation dialog
    await page.locator('[data-testid="confirm-cancel-button"]').click();

    // Request status updated to cancelled and confirmation shown
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule change request has been cancelled successfully');

    // Verify the cancellation processing time (within 2 seconds)
    const processingTime = Date.now() - startTime;
    expect(processingTime).toBeLessThan(2000);

    // Refresh the request list or view the cancelled request details
    await page.reload();
    await page.locator(`[data-request-id="${requestId}"]`).click();
    await expect(page.locator('[data-testid="request-status"]')).toHaveText('Cancelled');

    // Navigate to audit log section or view audit trail for the request
    await page.click('[data-testid="audit-log-tab"]');
    await expect(page.locator('[data-testid="audit-log-section"]')).toBeVisible();

    // Verify audit log records cancellation with user, timestamp, and cancellation action
    const auditEntries = page.locator('[data-testid="audit-entry"]');
    const cancellationEntry = auditEntries.filter({ hasText: 'Cancelled' }).first();
    await expect(cancellationEntry).toBeVisible();
    await expect(cancellationEntry).toContainText('schedule.coordinator@example.com');
    await expect(cancellationEntry).toContainText('Cancelled');
    await expect(cancellationEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();

    // Verify notification was sent to approvers
    await page.goto('/notifications/queue');
    const notificationEntry = page.locator('[data-testid="notification-item"]').filter({ hasText: requestId }).first();
    await expect(notificationEntry).toBeVisible();
    await expect(notificationEntry).toContainText('Schedule change request cancelled');
  });

  test('Verify cancellation blocked for approved requests (error-case)', async ({ page }) => {
    // Navigate to 'My Schedule Change Requests' page
    await page.goto('/schedule-change-requests/my-requests');
    await expect(page.locator('[data-testid="my-requests-page"]')).toBeVisible();

    // Locate and select an approved schedule change request from the list
    const approvedRequest = page.locator('[data-testid="request-row"]').filter({ hasText: 'Approved' }).first();
    await expect(approvedRequest).toBeVisible();
    const requestId = await approvedRequest.getAttribute('data-request-id');
    await approvedRequest.click();

    // Request details displayed
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-status"]')).toHaveText('Approved');

    // Attempt to access the cancel functionality for the approved request
    const cancelButton = page.locator('[data-testid="cancel-request-button"]');
    
    // Cancellation option disabled or not visible
    const isCancelButtonVisible = await cancelButton.isVisible();
    if (isCancelButtonVisible) {
      await expect(cancelButton).toBeDisabled();
      
      // If cancel button is visible, click it to attempt cancellation
      await cancelButton.click({ force: true }).catch(() => {});
      
      // Verify error message or no action taken
      const errorMessage = page.locator('[data-testid="error-message"]');
      if (await errorMessage.isVisible()) {
        await expect(errorMessage).toContainText('Cannot cancel approved requests');
      }
    } else {
      // Cancel button should not be visible for approved requests
      await expect(cancelButton).not.toBeVisible();
    }

    // Attempt direct API call to cancel approved request
    const response = await page.request.post(`/api/schedule-change-requests/${requestId}/cancel`);
    
    // Verify API returns error or forbidden status
    expect(response.status()).toBeGreaterThanOrEqual(400);
    expect([400, 403, 422]).toContain(response.status());

    // Verify request status remains unchanged
    await page.reload();
    await expect(page.locator('[data-testid="request-status"]')).toHaveText('Approved');
  });

  test('Test notification sent to approvers upon cancellation (happy-path)', async ({ page }) => {
    // Navigate to 'My Schedule Change Requests' page
    await page.goto('/schedule-change-requests/my-requests');
    await expect(page.locator('[data-testid="my-requests-page"]')).toBeVisible();

    // Locate a pending schedule change request and note the approvers
    const pendingRequest = page.locator('[data-testid="request-row"]').filter({ hasText: 'Pending' }).first();
    await expect(pendingRequest).toBeVisible();
    const requestId = await pendingRequest.getAttribute('data-request-id');
    await pendingRequest.click();

    // Note the approvers assigned to the request
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();
    const approversSection = page.locator('[data-testid="approvers-section"]');
    await expect(approversSection).toBeVisible();
    const approverElements = approversSection.locator('[data-testid="approver-name"]');
    const approverCount = await approverElements.count();
    const approverNames = [];
    for (let i = 0; i < approverCount; i++) {
      approverNames.push(await approverElements.nth(i).textContent());
    }
    expect(approverNames.length).toBeGreaterThan(0);

    // Click cancel button and confirm the cancellation action
    await page.click('[data-testid="cancel-request-button"]');
    await expect(page.locator('[data-testid="cancel-confirmation-dialog"]')).toBeVisible();
    await page.click('[data-testid="confirm-cancel-button"]');

    // Confirmation shown
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Check notification system logs or queue for outgoing notifications
    await page.goto('/admin/notifications/queue');
    await expect(page.locator('[data-testid="notification-queue"]')).toBeVisible();

    // Filter notifications for the cancelled request
    const notificationItems = page.locator('[data-testid="notification-item"]').filter({ hasText: requestId });
    await expect(notificationItems.first()).toBeVisible();

    // Verify notification content includes request details and cancellation information
    const firstNotification = notificationItems.first();
    await firstNotification.click();
    await expect(page.locator('[data-testid="notification-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-subject"]')).toContainText('Schedule change request cancelled');
    await expect(page.locator('[data-testid="notification-body"]')).toContainText(requestId);
    await expect(page.locator('[data-testid="notification-body"]')).toContainText('cancelled');

    // Verify all assigned approvers received the notification
    await page.goto('/admin/notifications/queue');
    const allNotifications = page.locator('[data-testid="notification-item"]').filter({ hasText: requestId });
    const notificationCount = await allNotifications.count();
    expect(notificationCount).toBe(approverNames.length);

    // Verify each approver is in the recipient list
    for (let i = 0; i < notificationCount; i++) {
      const notification = allNotifications.nth(i);
      const recipientText = await notification.locator('[data-testid="notification-recipient"]').textContent();
      const hasMatchingApprover = approverNames.some(approver => recipientText?.includes(approver || ''));
      expect(hasMatchingApprover).toBeTruthy();
    }
  });
});