import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Management - Edit and Withdraw', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    // Login as scheduler
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Edit a pending schedule change request successfully', async ({ page }) => {
    // Navigate to the list of schedule change requests
    await page.goto(`${BASE_URL}/schedule-change-requests`);
    await expect(page.locator('[data-testid="schedule-requests-list"]')).toBeVisible();

    // Identify and select a request with 'Pending Approval' status
    const pendingRequest = page.locator('[data-testid="request-item"]').filter({ hasText: 'Pending Approval' }).first();
    await expect(pendingRequest).toBeVisible();
    await pendingRequest.click();

    // Expected Result: Request details are displayed for editing
    await expect(page.locator('[data-testid="request-details-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="edit-button"]')).toBeEnabled();

    // Click edit button to enable editing
    await page.click('[data-testid="edit-button"]');

    // Modify the date field to a new valid date
    const newDate = new Date();
    newDate.setDate(newDate.getDate() + 7);
    const formattedDate = newDate.toISOString().split('T')[0];
    await page.fill('[data-testid="date-field"]', formattedDate);

    // Modify the reason field with updated text
    await page.fill('[data-testid="reason-field"]', 'Updated: Resource conflict resolved');

    // Expected Result: Changes accepted without validation errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();

    // Remove existing attachment and upload a new document
    const existingAttachment = page.locator('[data-testid="attachment-remove-button"]');
    if (await existingAttachment.isVisible()) {
      await existingAttachment.click();
    }

    // Upload a new document (size less than 10MB)
    const fileInput = page.locator('[data-testid="attachment-upload-input"]');
    await fileInput.setInputFiles({
      name: 'updated-document.pdf',
      mimeType: 'application/pdf',
      buffer: Buffer.from('Updated test document content')
    });

    // Click the Submit or Update button to save changes
    await page.click('[data-testid="submit-button"]');

    // Expected Result: Request updated and approvers notified within 1 minute
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request updated successfully');

    // Wait for 1 minute and verify approver notification
    await page.waitForTimeout(60000);
    
    // Verify notification was sent
    await page.goto(`${BASE_URL}/notifications`);
    const notification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Schedule change request updated' }).first();
    await expect(notification).toBeVisible();

    // View the updated request details
    await page.goto(`${BASE_URL}/schedule-change-requests`);
    await pendingRequest.click();
    await expect(page.locator('[data-testid="reason-field"]')).toHaveValue('Updated: Resource conflict resolved');
  });

  test('Withdraw a pending schedule change request', async ({ page }) => {
    // Navigate to the list of schedule change requests
    await page.goto(`${BASE_URL}/schedule-change-requests`);
    await expect(page.locator('[data-testid="schedule-requests-list"]')).toBeVisible();

    // Identify and select a request with 'Pending Approval' status
    const pendingRequest = page.locator('[data-testid="request-item"]').filter({ hasText: 'Pending Approval' }).first();
    const requestId = await pendingRequest.getAttribute('data-request-id');
    await expect(pendingRequest).toBeVisible();
    await pendingRequest.click();

    // Expected Result: Request details are displayed
    await expect(page.locator('[data-testid="request-details-form"]')).toBeVisible();

    // Click the Withdraw button
    await page.click('[data-testid="withdraw-button"]');

    // Click Confirm or Yes to proceed with withdrawal
    await expect(page.locator('[data-testid="withdraw-confirmation-dialog"]')).toBeVisible();
    await page.click('[data-testid="confirm-withdraw-button"]');

    // Expected Result: Request status updated to 'Withdrawn'
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Withdrawn', { timeout: 5000 });

    // Verify confirmation message is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request withdrawn successfully');

    // Wait for 1 minute and verify approver notification
    await page.waitForTimeout(60000);

    // Expected Result: Notification sent within 1 minute
    await page.goto(`${BASE_URL}/notifications`);
    const notification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Schedule change request withdrawn' }).first();
    await expect(notification).toBeVisible();

    // Verify the withdrawn request is no longer in the pending list
    await page.goto(`${BASE_URL}/schedule-change-requests`);
    await page.click('[data-testid="filter-pending"]');
    const withdrawnRequest = page.locator(`[data-testid="request-item"][data-request-id="${requestId}"]`);
    await expect(withdrawnRequest).not.toBeVisible();
  });

  test('Prevent editing or withdrawing approved requests', async ({ page }) => {
    // Navigate to the list of schedule change requests
    await page.goto(`${BASE_URL}/schedule-change-requests`);
    await expect(page.locator('[data-testid="schedule-requests-list"]')).toBeVisible();

    // Identify and select a request with 'Approved' status
    await page.click('[data-testid="filter-approved"]');
    const approvedRequest = page.locator('[data-testid="request-item"]').filter({ hasText: 'Approved' }).first();
    await expect(approvedRequest).toBeVisible();
    await approvedRequest.click();

    // Attempt to click the Edit button or modify any field
    const editButton = page.locator('[data-testid="edit-button"]');
    
    // Expected Result: Edit option disabled or error message displayed
    if (await editButton.isVisible()) {
      await expect(editButton).toBeDisabled();
    } else {
      await expect(page.locator('[data-testid="error-message"]')).toContainText('Cannot edit approved requests');
    }

    // Verify all input fields are non-editable
    const dateField = page.locator('[data-testid="date-field"]');
    const reasonField = page.locator('[data-testid="reason-field"]');
    
    if (await dateField.isVisible()) {
      await expect(dateField).toBeDisabled();
    }
    if (await reasonField.isVisible()) {
      await expect(reasonField).toBeDisabled();
    }

    // Attempt to click the Withdraw button
    const withdrawButton = page.locator('[data-testid="withdraw-button"]');
    
    // Expected Result: Withdrawal option disabled or error message displayed
    if (await withdrawButton.isVisible()) {
      await expect(withdrawButton).toBeDisabled();
      
      // Try clicking disabled button
      await withdrawButton.click({ force: true });
      
      // Verify no confirmation dialog appears for withdrawal
      await expect(page.locator('[data-testid="withdraw-confirmation-dialog"]')).not.toBeVisible();
    } else {
      await expect(page.locator('[data-testid="error-message"]')).toContainText('Cannot withdraw approved requests');
    }

    // Navigate back to the request list
    await page.click('[data-testid="back-to-list-button"]');
    await expect(page.locator('[data-testid="schedule-requests-list"]')).toBeVisible();
  });
});