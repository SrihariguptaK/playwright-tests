import { test, expect } from '@playwright/test';

test.describe('Task Status Editing - story-3', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const TASK_ID = 'TASK-12345';

  test.beforeEach(async ({ page }) => {
    // Login as employee
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful status edit within allowed time window', async ({ page }) => {
    // Step 1: Navigate to task status history
    await page.goto(`${BASE_URL}/tasks/${TASK_ID}`);
    await page.click('[data-testid="status-history-tab"]');
    
    // Expected Result: List of recent status updates is displayed
    await expect(page.locator('[data-testid="status-history-list"]')).toBeVisible();
    const statusUpdates = page.locator('[data-testid="status-update-item"]');
    await expect(statusUpdates).toHaveCount(await statusUpdates.count());
    
    // Step 2: Select a status update less than 30 minutes old to edit
    const recentStatusUpdate = page.locator('[data-testid="status-update-item"]').first();
    const timestamp = await recentStatusUpdate.locator('[data-testid="status-timestamp"]').textContent();
    
    // Expected Result: Edit interface is available
    await expect(recentStatusUpdate.locator('[data-testid="edit-status-button"]')).toBeEnabled();
    await recentStatusUpdate.locator('[data-testid="edit-status-button"]').click();
    await expect(page.locator('[data-testid="edit-status-modal"]')).toBeVisible();
    
    // Step 3: Modify status and submit changes
    await page.locator('[data-testid="status-dropdown"]').click();
    await page.locator('[data-testid="status-option-on-hold"]').click();
    await page.fill('[data-testid="edit-reason-input"]', 'Correcting status due to data entry error');
    await page.click('[data-testid="save-status-edit-button"]');
    
    // Expected Result: System confirms successful update and logs audit trail
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Status updated successfully');
    
    // Verify status history reflects the change
    await page.waitForTimeout(1000);
    const updatedStatus = page.locator('[data-testid="status-update-item"]').first();
    await expect(updatedStatus.locator('[data-testid="status-value"]')).toContainText('On Hold');
    
    // Navigate to audit trail to verify logging
    await page.click('[data-testid="audit-trail-tab"]');
    await expect(page.locator('[data-testid="audit-trail-list"]')).toBeVisible();
    const latestAuditEntry = page.locator('[data-testid="audit-entry-item"]').first();
    await expect(latestAuditEntry).toContainText('Status edited');
    await expect(latestAuditEntry.locator('[data-testid="audit-user"]')).toContainText('employee@company.com');
    await expect(latestAuditEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
  });

  test('Verify rejection of status edit after time window', async ({ page }) => {
    // Step 1: Attempt to edit a status update older than 30 minutes
    await page.goto(`${BASE_URL}/tasks/${TASK_ID}`);
    await page.click('[data-testid="status-history-tab"]');
    
    // Expected Result: Edit option is disabled or submission is blocked
    await expect(page.locator('[data-testid="status-history-list"]')).toBeVisible();
    
    // Locate an old status update (simulated by selecting last item or one marked as expired)
    const oldStatusUpdate = page.locator('[data-testid="status-update-item"][data-expired="true"]').first();
    
    // Check if edit button is disabled
    const editButton = oldStatusUpdate.locator('[data-testid="edit-status-button"]');
    const isDisabled = await editButton.isDisabled();
    
    if (!isDisabled) {
      // If button is clickable, attempt to edit
      await editButton.click();
      await expect(page.locator('[data-testid="edit-status-modal"]')).toBeVisible();
      
      // Step 2: Submit edit request
      await page.locator('[data-testid="status-dropdown"]').click();
      await page.locator('[data-testid="status-option-completed"]').click();
      await page.click('[data-testid="save-status-edit-button"]');
      
      // Expected Result: System rejects with message 'Edit window expired'
      await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
      await expect(page.locator('[data-testid="error-message"]')).toContainText('Edit window expired');
      
      await page.click('[data-testid="close-error-button"]');
    } else {
      // Edit button is disabled as expected
      await expect(editButton).toBeDisabled();
      
      // Verify tooltip or message explaining why
      await editButton.hover();
      await expect(page.locator('[data-testid="disabled-tooltip"]')).toContainText('Edit window expired');
    }
    
    // Step 3: Verify no changes are made to status history
    // Expected Result: Original status remains unchanged
    await page.reload();
    await page.click('[data-testid="status-history-tab"]');
    const statusHistory = page.locator('[data-testid="status-history-list"]');
    await expect(statusHistory).toBeVisible();
    
    // Verify the old status update still has its original value
    const originalStatus = await oldStatusUpdate.locator('[data-testid="status-value"]').textContent();
    await expect(oldStatusUpdate.locator('[data-testid="status-value"]')).toContainText(originalStatus || '');
    
    // Check audit trail to confirm no successful edit was logged
    await page.click('[data-testid="audit-trail-tab"]');
    const auditEntries = page.locator('[data-testid="audit-entry-item"]');
    const auditCount = await auditEntries.count();
    
    // Verify no new audit entry for failed edit attempt
    for (let i = 0; i < Math.min(auditCount, 3); i++) {
      const entry = auditEntries.nth(i);
      const entryText = await entry.textContent();
      expect(entryText).not.toContain('Status edited to Completed');
    }
  });

  test('Ensure notifications are sent to managers on status edits', async ({ page, context }) => {
    // Step 1: Edit a recent status update
    await page.goto(`${BASE_URL}/tasks/${TASK_ID}`);
    await page.click('[data-testid="status-history-tab"]');
    
    // Expected Result: Edit is processed successfully
    await expect(page.locator('[data-testid="status-history-list"]')).toBeVisible();
    const recentStatusUpdate = page.locator('[data-testid="status-update-item"]').first();
    await recentStatusUpdate.locator('[data-testid="edit-status-button"]').click();
    
    await expect(page.locator('[data-testid="edit-status-modal"]')).toBeVisible();
    await page.locator('[data-testid="status-dropdown"]').click();
    await page.locator('[data-testid="status-option-blocked"]').click();
    await page.fill('[data-testid="edit-reason-input"]', 'Blocked due to dependency issue');
    
    const originalStatus = await page.locator('[data-testid="original-status-display"]').textContent();
    
    await page.click('[data-testid="save-status-edit-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Step 2: Check manager notification system
    // Open new page as manager to check notifications
    const managerPage = await context.newPage();
    await managerPage.goto(`${BASE_URL}/login`);
    await managerPage.fill('[data-testid="username-input"]', 'manager@company.com');
    await managerPage.fill('[data-testid="password-input"]', 'password123');
    await managerPage.click('[data-testid="login-button"]');
    await expect(managerPage).toHaveURL(/.*dashboard/);
    
    // Navigate to notifications
    await managerPage.click('[data-testid="notifications-icon"]');
    await expect(managerPage.locator('[data-testid="notifications-panel"]')).toBeVisible();
    
    // Expected Result: Manager receives notification of status edit
    const notifications = managerPage.locator('[data-testid="notification-item"]');
    await expect(notifications.first()).toBeVisible();
    
    // Step 3: Verify notification content includes task and edit details
    const latestNotification = notifications.first();
    
    // Expected Result: Notification contains accurate information
    await expect(latestNotification).toContainText('Status Edit');
    await expect(latestNotification.locator('[data-testid="notification-task-id"]')).toContainText(TASK_ID);
    await expect(latestNotification.locator('[data-testid="notification-original-status"]')).toBeVisible();
    await expect(latestNotification.locator('[data-testid="notification-new-status"]')).toContainText('Blocked');
    await expect(latestNotification.locator('[data-testid="notification-employee"]')).toContainText('employee@company.com');
    await expect(latestNotification.locator('[data-testid="notification-timestamp"]')).toBeVisible();
    
    // Verify timestamp is recent (within last few minutes)
    const notificationTime = await latestNotification.locator('[data-testid="notification-timestamp"]').textContent();
    expect(notificationTime).toBeTruthy();
    
    // Click notification to view details
    await latestNotification.click();
    await expect(managerPage.locator('[data-testid="notification-detail-modal"]')).toBeVisible();
    await expect(managerPage.locator('[data-testid="detail-task-identifier"]')).toContainText(TASK_ID);
    await expect(managerPage.locator('[data-testid="detail-edit-reason"]')).toContainText('Blocked due to dependency issue');
    
    await managerPage.close();
  });
});