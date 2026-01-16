import { test, expect } from '@playwright/test';

test.describe('Modify Employee Schedules - Manager Functionality', () => {
  test.beforeEach(async ({ page }) => {
    // Login as Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Modify an assigned shift without conflicts', async ({ page }) => {
    // Step 1: Navigate to employee schedule management page
    await page.goto('/schedule-management');
    await expect(page.locator('[data-testid="schedule-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-list-item"]').first()).toBeVisible();

    // Step 2: Locate and select a specific shift from the schedule list
    const firstShift = page.locator('[data-testid="schedule-list-item"]').first();
    await firstShift.click();
    await expect(page.locator('[data-testid="shift-details-panel"]')).toBeVisible();

    // Step 3: Click the edit button to open the shift modification form
    await page.click('[data-testid="edit-shift-button"]');
    await expect(page.locator('[data-testid="shift-modification-form"]')).toBeVisible();

    // Step 4: Modify the shift details to a non-conflicting time slot
    const originalDate = await page.inputValue('[data-testid="shift-date-input"]');
    const newDate = new Date();
    newDate.setDate(newDate.getDate() + 7);
    const formattedDate = newDate.toISOString().split('T')[0];
    
    await page.fill('[data-testid="shift-date-input"]', formattedDate);
    await page.selectOption('[data-testid="shift-template-select"]', { label: 'Morning Shift' });
    
    // Verify no conflict errors are displayed
    await expect(page.locator('[data-testid="conflict-error"]')).not.toBeVisible();

    // Step 5: Submit the modification
    await page.click('[data-testid="submit-modification-button"]');

    // Step 6: Verify confirmation displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Shift updated successfully');

    // Step 7: Verify the updated shift appears in the schedule list
    await expect(page.locator('[data-testid="schedule-list"]')).toContainText(formattedDate);
    await expect(page.locator('[data-testid="schedule-list"]')).toContainText('Morning Shift');

    // Step 8: Check that notifications have been sent
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-item"]').first()).toContainText('Schedule modified');
  });

  test('Cancel an assigned shift with reason', async ({ page }) => {
    // Step 1: Navigate to the employee schedule management page
    await page.goto('/schedule-management');
    await expect(page.locator('[data-testid="schedule-list"]')).toBeVisible();

    // Step 2: Select a scheduled shift to cancel
    const shiftToCancel = page.locator('[data-testid="schedule-list-item"]').nth(1);
    const employeeName = await shiftToCancel.locator('[data-testid="employee-name"]').textContent();
    await shiftToCancel.click();
    await expect(page.locator('[data-testid="shift-details-panel"]')).toBeVisible();

    // Step 3: Click the cancel shift button
    await page.click('[data-testid="cancel-shift-button"]');
    
    // Verify cancellation form with reason input is displayed
    await expect(page.locator('[data-testid="cancellation-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="cancellation-reason-input"]')).toBeVisible();

    // Step 4: Enter a valid cancellation reason
    await page.fill('[data-testid="cancellation-reason-input"]', 'Employee requested time off');

    // Step 5: Click the confirm cancellation button
    await page.click('[data-testid="confirm-cancellation-button"]');

    // Step 6: Verify confirmation displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Shift cancelled successfully');

    // Step 7: Verify the cancelled shift is marked as cancelled in the schedule list
    const cancelledShift = page.locator('[data-testid="schedule-list-item"]', { hasText: employeeName || '' });
    await expect(cancelledShift.locator('[data-testid="shift-status"]')).toContainText('Cancelled');

    // Step 8: Check in-app notifications for the affected employee
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-list"]')).toBeVisible();
    const notification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'cancelled' });
    await expect(notification).toBeVisible();

    // Step 9: Verify notification sent to manager
    await expect(page.locator('[data-testid="notification-item"]').filter({ hasText: 'Employee requested time off' })).toBeVisible();
  });

  test('Verify audit logging of schedule modifications', async ({ page }) => {
    // Step 1: Navigate to the employee schedule management page
    await page.goto('/schedule-management');
    await expect(page.locator('[data-testid="schedule-list"]')).toBeVisible();

    // Step 2: Select a scheduled shift and modify its details
    const shiftToModify = page.locator('[data-testid="schedule-list-item"]').first();
    const shiftId = await shiftToModify.getAttribute('data-shift-id');
    const originalShiftDate = await shiftToModify.locator('[data-testid="shift-date"]').textContent();
    
    await shiftToModify.click();
    await page.click('[data-testid="edit-shift-button"]');
    await expect(page.locator('[data-testid="shift-modification-form"]')).toBeVisible();

    // Modify shift details
    const newDate = new Date();
    newDate.setDate(newDate.getDate() + 10);
    const formattedNewDate = newDate.toISOString().split('T')[0];
    
    await page.fill('[data-testid="shift-date-input"]', formattedNewDate);
    await page.selectOption('[data-testid="shift-template-select"]', { label: 'Evening Shift' });
    
    // Note the modification time
    const modificationTime = new Date();
    
    // Submit modification
    await page.click('[data-testid="submit-modification-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Step 3: Navigate to the audit log section
    await page.goto('/audit-logs');
    await expect(page.locator('[data-testid="audit-log-page"]')).toBeVisible();

    // Step 4: Search or filter the audit log for the recently modified shift
    await page.fill('[data-testid="audit-log-search-input"]', shiftId || '');
    await page.click('[data-testid="audit-log-search-button"]');
    
    // Wait for search results
    await expect(page.locator('[data-testid="audit-log-results"]')).toBeVisible();

    // Step 5: Verify the audit log entry contains the manager's user ID
    const auditLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditLogEntry).toBeVisible();
    await expect(auditLogEntry.locator('[data-testid="audit-user"]')).toContainText('manager@company.com');

    // Step 6: Verify the audit log entry contains an accurate timestamp
    const logTimestamp = await auditLogEntry.locator('[data-testid="audit-timestamp"]').textContent();
    expect(logTimestamp).toBeTruthy();

    // Step 7: Verify the audit log entry contains complete change details
    await expect(auditLogEntry.locator('[data-testid="audit-old-value"]')).toContainText(originalShiftDate || '');
    await expect(auditLogEntry.locator('[data-testid="audit-new-value"]')).toContainText(formattedNewDate);
    await expect(auditLogEntry.locator('[data-testid="audit-new-value"]')).toContainText('Evening Shift');

    // Step 8: Confirm the log entry includes the action type
    await expect(auditLogEntry.locator('[data-testid="audit-action-type"]')).toContainText('Modification');

    // Step 9: Verify log accuracy by comparing all logged details
    const auditDetails = await auditLogEntry.locator('[data-testid="audit-details"]').textContent();
    expect(auditDetails).toContain('shift date');
    expect(auditDetails).toContain('shift template');
  });

  test('Attempt to modify shift with conflict validation', async ({ page }) => {
    // Navigate to schedule management page
    await page.goto('/schedule-management');
    await expect(page.locator('[data-testid="schedule-list"]')).toBeVisible();

    // Select a shift to modify
    const shift = page.locator('[data-testid="schedule-list-item"]').first();
    await shift.click();
    await page.click('[data-testid="edit-shift-button"]');
    await expect(page.locator('[data-testid="shift-modification-form"]')).toBeVisible();

    // Attempt to modify to a conflicting time
    await page.fill('[data-testid="shift-date-input"]', new Date().toISOString().split('T')[0]);
    await page.selectOption('[data-testid="shift-template-select"]', { label: 'Morning Shift' });

    // Submit and verify validation
    await page.click('[data-testid="submit-modification-button"]');
    
    // System should prevent conflicts
    const errorMessage = page.locator('[data-testid="conflict-error"]');
    if (await errorMessage.isVisible()) {
      await expect(errorMessage).toContainText('conflict');
    }
  });

  test('Cancel shift without reason shows validation error', async ({ page }) => {
    // Navigate to schedule management page
    await page.goto('/schedule-management');
    await expect(page.locator('[data-testid="schedule-list"]')).toBeVisible();

    // Select a shift to cancel
    await page.locator('[data-testid="schedule-list-item"]').first().click();
    await page.click('[data-testid="cancel-shift-button"]');
    await expect(page.locator('[data-testid="cancellation-form"]')).toBeVisible();

    // Attempt to confirm without entering reason
    await page.click('[data-testid="confirm-cancellation-button"]');

    // Verify validation error for mandatory reason input
    await expect(page.locator('[data-testid="reason-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-validation-error"]')).toContainText('Reason is required');
  });
});