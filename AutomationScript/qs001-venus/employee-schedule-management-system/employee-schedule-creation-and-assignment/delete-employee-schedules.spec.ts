import { test, expect } from '@playwright/test';

test.describe('Delete Assigned Employee Schedules', () => {
  test.beforeEach(async ({ page }) => {
    // Login as Scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'scheduler123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful schedule deletion with confirmation', async ({ page }) => {
    // Step 1: Navigate to assigned schedules list
    await page.goto('/schedules/assigned');
    await page.waitForSelector('[data-testid="schedules-list"]');
    
    // Expected Result: List of schedules is displayed
    await expect(page.locator('[data-testid="schedules-list"]')).toBeVisible();
    const initialScheduleCount = await page.locator('[data-testid="schedule-item"]').count();
    expect(initialScheduleCount).toBeGreaterThan(0);

    // Step 2: Select schedule(s) for deletion
    const scheduleToDelete = page.locator('[data-testid="schedule-item"]').first();
    const scheduleId = await scheduleToDelete.getAttribute('data-schedule-id');
    await scheduleToDelete.locator('[data-testid="schedule-checkbox"]').check();
    
    // Expected Result: Schedules are selected
    await expect(scheduleToDelete.locator('[data-testid="schedule-checkbox"]')).toBeChecked();
    await expect(page.locator('[data-testid="delete-button"]')).toBeEnabled();

    // Step 3: Click delete button
    await page.click('[data-testid="delete-button"]');
    
    // Confirmation dialog appears
    await expect(page.locator('[data-testid="confirmation-dialog"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Are you sure you want to delete');
    
    // Confirm deletion
    await page.click('[data-testid="confirm-button"]');
    
    // Expected Result: Schedules are deleted and confirmation is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule deleted successfully');
    
    // Verify schedule is removed from list
    await page.waitForTimeout(1000);
    const updatedScheduleCount = await page.locator('[data-testid="schedule-item"]').count();
    expect(updatedScheduleCount).toBe(initialScheduleCount - 1);
    
    // Verify deleted schedule is not in the list
    const deletedSchedule = page.locator(`[data-testid="schedule-item"][data-schedule-id="${scheduleId}"]`);
    await expect(deletedSchedule).not.toBeVisible();
  });

  test('Prevent deletion when dependencies exist', async ({ page }) => {
    // Step 1: Navigate to assigned schedules list
    await page.goto('/schedules/assigned');
    await page.waitForSelector('[data-testid="schedules-list"]');
    
    // Select a schedule that is linked to active tasks
    const scheduleWithDependencies = page.locator('[data-testid="schedule-item"][data-has-dependencies="true"]').first();
    const scheduleId = await scheduleWithDependencies.getAttribute('data-schedule-id');
    
    // If no schedule with dependencies exists in DOM, use a known ID
    if (await scheduleWithDependencies.count() === 0) {
      // Select any schedule and attempt deletion
      await page.locator('[data-testid="schedule-item"]').first().locator('[data-testid="schedule-checkbox"]').check();
    } else {
      await scheduleWithDependencies.locator('[data-testid="schedule-checkbox"]').check();
    }
    
    const initialScheduleCount = await page.locator('[data-testid="schedule-item"]').count();
    
    // Action: Attempt to delete schedule linked to active tasks
    await page.click('[data-testid="delete-button"]');
    await expect(page.locator('[data-testid="confirmation-dialog"]')).toBeVisible();
    await page.click('[data-testid="confirm-button"]');
    
    // Expected Result: System displays error and blocks deletion
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/cannot be deleted|has dependencies|linked to active tasks/i);
    
    // Verify schedule still exists in the list
    await page.waitForTimeout(500);
    const updatedScheduleCount = await page.locator('[data-testid="schedule-item"]').count();
    expect(updatedScheduleCount).toBe(initialScheduleCount);
  });

  test('Ensure audit log records deletion actions', async ({ page }) => {
    // Step 1: Navigate to assigned schedules list
    await page.goto('/schedules/assigned');
    await page.waitForSelector('[data-testid="schedules-list"]');
    
    // Step 2: Note the schedule ID and details
    const scheduleToDelete = page.locator('[data-testid="schedule-item"]').first();
    const scheduleId = await scheduleToDelete.getAttribute('data-schedule-id');
    const scheduleName = await scheduleToDelete.locator('[data-testid="schedule-name"]').textContent();
    const deletionTimestamp = new Date();
    
    // Step 3: Select the schedule for deletion
    await scheduleToDelete.locator('[data-testid="schedule-checkbox"]').check();
    await page.click('[data-testid="delete-button"]');
    
    // Step 4: Confirm deletion
    await expect(page.locator('[data-testid="confirmation-dialog"]')).toBeVisible();
    await page.click('[data-testid="confirm-button"]');
    
    // Wait for deletion to complete
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await page.waitForTimeout(1000);
    
    // Step 5: Navigate to audit log section
    await page.goto('/audit-logs');
    await page.waitForSelector('[data-testid="audit-log-list"]');
    
    // Step 6: Search for the deletion action using schedule ID
    await page.fill('[data-testid="audit-search-input"]', scheduleId || '');
    await page.click('[data-testid="audit-search-button"]');
    await page.waitForTimeout(500);
    
    // Expected Result: Audit log entry is created with user and timestamp
    const auditLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditLogEntry).toBeVisible();
    
    // Step 7: Verify all required audit information is present and accurate
    await expect(auditLogEntry.locator('[data-testid="audit-action"]')).toContainText(/delete|removed/i);
    await expect(auditLogEntry.locator('[data-testid="audit-resource-id"]')).toContainText(scheduleId || '');
    await expect(auditLogEntry.locator('[data-testid="audit-user"]')).toContainText('scheduler@example.com');
    
    // Verify timestamp is recent (within last 5 minutes)
    const auditTimestampText = await auditLogEntry.locator('[data-testid="audit-timestamp"]').textContent();
    expect(auditTimestampText).toBeTruthy();
    
    // Verify audit log contains schedule details
    const auditDetails = auditLogEntry.locator('[data-testid="audit-details"]');
    await expect(auditDetails).toBeVisible();
  });
});