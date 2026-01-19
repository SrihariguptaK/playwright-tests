import { test, expect } from '@playwright/test';

test.describe('Task Assignee Acknowledgment of Task Update Notifications', () => {
  test.beforeEach(async ({ page }) => {
    // Login as task assignee
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'assignee@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate task assignee acknowledgment of task update (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the notifications section in the application
    await page.goto('/notifications');
    await expect(page.locator('[data-testid="notifications-section"]')).toBeVisible();

    // Step 2: Locate and click on the task update notification
    const taskUpdateNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Task Update' }).first();
    await expect(taskUpdateNotification).toBeVisible();
    await taskUpdateNotification.click();

    // Verify notification displayed in app
    await expect(page.locator('[data-testid="notification-detail"]')).toBeVisible();

    // Step 3: Click the acknowledge button
    const acknowledgeButton = page.locator('[data-testid="acknowledge-button"]');
    await expect(acknowledgeButton).toBeVisible();
    await acknowledgeButton.click();

    // Step 4: Enter optional comment in the comment field
    const commentField = page.locator('[data-testid="acknowledgment-comment"]');
    await expect(commentField).toBeVisible();
    await commentField.fill('Understood, will complete by deadline');

    // Step 5: Submit the acknowledgment
    await page.click('[data-testid="submit-acknowledgment-button"]');

    // Verify acknowledgment recorded and confirmation shown
    await expect(page.locator('[data-testid="acknowledgment-confirmation"]')).toBeVisible();
    await expect(page.locator('[data-testid="acknowledgment-confirmation"]')).toContainText('Acknowledgment recorded successfully');

    // Step 6: Navigate to system logs or acknowledgment history section
    await page.goto('/acknowledgments/history');
    await expect(page.locator('[data-testid="acknowledgment-history"]')).toBeVisible();

    // Step 7: Verify the acknowledgment record contains correct information
    const acknowledgmentRecord = page.locator('[data-testid="acknowledgment-record"]').first();
    await expect(acknowledgmentRecord).toBeVisible();
    await expect(acknowledgmentRecord).toContainText('Understood, will complete by deadline');
    
    // Verify acknowledgment with timestamp and comment present
    await expect(acknowledgmentRecord.locator('[data-testid="acknowledgment-timestamp"]')).toBeVisible();
    await expect(acknowledgmentRecord.locator('[data-testid="acknowledgment-comment"]')).toContainText('Understood, will complete by deadline');
  });

  test('Ensure acknowledgment processing performance (happy-path)', async ({ page }) => {
    // Step 1: Open the task update notification in the application
    await page.goto('/notifications');
    const taskUpdateNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Task Update' }).first();
    await taskUpdateNotification.click();
    await expect(page.locator('[data-testid="notification-detail"]')).toBeVisible();

    // Step 2: Note the current time and click the acknowledge button
    const startTime = Date.now();
    await page.click('[data-testid="acknowledge-button"]');

    // Step 3: Submit the acknowledgment via the UI
    await page.fill('[data-testid="acknowledgment-comment"]', 'Acknowledged promptly');
    await page.click('[data-testid="submit-acknowledgment-button"]');

    // Step 4: Record the time taken from submission to confirmation
    await expect(page.locator('[data-testid="acknowledgment-confirmation"]')).toBeVisible({ timeout: 5000 });
    const endTime = Date.now();
    const processingTime = endTime - startTime;

    // Verify acknowledgment processed promptly (within 5 seconds)
    expect(processingTime).toBeLessThan(5000);

    // Step 5: Access system logs or admin panel to view acknowledgment entries
    await page.goto('/admin/logs');
    await expect(page.locator('[data-testid="system-logs"]')).toBeVisible();

    // Step 6: Locate the acknowledgment entry just submitted
    const logEntry = page.locator('[data-testid="log-entry"]').filter({ hasText: 'Acknowledged promptly' }).first();
    await expect(logEntry).toBeVisible();

    // Step 7: Verify all details in the log entry
    await expect(logEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(logEntry.locator('[data-testid="log-user"]')).toContainText('assignee@example.com');
    await expect(logEntry.locator('[data-testid="log-action"]')).toContainText('Acknowledgment');
    await expect(logEntry).toContainText('Acknowledged promptly');
  });

  test('Verify system handles missing acknowledgment gracefully (error-case)', async ({ page }) => {
    // Step 1: Open a critical task update notification that requires acknowledgment
    await page.goto('/notifications');
    const criticalNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Critical' }).first();
    await criticalNotification.click();
    await expect(page.locator('[data-testid="notification-detail"]')).toBeVisible();

    // Step 2: Click the acknowledge button without completing any required fields
    await page.click('[data-testid="acknowledge-button"]');
    await expect(page.locator('[data-testid="acknowledgment-form"]')).toBeVisible();

    // Step 3: Attempt to submit the acknowledgment form with missing required fields
    await page.click('[data-testid="submit-acknowledgment-button"]');

    // Verify system displays validation errors and blocks submission
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('required');

    // Step 4: Verify that the notification status remains unchanged
    const notificationStatus = page.locator('[data-testid="notification-status"]');
    await expect(notificationStatus).toContainText('Unacknowledged');

    // Step 5: Complete all required fields in the acknowledgment form
    const requiredCommentField = page.locator('[data-testid="acknowledgment-comment"]');
    await requiredCommentField.fill('Critical task acknowledged and understood');

    // Check for any other required fields
    const requiredCheckbox = page.locator('[data-testid="acknowledgment-confirmation-checkbox"]');
    if (await requiredCheckbox.isVisible()) {
      await requiredCheckbox.check();
    }

    // Step 6: Resubmit the acknowledgment with all required fields completed
    await page.click('[data-testid="submit-acknowledgment-button"]');

    // Verify acknowledgment accepted and logged
    await expect(page.locator('[data-testid="acknowledgment-confirmation"]')).toBeVisible();
    await expect(page.locator('[data-testid="acknowledgment-confirmation"]')).toContainText('successfully');

    // Step 7: Verify the acknowledgment is logged in the system
    await page.goto('/acknowledgments/history');
    const acknowledgmentRecord = page.locator('[data-testid="acknowledgment-record"]').filter({ hasText: 'Critical task acknowledged and understood' }).first();
    await expect(acknowledgmentRecord).toBeVisible();

    // Step 8: Check the notification status after successful acknowledgment
    await page.goto('/notifications');
    const acknowledgedNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Critical' }).first();
    await acknowledgedNotification.click();
    await expect(page.locator('[data-testid="notification-status"]')).toContainText('Acknowledged');
  });
});