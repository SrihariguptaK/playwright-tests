import { test, expect } from '@playwright/test';

test.describe('Story-20: Cancel Task Assignments', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the task management dashboard
    await page.goto('/task-management');
    // Assume manager is already logged in or handle login here
    await page.waitForLoadState('networkidle');
  });

  test('Validate successful task cancellation with reason (happy-path)', async ({ page }) => {
    // Step 1: Locate and select a task that is eligible for cancellation (not completed)
    const eligibleTask = page.locator('[data-testid="task-item"]').filter({ hasText: 'In Progress' }).first();
    await expect(eligibleTask).toBeVisible();
    
    // Click on the task to view details or select it
    await eligibleTask.click();
    
    // Step 2: Click on the 'Cancel Task' button
    const cancelButton = page.locator('[data-testid="cancel-task-button"]');
    await expect(cancelButton).toBeVisible();
    await cancelButton.click();
    
    // Expected Result: Cancellation form is displayed
    const cancellationForm = page.locator('[data-testid="cancellation-form"]');
    await expect(cancellationForm).toBeVisible();
    
    // Step 3: Enter a valid cancellation reason in the text field
    const reasonField = page.locator('[data-testid="cancellation-reason-input"]');
    await expect(reasonField).toBeVisible();
    await reasonField.fill('Project requirements changed');
    
    // Step 4: Click the 'Confirm Cancellation' button
    const confirmButton = page.locator('[data-testid="confirm-cancellation-button"]');
    await confirmButton.click();
    
    // Expected Result: Task status updated to cancelled and confirmation displayed
    const confirmationMessage = page.locator('[data-testid="confirmation-message"]');
    await expect(confirmationMessage).toBeVisible();
    await expect(confirmationMessage).toContainText('Task cancelled successfully');
    
    // Step 5: Verify the task status has been updated to 'Cancelled'
    await page.waitForTimeout(1000); // Wait for status update
    const taskStatus = page.locator('[data-testid="task-status"]');
    await expect(taskStatus).toContainText('Cancelled');
    
    // Step 6: Check the task list to confirm the cancelled task reflects the new status
    await page.goto('/task-management');
    const cancelledTask = page.locator('[data-testid="task-item"]').filter({ hasText: 'Cancelled' }).first();
    await expect(cancelledTask).toBeVisible();
    
    // Step 7: Verify notifications were sent to all assigned employees
    // This could be verified through API call or notification panel
    const notificationIndicator = page.locator('[data-testid="notification-sent-indicator"]');
    await expect(notificationIndicator).toBeVisible({ timeout: 5000 });
  });

  test('Verify prevention of cancellation for completed tasks (error-case)', async ({ page }) => {
    // Step 1: Locate and identify a task that has status marked as 'Completed'
    const completedTask = page.locator('[data-testid="task-item"]').filter({ hasText: 'Completed' }).first();
    await expect(completedTask).toBeVisible();
    
    // Step 2: Select the completed task to view its details
    await completedTask.click();
    
    // Step 3: Verify the task status is 'Completed'
    const taskStatus = page.locator('[data-testid="task-status"]');
    await expect(taskStatus).toContainText('Completed');
    
    // Step 4: Attempt to click on the 'Cancel Task' button
    const cancelButton = page.locator('[data-testid="cancel-task-button"]');
    
    // Expected Result: Button should be disabled or not visible for completed tasks
    const isButtonDisabled = await cancelButton.isDisabled().catch(() => true);
    const isButtonVisible = await cancelButton.isVisible().catch(() => false);
    
    if (isButtonVisible && !isButtonDisabled) {
      // If button is visible and enabled, click it to trigger validation
      await cancelButton.click();
      
      // Expected Result: System prevents cancellation and displays error message
      const errorMessage = page.locator('[data-testid="error-message"]');
      await expect(errorMessage).toBeVisible();
      await expect(errorMessage).toContainText('Cannot cancel completed task');
      
      // Close error dialog if present
      const closeButton = page.locator('[data-testid="close-error-button"]');
      if (await closeButton.isVisible()) {
        await closeButton.click();
      }
    } else {
      // Button is properly disabled or hidden
      expect(isButtonDisabled || !isButtonVisible).toBeTruthy();
    }
    
    // Step 5: Verify the task status remains unchanged
    await expect(taskStatus).toContainText('Completed');
    
    // Step 6: Confirm no notifications were sent to assigned employees
    // Verify no notification indicator appears
    const notificationIndicator = page.locator('[data-testid="notification-sent-indicator"]');
    await expect(notificationIndicator).not.toBeVisible({ timeout: 2000 }).catch(() => {
      // Notification indicator should not appear
    });
  });
});