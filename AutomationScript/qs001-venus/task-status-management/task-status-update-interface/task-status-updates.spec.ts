import { test, expect } from '@playwright/test';

test.describe('Task Status Updates - Employee Progress Tracking', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and authenticate
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*tasks/);
  });

  test('Validate successful status update with valid input', async ({ page }) => {
    // Step 1: Navigate to the task detail page by clicking on an assigned task from the task list
    await page.click('[data-testid="task-list-item"]:first-child');
    await expect(page.locator('[data-testid="task-detail-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-task-status"]')).toBeVisible();
    const currentStatus = await page.locator('[data-testid="current-task-status"]').textContent();
    expect(currentStatus).toBeTruthy();

    // Step 2: Click on the status dropdown menu to view available status options
    await page.click('[data-testid="status-dropdown"]');
    await expect(page.locator('[data-testid="status-dropdown-menu"]')).toBeVisible();

    // Step 3: Select a valid new status from the dropdown menu (e.g., change from 'In Progress' to 'Completed')
    await page.click('[data-testid="status-option-completed"]');
    const selectedStatus = await page.locator('[data-testid="status-dropdown"]').textContent();
    expect(selectedStatus).toContain('Completed');

    // Step 4: Click the 'Submit' or 'Update Status' button to save the status change
    await page.click('[data-testid="update-status-button"]');
    
    // Verify system confirms successful update with a message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Status updated successfully');

    // Step 5: Navigate back to the task list view
    await page.click('[data-testid="back-to-task-list"]');
    await expect(page).toHaveURL(/.*tasks/);
    
    // Verify the updated status is reflected in the task list
    await expect(page.locator('[data-testid="task-list-item"]:first-child [data-testid="task-status"]')).toContainText('Completed');
  });

  test('Verify rejection of invalid status transition', async ({ page }) => {
    // Step 1: Navigate to the task detail page by selecting a task with a status that has restricted transitions
    await page.click('[data-testid="task-list-item"][data-status="completed"]:first-child');
    await expect(page.locator('[data-testid="task-detail-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-task-status"]')).toContainText('Completed');

    // Step 2: Click on the status dropdown to view available options
    await page.click('[data-testid="status-dropdown"]');
    await expect(page.locator('[data-testid="status-dropdown-menu"]')).toBeVisible();

    // Attempt to select an invalid status transition (e.g., from 'Completed' to 'Not Started')
    const invalidOption = page.locator('[data-testid="status-option-not-started"]');
    
    // Verify invalid status options are disabled
    if (await invalidOption.isVisible()) {
      await expect(invalidOption).toBeDisabled();
    }

    // If the invalid status was somehow selectable, attempt to click it
    const isEnabled = await invalidOption.isEnabled().catch(() => false);
    if (isEnabled) {
      await invalidOption.click();
      
      // Step 3: Click the 'Submit' or 'Update Status' button
      await page.click('[data-testid="update-status-button"]');
      
      // System blocks submission and displays error message
      await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
      await expect(page.locator('[data-testid="error-message"]')).toContainText('Invalid status transition');
    }

    // Step 4: Verify that the task status has not changed by checking the current status display
    await expect(page.locator('[data-testid="current-task-status"]')).toContainText('Completed');

    // Step 5: Navigate to the task list and verify the task status
    await page.click('[data-testid="back-to-task-list"]');
    await expect(page.locator('[data-testid="task-list-item"][data-status="completed"]:first-child [data-testid="task-status"]')).toContainText('Completed');
  });

  test('Ensure status update works on mobile devices', async ({ page, context }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });

    // Step 1: Open the task management application on a mobile device and navigate to the task list
    await page.goto('/tasks');
    await expect(page.locator('[data-testid="task-list-container"]')).toBeVisible();
    
    // Verify interface is responsive and usable
    const taskListContainer = page.locator('[data-testid="task-list-container"]');
    await expect(taskListContainer).toBeVisible();
    const boundingBox = await taskListContainer.boundingBox();
    expect(boundingBox?.width).toBeLessThanOrEqual(375);

    // Step 2: Tap on a task to access the task update interface
    await page.click('[data-testid="task-list-item"]:first-child');
    await expect(page.locator('[data-testid="task-detail-container"]')).toBeVisible();

    // Step 3: Tap on the status dropdown to view available status options
    await page.click('[data-testid="status-dropdown"]');
    await expect(page.locator('[data-testid="status-dropdown-menu"]')).toBeVisible();

    // Step 4: Select a valid new status from the dropdown by tapping on it
    await page.click('[data-testid="status-option-in-progress"]');
    await expect(page.locator('[data-testid="status-dropdown"]')).toContainText('In Progress');

    // Step 5: Tap the 'Submit' or 'Update Status' button to save the change
    await page.click('[data-testid="update-status-button"]');
    
    // Update is processed successfully with confirmation
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Status updated successfully');

    // Step 6: Navigate back to the task list view by using the back button or navigation menu
    await page.click('[data-testid="back-to-task-list"]');
    await expect(page).toHaveURL(/.*tasks/);

    // Step 7: Verify the status change persists in the task list
    await expect(page.locator('[data-testid="task-list-item"]:first-child [data-testid="task-status"]')).toContainText('In Progress');

    // Step 8: Verify the status change persists by closing and reopening the application
    await page.close();
    const newPage = await context.newPage();
    await newPage.setViewportSize({ width: 375, height: 667 });
    await newPage.goto('/tasks');
    await expect(newPage.locator('[data-testid="task-list-item"]:first-child [data-testid="task-status"]')).toContainText('In Progress');
    await newPage.close();
  });
});