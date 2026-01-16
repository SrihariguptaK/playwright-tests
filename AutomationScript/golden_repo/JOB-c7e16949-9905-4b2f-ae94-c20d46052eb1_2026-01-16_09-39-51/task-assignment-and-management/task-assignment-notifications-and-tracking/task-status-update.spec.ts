import { test, expect } from '@playwright/test';

test.describe('Story-14: Task Status Update', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page and authenticate as employee
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'employeePassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful task status update', async ({ page }) => {
    // Step 1: Employee navigates to 'My Tasks' or 'Assigned Tasks' section
    await page.click('[data-testid="my-tasks-link"]');
    await expect(page.locator('[data-testid="tasks-page-header"]')).toBeVisible();

    // Step 2: Employee identifies and clicks on a specific assigned task from the list
    const taskRow = page.locator('[data-testid="task-row"]').first();
    const taskTitle = await taskRow.locator('[data-testid="task-title"]').textContent();
    await taskRow.click();

    // Expected Result: Task details are displayed
    await expect(page.locator('[data-testid="task-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-details-title"]')).toContainText(taskTitle || '');

    // Step 3: Employee locates the status field or status update dropdown
    const statusDropdown = page.locator('[data-testid="task-status-dropdown"]');
    await expect(statusDropdown).toBeVisible();

    // Step 4: Employee selects 'In Progress' from the status dropdown menu
    await statusDropdown.click();
    await page.locator('[data-testid="status-option-in-progress"]').click();

    // Expected Result: Status update is accepted without errors
    await expect(statusDropdown).toContainText('In Progress');

    // Step 5: Employee clicks 'Save' or 'Update Status' button to submit the status change
    await page.click('[data-testid="update-status-button"]');

    // Expected Result: Status is saved and manager is notified
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Status updated successfully');

    // Step 6: Employee verifies the updated status is reflected in the task details page
    await expect(page.locator('[data-testid="task-status-display"]')).toContainText('In Progress');

    // Step 7: Employee navigates back to the task list view
    await page.click('[data-testid="back-to-tasks-button"]');
    await expect(page.locator('[data-testid="tasks-page-header"]')).toBeVisible();

    // Verify status is updated in the task list
    const updatedTaskRow = page.locator('[data-testid="task-row"]').filter({ hasText: taskTitle || '' });
    await expect(updatedTaskRow.locator('[data-testid="task-status-badge"]')).toContainText('In Progress');

    // Step 8: Verify manager notification (simulate checking as manager)
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Login as manager to verify notification
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'managerPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Check notifications
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-item"]').first()).toContainText('status updated');
  });

  test('Verify rejection of invalid status transitions', async ({ page }) => {
    // Step 1: Employee logs into the system and navigates to the assigned tasks list
    await page.click('[data-testid="my-tasks-link"]');
    await expect(page.locator('[data-testid="tasks-page-header"]')).toBeVisible();

    // Step 2: Employee selects a task that is currently in 'Completed' status
    // First, filter tasks to find one with 'Completed' status
    const completedTask = page.locator('[data-testid="task-row"]').filter({ 
      has: page.locator('[data-testid="task-status-badge"]', { hasText: 'Completed' })
    }).first();

    // If no completed task exists, create one for testing
    const completedTaskCount = await completedTask.count();
    if (completedTaskCount === 0) {
      // Select any task and set it to completed first
      await page.locator('[data-testid="task-row"]').first().click();
      await page.locator('[data-testid="task-status-dropdown"]').click();
      await page.locator('[data-testid="status-option-completed"]').click();
      await page.click('[data-testid="update-status-button"]');
      await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
      await page.click('[data-testid="back-to-tasks-button"]');
    }

    // Now select the completed task
    await page.locator('[data-testid="task-row"]').filter({ 
      has: page.locator('[data-testid="task-status-badge"]', { hasText: 'Completed' })
    }).first().click();

    await expect(page.locator('[data-testid="task-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-status-display"]')).toContainText('Completed');

    // Step 3: Employee attempts to change the status from 'Completed' to 'Not Started' (invalid backward transition)
    const statusDropdown = page.locator('[data-testid="task-status-dropdown"]');
    await statusDropdown.click();
    await page.locator('[data-testid="status-option-not-started"]').click();

    // Step 4: Employee clicks 'Save' or 'Update Status' button to submit the invalid status change
    await page.click('[data-testid="update-status-button"]');

    // Expected Result: System displays validation error and blocks update
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/invalid.*transition|not allowed|cannot change/i);

    // Step 5: System processes the validation and responds to the invalid transition attempt
    // Verify error message contains relevant information
    const errorMessage = await page.locator('[data-testid="error-message"]').textContent();
    expect(errorMessage).toBeTruthy();

    // Step 6: Employee verifies the task status remains unchanged
    await expect(page.locator('[data-testid="task-status-display"]')).toContainText('Completed');

    // Step 7: Employee dismisses the error message and checks available status options
    await page.click('[data-testid="close-error-button"]');
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();

    // Verify status dropdown still shows Completed
    await expect(statusDropdown).toContainText('Completed');

    // Check that only valid transitions are available
    await statusDropdown.click();
    const statusOptions = page.locator('[data-testid^="status-option-"]');
    const optionsCount = await statusOptions.count();
    expect(optionsCount).toBeGreaterThan(0);

    // Verify 'Not Started' option is either disabled or not present for completed tasks
    const notStartedOption = page.locator('[data-testid="status-option-not-started"]');
    const isNotStartedDisabled = await notStartedOption.getAttribute('disabled');
    const isNotStartedVisible = await notStartedOption.isVisible().catch(() => false);
    
    if (isNotStartedVisible) {
      expect(isNotStartedDisabled).toBeTruthy();
    }
  });
});