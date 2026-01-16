import { test, expect } from '@playwright/test';

test.describe('Task Assignment Confirmation Messages', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the task assignment page
    await page.goto('/task-assignment');
    // Assume manager is already authenticated
    await page.waitForLoadState('networkidle');
  });

  test('Display confirmation message after successful assignment (happy-path)', async ({ page }) => {
    // Select a task from the available tasks list
    await page.click('[data-testid="task-list"]');
    await page.click('[data-testid="task-item"]:first-child');
    const taskTitle = await page.locator('[data-testid="task-item"]:first-child').textContent();

    // Select an employee from the employee list to assign the task to
    await page.click('[data-testid="employee-list"]');
    await page.click('[data-testid="employee-item"]:first-child');
    const employeeName = await page.locator('[data-testid="employee-item"]:first-child').textContent();

    // Click the 'Assign Task' button to complete the assignment
    await page.click('[data-testid="assign-task-button"]');

    // Observe the screen for confirmation message
    const confirmationMessage = page.locator('[data-testid="confirmation-message"]');
    await expect(confirmationMessage).toBeVisible({ timeout: 1000 });

    // Verify the confirmation message contains task title
    await expect(confirmationMessage).toContainText(taskTitle || '');

    // Verify the confirmation message contains assignee details
    await expect(confirmationMessage).toContainText(employeeName || '');

    // Wait for the message timeout period or click dismiss button if available
    const dismissButton = page.locator('[data-testid="dismiss-confirmation"]');
    if (await dismissButton.isVisible()) {
      await dismissButton.click();
    } else {
      await page.waitForTimeout(3000);
    }

    // Verify the confirmation message disappears appropriately
    await expect(confirmationMessage).not.toBeVisible();

    // Verify the task assignment is reflected in the system
    await page.goto('/tasks');
    const assignedTask = page.locator(`[data-testid="assigned-task"][data-task-title="${taskTitle}"]`);
    await expect(assignedTask).toBeVisible();
    await expect(assignedTask).toContainText(employeeName || '');
  });

  test('Display error message on assignment failure (error-case)', async ({ page }) => {
    // Select a task from the available tasks list
    await page.click('[data-testid="task-list"]');
    await page.click('[data-testid="task-item"]:first-child');
    const taskTitle = await page.locator('[data-testid="task-item"]:first-child').textContent();

    // Attempt to assign a task with invalid data (select a task but no employee)
    // Do not select an employee - leave employee selection empty

    // Click the 'Assign Task' button with invalid data
    await page.click('[data-testid="assign-task-button"]');

    // Observe the screen for error message
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible();

    // Verify the error message is user-friendly and provides actionable information
    await expect(errorMessage).toContainText(/employee|select|required/i);

    // Correct the invalid data by properly selecting both a valid task and a valid employee
    await page.click('[data-testid="employee-list"]');
    await page.click('[data-testid="employee-item"]:first-child');
    const employeeName = await page.locator('[data-testid="employee-item"]:first-child').textContent();

    // Click the 'Assign Task' button again with corrected data
    await page.click('[data-testid="assign-task-button"]');

    // Observe the screen for confirmation message
    const confirmationMessage = page.locator('[data-testid="confirmation-message"]');
    await expect(confirmationMessage).toBeVisible({ timeout: 1000 });

    // Verify the confirmation message contains task and assignee details
    await expect(confirmationMessage).toContainText(taskTitle || '');
    await expect(confirmationMessage).toContainText(employeeName || '');

    // Verify the task assignment is now reflected in the system
    await page.goto('/tasks');
    const assignedTask = page.locator(`[data-testid="assigned-task"][data-task-title="${taskTitle}"]`);
    await expect(assignedTask).toBeVisible();
    await expect(assignedTask).toContainText(employeeName || '');
  });

  test('Confirmation message appears within 1 second of assignment completion', async ({ page }) => {
    // Select a task from the available tasks list
    await page.click('[data-testid="task-list"]');
    await page.click('[data-testid="task-item"]:first-child');

    // Select an employee from the employee list
    await page.click('[data-testid="employee-list"]');
    await page.click('[data-testid="employee-item"]:first-child');

    // Record the time before clicking assign
    const startTime = Date.now();

    // Click the 'Assign Task' button
    await page.click('[data-testid="assign-task-button"]');

    // Wait for confirmation message and verify it appears within 1 second
    const confirmationMessage = page.locator('[data-testid="confirmation-message"]');
    await expect(confirmationMessage).toBeVisible({ timeout: 1000 });

    const endTime = Date.now();
    const elapsedTime = endTime - startTime;

    // Verify the confirmation appeared within 1 second (1000ms)
    expect(elapsedTime).toBeLessThanOrEqual(1000);
  });
});