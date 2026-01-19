import { test, expect } from '@playwright/test';

test.describe('Story-18: Modify Task Assignments', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'managerPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful task update with valid data (happy-path)', async ({ page }) => {
    // Navigate to the task management dashboard and select an existing task to edit
    await page.goto('/tasks');
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    await page.click('[data-testid="task-item"]:first-child [data-testid="edit-task-button"]');
    
    // Task edit form is displayed with current task data
    await expect(page.locator('[data-testid="task-edit-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-title-input"]')).not.toBeEmpty();
    
    // Modify the task title to 'Updated Task Title'
    await page.fill('[data-testid="task-title-input"]', 'Updated Task Title');
    
    // Update the task description to include additional details
    await page.fill('[data-testid="task-description-input"]', 'This is an updated task description with additional details for testing purposes');
    
    // Change the deadline to a valid future date
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    const formattedDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="task-deadline-input"]', formattedDate);
    
    // Modify the priority level to a different valid priority value
    await page.selectOption('[data-testid="task-priority-select"]', 'high');
    
    // Reassign the task by removing one employee and adding a different available employee
    await page.click('[data-testid="assigned-employee"]:first-child [data-testid="remove-employee-button"]');
    await page.click('[data-testid="add-employee-button"]');
    await page.selectOption('[data-testid="employee-select"]', { index: 1 });
    await page.click('[data-testid="confirm-add-employee"]');
    
    // Inputs accept changes without validation errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    
    // Click the 'Submit' or 'Update Task' button to save the changes
    await page.click('[data-testid="submit-task-button"]');
    
    // Task is updated successfully, confirmation displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Task updated successfully');
    
    // Verify that notifications have been sent to affected employees
    await expect(page.locator('[data-testid="notification-sent-indicator"]')).toBeVisible();
    
    // Navigate back to the task list and locate the updated task
    await page.goto('/tasks');
    await expect(page.locator('[data-testid="task-item"]').filter({ hasText: 'Updated Task Title' })).toBeVisible();
    
    // Verify the updated task contains the new details
    const updatedTask = page.locator('[data-testid="task-item"]').filter({ hasText: 'Updated Task Title' });
    await expect(updatedTask).toContainText('high');
  });

  test('Verify rejection of invalid task updates (error-case)', async ({ page }) => {
    // Navigate to the task management dashboard and select an existing task to edit
    await page.goto('/tasks');
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    await page.click('[data-testid="task-item"]:first-child [data-testid="edit-task-button"]');
    await expect(page.locator('[data-testid="task-edit-form"]')).toBeVisible();
    
    // Clear the task title field leaving it empty
    await page.fill('[data-testid="task-title-input"]', '');
    
    // Enter a past date in the deadline field (e.g., yesterday's date)
    const pastDate = new Date();
    pastDate.setDate(pastDate.getDate() - 1);
    const formattedPastDate = pastDate.toISOString().split('T')[0];
    await page.fill('[data-testid="task-deadline-input"]', formattedPastDate);
    
    // Enter an invalid priority value or select an option outside the allowed priority range
    await page.selectOption('[data-testid="task-priority-select"]', '');
    
    // Attempt to remove all assigned employees without adding new ones
    const assignedEmployees = await page.locator('[data-testid="assigned-employee"]').count();
    for (let i = 0; i < assignedEmployees; i++) {
      await page.click('[data-testid="assigned-employee"]:first-child [data-testid="remove-employee-button"]');
    }
    
    // Click the 'Submit' or 'Update Task' button while validation errors are present
    await page.click('[data-testid="submit-task-button"]');
    
    // Validation errors are displayed
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="title-error"]')).toContainText('Title is required');
    await expect(page.locator('[data-testid="deadline-error"]')).toContainText('Deadline must be a future date');
    await expect(page.locator('[data-testid="priority-error"]')).toContainText('Priority is required');
    await expect(page.locator('[data-testid="employee-error"]')).toContainText('At least one employee must be assigned');
    
    // Submission blocked - verify we're still on the edit page
    await expect(page.locator('[data-testid="task-edit-form"]')).toBeVisible();
    
    // Correct the task title by entering a valid title
    await page.fill('[data-testid="task-title-input"]', 'Valid Task Title');
    await expect(page.locator('[data-testid="title-error"]')).not.toBeVisible();
    
    // Correct the deadline by entering a valid future date
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 5);
    const formattedFutureDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="task-deadline-input"]', formattedFutureDate);
    await expect(page.locator('[data-testid="deadline-error"]')).not.toBeVisible();
    
    // Select a valid priority value
    await page.selectOption('[data-testid="task-priority-select"]', 'medium');
    await expect(page.locator('[data-testid="priority-error"]')).not.toBeVisible();
    
    // Assign at least one valid employee to the task
    await page.click('[data-testid="add-employee-button"]');
    await page.selectOption('[data-testid="employee-select"]', { index: 1 });
    await page.click('[data-testid="confirm-add-employee"]');
    await expect(page.locator('[data-testid="employee-error"]')).not.toBeVisible();
    
    // Click the 'Submit' or 'Update Task' button after correcting all errors
    await page.click('[data-testid="submit-task-button"]');
    
    // Verify successful submission
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Task updated successfully');
  });

  test('Ensure notifications are sent upon reassignment (happy-path)', async ({ page }) => {
    // Navigate to the task management dashboard and select an existing task with assigned employees
    await page.goto('/tasks');
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    await page.click('[data-testid="task-item"]:first-child [data-testid="edit-task-button"]');
    await expect(page.locator('[data-testid="task-edit-form"]')).toBeVisible();
    
    // Note the currently assigned employees for reference
    const initialEmployeeCount = await page.locator('[data-testid="assigned-employee"]').count();
    expect(initialEmployeeCount).toBeGreaterThan(0);
    const firstEmployeeName = await page.locator('[data-testid="assigned-employee"]:first-child [data-testid="employee-name"]').textContent();
    
    // Remove one or more currently assigned employees from the task
    await page.click('[data-testid="assigned-employee"]:first-child [data-testid="remove-employee-button"]');
    
    // Add one or more different available employees to the task assignment
    await page.click('[data-testid="add-employee-button"]');
    await page.selectOption('[data-testid="employee-select"]', { index: 2 });
    await page.click('[data-testid="confirm-add-employee"]');
    const newEmployeeName = await page.locator('[data-testid="assigned-employee"]:last-child [data-testid="employee-name"]').textContent();
    
    // Click the 'Submit' or 'Update Task' button to save the reassignment
    const beforeSubmitTime = new Date();
    await page.click('[data-testid="submit-task-button"]');
    
    // Task update is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Task updated successfully');
    
    // Access the notification system or notification log to verify sent notifications
    await page.goto('/notifications');
    await expect(page.locator('[data-testid="notification-log"]')).toBeVisible();
    
    // Verify notification was sent to the newly assigned employee(s)
    const newEmployeeNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: newEmployeeName });
    await expect(newEmployeeNotification).toBeVisible();
    await expect(newEmployeeNotification).toContainText('assigned to task');
    
    // Verify notification was sent to the previously assigned employee(s) who were removed
    const removedEmployeeNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: firstEmployeeName });
    await expect(removedEmployeeNotification).toBeVisible();
    await expect(removedEmployeeNotification).toContainText('removed from task');
    
    // Check the content of the notifications to ensure they contain relevant task information
    await expect(newEmployeeNotification).toContainText('Task');
    await expect(removedEmployeeNotification).toContainText('Task');
    
    // Verify the timestamp of notifications to ensure they were sent within the 5-second requirement
    const newEmployeeTimestamp = await newEmployeeNotification.locator('[data-testid="notification-timestamp"]').textContent();
    const removedEmployeeTimestamp = await removedEmployeeNotification.locator('[data-testid="notification-timestamp"]').textContent();
    
    // Parse timestamps and verify they are within 5 seconds of submission
    const afterSubmitTime = new Date();
    const timeDifference = (afterSubmitTime.getTime() - beforeSubmitTime.getTime()) / 1000;
    expect(timeDifference).toBeLessThanOrEqual(5);
  });
});