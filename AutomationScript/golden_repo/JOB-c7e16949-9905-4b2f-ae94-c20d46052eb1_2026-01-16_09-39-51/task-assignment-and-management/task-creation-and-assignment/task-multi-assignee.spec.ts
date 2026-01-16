import { test, expect } from '@playwright/test';

test.describe('Task Assignment - Multiple Assignees', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'Manager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate task creation with multiple assignees (happy-path)', async ({ page }) => {
    // Navigate to task creation page by clicking on 'Create Task' button or menu option
    await page.click('[data-testid="create-task-button"]');
    await expect(page.locator('[data-testid="task-creation-form"]')).toBeVisible();

    // Enter valid task title in the title field
    await page.fill('[data-testid="task-title-input"]', 'Team Training Session');

    // Enter valid task description in the description field
    await page.fill('[data-testid="task-description-input"]', 'Attend mandatory safety training session');

    // Select a future deadline date and time using the date/time picker
    await page.click('[data-testid="task-deadline-picker"]');
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    const formattedDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="task-deadline-input"]', formattedDate);
    await page.fill('[data-testid="task-time-input"]', '14:00');

    // Select priority level from the priority dropdown
    await page.click('[data-testid="task-priority-dropdown"]');
    await page.click('[data-testid="priority-option-high"]');
    await expect(page.locator('[data-testid="task-priority-dropdown"]')).toContainText('High');

    // Select the first employee from the assignee list
    await page.click('[data-testid="assignee-select-dropdown"]');
    await page.click('[data-testid="employee-checkbox-1"]');
    
    // Select the second employee from the assignee list
    await page.click('[data-testid="employee-checkbox-2"]');
    
    // Select the third employee from the assignee list
    await page.click('[data-testid="employee-checkbox-3"]');

    // Verify that all selected employees are visible in the assignee display area
    await expect(page.locator('[data-testid="selected-assignees-display"]')).toBeVisible();
    const selectedAssignees = page.locator('[data-testid="selected-assignee-item"]');
    await expect(selectedAssignees).toHaveCount(3);

    // Click the 'Submit' or 'Create Task' button to submit the task creation form
    await page.click('[data-testid="submit-task-button"]');

    // Verify the task details in the confirmation message or task list
    await expect(page.locator('[data-testid="task-confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-confirmation-message"]')).toContainText('Team Training Session');
    await expect(page.locator('[data-testid="confirmation-assignees-list"]')).toBeVisible();
    const confirmedAssignees = page.locator('[data-testid="confirmed-assignee-name"]');
    await expect(confirmedAssignees).toHaveCount(3);
  });

  test('Verify validation error when no assignee selected (error-case)', async ({ page }) => {
    // Navigate to task creation page by clicking on 'Create Task' button or menu option
    await page.click('[data-testid="create-task-button"]');
    await expect(page.locator('[data-testid="task-creation-form"]')).toBeVisible();

    // Enter valid task title in the title field
    await page.fill('[data-testid="task-title-input"]', 'Database Backup');

    // Enter valid task description in the description field
    await page.fill('[data-testid="task-description-input"]', 'Perform weekly database backup and verification');

    // Select a future deadline date and time using the date/time picker
    await page.click('[data-testid="task-deadline-picker"]');
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 5);
    const formattedDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="task-deadline-input"]', formattedDate);
    await page.fill('[data-testid="task-time-input"]', '10:00');

    // Select priority level from the priority dropdown
    await page.click('[data-testid="task-priority-dropdown"]');
    await page.click('[data-testid="priority-option-medium"]');
    await expect(page.locator('[data-testid="task-priority-dropdown"]')).toContainText('Medium');

    // Verify that no employee is selected in the assignee field
    const selectedAssigneesBefore = page.locator('[data-testid="selected-assignee-item"]');
    await expect(selectedAssigneesBefore).toHaveCount(0);

    // Click the 'Submit' or 'Create Task' button to attempt form submission without selecting any assignee
    await page.click('[data-testid="submit-task-button"]');

    // Verify that the form submission is blocked
    await expect(page.locator('[data-testid="assignee-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="assignee-validation-error"]')).toContainText('at least one assignee is required');
    
    // Verify form is still visible (not submitted)
    await expect(page.locator('[data-testid="task-creation-form"]')).toBeVisible();

    // Select one employee from the assignee list
    await page.click('[data-testid="assignee-select-dropdown"]');
    await page.click('[data-testid="employee-checkbox-1"]');
    
    // Verify employee is selected
    const selectedAssigneesAfter = page.locator('[data-testid="selected-assignee-item"]');
    await expect(selectedAssigneesAfter).toHaveCount(1);

    // Click the 'Submit' or 'Create Task' button again to resubmit the form with an assignee selected
    await page.click('[data-testid="submit-task-button"]');

    // Verify successful submission
    await expect(page.locator('[data-testid="task-confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-confirmation-message"]')).toContainText('Database Backup');
    await expect(page.locator('[data-testid="assignee-validation-error"]')).not.toBeVisible();
  });
});