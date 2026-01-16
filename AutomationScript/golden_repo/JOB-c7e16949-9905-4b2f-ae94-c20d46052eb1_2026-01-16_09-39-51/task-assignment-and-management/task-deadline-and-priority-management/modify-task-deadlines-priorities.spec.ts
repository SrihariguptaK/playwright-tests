import { test, expect } from '@playwright/test';

test.describe('Story-16: Modify Task Deadlines and Priorities', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const testTaskName = 'Sample Task for Editing';

  test.beforeEach(async ({ page }) => {
    // Login as Manager
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful update of deadline and priority', async ({ page }) => {
    // Step 1: Navigate to task edit page
    await page.goto(`${baseURL}/tasks`);
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    
    // Locate and click on the task to edit
    const taskRow = page.locator(`[data-testid="task-row"]:has-text("${testTaskName}")`).first();
    await expect(taskRow).toBeVisible();
    await taskRow.click();
    
    // Click edit button
    await page.click('[data-testid="edit-task-button"]');
    await expect(page.locator('[data-testid="task-edit-form"]')).toBeVisible();
    
    // Step 2: Modify deadline to a valid future date and priority to a valid level
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    const formattedDate = futureDate.toISOString().split('T')[0];
    
    await page.fill('[data-testid="deadline-input"]', formattedDate);
    await page.selectOption('[data-testid="priority-select"]', 'High');
    
    // Verify no validation errors
    await expect(page.locator('[data-testid="deadline-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="priority-error"]')).not.toBeVisible();
    
    // Step 3: Submit the form
    await page.click('[data-testid="submit-task-button"]');
    
    // Wait for success message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Task updated successfully');
    
    // Verify task updates are saved and reflected in task views
    await page.goto(`${baseURL}/tasks`);
    const updatedTask = page.locator(`[data-testid="task-row"]:has-text("${testTaskName}")`).first();
    await expect(updatedTask.locator('[data-testid="task-deadline"]')).toContainText(formattedDate);
    await expect(updatedTask.locator('[data-testid="task-priority"]')).toContainText('High');
    
    // Verify notification was sent to assignee
    await page.goto(`${baseURL}/notifications`);
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toContainText('Task updated');
    await expect(notification).toContainText(testTaskName);
  });

  test('Verify rejection of invalid deadline during edit', async ({ page }) => {
    // Step 1: Navigate to task edit page
    await page.goto(`${baseURL}/tasks`);
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    
    // Locate and click on the task to edit
    const taskRow = page.locator(`[data-testid="task-row"]:has-text("${testTaskName}")`).first();
    await expect(taskRow).toBeVisible();
    
    // Store original deadline for verification
    const originalDeadline = await taskRow.locator('[data-testid="task-deadline"]').textContent();
    
    await taskRow.click();
    
    // Click edit button
    await page.click('[data-testid="edit-task-button"]');
    await expect(page.locator('[data-testid="task-edit-form"]')).toBeVisible();
    
    // Step 2: Set deadline to a past date
    const pastDate = new Date();
    pastDate.setDate(pastDate.getDate() - 5);
    const formattedPastDate = pastDate.toISOString().split('T')[0];
    
    await page.fill('[data-testid="deadline-input"]', formattedPastDate);
    
    // Click outside the deadline field to trigger validation
    await page.click('[data-testid="priority-select"]');
    
    // Verify validation error is displayed
    await expect(page.locator('[data-testid="deadline-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="deadline-error"]')).toContainText(/past|invalid|cannot be before/);
    
    // Step 3: Attempt to submit form
    await page.click('[data-testid="submit-task-button"]');
    
    // Verify submission is blocked
    await expect(page.locator('[data-testid="task-edit-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="deadline-error"]')).toBeVisible();
    
    // Verify no success message appears
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
    
    // Cancel the edit
    await page.click('[data-testid="cancel-edit-button"]');
    
    // Verify task retains original deadline value
    await page.goto(`${baseURL}/tasks`);
    const unchangedTask = page.locator(`[data-testid="task-row"]:has-text("${testTaskName}")`).first();
    await expect(unchangedTask.locator('[data-testid="task-deadline"]')).toContainText(originalDeadline || '');
  });

  test('Validate successful update of deadline and priority - detailed flow', async ({ page }) => {
    // Navigate to the task list page
    await page.goto(`${baseURL}/tasks`);
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    
    // Locate a specific task to edit
    const taskToEdit = page.locator('[data-testid="task-row"]').first();
    await expect(taskToEdit).toBeVisible();
    
    // Click on the task or select the Edit button/icon
    const editButton = taskToEdit.locator('[data-testid="edit-icon"]');
    if (await editButton.isVisible()) {
      await editButton.click();
    } else {
      await taskToEdit.click();
      await page.click('[data-testid="edit-task-button"]');
    }
    
    // Verify task edit form is displayed
    await expect(page.locator('[data-testid="task-edit-form"]')).toBeVisible();
    
    // Modify the deadline field by selecting a valid future date (at least 1 day from current date)
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 3);
    const newDeadline = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="deadline-input"]', newDeadline);
    
    // Modify the priority field by selecting a different valid priority level
    await page.selectOption('[data-testid="priority-select"]', 'Medium');
    
    // Click the Save or Submit button to save the changes
    await page.click('[data-testid="submit-task-button"]');
    
    // Wait for save operation to complete
    await page.waitForResponse(response => 
      response.url().includes('/api/tasks/') && response.status() === 200,
      { timeout: 5000 }
    );
    
    // Verify the task details reflect the updated deadline and priority
    await page.goto(`${baseURL}/tasks`);
    const updatedTaskRow = page.locator('[data-testid="task-row"]').first();
    await expect(updatedTaskRow.locator('[data-testid="task-deadline"]')).toContainText(newDeadline);
    await expect(updatedTaskRow.locator('[data-testid="task-priority"]')).toContainText('Medium');
    
    // Check that a notification was sent to the task assignee
    await page.goto(`${baseURL}/notifications`);
    await expect(page.locator('[data-testid="notification-list"]')).toBeVisible();
    const latestNotification = page.locator('[data-testid="notification-item"]').first();
    await expect(latestNotification).toContainText(/updated|modified/);
  });

  test('Verify rejection of invalid deadline during edit - detailed flow', async ({ page }) => {
    // Navigate to the task list page
    await page.goto(`${baseURL}/tasks`);
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    
    // Locate a specific task to edit
    const taskToEdit = page.locator('[data-testid="task-row"]').first();
    await expect(taskToEdit).toBeVisible();
    
    // Store original deadline for later verification
    const originalDeadlineText = await taskToEdit.locator('[data-testid="task-deadline"]').textContent();
    
    // Click on the task or select the Edit button/icon
    const editButton = taskToEdit.locator('[data-testid="edit-icon"]');
    if (await editButton.isVisible()) {
      await editButton.click();
    } else {
      await taskToEdit.click();
      await page.click('[data-testid="edit-task-button"]');
    }
    
    // Verify task edit form is displayed
    await expect(page.locator('[data-testid="task-edit-form"]')).toBeVisible();
    
    // Modify the deadline field by selecting or entering a past date
    const pastDate = new Date();
    pastDate.setDate(pastDate.getDate() - 3);
    const invalidDeadline = pastDate.toISOString().split('T')[0];
    await page.fill('[data-testid="deadline-input"]', invalidDeadline);
    
    // Click outside the deadline field or tab to the next field to trigger validation
    await page.press('[data-testid="deadline-input"]', 'Tab');
    
    // Wait for validation to trigger
    await page.waitForTimeout(500);
    
    // Verify validation error is displayed
    const validationError = page.locator('[data-testid="deadline-error"]');
    await expect(validationError).toBeVisible();
    await expect(validationError).toContainText(/past|cannot|invalid/);
    
    // Attempt to submit the form by clicking the Save or Submit button
    await page.click('[data-testid="submit-task-button"]');
    
    // Verify submission is blocked (form still visible, error still displayed)
    await expect(page.locator('[data-testid="task-edit-form"]')).toBeVisible();
    await expect(validationError).toBeVisible();
    
    // Cancel the edit
    const cancelButton = page.locator('[data-testid="cancel-edit-button"]');
    if (await cancelButton.isVisible()) {
      await cancelButton.click();
    } else {
      await page.keyboard.press('Escape');
    }
    
    // Verify that the task retains its original deadline value
    await page.goto(`${baseURL}/tasks`);
    const unchangedTaskRow = page.locator('[data-testid="task-row"]').first();
    await expect(unchangedTaskRow.locator('[data-testid="task-deadline"]')).toContainText(originalDeadlineText || '');
  });
});