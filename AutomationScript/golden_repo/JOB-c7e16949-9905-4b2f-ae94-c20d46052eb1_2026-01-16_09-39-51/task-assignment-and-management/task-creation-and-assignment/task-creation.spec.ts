import { test, expect } from '@playwright/test';

test.describe('Task Creation - story-9', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful task creation with valid input', async ({ page }) => {
    // Step 1: Navigate to task creation page
    await page.click('[data-testid="create-task-button"]');
    await expect(page.locator('[data-testid="task-creation-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-title-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-description-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-deadline-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-priority-select"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-assignee-select"]')).toBeVisible();

    // Step 2: Enter valid task title, description, deadline, priority, and select assignees
    await page.fill('[data-testid="task-title-input"]', 'Complete Q4 Report');
    await expect(page.locator('[data-testid="task-title-input"]')).toHaveValue('Complete Q4 Report');

    await page.fill('[data-testid="task-description-input"]', 'Prepare and submit the quarterly financial report including all departmental expenses');
    await expect(page.locator('[data-testid="task-description-input"]')).toHaveValue('Prepare and submit the quarterly financial report including all departmental expenses');

    // Set deadline to 7 days from now
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    const formattedDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="task-deadline-input"]', formattedDate);
    await expect(page.locator('[data-testid="task-deadline-input"]')).toHaveValue(formattedDate);

    await page.selectOption('[data-testid="task-priority-select"]', 'High');
    await expect(page.locator('[data-testid="task-priority-select"]')).toHaveValue('High');

    await page.click('[data-testid="task-assignee-select"]');
    await page.click('[data-testid="assignee-option-1"]');
    await expect(page.locator('[data-testid="selected-assignee-1"]')).toBeVisible();

    // Verify no validation errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();

    // Step 3: Submit the task creation form
    await page.click('[data-testid="submit-task-button"]');
    
    // Verify task is created successfully and confirmation message is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Task created successfully');
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
  });

  test('Verify rejection of task creation with missing mandatory fields', async ({ page }) => {
    // Step 1: Navigate to task creation page
    await page.click('[data-testid="create-task-button"]');
    await expect(page.locator('[data-testid="task-creation-form"]')).toBeVisible();

    // Step 2: Leave mandatory fields empty and attempt to submit
    // Verify all fields are empty
    await expect(page.locator('[data-testid="task-title-input"]')).toHaveValue('');
    await expect(page.locator('[data-testid="task-description-input"]')).toHaveValue('');
    await expect(page.locator('[data-testid="task-deadline-input"]')).toHaveValue('');

    // Step 3: Attempt to submit the form
    await page.click('[data-testid="submit-task-button"]');

    // Verify validation errors are displayed for each missing field
    await expect(page.locator('[data-testid="title-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="title-error"]')).toContainText(/required|mandatory/i);
    
    await expect(page.locator('[data-testid="description-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="description-error"]')).toContainText(/required|mandatory/i);
    
    await expect(page.locator('[data-testid="deadline-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="deadline-error"]')).toContainText(/required|mandatory/i);
    
    await expect(page.locator('[data-testid="priority-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="priority-error"]')).toContainText(/required|mandatory/i);
    
    await expect(page.locator('[data-testid="assignee-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="assignee-error"]')).toContainText(/required|mandatory/i);

    // Verify submission is blocked - success message should not appear
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();

    // Fill in one mandatory field and attempt to submit again
    await page.fill('[data-testid="task-title-input"]', 'Test Task');
    await page.click('[data-testid="submit-task-button"]');

    // Verify other validation errors still present
    await expect(page.locator('[data-testid="description-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="deadline-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="priority-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="assignee-error"]')).toBeVisible();
    
    // Verify submission is still blocked
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
  });

  test('Test validation for deadline in the past', async ({ page }) => {
    // Step 1: Navigate to task creation page
    await page.click('[data-testid="create-task-button"]');
    await expect(page.locator('[data-testid="task-creation-form"]')).toBeVisible();

    // Step 2: Enter valid data in task title field
    await page.fill('[data-testid="task-title-input"]', 'Review Documentation');
    await expect(page.locator('[data-testid="task-title-input"]')).toHaveValue('Review Documentation');

    // Enter valid data in task description field
    await page.fill('[data-testid="task-description-input"]', 'Review and update project documentation');
    await expect(page.locator('[data-testid="task-description-input"]')).toHaveValue('Review and update project documentation');

    // Select a priority level
    await page.selectOption('[data-testid="task-priority-select"]', 'Medium');
    await expect(page.locator('[data-testid="task-priority-select"]')).toHaveValue('Medium');

    // Select at least one employee from assignee selection
    await page.click('[data-testid="task-assignee-select"]');
    await page.click('[data-testid="assignee-option-1"]');
    await expect(page.locator('[data-testid="selected-assignee-1"]')).toBeVisible();

    // Enter a deadline date/time that is in the past
    const pastDate = new Date();
    pastDate.setDate(pastDate.getDate() - 1);
    const formattedPastDate = pastDate.toISOString().split('T')[0];
    await page.fill('[data-testid="task-deadline-input"]', formattedPastDate);

    // Attempt to submit form with past deadline
    await page.click('[data-testid="submit-task-button"]');

    // Verify validation error message is displayed indicating invalid deadline
    await expect(page.locator('[data-testid="deadline-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="deadline-error"]')).toContainText(/past|invalid|future/i);

    // Verify submission is blocked
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();

    // Correct the deadline by selecting a future date
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 3);
    const formattedFutureDate = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="task-deadline-input"]', formattedFutureDate);
    await expect(page.locator('[data-testid="task-deadline-input"]')).toHaveValue(formattedFutureDate);

    // Click submit button again with corrected deadline
    await page.click('[data-testid="submit-task-button"]');

    // Verify task is created successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Task created successfully');
    await expect(page.locator('[data-testid="deadline-error"]')).not.toBeVisible();
  });
});