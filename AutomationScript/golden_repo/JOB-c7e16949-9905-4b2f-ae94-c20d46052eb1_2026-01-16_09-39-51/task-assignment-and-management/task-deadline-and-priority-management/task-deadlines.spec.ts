import { test, expect } from '@playwright/test';

test.describe('Task Deadline Management', () => {
  const baseURL = 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    // Login as manager before each test
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate setting a valid future deadline', async ({ page }) => {
    // Step 1: Navigate to task creation page
    await page.goto(`${baseURL}/tasks/create`);
    await expect(page.locator('[data-testid="task-creation-form"]')).toBeVisible();
    
    // Step 2: Enter a valid future date/time as deadline
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    tomorrow.setHours(17, 0, 0, 0);
    const futureDate = tomorrow.toISOString().slice(0, 16);
    
    await page.fill('[data-testid="task-name-input"]', 'Test Task with Future Deadline');
    await page.fill('[data-testid="task-description-input"]', 'This task has a valid future deadline');
    await page.fill('[data-testid="task-deadline-input"]', futureDate);
    await page.selectOption('[data-testid="task-assignee-select"]', { label: 'John Doe' });
    
    // Verify no validation errors are shown
    await expect(page.locator('[data-testid="deadline-error"]')).not.toBeVisible();
    
    // Step 3: Submit the form
    await page.click('[data-testid="submit-task-button"]');
    
    // Expected Result: Task is created with the specified deadline
    await expect(page).toHaveURL(/.*tasks\/\d+/);
    await expect(page.locator('[data-testid="task-deadline-display"]')).toContainText(tomorrow.toLocaleDateString());
    
    // Verify deadline is displayed in task details view
    const deadlineDisplay = await page.locator('[data-testid="task-deadline-display"]').textContent();
    expect(deadlineDisplay).toBeTruthy();
    
    // Navigate to task list view and verify
    await page.goto(`${baseURL}/tasks`);
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    await expect(page.locator('text=Test Task with Future Deadline')).toBeVisible();
  });

  test('Verify rejection of past deadline', async ({ page }) => {
    // Step 1: Navigate to task creation page
    await page.goto(`${baseURL}/tasks/create`);
    await expect(page.locator('[data-testid="task-creation-form"]')).toBeVisible();
    
    // Step 2: Enter a past date/time as deadline
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    yesterday.setHours(10, 0, 0, 0);
    const pastDate = yesterday.toISOString().slice(0, 16);
    
    await page.fill('[data-testid="task-name-input"]', 'Test Task with Past Deadline');
    await page.fill('[data-testid="task-description-input"]', 'This task has an invalid past deadline');
    await page.selectOption('[data-testid="task-assignee-select"]', { label: 'John Doe' });
    await page.fill('[data-testid="task-deadline-input"]', pastDate);
    
    // Expected Result: Validation error message is displayed
    await expect(page.locator('[data-testid="deadline-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="deadline-error"]')).toContainText(/deadline.*past|past.*deadline/i);
    
    // Step 3: Attempt to submit the form
    await page.click('[data-testid="submit-task-button"]');
    
    // Expected Result: Submission is blocked until deadline is corrected
    await expect(page).toHaveURL(/.*tasks\/create/);
    await expect(page.locator('[data-testid="deadline-error"]')).toBeVisible();
    
    // Verify task was not created by checking we're still on creation page
    const currentURL = page.url();
    expect(currentURL).toContain('/tasks/create');
  });

  test('Validate modifying deadline with valid future date', async ({ page }) => {
    // Create a task first
    await page.goto(`${baseURL}/tasks/create`);
    const initialDate = new Date();
    initialDate.setDate(initialDate.getDate() + 2);
    initialDate.setHours(14, 0, 0, 0);
    const initialDeadline = initialDate.toISOString().slice(0, 16);
    
    await page.fill('[data-testid="task-name-input"]', 'Task to Modify Deadline');
    await page.fill('[data-testid="task-description-input"]', 'This task deadline will be modified');
    await page.fill('[data-testid="task-deadline-input"]', initialDeadline);
    await page.selectOption('[data-testid="task-assignee-select"]', { label: 'John Doe' });
    await page.click('[data-testid="submit-task-button"]');
    await expect(page).toHaveURL(/.*tasks\/\d+/);
    
    // Navigate to task edit page
    await page.click('[data-testid="edit-task-button"]');
    await expect(page).toHaveURL(/.*tasks\/\d+\/edit/);
    await expect(page.locator('[data-testid="task-edit-form"]')).toBeVisible();
    
    // Modify the deadline to a different valid future date/time
    const newDate = new Date();
    newDate.setDate(newDate.getDate() + 5);
    newDate.setHours(16, 30, 0, 0);
    const newDeadline = newDate.toISOString().slice(0, 16);
    
    await page.fill('[data-testid="task-deadline-input"]', newDeadline);
    await expect(page.locator('[data-testid="deadline-error"]')).not.toBeVisible();
    
    // Submit the form
    await page.click('[data-testid="update-task-button"]');
    
    // Verify the updated deadline in task details view
    await expect(page).toHaveURL(/.*tasks\/\d+/);
    await expect(page.locator('[data-testid="task-deadline-display"]')).toContainText(newDate.toLocaleDateString());
    
    // Check the task list view
    await page.goto(`${baseURL}/tasks`);
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    await expect(page.locator('text=Task to Modify Deadline')).toBeVisible();
  });

  test('Verify rejection of past deadline during task modification', async ({ page }) => {
    // Create a task first
    await page.goto(`${baseURL}/tasks/create`);
    const validDate = new Date();
    validDate.setDate(validDate.getDate() + 3);
    validDate.setHours(15, 0, 0, 0);
    const validDeadline = validDate.toISOString().slice(0, 16);
    
    await page.fill('[data-testid="task-name-input"]', 'Task with Valid Deadline');
    await page.fill('[data-testid="task-description-input"]', 'Attempt to modify with past deadline');
    await page.fill('[data-testid="task-deadline-input"]', validDeadline);
    await page.selectOption('[data-testid="task-assignee-select"]', { label: 'John Doe' });
    await page.click('[data-testid="submit-task-button"]');
    await expect(page).toHaveURL(/.*tasks\/\d+/);
    
    // Store the original deadline for verification
    const originalDeadline = await page.locator('[data-testid="task-deadline-display"]').textContent();
    
    // Navigate to task edit page
    await page.click('[data-testid="edit-task-button"]');
    await expect(page).toHaveURL(/.*tasks\/\d+\/edit/);
    
    // Modify the deadline to a past date/time
    const pastDate = new Date();
    pastDate.setDate(pastDate.getDate() - 2);
    pastDate.setHours(9, 0, 0, 0);
    const pastDeadline = pastDate.toISOString().slice(0, 16);
    
    await page.fill('[data-testid="task-deadline-input"]', pastDeadline);
    
    // Verify validation error is displayed
    await expect(page.locator('[data-testid="deadline-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="deadline-error"]')).toContainText(/deadline.*past|past.*deadline/i);
    
    // Attempt to submit the form
    await page.click('[data-testid="update-task-button"]');
    
    // Verify submission is blocked
    await expect(page).toHaveURL(/.*tasks\/\d+\/edit/);
    await expect(page.locator('[data-testid="deadline-error"]')).toBeVisible();
    
    // Navigate back to task details to verify original deadline remains
    await page.goto(page.url().replace('/edit', ''));
    const currentDeadline = await page.locator('[data-testid="task-deadline-display"]').textContent();
    expect(currentDeadline).toBe(originalDeadline);
  });
});