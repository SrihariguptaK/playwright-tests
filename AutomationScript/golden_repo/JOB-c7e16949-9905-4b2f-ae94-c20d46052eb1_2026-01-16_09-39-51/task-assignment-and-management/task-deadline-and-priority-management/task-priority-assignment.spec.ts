import { test, expect } from '@playwright/test';

test.describe('Task Priority Assignment - Story 12', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const apiURL = process.env.API_URL || 'http://localhost:3000/api';

  test.beforeEach(async ({ page }) => {
    // Login as manager before each test
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate selection of valid priority levels', async ({ page }) => {
    // Step 1: Navigate to task creation page
    await page.goto(`${baseURL}/tasks/create`);
    await expect(page.locator('[data-testid="task-creation-form"]')).toBeVisible();

    // Step 2: Select 'Low' priority level
    await page.click('[data-testid="priority-dropdown"]');
    await page.click('[data-testid="priority-option-low"]');
    await expect(page.locator('[data-testid="priority-dropdown"]')).toContainText('Low');

    // Fill in other required task fields
    await page.fill('[data-testid="task-name-input"]', 'Test Task Low Priority');
    await page.fill('[data-testid="task-description-input"]', 'This is a test task with low priority');
    await page.click('[data-testid="assignee-dropdown"]');
    await page.click('[data-testid="assignee-option-first"]');
    await page.fill('[data-testid="deadline-input"]', '2024-12-31');

    // Step 3: Submit the form
    await page.click('[data-testid="submit-task-button"]');

    // Verify task is created with selected priority
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-priority-display"]')).toContainText('Low');

    // Test Medium priority
    await page.goto(`${baseURL}/tasks/create`);
    await page.click('[data-testid="priority-dropdown"]');
    await page.click('[data-testid="priority-option-medium"]');
    await expect(page.locator('[data-testid="priority-dropdown"]')).toContainText('Medium');
    await page.fill('[data-testid="task-name-input"]', 'Test Task Medium Priority');
    await page.fill('[data-testid="task-description-input"]', 'This is a test task with medium priority');
    await page.click('[data-testid="assignee-dropdown"]');
    await page.click('[data-testid="assignee-option-first"]');
    await page.fill('[data-testid="deadline-input"]', '2024-12-31');
    await page.click('[data-testid="submit-task-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-priority-display"]')).toContainText('Medium');

    // Test High priority
    await page.goto(`${baseURL}/tasks/create`);
    await page.click('[data-testid="priority-dropdown"]');
    await page.click('[data-testid="priority-option-high"]');
    await expect(page.locator('[data-testid="priority-dropdown"]')).toContainText('High');
    await page.fill('[data-testid="task-name-input"]', 'Test Task High Priority');
    await page.fill('[data-testid="task-description-input"]', 'This is a test task with high priority');
    await page.click('[data-testid="assignee-dropdown"]');
    await page.click('[data-testid="assignee-option-first"]');
    await page.fill('[data-testid="deadline-input"]', '2024-12-31');
    await page.click('[data-testid="submit-task-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-priority-display"]')).toContainText('High');

    // Verify all tasks in task list view
    await page.goto(`${baseURL}/tasks`);
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    await expect(page.locator('text=Test Task Low Priority')).toBeVisible();
    await expect(page.locator('text=Test Task Medium Priority')).toBeVisible();
    await expect(page.locator('text=Test Task High Priority')).toBeVisible();
  });

  test('Verify rejection of invalid priority values', async ({ page, request }) => {
    // Prepare API request payload with invalid priority value 'Critical'
    const invalidPayload1 = {
      name: 'Test Task Invalid Priority Critical',
      description: 'Task with invalid priority',
      assignee: 'user@example.com',
      deadline: '2024-12-31',
      priority: 'Critical'
    };

    // Send POST request with invalid priority
    const response1 = await request.post(`${apiURL}/tasks`, {
      data: invalidPayload1,
      headers: {
        'Content-Type': 'application/json'
      }
    });

    // Verify API returns validation error
    expect(response1.status()).toBe(400);
    const responseBody1 = await response1.json();
    expect(responseBody1).toHaveProperty('error');
    expect(responseBody1.error).toMatch(/priority|invalid|validation/i);

    // Attempt with invalid priority 'Urgent'
    const invalidPayload2 = {
      name: 'Test Task Invalid Priority Urgent',
      description: 'Task with invalid priority',
      assignee: 'user@example.com',
      deadline: '2024-12-31',
      priority: 'Urgent'
    };

    const response2 = await request.post(`${apiURL}/tasks`, {
      data: invalidPayload2,
      headers: {
        'Content-Type': 'application/json'
      }
    });

    expect(response2.status()).toBe(400);
    const responseBody2 = await response2.json();
    expect(responseBody2).toHaveProperty('error');

    // Attempt with numeric priority value
    const invalidPayload3 = {
      name: 'Test Task Invalid Priority Numeric',
      description: 'Task with invalid priority',
      assignee: 'user@example.com',
      deadline: '2024-12-31',
      priority: 1
    };

    const response3 = await request.post(`${apiURL}/tasks`, {
      data: invalidPayload3,
      headers: {
        'Content-Type': 'application/json'
      }
    });

    expect(response3.status()).toBe(400);

    // Attempt with empty priority value
    const invalidPayload4 = {
      name: 'Test Task Empty Priority',
      description: 'Task with empty priority',
      assignee: 'user@example.com',
      deadline: '2024-12-31',
      priority: ''
    };

    const response4 = await request.post(`${apiURL}/tasks`, {
      data: invalidPayload4,
      headers: {
        'Content-Type': 'application/json'
      }
    });

    expect(response4.status()).toBe(400);

    // Attempt with null priority value
    const invalidPayload5 = {
      name: 'Test Task Null Priority',
      description: 'Task with null priority',
      assignee: 'user@example.com',
      deadline: '2024-12-31',
      priority: null
    };

    const response5 = await request.post(`${apiURL}/tasks`, {
      data: invalidPayload5,
      headers: {
        'Content-Type': 'application/json'
      }
    });

    expect(response5.status()).toBe(400);

    // Verify API works with valid priority value
    const validPayload = {
      name: 'Test Task Valid Priority',
      description: 'Task with valid priority',
      assignee: 'user@example.com',
      deadline: '2024-12-31',
      priority: 'High'
    };

    const validResponse = await request.post(`${apiURL}/tasks`, {
      data: validPayload,
      headers: {
        'Content-Type': 'application/json'
      }
    });

    expect(validResponse.status()).toBe(201);
    const validResponseBody = await validResponse.json();
    expect(validResponseBody).toHaveProperty('priority', 'High');
  });

  test('Validate updating task priority with valid values', async ({ page }) => {
    // Create a task with Low priority first
    await page.goto(`${baseURL}/tasks/create`);
    await page.click('[data-testid="priority-dropdown"]');
    await page.click('[data-testid="priority-option-low"]');
    await page.fill('[data-testid="task-name-input"]', 'Task for Priority Update Test');
    await page.fill('[data-testid="task-description-input"]', 'This task will be updated');
    await page.click('[data-testid="assignee-dropdown"]');
    await page.click('[data-testid="assignee-option-first"]');
    await page.fill('[data-testid="deadline-input"]', '2024-12-31');
    await page.click('[data-testid="submit-task-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Get the task ID from URL or page
    const taskUrl = page.url();
    const taskId = taskUrl.split('/').pop();

    // Navigate to task edit page
    await page.goto(`${baseURL}/tasks/${taskId}/edit`);
    await expect(page.locator('[data-testid="task-edit-form"]')).toBeVisible();

    // Verify current priority is Low
    await expect(page.locator('[data-testid="priority-dropdown"]')).toContainText('Low');

    // Change priority from Low to High
    await page.click('[data-testid="priority-dropdown"]');
    await page.click('[data-testid="priority-option-high"]');
    await expect(page.locator('[data-testid="priority-dropdown"]')).toContainText('High');

    // Submit the form
    await page.click('[data-testid="update-task-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Verify updated priority in task details view
    await expect(page.locator('[data-testid="task-priority-display"]')).toContainText('High');

    // Navigate to task list view
    await page.goto(`${baseURL}/tasks`);
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();

    // Find the task and verify priority
    const taskRow = page.locator(`[data-testid="task-row-${taskId}"]`);
    await expect(taskRow.locator('[data-testid="task-priority"]')).toContainText('High');

    // Edit the same task again and change priority to Medium
    await page.goto(`${baseURL}/tasks/${taskId}/edit`);
    await page.click('[data-testid="priority-dropdown"]');
    await page.click('[data-testid="priority-option-medium"]');
    await expect(page.locator('[data-testid="priority-dropdown"]')).toContainText('Medium');
    await page.click('[data-testid="update-task-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-priority-display"]')).toContainText('Medium');
  });
});