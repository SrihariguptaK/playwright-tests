import { test, expect } from '@playwright/test';

test.describe('Task Status Update - Story 11', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_EMPLOYEE_USERNAME = 'employee@company.com';
  const VALID_EMPLOYEE_PASSWORD = 'Password123!';
  const UNAUTHORIZED_USERNAME = 'unauthorized@company.com';
  const UNAUTHORIZED_PASSWORD = 'Password123!';

  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate successful status update with valid input', async ({ page }) => {
    // Step 1: Employee logs into the system and navigates to assigned tasks
    await page.fill('[data-testid="username-input"]', VALID_EMPLOYEE_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Task list is displayed
    await expect(page).toHaveURL(/.*dashboard/);
    await page.click('[data-testid="my-tasks-nav"]');
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-item"]').first()).toBeVisible();

    // Step 2: Employee selects a task and chooses a valid status
    const firstTask = page.locator('[data-testid="task-item"]').first();
    const taskTitle = await firstTask.locator('[data-testid="task-title"]').textContent();
    await firstTask.click();
    
    // Expected Result: Task details view opens
    await expect(page.locator('[data-testid="task-details-view"]')).toBeVisible();
    
    // Locate and click status dropdown
    await page.click('[data-testid="status-dropdown"]');
    await expect(page.locator('[data-testid="status-options"]')).toBeVisible();
    
    // Select a new valid status
    const statusOptions = page.locator('[data-testid="status-option"]');
    await expect(statusOptions).toHaveCount(await statusOptions.count());
    await page.click('[data-testid="status-option-in-progress"]');
    
    // Expected Result: Status selection is accepted
    await expect(page.locator('[data-testid="status-dropdown"]')).toContainText('In Progress');

    // Step 3: Employee submits the status update
    await page.click('[data-testid="submit-status-button"]');
    
    // Expected Result: Status is updated, confirmation message displayed
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Status updated successfully');
    
    // Verify status update persists
    await page.click('[data-testid="my-tasks-nav"]');
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    
    const updatedTask = page.locator('[data-testid="task-item"]').filter({ hasText: taskTitle || '' });
    await expect(updatedTask.locator('[data-testid="task-status"]')).toContainText('In Progress');
  });

  test('Reject status update with invalid status value', async ({ page, request }) => {
    // Login as valid employee
    await page.fill('[data-testid="username-input"]', VALID_EMPLOYEE_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to assigned tasks
    await page.click('[data-testid="my-tasks-nav"]');
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    
    // Select a task
    const firstTask = page.locator('[data-testid="task-item"]').first();
    const taskId = await firstTask.getAttribute('data-task-id');
    const originalStatus = await firstTask.locator('[data-testid="task-status"]').textContent();
    await firstTask.click();
    
    // Step 1: Attempt to submit invalid status via API manipulation
    const authToken = await page.evaluate(() => localStorage.getItem('authToken'));
    
    const response = await request.put(`${BASE_URL}/api/tasks/${taskId}/status`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      data: {
        status: 'INVALID_STATUS_VALUE'
      }
    });
    
    // Expected Result: System displays error message and prevents update
    expect(response.status()).toBe(400);
    const responseBody = await response.json();
    expect(responseBody.error).toBeTruthy();
    expect(responseBody.message).toContain('invalid');
    
    // Verify status remains unchanged
    await page.reload();
    await page.click('[data-testid="my-tasks-nav"]');
    const unchangedTask = page.locator(`[data-task-id="${taskId}"]`);
    await expect(unchangedTask.locator('[data-testid="task-status"]')).toContainText(originalStatus || '');
    
    // Step 2: Correct status to valid option
    await unchangedTask.click();
    await page.click('[data-testid="status-dropdown"]');
    await page.click('[data-testid="status-option-completed"]');
    await page.click('[data-testid="submit-status-button"]');
    
    // Expected Result: System accepts update
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Status updated successfully');
    await expect(page.locator('[data-testid="task-status"]')).toContainText('Completed');
  });

  test('Prevent unauthorized user from updating task status', async ({ page, request }) => {
    // Step 1: Log in as unauthorized user
    await page.fill('[data-testid="username-input"]', UNAUTHORIZED_USERNAME);
    await page.fill('[data-testid="password-input"]', UNAUTHORIZED_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Get a task ID that belongs to another user
    const unauthorizedTaskId = '12345'; // Task not assigned to this user
    
    // Step 2: Attempt to navigate to unauthorized task
    await page.goto(`${BASE_URL}/tasks/${unauthorizedTaskId}`);
    
    // Expected Result: System denies access
    const isAccessDenied = await page.locator('[data-testid="access-denied-message"]').isVisible().catch(() => false);
    const isNotFound = await page.locator('[data-testid="not-found-message"]').isVisible().catch(() => false);
    const isUnauthorized = await page.locator('[data-testid="unauthorized-message"]').isVisible().catch(() => false);
    
    expect(isAccessDenied || isNotFound || isUnauthorized).toBeTruthy();
    
    // Step 3: Verify status update controls are not available
    const statusDropdownExists = await page.locator('[data-testid="status-dropdown"]').isVisible().catch(() => false);
    const submitButtonExists = await page.locator('[data-testid="submit-status-button"]').isVisible().catch(() => false);
    
    expect(statusDropdownExists).toBeFalsy();
    expect(submitButtonExists).toBeFalsy();
    
    // Step 4: Attempt direct API call with unauthorized token
    const unauthorizedToken = await page.evaluate(() => localStorage.getItem('authToken'));
    
    const apiResponse = await request.put(`${BASE_URL}/api/tasks/${unauthorizedTaskId}/status`, {
      headers: {
        'Authorization': `Bearer ${unauthorizedToken}`,
        'Content-Type': 'application/json'
      },
      data: {
        status: 'IN_PROGRESS'
      }
    });
    
    // Expected Result: API returns authorization error
    expect(apiResponse.status()).toBe(403);
    const apiResponseBody = await apiResponse.json();
    expect(apiResponseBody.error).toBeTruthy();
    expect(apiResponseBody.message).toMatch(/unauthorized|forbidden|access denied/i);
    
    // Step 5: Verify no status change in database by logging in as authorized user
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', VALID_EMPLOYEE_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    await page.goto(`${BASE_URL}/tasks/${unauthorizedTaskId}`);
    
    // Verify task status was not changed by unauthorized attempt
    const currentStatus = await page.locator('[data-testid="task-status"]').textContent();
    expect(currentStatus).not.toBe('IN_PROGRESS');
  });
});