import { test, expect } from '@playwright/test';

test.describe('Story-9: Modify Task Priorities', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to task list
    await page.click('[data-testid="tasks-menu"]');
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
  });

  test('Modify task priority with valid level', async ({ page }) => {
    // Step 1: Select task and open priority edit form
    await page.click('[data-testid="task-item"]:first-child');
    await page.click('[data-testid="edit-priority-button"]');
    
    // Expected Result: Form displayed with current priority
    await expect(page.locator('[data-testid="priority-edit-form"]')).toBeVisible();
    const currentPriority = await page.locator('[data-testid="current-priority"]').textContent();
    expect(currentPriority).toBeTruthy();
    
    // Step 2: Select new valid priority (e.g., Medium)
    await page.selectOption('[data-testid="priority-select"]', 'Medium');
    
    // Expected Result: Input accepted without errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    const selectedValue = await page.locator('[data-testid="priority-select"]').inputValue();
    expect(selectedValue).toBe('Medium');
    
    // Step 3: Submit priority update
    await page.click('[data-testid="submit-priority-button"]');
    
    // Expected Result: Priority updated and confirmation displayed
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Priority updated successfully');
    
    // Verify the task list displays the updated priority
    await page.waitForTimeout(1000); // Wait for update to propagate
    const updatedPriority = await page.locator('[data-testid="task-item"]:first-child [data-testid="task-priority"]').textContent();
    expect(updatedPriority).toContain('Medium');
  });

  test('Reject modification with invalid priority', async ({ page }) => {
    // Step 1: Open priority edit form
    await page.click('[data-testid="task-item"]:first-child');
    await page.click('[data-testid="edit-priority-button"]');
    
    // Expected Result: Form displayed
    await expect(page.locator('[data-testid="priority-edit-form"]')).toBeVisible();
    
    // Step 2: Enter invalid priority value
    // Store original priority for verification
    const originalPriority = await page.locator('[data-testid="current-priority"]').textContent();
    
    // Attempt to enter invalid priority by manipulating the select or input
    await page.evaluate(() => {
      const select = document.querySelector('[data-testid="priority-select"]') as HTMLSelectElement;
      if (select) {
        const option = document.createElement('option');
        option.value = 'Critical';
        option.text = 'Critical';
        select.add(option);
        select.value = 'Critical';
      }
    });
    
    // Expected Result: Validation error displayed
    await page.click('[data-testid="submit-priority-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText(/invalid priority|must be Low, Medium, or High/i);
    
    // Step 3: Attempt to submit update
    // Expected Result: Submission blocked with error message
    await expect(page.locator('[data-testid="priority-edit-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    
    // Close the form
    await page.click('[data-testid="cancel-button"]');
    
    // Verify the original priority remains unchanged
    const currentPriority = await page.locator('[data-testid="task-item"]:first-child [data-testid="task-priority"]').textContent();
    expect(currentPriority).toContain(originalPriority);
  });

  test('Modify task priority from Low to High', async ({ page }) => {
    // Navigate to task list and select a task with Low priority
    await page.click('[data-testid="task-item"][data-priority="Low"]:first-child');
    await page.click('[data-testid="edit-priority-button"]');
    
    // Verify form displays current priority as Low
    await expect(page.locator('[data-testid="priority-edit-form"]')).toBeVisible();
    const currentPriority = await page.locator('[data-testid="current-priority"]').textContent();
    expect(currentPriority).toContain('Low');
    
    // Select High priority
    await page.selectOption('[data-testid="priority-select"]', 'High');
    
    // Submit the update
    await page.click('[data-testid="submit-priority-button"]');
    
    // Verify confirmation message
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Priority updated successfully');
    
    // Verify updated priority in task list
    await page.waitForTimeout(1000);
    const updatedPriority = await page.locator('[data-testid="task-item"]:first-child [data-testid="task-priority"]').textContent();
    expect(updatedPriority).toContain('High');
  });

  test('Verify employee notification after priority change', async ({ page }) => {
    // Select a task and note the assigned employee
    await page.click('[data-testid="task-item"]:first-child');
    const assignedEmployee = await page.locator('[data-testid="assigned-employee"]').textContent();
    
    // Open priority edit form
    await page.click('[data-testid="edit-priority-button"]');
    await expect(page.locator('[data-testid="priority-edit-form"]')).toBeVisible();
    
    // Change priority to Medium
    await page.selectOption('[data-testid="priority-select"]', 'Medium');
    await page.click('[data-testid="submit-priority-button"]');
    
    // Verify confirmation message
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    
    // Navigate to notifications or verify notification was sent
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-list"]')).toBeVisible();
    
    // Verify notification contains priority change information
    const notificationText = await page.locator('[data-testid="notification-item"]:first-child').textContent();
    expect(notificationText).toContain('priority');
    expect(notificationText).toContain('Medium');
  });

  test('Cancel priority modification without saving', async ({ page }) => {
    // Select task and open priority edit form
    await page.click('[data-testid="task-item"]:first-child');
    const originalPriority = await page.locator('[data-testid="task-priority"]').textContent();
    
    await page.click('[data-testid="edit-priority-button"]');
    await expect(page.locator('[data-testid="priority-edit-form"]')).toBeVisible();
    
    // Change priority but cancel
    await page.selectOption('[data-testid="priority-select"]', 'High');
    await page.click('[data-testid="cancel-button"]');
    
    // Verify form is closed
    await expect(page.locator('[data-testid="priority-edit-form"]')).not.toBeVisible();
    
    // Verify priority remains unchanged
    const currentPriority = await page.locator('[data-testid="task-item"]:first-child [data-testid="task-priority"]').textContent();
    expect(currentPriority).toBe(originalPriority);
  });

  test('Verify priority update processes within 2 seconds', async ({ page }) => {
    // Select task and open priority edit form
    await page.click('[data-testid="task-item"]:first-child');
    await page.click('[data-testid="edit-priority-button"]');
    await expect(page.locator('[data-testid="priority-edit-form"]')).toBeVisible();
    
    // Change priority and measure update time
    await page.selectOption('[data-testid="priority-select"]', 'High');
    
    const startTime = Date.now();
    await page.click('[data-testid="submit-priority-button"]');
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    const endTime = Date.now();
    
    const updateDuration = endTime - startTime;
    expect(updateDuration).toBeLessThan(2000);
  });
});