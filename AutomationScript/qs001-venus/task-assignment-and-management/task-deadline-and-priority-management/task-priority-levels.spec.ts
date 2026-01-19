import { test, expect } from '@playwright/test';

test.describe('Task Priority Management', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const MANAGER_EMAIL = 'manager@example.com';
  const MANAGER_PASSWORD = 'Manager123!';

  test.beforeEach(async ({ page }) => {
    // Login as manager before each test
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful priority assignment with valid value', async ({ page }) => {
    // Step 1: Navigate to task priority update page
    await page.goto(`${BASE_URL}/tasks`);
    await page.click('[data-testid="task-item"]:first-child');
    await expect(page.locator('[data-testid="task-details"]')).toBeVisible();
    
    // Click on priority update or edit button
    await page.click('[data-testid="edit-priority-button"]');
    await expect(page.locator('[data-testid="priority-selection-form"]')).toBeVisible();
    
    // Step 2: Select a valid priority level (High)
    await page.click('[data-testid="priority-dropdown"]');
    await expect(page.locator('[data-testid="priority-option-high"]')).toBeVisible();
    await page.click('[data-testid="priority-option-high"]');
    
    // Verify selection accepted without validation errors
    await expect(page.locator('[data-testid="priority-validation-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="priority-dropdown"]')).toContainText('High');
    
    // Step 3: Submit the priority update
    await page.click('[data-testid="submit-priority-button"]');
    
    // Verify priority is saved and confirmation displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Priority updated successfully');
    
    // Verify task details show updated priority
    await expect(page.locator('[data-testid="task-priority-display"]')).toContainText('High');
    
    // Verify notifications were sent (check notification indicator or log)
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-item"]').first()).toContainText('Priority update');
  });

  test('Verify rejection of invalid priority values', async ({ page }) => {
    // Step 1: Navigate to priority update page
    await page.goto(`${BASE_URL}/tasks`);
    await page.click('[data-testid="task-item"]:first-child');
    await expect(page.locator('[data-testid="task-details"]')).toBeVisible();
    
    // Click on priority update or edit button
    await page.click('[data-testid="edit-priority-button"]');
    await expect(page.locator('[data-testid="priority-selection-form"]')).toBeVisible();
    
    // Step 2: Attempt to enter an invalid priority value
    // Check if field allows text input and try invalid value
    const priorityInput = page.locator('[data-testid="priority-input"]');
    const isInputVisible = await priorityInput.isVisible().catch(() => false);
    
    if (isInputVisible) {
      await priorityInput.fill('Critical');
      
      // Verify validation error displayed
      await expect(page.locator('[data-testid="priority-validation-error"]')).toBeVisible();
      await expect(page.locator('[data-testid="priority-validation-error"]')).toContainText('invalid priority');
    }
    
    // Step 3: Attempt to submit the form with invalid priority
    const submitButton = page.locator('[data-testid="submit-priority-button"]');
    
    if (isInputVisible) {
      // Verify submission is blocked
      await expect(submitButton).toBeDisabled();
      
      // Clear invalid value and select valid priority
      await priorityInput.clear();
    }
    
    // Select valid priority from dropdown
    await page.click('[data-testid="priority-dropdown"]');
    await page.click('[data-testid="priority-option-medium"]');
    
    // Verify validation error is cleared
    await expect(page.locator('[data-testid="priority-validation-error"]')).not.toBeVisible();
    
    // Verify submit button is now enabled
    await expect(submitButton).toBeEnabled();
    
    // Submit with valid priority
    await submitButton.click();
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
  });

  test('Ensure notifications are sent upon priority update', async ({ page }) => {
    // Step 1: Navigate to task with assigned employees
    await page.goto(`${BASE_URL}/tasks`);
    
    // Select a task that has employees assigned
    await page.click('[data-testid="task-item-with-assignees"]');
    await expect(page.locator('[data-testid="task-details"]')).toBeVisible();
    
    // Verify task has assigned employees
    await expect(page.locator('[data-testid="assigned-employees"]')).toBeVisible();
    const assigneeCount = await page.locator('[data-testid="assignee-item"]').count();
    expect(assigneeCount).toBeGreaterThan(0);
    
    // Click on priority update or edit button
    await page.click('[data-testid="edit-priority-button"]');
    await expect(page.locator('[data-testid="priority-selection-form"]')).toBeVisible();
    
    // Step 2: Select a valid priority level (High)
    await page.click('[data-testid="priority-dropdown"]');
    await page.click('[data-testid="priority-option-high"]');
    
    // Submit the priority update
    await page.click('[data-testid="submit-priority-button"]');
    
    // Step 3: Verify priority update is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-priority-display"]')).toContainText('High');
    
    // Verify confirmation message to manager
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Priority updated successfully');
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Notifications sent to assigned employees');
    
    // Check notification system
    await page.goto(`${BASE_URL}/notifications`);
    await expect(page.locator('[data-testid="notifications-page"]')).toBeVisible();
    
    // Verify notifications were sent to assigned employees
    const notificationItems = page.locator('[data-testid="sent-notification-item"]');
    await expect(notificationItems.first()).toBeVisible();
    
    // Verify notification content for accuracy
    await expect(notificationItems.first()).toContainText('Priority update');
    await expect(notificationItems.first()).toContainText('High');
    
    // Verify all assigned employees received notifications
    const sentNotificationCount = await notificationItems.count();
    expect(sentNotificationCount).toBeGreaterThanOrEqual(assigneeCount);
    
    // Navigate back to task page and verify manager sees confirmation
    await page.goto(`${BASE_URL}/tasks`);
    await page.click('[data-testid="task-item-with-assignees"]');
    await expect(page.locator('[data-testid="task-priority-display"]')).toContainText('High');
  });
});