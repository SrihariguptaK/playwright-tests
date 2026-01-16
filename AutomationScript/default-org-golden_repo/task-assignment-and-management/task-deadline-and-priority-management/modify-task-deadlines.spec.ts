import { test, expect } from '@playwright/test';

test.describe('Story-8: Modify Task Deadlines', () => {
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

  test('Modify task deadline with valid future date', async ({ page }) => {
    // Step 1: Select task and open deadline edit form
    await page.click('[data-testid="task-item"]:first-child');
    await page.click('[data-testid="edit-deadline-button"]');
    
    // Expected Result: Form displayed with current deadline
    await expect(page.locator('[data-testid="deadline-edit-form"]')).toBeVisible();
    const currentDeadline = await page.locator('[data-testid="deadline-input"]').inputValue();
    expect(currentDeadline).toBeTruthy();
    
    // Step 2: Enter new valid future deadline
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    const futureDateString = futureDate.toISOString().split('T')[0];
    
    await page.fill('[data-testid="deadline-input"]', futureDateString);
    
    // Expected Result: Input accepted without errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    
    // Step 3: Submit deadline update
    await page.click('[data-testid="submit-deadline-button"]');
    
    // Expected Result: Deadline updated and confirmation displayed
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Deadline updated successfully');
    
    // Verify the task list displays the updated deadline
    await page.waitForTimeout(1000);
    const updatedDeadline = await page.locator('[data-testid="task-item"]:first-child [data-testid="task-deadline"]').textContent();
    expect(updatedDeadline).toContain(futureDateString);
    
    // Check that notification indicator is present
    await expect(page.locator('[data-testid="notification-sent-indicator"]')).toBeVisible();
  });

  test('Reject modification with past date', async ({ page }) => {
    // Step 1: Open deadline edit form
    await page.click('[data-testid="task-item"]:first-child');
    const originalDeadline = await page.locator('[data-testid="task-item"]:first-child [data-testid="task-deadline"]').textContent();
    
    await page.click('[data-testid="edit-deadline-button"]');
    
    // Expected Result: Form displayed
    await expect(page.locator('[data-testid="deadline-edit-form"]')).toBeVisible();
    
    // Step 2: Enter past date as new deadline
    const pastDate = new Date();
    pastDate.setDate(pastDate.getDate() - 1);
    const pastDateString = pastDate.toISOString().split('T')[0];
    
    await page.fill('[data-testid="deadline-input"]', pastDateString);
    await page.click('[data-testid="deadline-edit-form"]'); // Trigger validation by clicking outside
    
    // Expected Result: Validation error displayed
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Deadline must be a future date');
    
    // Step 3: Attempt to submit update
    await page.click('[data-testid="submit-deadline-button"]');
    
    // Expected Result: Submission blocked with error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Cannot set deadline to a past date');
    
    // Verify the original deadline remains unchanged
    await page.click('[data-testid="cancel-button"]');
    await page.waitForTimeout(500);
    
    const currentDeadline = await page.locator('[data-testid="task-item"]:first-child [data-testid="task-deadline"]').textContent();
    expect(currentDeadline).toBe(originalDeadline);
    
    // Verify no confirmation message is displayed
    await expect(page.locator('[data-testid="confirmation-message"]')).not.toBeVisible();
  });

  test('Verify deadline change is logged for audit', async ({ page }) => {
    // Select task and open deadline edit form
    await page.click('[data-testid="task-item"]:first-child');
    const taskName = await page.locator('[data-testid="task-item"]:first-child [data-testid="task-name"]').textContent();
    
    await page.click('[data-testid="edit-deadline-button"]');
    await expect(page.locator('[data-testid="deadline-edit-form"]')).toBeVisible();
    
    // Enter new valid future deadline
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 10);
    const futureDateString = futureDate.toISOString().split('T')[0];
    
    await page.fill('[data-testid="deadline-input"]', futureDateString);
    await page.click('[data-testid="submit-deadline-button"]');
    
    // Wait for confirmation
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    
    // Navigate to audit log
    await page.click('[data-testid="audit-log-menu"]');
    await expect(page.locator('[data-testid="audit-log-list"]')).toBeVisible();
    
    // Verify deadline change is logged
    const latestLogEntry = page.locator('[data-testid="audit-log-entry"]:first-child');
    await expect(latestLogEntry).toContainText('Deadline modified');
    await expect(latestLogEntry).toContainText(taskName || '');
  });

  test('Verify system processes update within 2 seconds', async ({ page }) => {
    // Select task and open deadline edit form
    await page.click('[data-testid="task-item"]:first-child');
    await page.click('[data-testid="edit-deadline-button"]');
    await expect(page.locator('[data-testid="deadline-edit-form"]')).toBeVisible();
    
    // Enter new valid future deadline
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 5);
    const futureDateString = futureDate.toISOString().split('T')[0];
    
    await page.fill('[data-testid="deadline-input"]', futureDateString);
    
    // Record start time and submit
    const startTime = Date.now();
    await page.click('[data-testid="submit-deadline-button"]');
    
    // Wait for confirmation
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible({ timeout: 2000 });
    const endTime = Date.now();
    
    // Verify processing time is within 2 seconds
    const processingTime = endTime - startTime;
    expect(processingTime).toBeLessThan(2000);
  });
});