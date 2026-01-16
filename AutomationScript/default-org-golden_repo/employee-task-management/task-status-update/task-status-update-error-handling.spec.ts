import { test, expect } from '@playwright/test';

test.describe('Task Status Update Error Handling', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the task management page
    await page.goto('/tasks');
    await page.waitForLoadState('networkidle');
  });

  test('Verify error message displayed on status update failure', async ({ page }) => {
    // Select a task from the task list
    await page.click('[data-testid="task-list-item"]:first-child');
    await expect(page.locator('[data-testid="task-details"]')).toBeVisible();

    // Get the current task status before update attempt
    const currentStatus = await page.locator('[data-testid="task-status-display"]').textContent();

    // Click on the status dropdown or status update button
    await page.click('[data-testid="status-dropdown-button"]');
    await expect(page.locator('[data-testid="status-dropdown-menu"]')).toBeVisible();

    // Simulate failure during status update by intercepting the API call
    await page.route('**/api/tasks/*/status', async (route) => {
      await route.abort('failed');
    });

    // Select a new status from the available options
    await page.click('[data-testid="status-option-in-progress"]');

    // Verify that the error message is displayed
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible({ timeout: 5000 });
    
    // Verify error message contains descriptive text
    const errorText = await errorMessage.textContent();
    expect(errorText).toBeTruthy();
    expect(errorText?.length).toBeGreaterThan(0);

    // Verify that the error message does not contain sensitive technical information
    expect(errorText?.toLowerCase()).not.toContain('password');
    expect(errorText?.toLowerCase()).not.toContain('token');
    expect(errorText?.toLowerCase()).not.toContain('api key');
    expect(errorText?.toLowerCase()).not.toContain('secret');

    // Check the current task status in the system remains unchanged
    const statusAfterFailure = await page.locator('[data-testid="task-status-display"]').textContent();
    expect(statusAfterFailure).toBe(currentStatus);
  });

  test('Verify error logging on update failure', async ({ page, context }) => {
    // Note the current timestamp before triggering the failure
    const testStartTime = new Date();
    const timestampBeforeFailure = testStartTime.toISOString();

    // Select a task from the task list
    await page.click('[data-testid="task-list-item"]:first-child');
    await expect(page.locator('[data-testid="task-details"]')).toBeVisible();

    // Get task ID and user information for log verification
    const taskId = await page.locator('[data-testid="task-id"]').textContent();
    const userId = await page.locator('[data-testid="current-user-id"]').textContent();

    // Get current status before update attempt
    const currentStatus = await page.locator('[data-testid="task-status-display"]').textContent();

    // Set up console log capture to verify error logging
    const consoleLogs: string[] = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        consoleLogs.push(msg.text());
      }
    });

    // Trigger status update failure by simulating API error
    await page.route('**/api/tasks/*/status', async (route) => {
      await route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'Database connection failure',
          message: 'Unable to update task status'
        })
      });
    });

    // Attempt to update the task status to a new value
    await page.click('[data-testid="status-dropdown-button"]');
    await page.click('[data-testid="status-option-completed"]');

    // Wait for error to be processed
    await page.waitForTimeout(1000);

    // Access the system error logs or log monitoring dashboard
    await page.goto('/admin/logs');
    await page.waitForLoadState('networkidle');

    // Search for error entries matching the timestamp of the failed update
    await page.fill('[data-testid="log-search-timestamp"]', timestampBeforeFailure);
    await page.click('[data-testid="log-search-button"]');
    await page.waitForSelector('[data-testid="log-entry"]');

    // Verify the error log contains essential details
    const logEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(logEntry).toBeVisible();

    const logContent = await logEntry.textContent();
    
    // Verify timestamp is present
    expect(logContent).toContain(testStartTime.getFullYear().toString());

    // Verify user ID is logged
    if (userId) {
      expect(logContent).toContain(userId);
    }

    // Verify task ID is logged
    if (taskId) {
      expect(logContent).toContain(taskId);
    }

    // Verify error type is logged
    expect(logContent?.toLowerCase()).toMatch(/error|failure|exception/);

    // Verify error description is present
    expect(logContent?.length).toBeGreaterThan(50);

    // Verify that the error log includes technical details suitable for support team
    const logDetails = page.locator('[data-testid="log-details"]');
    if (await logDetails.isVisible()) {
      const detailsText = await logDetails.textContent();
      expect(detailsText).toBeTruthy();
      expect(detailsText?.toLowerCase()).toMatch(/status|update|task/);
    }

    // Confirm that sensitive information is not exposed in the logs
    expect(logContent?.toLowerCase()).not.toContain('password');
    expect(logContent?.toLowerCase()).not.toContain('token');
    expect(logContent?.toLowerCase()).not.toContain('api key');
    expect(logContent?.toLowerCase()).not.toContain('secret');
    expect(logContent?.toLowerCase()).not.toContain('credential');
  });
});