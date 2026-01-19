import { test, expect } from '@playwright/test';

test.describe('Task Status Validation', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate acceptance of valid status update (happy-path)', async ({ page }) => {
    // Navigate to the task management page
    await page.goto('/tasks');
    await expect(page.locator('[data-testid="task-management-page"]')).toBeVisible();

    // Select a task with status 'In Progress'
    await page.click('[data-testid="task-row"][data-status="In Progress"]');
    await expect(page.locator('[data-testid="task-details-panel"]')).toBeVisible();

    // Click on the status dropdown and select a valid next status
    await page.click('[data-testid="status-dropdown"]');
    await page.click('[data-testid="status-option-completed"]');

    // Fill in all mandatory fields required for the status update
    await page.fill('[data-testid="completion-notes-input"]', 'Task completed successfully with all requirements met');
    await page.fill('[data-testid="actual-hours-input"]', '8.5');

    // Click the 'Update Status' button to submit the status change
    await page.click('[data-testid="update-status-button"]');

    // Verify confirmation message is displayed on the screen
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Status updated successfully');

    // Refresh the task details page and verify the status has been updated
    await page.reload();
    await expect(page.locator('[data-testid="task-status-display"]')).toContainText('Completed');

    // Navigate to the audit logs section
    await page.click('[data-testid="audit-logs-link"]');
    await expect(page).toHaveURL(/.*audit-logs/);

    // Search for the task update record
    await page.fill('[data-testid="audit-search-input"]', 'status update');
    await page.click('[data-testid="audit-search-button"]');

    // Verify all details in the audit log are correct and complete
    const auditLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditLogEntry).toBeVisible();
    await expect(auditLogEntry.locator('[data-testid="audit-action"]')).toContainText('Status Update');
    await expect(auditLogEntry.locator('[data-testid="audit-old-status"]')).toContainText('In Progress');
    await expect(auditLogEntry.locator('[data-testid="audit-new-status"]')).toContainText('Completed');
  });

  test('Verify rejection of invalid status update (error-case)', async ({ page }) => {
    // Navigate to the task management page
    await page.goto('/tasks');
    await expect(page.locator('[data-testid="task-management-page"]')).toBeVisible();

    // Select a task with status 'Completed'
    await page.click('[data-testid="task-row"][data-status="Completed"]');
    await expect(page.locator('[data-testid="task-details-panel"]')).toBeVisible();

    // Store the current status for verification
    const currentStatus = await page.locator('[data-testid="task-status-display"]').textContent();

    // Attempt to change the status to an invalid transition state
    await page.click('[data-testid="status-dropdown"]');
    await page.click('[data-testid="status-option-in-progress"]');

    // Fill in any required fields
    await page.fill('[data-testid="status-notes-input"]', 'Attempting invalid transition');

    // Click 'Update Status' button to submit the invalid status update
    await page.click('[data-testid="update-status-button"]');

    // Verify that an error message is displayed on the screen
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Invalid status transition');

    // Verify that the task status remains unchanged in the system
    await page.reload();
    await expect(page.locator('[data-testid="task-status-display"]')).toContainText(currentStatus || 'Completed');

    // Review the error message details to understand the validation failure reason
    await page.click('[data-testid="status-dropdown"]');
    await page.click('[data-testid="status-option-in-progress"]');
    await page.click('[data-testid="update-status-button"]');
    const errorDetails = await page.locator('[data-testid="error-details"]').textContent();
    expect(errorDetails).toContain('Cannot transition from Completed to In Progress');

    // Correct the status by selecting a valid transition
    await page.click('[data-testid="status-dropdown"]');
    await page.click('[data-testid="status-option-archived"]');

    // Resubmit the status update with the corrected valid status
    await page.fill('[data-testid="status-notes-input"]', 'Archiving completed task');
    await page.click('[data-testid="update-status-button"]');

    // Verify the task now shows the new valid status
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await page.reload();
    await expect(page.locator('[data-testid="task-status-display"]')).toContainText('Archived');
  });

  test('Ensure validation completes within performance SLA (boundary)', async ({ page }) => {
    // Navigate to the task management page
    await page.goto('/tasks');
    await expect(page.locator('[data-testid="task-management-page"]')).toBeVisible();

    const validationTimes: number[] = [];
    const taskCount = 10;

    // Submit multiple status updates and measure validation time
    for (let i = 0; i < taskCount; i++) {
      // Navigate to a task
      await page.click(`[data-testid="task-row"]:nth-child(${i + 1})`);
      await expect(page.locator('[data-testid="task-details-panel"]')).toBeVisible();

      // Initiate a valid status update and measure time
      const startTime = Date.now();
      
      await page.click('[data-testid="status-dropdown"]');
      await page.click('[data-testid="status-option"]:first-child');
      await page.fill('[data-testid="status-notes-input"]', `Performance test update ${i + 1}`);
      await page.click('[data-testid="update-status-button"]');
      
      // Wait for validation response
      await page.waitForSelector('[data-testid="success-message"], [data-testid="error-message"]');
      
      const endTime = Date.now();
      const validationTime = endTime - startTime;
      validationTimes.push(validationTime);

      // Verify validation completes within 1 second (1000ms)
      expect(validationTime).toBeLessThanOrEqual(1000);

      // Navigate back to task list for next iteration
      await page.click('[data-testid="back-to-tasks-button"]');
    }

    // Record the validation times
    console.log('Validation times (ms):', validationTimes);
    const averageTime = validationTimes.reduce((a, b) => a + b, 0) / validationTimes.length;
    console.log('Average validation time (ms):', averageTime);
    expect(averageTime).toBeLessThanOrEqual(1000);

    // Submit a status update with invalid data to trigger a validation error
    await page.click('[data-testid="task-row"]:first-child');
    await page.click('[data-testid="status-dropdown"]');
    await page.click('[data-testid="status-option-invalid"]');
    await page.click('[data-testid="update-status-button"]');
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();

    // Navigate to system logs
    await page.goto('/admin/logs');
    await expect(page.locator('[data-testid="system-logs-page"]')).toBeVisible();

    // Search for validation error entries
    await page.fill('[data-testid="log-search-input"]', 'validation error');
    await page.click('[data-testid="log-search-button"]');

    // Verify each validation error log entry contains complete information
    const logEntries = page.locator('[data-testid="log-entry"]');
    const logCount = await logEntries.count();
    expect(logCount).toBeGreaterThan(0);

    for (let i = 0; i < Math.min(logCount, 5); i++) {
      const logEntry = logEntries.nth(i);
      await expect(logEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
      await expect(logEntry.locator('[data-testid="log-task-id"]')).toBeVisible();
      await expect(logEntry.locator('[data-testid="log-error-type"]')).toBeVisible();
      await expect(logEntry.locator('[data-testid="log-error-message"]')).toBeVisible();
      await expect(logEntry.locator('[data-testid="log-employee-id"]')).toBeVisible();
    }

    // Monitor system resource utilization
    await page.goto('/admin/monitoring');
    await expect(page.locator('[data-testid="monitoring-dashboard"]')).toBeVisible();

    const cpuUsage = await page.locator('[data-testid="cpu-usage"]').textContent();
    const memoryUsage = await page.locator('[data-testid="memory-usage"]').textContent();
    const responseTime = await page.locator('[data-testid="avg-response-time"]').textContent();

    console.log('CPU Usage:', cpuUsage);
    console.log('Memory Usage:', memoryUsage);
    console.log('Response Time:', responseTime);

    // Verify system responsiveness by navigating to different pages
    const navigationStartTime = Date.now();
    await page.goto('/tasks');
    await expect(page.locator('[data-testid="task-management-page"]')).toBeVisible();
    const navigationTime = Date.now() - navigationStartTime;
    expect(navigationTime).toBeLessThanOrEqual(3000);

    await page.goto('/dashboard');
    await expect(page.locator('[data-testid="dashboard-page"]')).toBeVisible();

    // Verify all validations met the 1-second SLA
    const allValidationsMeetSLA = validationTimes.every(time => time <= 1000);
    expect(allValidationsMeetSLA).toBeTruthy();
  });
});