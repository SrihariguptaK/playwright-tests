import { test, expect } from '@playwright/test';

test.describe('Task Status Report Priority Filtering', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Team Lead
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'teamlead@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Filter task status report by valid priority - High priority', async ({ page }) => {
    // Action: Navigate to Task Status Reporting section
    await page.click('[data-testid="task-status-reporting-link"]');
    
    // Expected Result: Task status report UI is displayed
    await expect(page.locator('[data-testid="task-status-report-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="priority-filter-dropdown"]')).toBeVisible();
    
    // Action: Select a valid priority from filter dropdown
    await page.click('[data-testid="priority-filter-dropdown"]');
    await page.click('[data-testid="priority-option-high"]');
    
    // Expected Result: Priority filter is applied
    await expect(page.locator('[data-testid="priority-filter-dropdown"]')).toContainText('High');
    
    // Action: Generate report
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Report displays task status data only for selected priority
    await expect(page.locator('[data-testid="report-results"]')).toBeVisible({ timeout: 10000 });
    
    // Verify all tasks displayed have 'High' priority
    const taskRows = page.locator('[data-testid="task-row"]');
    const taskCount = await taskRows.count();
    
    for (let i = 0; i < taskCount; i++) {
      const priorityCell = taskRows.nth(i).locator('[data-testid="task-priority"]');
      await expect(priorityCell).toContainText('High');
    }
    
    // Verify no tasks with Medium or Low priority are displayed
    await expect(page.locator('[data-testid="task-priority"]:has-text("Medium")')).toHaveCount(0);
    await expect(page.locator('[data-testid="task-priority"]:has-text("Low")')).toHaveCount(0);
  });

  test('Filter task status report by valid priority - Medium priority', async ({ page }) => {
    // Navigate to Task Status Reporting section
    await page.click('[data-testid="task-status-reporting-link"]');
    await expect(page.locator('[data-testid="task-status-report-container"]')).toBeVisible();
    
    // Change the priority filter to 'Medium'
    await page.click('[data-testid="priority-filter-dropdown"]');
    await page.click('[data-testid="priority-option-medium"]');
    await expect(page.locator('[data-testid="priority-filter-dropdown"]')).toContainText('Medium');
    
    // Regenerate the report
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-results"]')).toBeVisible({ timeout: 10000 });
    
    // Verify the filtered report accuracy for Medium priority
    const taskRows = page.locator('[data-testid="task-row"]');
    const taskCount = await taskRows.count();
    
    for (let i = 0; i < taskCount; i++) {
      const priorityCell = taskRows.nth(i).locator('[data-testid="task-priority"]');
      await expect(priorityCell).toContainText('Medium');
    }
    
    // Verify no tasks with High or Low priority are displayed
    await expect(page.locator('[data-testid="task-priority"]:has-text("High")')).toHaveCount(0);
    await expect(page.locator('[data-testid="task-priority"]:has-text("Low")')).toHaveCount(0);
  });

  test('Handle invalid priority filter input - text input', async ({ page }) => {
    // Action: Navigate to Task Status Reporting section
    await page.click('[data-testid="task-status-reporting-link"]');
    await expect(page.locator('[data-testid="task-status-report-container"]')).toBeVisible();
    
    // Action: Enter invalid priority value in filter
    await page.fill('[data-testid="priority-filter-input"]', 'InvalidPriority');
    
    // Expected Result: System displays validation error
    await expect(page.locator('[data-testid="priority-filter-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="priority-filter-error"]')).toContainText(/invalid|error/i);
    
    // Verify the error message is clearly visible and user-friendly
    const errorMessage = await page.locator('[data-testid="priority-filter-error"]').textContent();
    expect(errorMessage).toBeTruthy();
    expect(errorMessage?.length).toBeGreaterThan(0);
    
    // Action: Attempt to generate report
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Report generation is blocked until valid input is provided
    await expect(page.locator('[data-testid="report-results"]')).not.toBeVisible();
    
    // Verify no report is generated with invalid filter
    const reportContainer = page.locator('[data-testid="report-results"]');
    await expect(reportContainer).toHaveCount(0);
  });

  test('Handle invalid priority filter input - numeric input', async ({ page }) => {
    // Navigate to Task Status Reporting section
    await page.click('[data-testid="task-status-reporting-link"]');
    await expect(page.locator('[data-testid="task-status-report-container"]')).toBeVisible();
    
    // Enter a numeric value '123' in the priority filter field
    await page.fill('[data-testid="priority-filter-input"]', '123');
    
    // Verify validation error is displayed
    await expect(page.locator('[data-testid="priority-filter-error"]')).toBeVisible();
    
    // Attempt to generate report with numeric invalid input
    await page.click('[data-testid="generate-report-button"]');
    
    // Verify report generation is blocked
    await expect(page.locator('[data-testid="report-results"]')).not.toBeVisible();
    
    // Clear the invalid input and select a valid priority 'High' from the dropdown
    await page.fill('[data-testid="priority-filter-input"]', '');
    await page.click('[data-testid="priority-filter-dropdown"]');
    await page.click('[data-testid="priority-option-high"]');
    
    // Verify error message is cleared
    await expect(page.locator('[data-testid="priority-filter-error"]')).not.toBeVisible();
    
    // Click 'Generate Report' with valid priority selected
    await page.click('[data-testid="generate-report-button"]');
    
    // Verify report is successfully generated
    await expect(page.locator('[data-testid="report-results"]')).toBeVisible({ timeout: 10000 });
    
    // Verify tasks are displayed with High priority
    const taskRows = page.locator('[data-testid="task-row"]');
    const taskCount = await taskRows.count();
    expect(taskCount).toBeGreaterThan(0);
  });

  test('Export filtered task status report', async ({ page }) => {
    // Navigate to Task Status Reporting section
    await page.click('[data-testid="task-status-reporting-link"]');
    await expect(page.locator('[data-testid="task-status-report-container"]')).toBeVisible();
    
    // Select High priority filter
    await page.click('[data-testid="priority-filter-dropdown"]');
    await page.click('[data-testid="priority-option-high"]');
    
    // Generate report
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-results"]')).toBeVisible({ timeout: 10000 });
    
    // Setup download listener
    const downloadPromise = page.waitForEvent('download');
    
    // Click export button
    await page.click('[data-testid="export-report-button"]');
    
    // Wait for download to complete
    const download = await downloadPromise;
    
    // Verify download was successful
    expect(download.suggestedFilename()).toMatch(/task.*status.*report/i);
    
    // Verify file was downloaded
    const path = await download.path();
    expect(path).toBeTruthy();
  });
});