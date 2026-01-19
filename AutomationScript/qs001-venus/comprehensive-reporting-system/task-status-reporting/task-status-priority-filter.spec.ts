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
    // Navigate to Task Status Reporting section from the main dashboard
    await page.click('[data-testid="task-status-reporting-link"]');
    await expect(page.locator('[data-testid="task-status-report-ui"]')).toBeVisible();
    
    // Click on the priority filter dropdown to view available priority options
    await page.click('[data-testid="priority-filter-dropdown"]');
    await expect(page.locator('[data-testid="priority-dropdown-menu"]')).toBeVisible();
    
    // Select 'High' priority from the filter dropdown
    await page.click('[data-testid="priority-option-high"]');
    await expect(page.locator('[data-testid="priority-filter-dropdown"]')).toContainText('High');
    
    // Click the 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report to be generated
    await page.waitForSelector('[data-testid="report-results"]', { timeout: 5000 });
    
    // Verify all displayed tasks have 'High' priority assigned
    const taskRows = await page.locator('[data-testid="task-row"]').all();
    expect(taskRows.length).toBeGreaterThan(0);
    
    for (const taskRow of taskRows) {
      const priorityCell = taskRow.locator('[data-testid="task-priority"]');
      await expect(priorityCell).toContainText('High');
    }
    
    // Verify tasks are categorized by status (pending, in-progress, completed) within the priority filter
    await expect(page.locator('[data-testid="status-pending-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="status-inprogress-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="status-completed-section"]')).toBeVisible();
    
    // Change priority filter to 'Medium' and regenerate the report
    await page.click('[data-testid="priority-filter-dropdown"]');
    await page.click('[data-testid="priority-option-medium"]');
    await expect(page.locator('[data-testid="priority-filter-dropdown"]')).toContainText('Medium');
    
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="report-results"]', { timeout: 5000 });
    
    // Verify all displayed tasks have 'Medium' priority assigned
    const mediumTaskRows = await page.locator('[data-testid="task-row"]').all();
    for (const taskRow of mediumTaskRows) {
      const priorityCell = taskRow.locator('[data-testid="task-priority"]');
      await expect(priorityCell).toContainText('Medium');
    }
  });

  test('Filter task status report by valid priority - Low priority', async ({ page }) => {
    // Navigate to Task Status Reporting section
    await page.click('[data-testid="task-status-reporting-link"]');
    await expect(page.locator('[data-testid="task-status-report-ui"]')).toBeVisible();
    
    // Select a valid priority from filter dropdown
    await page.click('[data-testid="priority-filter-dropdown"]');
    await page.click('[data-testid="priority-option-low"]');
    await expect(page.locator('[data-testid="priority-filter-dropdown"]')).toContainText('Low');
    
    // Generate report
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="report-results"]', { timeout: 5000 });
    
    // Report displays task status data only for selected priority
    const taskRows = await page.locator('[data-testid="task-row"]').all();
    for (const taskRow of taskRows) {
      const priorityCell = taskRow.locator('[data-testid="task-priority"]');
      await expect(priorityCell).toContainText('Low');
    }
  });

  test('Handle invalid priority filter input - invalid text', async ({ page }) => {
    // Navigate to Task Status Reporting section
    await page.click('[data-testid="task-status-reporting-link"]');
    await expect(page.locator('[data-testid="task-status-report-ui"]')).toBeVisible();
    
    // Attempt to enter an invalid priority value in the priority filter field
    await page.click('[data-testid="priority-filter-dropdown"]');
    const filterInput = page.locator('[data-testid="priority-filter-input"]');
    await filterInput.fill('Invalid');
    
    // Verify the error message is clearly visible near the priority filter field
    await expect(page.locator('[data-testid="priority-filter-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="priority-filter-error"]')).toContainText('validation error');
    
    // Click the 'Generate Report' button while invalid priority value is entered
    await page.click('[data-testid="generate-report-button"]');
    
    // Verify the Generate Report button remains disabled or shows validation warning
    const generateButton = page.locator('[data-testid="generate-report-button"]');
    const isDisabled = await generateButton.isDisabled();
    if (!isDisabled) {
      await expect(page.locator('[data-testid="validation-warning"]')).toBeVisible();
    }
    
    // Clear the invalid input and select a valid priority value from the dropdown
    await filterInput.clear();
    await page.click('[data-testid="priority-option-high"]');
    await expect(page.locator('[data-testid="priority-filter-error"]')).not.toBeVisible();
    
    // Click 'Generate Report' with valid priority filter
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="report-results"]', { timeout: 5000 });
    await expect(page.locator('[data-testid="report-results"]')).toBeVisible();
  });

  test('Handle invalid priority filter input - special characters', async ({ page }) => {
    // Navigate to Task Status Reporting section
    await page.click('[data-testid="task-status-reporting-link"]');
    await expect(page.locator('[data-testid="task-status-report-ui"]')).toBeVisible();
    
    // Enter invalid priority value with special characters
    await page.click('[data-testid="priority-filter-dropdown"]');
    const filterInput = page.locator('[data-testid="priority-filter-input"]');
    await filterInput.fill('@#$%^&*');
    
    // System displays validation error
    await expect(page.locator('[data-testid="priority-filter-error"]')).toBeVisible();
    
    // Attempt to generate report
    await page.click('[data-testid="generate-report-button"]');
    
    // Report generation is blocked until valid input is provided
    const reportResults = page.locator('[data-testid="report-results"]');
    await expect(reportResults).not.toBeVisible();
  });

  test('Handle invalid priority filter input - numeric values', async ({ page }) => {
    // Navigate to Task Status Reporting section
    await page.click('[data-testid="task-status-reporting-link"]');
    await expect(page.locator('[data-testid="task-status-report-ui"]')).toBeVisible();
    
    // Enter invalid priority value with numeric values
    await page.click('[data-testid="priority-filter-dropdown"]');
    const filterInput = page.locator('[data-testid="priority-filter-input"]');
    await filterInput.fill('12345');
    
    // System displays validation error
    await expect(page.locator('[data-testid="priority-filter-error"]')).toBeVisible();
    
    // Attempt to generate report
    await page.click('[data-testid="generate-report-button"]');
    
    // Verify Generate Report button remains disabled or shows validation warning
    const generateButton = page.locator('[data-testid="generate-report-button"]');
    const isDisabled = await generateButton.isDisabled();
    if (!isDisabled) {
      await expect(page.locator('[data-testid="validation-warning"]')).toBeVisible();
    }
    
    // Report generation is blocked until valid input is provided
    const reportResults = page.locator('[data-testid="report-results"]');
    await expect(reportResults).not.toBeVisible();
  });

  test('Export filtered task status reports correctly', async ({ page }) => {
    // Navigate to Task Status Reporting section
    await page.click('[data-testid="task-status-reporting-link"]');
    await expect(page.locator('[data-testid="task-status-report-ui"]')).toBeVisible();
    
    // Select priority filter and generate report
    await page.click('[data-testid="priority-filter-dropdown"]');
    await page.click('[data-testid="priority-option-high"]');
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="report-results"]', { timeout: 5000 });
    
    // Set up download listener
    const downloadPromise = page.waitForEvent('download');
    
    // Click export button
    await page.click('[data-testid="export-report-button"]');
    
    // Wait for download to complete
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('task-status-report');
    
    // Verify download was successful
    const path = await download.path();
    expect(path).toBeTruthy();
  });
});