import { test, expect } from '@playwright/test';

test.describe('Task Tracking Dashboard - Manager Task Status Monitoring', () => {
  test.beforeEach(async ({ page }) => {
    // Manager logs into the system
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('View task list with statuses (happy-path)', async ({ page }) => {
    // Manager navigates to the task tracking dashboard
    await page.goto('/task-tracking-dashboard');
    await expect(page.locator('[data-testid="task-tracking-dashboard"]')).toBeVisible();
    
    // Verify that each task displays its current status, priority, deadline, assigned employee, and progress percentage
    const taskList = page.locator('[data-testid="task-list"]');
    await expect(taskList).toBeVisible();
    
    const firstTask = taskList.locator('[data-testid="task-item"]').first();
    await expect(firstTask.locator('[data-testid="task-status"]')).toBeVisible();
    await expect(firstTask.locator('[data-testid="task-priority"]')).toBeVisible();
    await expect(firstTask.locator('[data-testid="task-deadline"]')).toBeVisible();
    await expect(firstTask.locator('[data-testid="task-assigned-employee"]')).toBeVisible();
    await expect(firstTask.locator('[data-testid="task-progress-percentage"]')).toBeVisible();
    
    // Manager clicks on the priority filter dropdown and selects 'High' priority
    await page.click('[data-testid="priority-filter-dropdown"]');
    await page.click('[data-testid="priority-filter-high"]');
    await expect(page.locator('[data-testid="priority-filter-dropdown"]')).toContainText('High');
    
    // Manager adds a deadline filter to show tasks due within the next 7 days
    await page.click('[data-testid="deadline-filter-dropdown"]');
    await page.click('[data-testid="deadline-filter-next-7-days"]');
    await expect(page.locator('[data-testid="deadline-filter-dropdown"]')).toContainText('Next 7 days');
    
    // Verify the filtered task count matches the number of tasks displayed
    const filteredTaskCount = await page.locator('[data-testid="task-count"]').textContent();
    const displayedTasks = await page.locator('[data-testid="task-item"]').count();
    expect(filteredTaskCount).toContain(displayedTasks.toString());
    
    // Manager clicks on the status column header to sort tasks by status
    await page.click('[data-testid="status-column-header"]');
    await expect(page.locator('[data-testid="status-column-header"]')).toHaveAttribute('data-sort', 'asc');
    
    // Manager clicks the status column header again to reverse the sort order
    await page.click('[data-testid="status-column-header"]');
    await expect(page.locator('[data-testid="status-column-header"]')).toHaveAttribute('data-sort', 'desc');
    
    // Manager clears all filters to view the complete task list again
    await page.click('[data-testid="clear-filters-button"]');
    await expect(page.locator('[data-testid="priority-filter-dropdown"]')).toContainText('All Priorities');
    await expect(page.locator('[data-testid="deadline-filter-dropdown"]')).toContainText('All Deadlines');
  });

  test('Update task status successfully (happy-path)', async ({ page }) => {
    // Manager navigates to the task tracking dashboard and locates a task with 'In Progress' status
    await page.goto('/task-tracking-dashboard');
    await expect(page.locator('[data-testid="task-tracking-dashboard"]')).toBeVisible();
    
    const inProgressTask = page.locator('[data-testid="task-item"]').filter({ has: page.locator('[data-testid="task-status"]:has-text("In Progress")') }).first();
    await expect(inProgressTask).toBeVisible();
    
    // Manager clicks on the task to open task details view
    await inProgressTask.click();
    await expect(page.locator('[data-testid="task-details-modal"]')).toBeVisible();
    
    // Manager clicks on the status dropdown or edit button to change the task status
    await page.click('[data-testid="task-status-dropdown"]');
    await expect(page.locator('[data-testid="status-options"]')).toBeVisible();
    
    // Manager selects 'Completed' from the status dropdown
    await page.click('[data-testid="status-option-completed"]');
    await expect(page.locator('[data-testid="task-status-dropdown"]')).toContainText('Completed');
    
    // Manager adds optional comments explaining the status change
    await page.fill('[data-testid="status-change-comment"]', 'Task completed successfully. All deliverables met.');
    
    // Manager clicks the 'Submit' or 'Save' button to confirm the status update
    await page.click('[data-testid="submit-status-update-button"]');
    
    // Verify status update accepted and confirmation displayed
    await expect(page.locator('[data-testid="status-update-confirmation"]')).toBeVisible();
    await expect(page.locator('[data-testid="status-update-confirmation"]')).toContainText('Status updated successfully');
    
    // Manager returns to the task tracking dashboard
    await page.click('[data-testid="close-task-details-button"]');
    await expect(page.locator('[data-testid="task-tracking-dashboard"]')).toBeVisible();
    
    // Manager locates the previously updated task in the task list
    const updatedTask = page.locator('[data-testid="task-item"]').filter({ has: page.locator('[data-testid="task-status"]:has-text("Completed")') }).first();
    await expect(updatedTask).toBeVisible();
    
    // Manager clicks on the task again to verify the status change is persisted
    await updatedTask.click();
    await expect(page.locator('[data-testid="task-details-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-status-dropdown"]')).toContainText('Completed');
    await expect(page.locator('[data-testid="status-change-comment"]')).toHaveValue('Task completed successfully. All deliverables met.');
  });

  test('Dashboard performance under normal load (happy-path)', async ({ page }) => {
    // Manager navigates to the task tracking dashboard URL and starts timer
    const startTime = Date.now();
    await page.goto('/task-tracking-dashboard');
    
    // Measure the time taken for the dashboard to fully load with all task data and status indicators
    await expect(page.locator('[data-testid="task-tracking-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    await page.waitForSelector('[data-testid="task-item"]');
    
    const loadTime = Date.now() - startTime;
    expect(loadTime).toBeLessThan(3000); // Dashboard loads within 3 seconds
    
    // Verify all dashboard elements are interactive and responsive
    await expect(page.locator('[data-testid="priority-filter-dropdown"]')).toBeEnabled();
    await expect(page.locator('[data-testid="deadline-filter-dropdown"]')).toBeEnabled();
    await expect(page.locator('[data-testid="status-column-header"]')).toBeEnabled();
    
    // Manager applies a filter for 'High' priority tasks
    await page.click('[data-testid="priority-filter-dropdown"]');
    await page.click('[data-testid="priority-filter-high"]');
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    
    // Manager adds an additional filter for tasks with 'In Progress' status
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-filter-in-progress"]');
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    
    // Manager sorts the filtered results by deadline in ascending order
    await page.click('[data-testid="deadline-column-header"]');
    await expect(page.locator('[data-testid="deadline-column-header"]')).toHaveAttribute('data-sort', 'asc');
    
    // Manager clears all filters and sorts to return to default view
    await page.click('[data-testid="clear-filters-button"]');
    await expect(page.locator('[data-testid="priority-filter-dropdown"]')).toContainText('All Priorities');
    await expect(page.locator('[data-testid="status-filter-dropdown"]')).toContainText('All Statuses');
    
    // Manager clicks the 'Export' button to generate a CSV report of task statuses
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-button"]');
    
    // Wait for CSV file generation and download to complete
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.csv');
    
    // Open the downloaded CSV file and verify data accuracy
    const path = await download.path();
    expect(path).toBeTruthy();
    
    // Verify download completed successfully
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('CSV exported successfully');
  });
});