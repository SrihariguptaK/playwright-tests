import { test, expect } from '@playwright/test';

test.describe('Story-17: Track Task Status Updates', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto('/login');
    
    // Login with manager credentials
    await page.fill('[data-testid="username-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'Manager123!');
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and redirect
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate display of current task statuses - happy path', async ({ page }) => {
    // Navigate to manager task dashboard
    await page.click('text=Tasks');
    await expect(page).toHaveURL(/.*tasks/);
    
    // Verify that the status column is visible and clearly labeled
    const statusColumnHeader = page.locator('[data-testid="task-status-column-header"]').or(page.locator('th:has-text("Status")')).first();
    await expect(statusColumnHeader).toBeVisible();
    
    // Verify task list is displayed
    const taskList = page.locator('[data-testid="task-list"]').or(page.locator('table tbody')).first();
    await expect(taskList).toBeVisible();
    
    // Review status values for at least 5 different tasks
    const taskRows = page.locator('[data-testid="task-row"]').or(page.locator('table tbody tr'));
    const taskCount = await taskRows.count();
    expect(taskCount).toBeGreaterThanOrEqual(5);
    
    // Verify status values for multiple tasks
    for (let i = 0; i < Math.min(5, taskCount); i++) {
      const taskRow = taskRows.nth(i);
      const statusCell = taskRow.locator('[data-testid="task-status"]').or(taskRow.locator('td').nth(2));
      await expect(statusCell).toBeVisible();
      
      const statusText = await statusCell.textContent();
      expect(statusText).toBeTruthy();
      expect(['Not Started', 'In Progress', 'Completed', 'On Hold', 'Blocked']).toContain(statusText?.trim());
    }
    
    // Scroll through task list to verify status display for additional tasks
    if (taskCount > 5) {
      await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
      await page.waitForTimeout(500);
      
      const lastTaskRow = taskRows.last();
      const lastStatusCell = lastTaskRow.locator('[data-testid="task-status"]').or(lastTaskRow.locator('td').nth(2));
      await expect(lastStatusCell).toBeVisible();
    }
  });

  test('Validate filtering tasks by status - happy path', async ({ page }) => {
    // Navigate to manager task dashboard
    await page.click('text=Tasks');
    await expect(page).toHaveURL(/.*tasks/);
    
    // Note the total number of tasks displayed before applying filter
    const taskRows = page.locator('[data-testid="task-row"]').or(page.locator('table tbody tr'));
    await taskRows.first().waitFor({ state: 'visible' });
    const initialTaskCount = await taskRows.count();
    expect(initialTaskCount).toBeGreaterThan(0);
    
    // Locate the status filter control
    const statusFilter = page.locator('[data-testid="status-filter"]').or(page.locator('select[name="status"]')).or(page.locator('[placeholder*="Filter"]')).first();
    await expect(statusFilter).toBeVisible();
    
    // Click on status filter control to open filter options
    await statusFilter.click();
    
    // Select 'In Progress' status from filter options
    const inProgressOption = page.locator('[data-testid="status-option-in-progress"]').or(page.locator('option:has-text("In Progress")')).or(page.locator('text="In Progress"')).first();
    await inProgressOption.click();
    
    // Apply filter if there's an apply button
    const applyButton = page.locator('[data-testid="apply-filter-button"]').or(page.locator('button:has-text("Apply")')).or(page.locator('button:has-text("Filter")'));
    if (await applyButton.count() > 0) {
      await applyButton.first().click();
    }
    
    // Wait for filter to be applied
    await page.waitForTimeout(1000);
    
    // Verify all displayed tasks show 'In Progress' status
    const filteredTaskRows = page.locator('[data-testid="task-row"]').or(page.locator('table tbody tr'));
    const filteredCount = await filteredTaskRows.count();
    expect(filteredCount).toBeGreaterThan(0);
    expect(filteredCount).toBeLessThanOrEqual(initialTaskCount);
    
    // Verify each task has 'In Progress' status
    for (let i = 0; i < filteredCount; i++) {
      const taskRow = filteredTaskRows.nth(i);
      const statusCell = taskRow.locator('[data-testid="task-status"]').or(taskRow.locator('td').nth(2));
      const statusText = await statusCell.textContent();
      expect(statusText?.trim()).toBe('In Progress');
    }
    
    // Clear filter or select 'All' to return to unfiltered view
    const clearFilterButton = page.locator('[data-testid="clear-filter-button"]').or(page.locator('button:has-text("Clear")')).or(page.locator('button:has-text("Reset")'));
    if (await clearFilterButton.count() > 0) {
      await clearFilterButton.first().click();
    } else {
      await statusFilter.click();
      const allOption = page.locator('[data-testid="status-option-all"]').or(page.locator('option:has-text("All")')).or(page.locator('text="All"')).first();
      await allOption.click();
      if (await applyButton.count() > 0) {
        await applyButton.first().click();
      }
    }
    
    // Verify task list returns to showing all tasks
    await page.waitForTimeout(1000);
    const unfilteredTaskRows = page.locator('[data-testid="task-row"]').or(page.locator('table tbody tr'));
    const unfilteredCount = await unfilteredTaskRows.count();
    expect(unfilteredCount).toBe(initialTaskCount);
  });

  test('Validate display of current task statuses - verify status values match latest updates', async ({ page }) => {
    // Navigate to manager task dashboard
    await page.click('text=Tasks');
    await expect(page).toHaveURL(/.*tasks/);
    
    // Get task list
    const taskRows = page.locator('[data-testid="task-row"]').or(page.locator('table tbody tr'));
    await taskRows.first().waitFor({ state: 'visible' });
    const taskCount = await taskRows.count();
    expect(taskCount).toBeGreaterThan(0);
    
    // Verify status values for multiple tasks match latest updates
    for (let i = 0; i < Math.min(3, taskCount); i++) {
      const taskRow = taskRows.nth(i);
      
      // Get task name/ID
      const taskNameCell = taskRow.locator('[data-testid="task-name"]').or(taskRow.locator('td').first());
      const taskName = await taskNameCell.textContent();
      
      // Get displayed status
      const statusCell = taskRow.locator('[data-testid="task-status"]').or(taskRow.locator('td').nth(2));
      const displayedStatus = await statusCell.textContent();
      
      // Click on task to view details
      await taskRow.click();
      
      // Wait for task details modal or page
      const taskDetailsModal = page.locator('[data-testid="task-details-modal"]').or(page.locator('[role="dialog"]')).first();
      await taskDetailsModal.waitFor({ state: 'visible', timeout: 5000 });
      
      // Verify status in details matches dashboard status
      const detailsStatus = page.locator('[data-testid="task-details-status"]').or(page.locator('text=/Status:/')).first();
      await expect(detailsStatus).toContainText(displayedStatus?.trim() || '');
      
      // Close modal
      const closeButton = page.locator('[data-testid="close-modal-button"]').or(page.locator('button:has-text("Close")')).or(page.locator('[aria-label="Close"]')).first();
      await closeButton.click();
      await taskDetailsModal.waitFor({ state: 'hidden', timeout: 3000 });
    }
  });

  test('Validate dashboard loads task status information within 3 seconds', async ({ page }) => {
    // Record start time
    const startTime = Date.now();
    
    // Navigate to manager task dashboard
    await page.click('text=Tasks');
    await expect(page).toHaveURL(/.*tasks/);
    
    // Wait for task list to be visible
    const taskList = page.locator('[data-testid="task-list"]').or(page.locator('table tbody')).first();
    await taskList.waitFor({ state: 'visible' });
    
    // Wait for at least one task row with status to be visible
    const taskRows = page.locator('[data-testid="task-row"]').or(page.locator('table tbody tr'));
    await taskRows.first().waitFor({ state: 'visible' });
    
    const firstStatusCell = taskRows.first().locator('[data-testid="task-status"]').or(taskRows.first().locator('td').nth(2));
    await firstStatusCell.waitFor({ state: 'visible' });
    
    // Calculate load time
    const loadTime = Date.now() - startTime;
    
    // Verify dashboard loaded within 3 seconds (3000ms)
    expect(loadTime).toBeLessThan(3000);
    
    // Verify status information is displayed
    const statusText = await firstStatusCell.textContent();
    expect(statusText).toBeTruthy();
  });
});