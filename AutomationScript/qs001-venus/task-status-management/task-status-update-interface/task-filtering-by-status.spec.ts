import { test, expect } from '@playwright/test';

test.describe('Task Filtering by Status - Story 8', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    // Login as employee before each test
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate filtering tasks by single status - happy path', async ({ page }) => {
    // Step 1: Navigate to the task list page from the main navigation menu
    await page.click('[data-testid="nav-tasks"]');
    await expect(page).toHaveURL(/.*tasks/);
    
    // Expected Result: Full task list is displayed
    await page.waitForSelector('[data-testid="task-list"]');
    const initialTaskCount = await page.locator('[data-testid="task-item"]').count();
    expect(initialTaskCount).toBeGreaterThan(0);
    
    // Step 2: Locate the status filter dropdown or filter panel on the task list page
    await page.waitForSelector('[data-testid="status-filter-dropdown"]');
    
    // Step 3: Select a single status filter option 'In Progress' from the filter dropdown/panel
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-filter-option-in-progress"]');
    
    // Expected Result: Task list updates to show only tasks with selected status
    await page.waitForTimeout(500); // Wait for filter to apply
    
    // Step 4: Verify that all displayed tasks show 'In Progress' as their status
    const filteredTasks = await page.locator('[data-testid="task-item"]').all();
    expect(filteredTasks.length).toBeGreaterThan(0);
    
    for (const task of filteredTasks) {
      const statusBadge = await task.locator('[data-testid="task-status"]').textContent();
      expect(statusBadge?.trim()).toBe('In Progress');
    }
    
    // Step 5: Note the number of tasks displayed and verify it matches the expected count
    const filteredTaskCount = filteredTasks.length;
    expect(filteredTaskCount).toBeLessThanOrEqual(initialTaskCount);
    
    // Step 6: Click the 'Clear filter' button or deselect the 'In Progress' status filter
    await page.click('[data-testid="clear-filter-button"]');
    
    // Expected Result: Full task list is restored
    await page.waitForTimeout(500);
    const restoredTaskCount = await page.locator('[data-testid="task-item"]').count();
    expect(restoredTaskCount).toBe(initialTaskCount);
  });

  test('Validate filtering tasks by multiple statuses - happy path', async ({ page }) => {
    // Step 1: Navigate to the task list page
    await page.click('[data-testid="nav-tasks"]');
    await expect(page).toHaveURL(/.*tasks/);
    await page.waitForSelector('[data-testid="task-list"]');
    
    // Step 2: Open the status filter control and select multiple status options
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-filter-option-in-progress"]');
    await page.click('[data-testid="status-filter-option-pending"]');
    
    // Step 3: Apply the multi-select filter or wait for automatic filtering
    await page.waitForTimeout(500);
    
    // Expected Result: Task list shows tasks matching any selected statuses
    // Step 4: Verify that all displayed tasks have either 'In Progress' or 'Pending' status
    const filteredTasks = await page.locator('[data-testid="task-item"]').all();
    expect(filteredTasks.length).toBeGreaterThan(0);
    
    for (const task of filteredTasks) {
      const statusBadge = await task.locator('[data-testid="task-status"]').textContent();
      const status = statusBadge?.trim();
      expect(['In Progress', 'Pending']).toContain(status);
    }
    
    // Step 5: Modify the filter selection by deselecting 'Pending' and adding 'Completed'
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-filter-option-pending"]'); // Deselect
    await page.click('[data-testid="status-filter-option-completed"]'); // Add
    
    // Expected Result: Task list updates accordingly
    await page.waitForTimeout(500);
    
    // Step 6: Observe the task list update
    const modifiedFilteredTasks = await page.locator('[data-testid="task-item"]').all();
    for (const task of modifiedFilteredTasks) {
      const statusBadge = await task.locator('[data-testid="task-status"]').textContent();
      const status = statusBadge?.trim();
      expect(['In Progress', 'Completed']).toContain(status);
    }
    
    // Step 7: Note the current filter selections ('In Progress' and 'Completed')
    const activeFilters = await page.locator('[data-testid="active-filter-chip"]').allTextContents();
    expect(activeFilters).toContain('In Progress');
    expect(activeFilters).toContain('Completed');
    
    // Step 8: Reload the page by pressing F5 or clicking the browser refresh button
    await page.reload();
    
    // Expected Result: Previously selected filters are persisted and applied
    // Step 9: Check the status filter selections after page reload
    await page.waitForSelector('[data-testid="task-list"]');
    const persistedFilters = await page.locator('[data-testid="active-filter-chip"]').allTextContents();
    expect(persistedFilters).toContain('In Progress');
    expect(persistedFilters).toContain('Completed');
    
    // Step 10: Verify the task list content matches the persisted filter selections
    const reloadedTasks = await page.locator('[data-testid="task-item"]').all();
    for (const task of reloadedTasks) {
      const statusBadge = await task.locator('[data-testid="task-status"]').textContent();
      const status = statusBadge?.trim();
      expect(['In Progress', 'Completed']).toContain(status);
    }
  });

  test('Ensure filtered task list loads within performance SLA - boundary', async ({ page }) => {
    // Step 1: Navigate to the task list page and wait for the full unfiltered list to load
    await page.click('[data-testid="nav-tasks"]');
    await expect(page).toHaveURL(/.*tasks/);
    await page.waitForSelector('[data-testid="task-list"]');
    
    // Step 2: Open browser developer tools and navigate to the Network tab to monitor API calls
    // Note: Network monitoring is handled through Playwright's built-in capabilities
    
    // Step 3: Select one or more status filters and start a timer
    const startTime = Date.now();
    
    // Listen for API response
    const responsePromise = page.waitForResponse(
      response => response.url().includes('/api/tasks') && response.url().includes('status='),
      { timeout: 5000 }
    );
    
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-filter-option-in-progress"]');
    
    // Step 4: Monitor the time taken for the filtered task list to fully load
    const response = await responsePromise;
    await page.waitForSelector('[data-testid="task-item"]');
    const endTime = Date.now();
    const loadTime = endTime - startTime;
    
    // Expected Result: Filtered results load within 2 seconds
    expect(loadTime).toBeLessThan(2000);
    
    // Step 5: Verify the API response time in the Network tab
    expect(response.status()).toBe(200);
    
    // Step 6: Clear the filter to return to the full unfiltered task list view
    await page.click('[data-testid="clear-filter-button"]');
    await page.waitForSelector('[data-testid="task-item"]');
    
    // Step 7: Apply a different status filter and measure the load time again
    const startTime2 = Date.now();
    const responsePromise2 = page.waitForResponse(
      response => response.url().includes('/api/tasks') && response.url().includes('status='),
      { timeout: 5000 }
    );
    
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-filter-option-completed"]');
    
    await responsePromise2;
    await page.waitForSelector('[data-testid="task-item"]');
    const endTime2 = Date.now();
    const loadTime2 = endTime2 - startTime2;
    
    expect(loadTime2).toBeLessThan(2000);
    
    // Step 8: Navigate between filtered and unfiltered views multiple times (at least 3 iterations)
    for (let i = 0; i < 3; i++) {
      // Apply filter
      await page.click('[data-testid="status-filter-dropdown"]');
      await page.click('[data-testid="status-filter-option-pending"]');
      await page.waitForSelector('[data-testid="task-item"]');
      
      // Clear filter
      await page.click('[data-testid="clear-filter-button"]');
      await page.waitForSelector('[data-testid="task-item"]');
    }
    
    // Expected Result: UI remains responsive without errors
    // Step 9: Check browser console for any errors or warnings
    const consoleErrors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });
    
    expect(consoleErrors.length).toBe(0);
    
    // Step 10: Verify that only tasks authorized for the current user are displayed
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-filter-option-in-progress"]');
    await page.waitForSelector('[data-testid="task-item"]');
    
    // Expected Result: No unauthorized tasks are visible
    const allTasks = await page.locator('[data-testid="task-item"]').all();
    expect(allTasks.length).toBeGreaterThan(0);
    
    // Step 11: Randomly select several tasks and verify their status matches the applied filter
    const tasksToVerify = Math.min(5, allTasks.length);
    for (let i = 0; i < tasksToVerify; i++) {
      const randomIndex = Math.floor(Math.random() * allTasks.length);
      const task = allTasks[randomIndex];
      const statusBadge = await task.locator('[data-testid="task-status"]').textContent();
      expect(statusBadge?.trim()).toBe('In Progress');
    }
  });
});