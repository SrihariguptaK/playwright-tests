import { test, expect } from '@playwright/test';

test.describe('Story-15: Task Sorting and Filtering for Managers', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'Manager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate sorting tasks by priority', async ({ page }) => {
    // Step 1: Navigate to task list page
    await page.click('[data-testid="tasks-menu-item"]');
    await expect(page).toHaveURL(/.*tasks/);
    await page.waitForSelector('[data-testid="task-list"]');
    
    // Verify task list is displayed
    const taskList = page.locator('[data-testid="task-list"]');
    await expect(taskList).toBeVisible();
    
    // Step 2: Select sort by priority option
    await page.click('[data-testid="sort-dropdown"]');
    await page.click('[data-testid="sort-by-priority"]');
    
    // Wait for tasks to be reordered
    await page.waitForTimeout(1000);
    
    // Step 3: Verify task order - tasks are reordered from High to Low priority
    const taskPriorities = await page.locator('[data-testid="task-priority"]').allTextContents();
    
    // Verify tasks appear correctly sorted by priority (High, Medium, Low)
    const priorityOrder = ['High', 'Medium', 'Low'];
    let lastPriorityIndex = -1;
    
    for (const priority of taskPriorities) {
      const currentPriorityIndex = priorityOrder.indexOf(priority);
      expect(currentPriorityIndex).toBeGreaterThanOrEqual(lastPriorityIndex);
      lastPriorityIndex = currentPriorityIndex;
    }
    
    // Scroll through the entire task list to confirm consistent sorting
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await page.waitForTimeout(500);
    
    const allTaskPriorities = await page.locator('[data-testid="task-priority"]').allTextContents();
    expect(allTaskPriorities.length).toBeGreaterThan(0);
    
    // Verify first task has High priority
    const firstTaskPriority = await page.locator('[data-testid="task-priority"]').first().textContent();
    expect(firstTaskPriority).toBe('High');
  });

  test('Validate filtering tasks by assignee', async ({ page }) => {
    // Step 1: Navigate to task list page
    await page.click('[data-testid="tasks-menu-item"]');
    await expect(page).toHaveURL(/.*tasks/);
    await page.waitForSelector('[data-testid="task-list"]');
    
    // Verify task list is displayed
    const taskList = page.locator('[data-testid="task-list"]');
    await expect(taskList).toBeVisible();
    
    // Get initial task count
    const initialTaskCount = await page.locator('[data-testid="task-item"]').count();
    expect(initialTaskCount).toBeGreaterThan(0);
    
    // Step 2: Apply filter for specific employee assignee
    await page.click('[data-testid="filter-by-assignee"]');
    await page.waitForSelector('[data-testid="assignee-dropdown"]');
    
    // Select a specific employee from the assignee dropdown list
    await page.click('[data-testid="assignee-dropdown"]');
    const selectedEmployee = 'John Doe';
    await page.click(`[data-testid="assignee-option-${selectedEmployee.toLowerCase().replace(' ', '-')}"]`);
    
    // Wait for task list to update
    await page.waitForTimeout(1000);
    
    // Step 3: Verify task list updates to show only tasks assigned to selected employee
    const filteredTasks = await page.locator('[data-testid="task-item"]').count();
    expect(filteredTasks).toBeLessThanOrEqual(initialTaskCount);
    
    // Verify that all displayed tasks show the selected employee as the assignee
    const assigneeNames = await page.locator('[data-testid="task-assignee"]').allTextContents();
    
    for (const assignee of assigneeNames) {
      expect(assignee.trim()).toBe(selectedEmployee);
    }
    
    // Check the task count or summary information to confirm the number of filtered tasks
    const taskCountDisplay = await page.locator('[data-testid="task-count"]').textContent();
    const displayedCount = parseInt(taskCountDisplay?.match(/\d+/)?.[0] || '0');
    expect(displayedCount).toBe(filteredTasks);
    
    // Verify filter is applied by checking filter indicator
    const filterIndicator = page.locator('[data-testid="active-filter-assignee"]');
    await expect(filterIndicator).toBeVisible();
    await expect(filterIndicator).toContainText(selectedEmployee);
  });

  test('Validate sorting tasks by priority - detailed verification', async ({ page }) => {
    // Navigate to the task list page by clicking on 'Tasks' menu item
    await page.click('text=Tasks');
    await expect(page).toHaveURL(/.*tasks/);
    
    // Wait for task list to load
    await page.waitForSelector('[data-testid="task-list"]', { state: 'visible' });
    
    // Locate the sorting options dropdown or button and select 'Sort by Priority' option
    const sortButton = page.locator('[data-testid="sort-options"]');
    await sortButton.click();
    
    await page.locator('text=Sort by Priority').click();
    await page.waitForTimeout(800);
    
    // Verify the task order by examining the priority column or labels for each task
    const priorityLabels = page.locator('[data-testid="task-priority-label"]');
    const count = await priorityLabels.count();
    expect(count).toBeGreaterThan(0);
    
    const priorities = await priorityLabels.allTextContents();
    
    // Scroll through the entire task list to confirm consistent sorting throughout
    let previousPriorityValue = 3; // High=3, Medium=2, Low=1
    
    for (let i = 0; i < priorities.length; i++) {
      const priority = priorities[i].trim();
      let currentPriorityValue = 0;
      
      if (priority === 'High') currentPriorityValue = 3;
      else if (priority === 'Medium') currentPriorityValue = 2;
      else if (priority === 'Low') currentPriorityValue = 1;
      
      expect(currentPriorityValue).toBeLessThanOrEqual(previousPriorityValue);
      previousPriorityValue = currentPriorityValue;
      
      // Scroll to view each task
      if (i % 5 === 0) {
        await page.locator(`[data-testid="task-item-${i}"]`).scrollIntoViewIfNeeded();
      }
    }
  });

  test('Validate filtering tasks by assignee - detailed verification', async ({ page }) => {
    // Navigate to the task list page by accessing the task list URL
    await page.goto('/tasks');
    await page.waitForLoadState('networkidle');
    
    // Verify task list is loaded
    await expect(page.locator('[data-testid="task-list"]')).toBeVisible();
    
    // Locate the filter options section and click on the 'Filter by Assignee' dropdown
    const filterSection = page.locator('[data-testid="filter-section"]');
    await expect(filterSection).toBeVisible();
    
    const assigneeFilter = page.locator('[data-testid="filter-assignee-control"]');
    await assigneeFilter.click();
    
    // Select a specific employee from the assignee dropdown list
    await page.waitForSelector('[data-testid="assignee-list"]');
    const employeeName = 'Jane Smith';
    await page.click(`text=${employeeName}`);
    
    // Wait for filtering to complete
    await page.waitForTimeout(1000);
    await page.waitForLoadState('networkidle');
    
    // Verify that all displayed tasks show the selected employee as the assignee
    const taskItems = page.locator('[data-testid="task-item"]');
    const taskCount = await taskItems.count();
    
    for (let i = 0; i < taskCount; i++) {
      const assigneeText = await taskItems.nth(i).locator('[data-testid="task-assignee-name"]').textContent();
      expect(assigneeText?.trim()).toBe(employeeName);
    }
    
    // Check the task count or summary information to confirm the number of filtered tasks
    const summaryInfo = page.locator('[data-testid="task-summary"]');
    await expect(summaryInfo).toBeVisible();
    
    const summaryText = await summaryInfo.textContent();
    expect(summaryText).toContain(`${taskCount}`);
    expect(summaryText).toContain('task');
    
    // Verify filter chip or indicator is displayed
    const activeFilter = page.locator('[data-testid="filter-chip-assignee"]');
    await expect(activeFilter).toBeVisible();
    await expect(activeFilter).toContainText(employeeName);
  });
});