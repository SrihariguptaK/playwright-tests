import { test, expect } from '@playwright/test';

test.describe('Task Assignment Dashboard - Manager View', () => {
  const MANAGER_EMAIL = 'manager@example.com';
  const MANAGER_PASSWORD = 'Manager123!';
  const EMPLOYEE_EMAIL = 'employee@example.com';
  const EMPLOYEE_PASSWORD = 'Employee123!';
  const DASHBOARD_URL = '/dashboard/task-assignments';
  const MAX_LOAD_TIME = 3000;

  test('Validate dashboard displays assigned tasks with correct details', async ({ page }) => {
    // Step 1: Manager opens the application and enters valid login credentials
    await page.goto('/');
    await page.fill('input[data-testid="email-input"]', MANAGER_EMAIL);
    await page.fill('input[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('button[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Manager clicks on the 'Task Assignment Dashboard' menu option
    await page.click('a[data-testid="task-assignment-dashboard-link"]');
    await expect(page).toHaveURL(new RegExp(DASHBOARD_URL));

    // Step 3: Manager verifies the dashboard displays all assigned tasks in a list or table format
    const taskTable = page.locator('table[data-testid="task-assignment-table"]');
    await expect(taskTable).toBeVisible();
    const taskRows = page.locator('tbody[data-testid="task-list"] tr');
    await expect(taskRows).toHaveCount(await taskRows.count());
    expect(await taskRows.count()).toBeGreaterThan(0);

    // Step 4: Manager verifies each task displays correct status information
    const firstTaskStatus = page.locator('tbody[data-testid="task-list"] tr:first-child td[data-testid="task-status"]');
    await expect(firstTaskStatus).toBeVisible();
    const statusText = await firstTaskStatus.textContent();
    expect(['Not Started', 'In Progress', 'Completed', 'On Hold']).toContain(statusText?.trim());

    // Step 5: Manager verifies each task displays correct deadline information
    const firstTaskDeadline = page.locator('tbody[data-testid="task-list"] tr:first-child td[data-testid="task-deadline"]');
    await expect(firstTaskDeadline).toBeVisible();
    const deadlineText = await firstTaskDeadline.textContent();
    expect(deadlineText).toMatch(/\d{1,2}\/\d{1,2}\/\d{4}|\d{4}-\d{2}-\d{2}/);

    // Step 6: Manager verifies each task displays correct priority information
    const firstTaskPriority = page.locator('tbody[data-testid="task-list"] tr:first-child td[data-testid="task-priority"]');
    await expect(firstTaskPriority).toBeVisible();
    const priorityText = await firstTaskPriority.textContent();
    expect(['Low', 'Medium', 'High', 'Critical']).toContain(priorityText?.trim());

    // Step 7: Manager locates and clicks on the priority filter dropdown and selects 'High' priority
    await page.click('select[data-testid="priority-filter"]');
    await page.selectOption('select[data-testid="priority-filter"]', 'High');

    // Step 8: Manager locates and clicks on the status filter dropdown and selects 'In Progress' status
    await page.click('select[data-testid="status-filter"]');
    await page.selectOption('select[data-testid="status-filter"]', 'In Progress');

    // Step 9: Manager verifies the filtered results display only tasks matching both filter criteria
    await page.waitForTimeout(500); // Wait for filter to apply
    const filteredRows = page.locator('tbody[data-testid="task-list"] tr');
    const filteredCount = await filteredRows.count();
    
    for (let i = 0; i < filteredCount; i++) {
      const row = filteredRows.nth(i);
      const status = await row.locator('td[data-testid="task-status"]').textContent();
      const priority = await row.locator('td[data-testid="task-priority"]').textContent();
      expect(status?.trim()).toBe('In Progress');
      expect(priority?.trim()).toBe('High');
    }

    // Step 10: Manager clears all filters to view all tasks again
    await page.selectOption('select[data-testid="priority-filter"]', '');
    await page.selectOption('select[data-testid="status-filter"]', '');
    await page.waitForTimeout(500);
    const allTasksAgain = page.locator('tbody[data-testid="task-list"] tr');
    expect(await allTasksAgain.count()).toBeGreaterThanOrEqual(filteredCount);

    // Step 11: Manager clicks on a specific task from the list to view detailed information
    await page.click('tbody[data-testid="task-list"] tr:first-child');
    const taskDetailModal = page.locator('[data-testid="task-detail-modal"]');
    await expect(taskDetailModal).toBeVisible();

    // Step 12: Manager verifies task details include all required information
    await expect(page.locator('[data-testid="task-detail-title"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-detail-description"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-detail-assigned-employee"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-detail-deadline"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-detail-priority"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-assignment-history"]')).toBeVisible();
  });

  test('Ensure dashboard access is restricted to authorized managers', async ({ page }) => {
    // Step 1: Open the application without logging in and attempt to navigate directly to the dashboard URL
    await page.goto(DASHBOARD_URL);
    
    // Step 2: Verify that the error message clearly indicates authentication is required
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible();
    const errorText = await errorMessage.textContent();
    expect(errorText?.toLowerCase()).toMatch(/authentication|login|unauthorized|access denied/);
    await expect(page).toHaveURL(/.*login/);

    // Step 3: Log into the system using employee credentials (non-manager role)
    await page.fill('input[data-testid="email-input"]', EMPLOYEE_EMAIL);
    await page.fill('input[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    await page.click('button[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 4: Employee attempts to navigate to the task assignment dashboard URL directly
    await page.goto(DASHBOARD_URL);

    // Step 5: Verify that the dashboard menu option is not visible in the employee's navigation menu
    const dashboardLink = page.locator('a[data-testid="task-assignment-dashboard-link"]');
    await expect(dashboardLink).not.toBeVisible();
    
    // Verify access denied message or redirect
    const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
    if (await accessDeniedMessage.isVisible()) {
      const deniedText = await accessDeniedMessage.textContent();
      expect(deniedText?.toLowerCase()).toMatch(/access denied|unauthorized|permission/);
    } else {
      // Should be redirected away from dashboard
      await expect(page).not.toHaveURL(new RegExp(DASHBOARD_URL));
    }

    // Step 6: Log out from employee account and log in using valid manager credentials
    await page.click('button[data-testid="logout-button"]');
    await page.fill('input[data-testid="email-input"]', MANAGER_EMAIL);
    await page.fill('input[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('button[data-testid="login-button"]');

    // Step 7: Manager navigates to the task assignment dashboard
    await page.click('a[data-testid="task-assignment-dashboard-link"]');
    await expect(page).toHaveURL(new RegExp(DASHBOARD_URL));

    // Step 8: Verify manager has full access to all dashboard features including filters and task details
    await expect(page.locator('table[data-testid="task-assignment-table"]')).toBeVisible();
    await expect(page.locator('select[data-testid="priority-filter"]')).toBeVisible();
    await expect(page.locator('select[data-testid="status-filter"]')).toBeVisible();
    await expect(page.locator('select[data-testid="deadline-filter"]')).toBeVisible();
  });

  test('Verify dashboard load time under normal conditions', async ({ page }) => {
    // Step 1: Manager logs into the system with valid credentials
    await page.goto('/');
    await page.fill('input[data-testid="email-input"]', MANAGER_EMAIL);
    await page.fill('input[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('button[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Perform test 4 times to ensure consistent performance
    const loadTimes: number[] = [];

    for (let iteration = 1; iteration <= 4; iteration++) {
      // Step 2: Clear browser cache and refresh the page to ensure clean test conditions
      await page.context().clearCookies();
      await page.reload();
      
      // Re-login after cache clear
      await page.fill('input[data-testid="email-input"]', MANAGER_EMAIL);
      await page.fill('input[data-testid="password-input"]', MANAGER_PASSWORD);
      await page.click('button[data-testid="login-button"]');

      // Step 3: Start performance timer
      const startTime = Date.now();

      // Step 4: Manager clicks on the 'Task Assignment Dashboard' menu option
      await page.click('a[data-testid="task-assignment-dashboard-link"]');

      // Step 5: Monitor the page load process and wait for dashboard to fully render with all task data
      await page.waitForLoadState('networkidle');
      await expect(page.locator('table[data-testid="task-assignment-table"]')).toBeVisible();
      await expect(page.locator('tbody[data-testid="task-list"] tr:first-child')).toBeVisible();

      // Step 6: Stop the performance timer when dashboard is fully interactive and all data is displayed
      const endTime = Date.now();
      const loadTime = endTime - startTime;
      loadTimes.push(loadTime);

      // Step 7: Verify the recorded load time is 3 seconds or less
      expect(loadTime).toBeLessThanOrEqual(MAX_LOAD_TIME);

      console.log(`Dashboard load time (iteration ${iteration}): ${loadTime}ms`);
    }

    // Step 8: Verify consistent performance across all iterations
    const averageLoadTime = loadTimes.reduce((a, b) => a + b, 0) / loadTimes.length;
    console.log(`Average dashboard load time: ${averageLoadTime}ms`);
    expect(averageLoadTime).toBeLessThanOrEqual(MAX_LOAD_TIME);

    // Verify all load times were under threshold
    loadTimes.forEach((time, index) => {
      expect(time).toBeLessThanOrEqual(MAX_LOAD_TIME);
    });
  });
});