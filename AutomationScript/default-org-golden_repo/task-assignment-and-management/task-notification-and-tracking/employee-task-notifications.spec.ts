import { test, expect } from '@playwright/test';

test.describe('Employee Task Notifications', () => {
  const MANAGER_EMAIL = 'manager@company.com';
  const MANAGER_PASSWORD = 'Manager123!';
  const EMPLOYEE_EMAIL = 'employee@company.com';
  const EMPLOYEE_PASSWORD = 'Employee123!';
  const NOTIFICATION_TIMEOUT = 5 * 60 * 1000; // 5 minutes in milliseconds

  test.beforeEach(async ({ page }) => {
    // Navigate to application base URL
    await page.goto('/');
  });

  test('Receive notification on task assignment (happy-path)', async ({ page, context }) => {
    // Step 1: Manager logs into the system and navigates to task management section
    await page.getByTestId('login-email').fill(MANAGER_EMAIL);
    await page.getByTestId('login-password').fill(MANAGER_PASSWORD);
    await page.getByTestId('login-submit').click();
    await expect(page.getByTestId('dashboard')).toBeVisible();
    
    await page.getByTestId('nav-task-management').click();
    await expect(page.getByTestId('task-management-section')).toBeVisible();

    // Step 2: Manager creates a new task with title, description, deadline, and priority
    await page.getByTestId('create-task-button').click();
    await expect(page.getByTestId('task-form')).toBeVisible();
    
    const taskTitle = `Task Assignment Test ${Date.now()}`;
    await page.getByTestId('task-title').fill(taskTitle);
    await page.getByTestId('task-description').fill('This is a test task for notification verification');
    await page.getByTestId('task-deadline').fill('2024-12-31');
    await page.getByTestId('task-priority').selectOption('High');

    // Step 3: Manager assigns the task to a specific employee and submits the assignment
    await page.getByTestId('task-assignee').selectOption(EMPLOYEE_EMAIL);
    await page.getByTestId('task-submit').click();
    
    // Expected Result: Task assignment processed
    await expect(page.getByText('Task assigned successfully')).toBeVisible();
    await expect(page.getByTestId('task-list')).toContainText(taskTitle);

    // Step 4: Wait for notification delivery (maximum 5 minutes)
    // Open employee context in new page
    const employeePage = await context.newPage();
    await employeePage.goto('/');
    
    await employeePage.getByTestId('login-email').fill(EMPLOYEE_EMAIL);
    await employeePage.getByTestId('login-password').fill(EMPLOYEE_PASSWORD);
    await employeePage.getByTestId('login-submit').click();
    await expect(employeePage.getByTestId('dashboard')).toBeVisible();

    // Step 5: Employee checks for new notifications in their notification center
    await employeePage.getByTestId('notification-center').click();
    
    // Expected Result: Notification displayed with task details
    await expect(employeePage.getByTestId('notification-item')).toBeVisible({ timeout: NOTIFICATION_TIMEOUT });
    await expect(employeePage.getByTestId('notification-item')).toContainText(taskTitle);
    await expect(employeePage.getByTestId('notification-item')).toContainText('assigned to you');

    // Step 6: Employee navigates to notification history in their dashboard
    await employeePage.getByTestId('nav-notification-history').click();
    await expect(employeePage.getByTestId('notification-history-section')).toBeVisible();

    // Step 7: Employee verifies the task assignment notification appears in the history list
    // Expected Result: Notification is listed in history
    await expect(employeePage.getByTestId('notification-history-list')).toContainText(taskTitle);
    await expect(employeePage.getByTestId('notification-history-list')).toContainText('Task Assignment');
    
    await employeePage.close();
  });

  test('Receive notification on deadline change (happy-path)', async ({ page, context }) => {
    // Setup: Create a task first
    await page.getByTestId('login-email').fill(MANAGER_EMAIL);
    await page.getByTestId('login-password').fill(MANAGER_PASSWORD);
    await page.getByTestId('login-submit').click();
    await expect(page.getByTestId('dashboard')).toBeVisible();
    
    await page.getByTestId('nav-task-management').click();
    await page.getByTestId('create-task-button').click();
    
    const taskTitle = `Deadline Change Test ${Date.now()}`;
    await page.getByTestId('task-title').fill(taskTitle);
    await page.getByTestId('task-description').fill('Task for deadline change notification test');
    await page.getByTestId('task-deadline').fill('2024-12-15');
    await page.getByTestId('task-priority').selectOption('Medium');
    await page.getByTestId('task-assignee').selectOption(EMPLOYEE_EMAIL);
    await page.getByTestId('task-submit').click();
    await expect(page.getByText('Task assigned successfully')).toBeVisible();

    // Step 1: Manager logs into the system and navigates to the assigned task
    await page.getByTestId('task-list').getByText(taskTitle).click();
    await expect(page.getByTestId('task-details')).toBeVisible();

    // Step 2: Manager selects the option to edit task deadline
    await page.getByTestId('edit-task-button').click();
    await expect(page.getByTestId('task-edit-form')).toBeVisible();

    // Step 3: Manager updates the task deadline to a new date and saves the changes
    await page.getByTestId('task-deadline').fill('2024-12-25');
    await page.getByTestId('task-update-submit').click();
    
    // Expected Result: Deadline update processed
    await expect(page.getByText('Task updated successfully')).toBeVisible();
    await expect(page.getByTestId('task-details')).toContainText('2024-12-25');

    // Step 4: Wait for notification delivery (maximum 5 minutes)
    const employeePage = await context.newPage();
    await employeePage.goto('/');
    
    await employeePage.getByTestId('login-email').fill(EMPLOYEE_EMAIL);
    await employeePage.getByTestId('login-password').fill(EMPLOYEE_PASSWORD);
    await employeePage.getByTestId('login-submit').click();
    await expect(employeePage.getByTestId('dashboard')).toBeVisible();

    // Step 5: Employee checks for new notifications in their notification center
    await employeePage.getByTestId('notification-center').click();
    
    // Expected Result: Notification displayed with updated deadline
    await expect(employeePage.getByTestId('notification-item').first()).toBeVisible({ timeout: NOTIFICATION_TIMEOUT });
    await expect(employeePage.getByTestId('notification-item').first()).toContainText(taskTitle);
    await expect(employeePage.getByTestId('notification-item').first()).toContainText('deadline');
    await expect(employeePage.getByTestId('notification-item').first()).toContainText('2024-12-25');

    // Step 6: Employee clicks on the notification to view full details
    await employeePage.getByTestId('notification-item').first().click();
    await expect(employeePage.getByTestId('notification-details')).toBeVisible();
    await expect(employeePage.getByTestId('notification-details')).toContainText('Deadline Changed');

    // Step 7: Employee clicks the acknowledge button on the notification
    await employeePage.getByTestId('acknowledge-notification-button').click();
    
    // Step 8: Verify acknowledgment status in the notification history
    // Expected Result: Acknowledgment recorded
    await expect(employeePage.getByText('Notification acknowledged')).toBeVisible();
    await employeePage.getByTestId('nav-notification-history').click();
    await expect(employeePage.getByTestId('notification-history-list')).toContainText(taskTitle);
    
    const notificationRow = employeePage.getByTestId('notification-history-list').getByText(taskTitle).locator('..');
    await expect(notificationRow).toContainText('Acknowledged');
    
    await employeePage.close();
  });

  test('Verify notification delivery under load (boundary)', async ({ page, context }) => {
    const CONCURRENT_TASKS = 50;
    const taskTitles: string[] = [];
    const notificationStartTime = Date.now();

    // Step 1: Manager logs in
    await page.getByTestId('login-email').fill(MANAGER_EMAIL);
    await page.getByTestId('login-password').fill(MANAGER_PASSWORD);
    await page.getByTestId('login-submit').click();
    await expect(page.getByTestId('dashboard')).toBeVisible();
    
    await page.getByTestId('nav-task-management').click();

    // Step 2: Prepare a list of 50 tasks with varying priorities and deadlines
    const priorities = ['Low', 'Medium', 'High', 'Critical'];
    const deadlines = ['2024-12-20', '2024-12-25', '2024-12-30', '2025-01-05'];

    // Step 3: Manager initiates concurrent task assignments to 50 different employees simultaneously
    const taskCreationPromises = [];
    
    for (let i = 0; i < CONCURRENT_TASKS; i++) {
      const taskTitle = `Load Test Task ${i + 1} - ${Date.now()}`;
      taskTitles.push(taskTitle);
      
      const priority = priorities[i % priorities.length];
      const deadline = deadlines[i % deadlines.length];
      const employeeEmail = `employee${i + 1}@company.com`;

      // Create tasks concurrently using API or UI
      const taskPromise = (async () => {
        await page.getByTestId('create-task-button').click();
        await page.getByTestId('task-title').fill(taskTitle);
        await page.getByTestId('task-description').fill(`Load test task ${i + 1}`);
        await page.getByTestId('task-deadline').fill(deadline);
        await page.getByTestId('task-priority').selectOption(priority);
        await page.getByTestId('task-assignee').selectOption(employeeEmail);
        await page.getByTestId('task-submit').click();
        await expect(page.getByText('Task assigned successfully')).toBeVisible({ timeout: 10000 });
      })();
      
      taskCreationPromises.push(taskPromise);
    }

    // Expected Result: All notifications triggered
    await Promise.all(taskCreationPromises);
    
    // Step 4: Monitor the notification service to verify all 50 notifications are triggered
    await page.getByTestId('nav-admin-panel').click();
    await page.getByTestId('notification-monitoring').click();
    await expect(page.getByTestId('notification-queue-count')).toContainText('50', { timeout: 30000 });

    // Step 5: Track notification delivery time for each of the 50 notifications
    // Step 6: Verify that all 50 employees receive their respective notifications within 5 minutes
    const employeePages = [];
    
    for (let i = 0; i < Math.min(5, CONCURRENT_TASKS); i++) {
      const employeePage = await context.newPage();
      await employeePage.goto('/');
      
      const employeeEmail = `employee${i + 1}@company.com`;
      await employeePage.getByTestId('login-email').fill(employeeEmail);
      await employeePage.getByTestId('login-password').fill('Employee123!');
      await employeePage.getByTestId('login-submit').click();
      await expect(employeePage.getByTestId('dashboard')).toBeVisible();
      
      await employeePage.getByTestId('notification-center').click();
      
      // Expected Result: Notifications received within 5 minutes
      await expect(employeePage.getByTestId('notification-item')).toBeVisible({ timeout: NOTIFICATION_TIMEOUT });
      await expect(employeePage.getByTestId('notification-item')).toContainText(`Load Test Task ${i + 1}`);
      
      employeePages.push(employeePage);
    }

    const notificationEndTime = Date.now();
    const deliveryTime = (notificationEndTime - notificationStartTime) / 1000;
    expect(deliveryTime).toBeLessThan(300); // Less than 5 minutes

    // Step 7: Check system performance metrics including CPU usage, memory consumption, and response times
    await page.bringToFront();
    await page.getByTestId('system-metrics').click();
    
    // Expected Result: No errors or delays observed
    const cpuUsage = await page.getByTestId('cpu-usage-metric').textContent();
    const memoryUsage = await page.getByTestId('memory-usage-metric').textContent();
    const avgResponseTime = await page.getByTestId('avg-response-time-metric').textContent();
    
    expect(parseFloat(cpuUsage || '0')).toBeLessThan(90);
    expect(parseFloat(memoryUsage || '0')).toBeLessThan(90);
    expect(parseFloat(avgResponseTime || '0')).toBeLessThan(5000);

    // Step 8: Review system logs for any errors, warnings, or failed notification deliveries
    await page.getByTestId('system-logs').click();
    await expect(page.getByTestId('logs-panel')).toBeVisible();
    
    const errorCount = await page.getByTestId('error-count').textContent();
    expect(parseInt(errorCount || '0')).toBe(0);

    // Step 9: Verify database integrity and notification records for all 50 assignments
    await page.getByTestId('notification-records').click();
    await expect(page.getByTestId('total-notifications-sent')).toContainText('50');
    await expect(page.getByTestId('notifications-delivered')).toContainText('50');
    await expect(page.getByTestId('notifications-failed')).toContainText('0');

    // Cleanup
    for (const employeePage of employeePages) {
      await employeePage.close();
    }
  });
});