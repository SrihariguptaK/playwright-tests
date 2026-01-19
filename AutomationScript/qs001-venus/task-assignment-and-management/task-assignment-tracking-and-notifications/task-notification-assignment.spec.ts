import { test, expect } from '@playwright/test';

test.describe('Task Notification Assignment - Story 15', () => {
  const MANAGER_EMAIL = 'manager@company.com';
  const MANAGER_PASSWORD = 'Manager123!';
  const EMPLOYEE_EMAIL = 'employee@company.com';
  const EMPLOYEE_PASSWORD = 'Employee123!';
  const NOTIFICATION_TIMEOUT = 5000;

  test.beforeEach(async ({ page }) => {
    // Navigate to application base URL
    await page.goto('/');
  });

  test('Validate notification delivery upon task assignment (happy-path)', async ({ page, context }) => {
    // Step 1: Manager logs into the system and navigates to task assignment page
    await page.getByTestId('login-email').fill(MANAGER_EMAIL);
    await page.getByTestId('login-password').fill(MANAGER_PASSWORD);
    await page.getByTestId('login-submit-button').click();
    await expect(page.getByTestId('dashboard-header')).toBeVisible();
    
    await page.getByTestId('nav-tasks').click();
    await page.getByTestId('create-task-button').click();
    
    // Step 2: Manager creates a new task and assigns it to employee
    const taskTitle = `Task Assignment Test ${Date.now()}`;
    const taskDescription = 'This is a test task for notification validation';
    const taskDeadline = '2024-12-31';
    const taskPriority = 'High';
    
    await page.getByTestId('task-title-input').fill(taskTitle);
    await page.getByTestId('task-description-input').fill(taskDescription);
    await page.getByTestId('task-deadline-input').fill(taskDeadline);
    await page.getByTestId('task-priority-select').selectOption(taskPriority);
    await page.getByTestId('task-assignee-select').selectOption(EMPLOYEE_EMAIL);
    
    // Record timestamp before assignment
    const assignmentTime = Date.now();
    await page.getByTestId('task-submit-button').click();
    
    await expect(page.getByText('Task created successfully')).toBeVisible();
    
    // Step 3: Employee logs into the system in a new page
    const employeePage = await context.newPage();
    await employeePage.goto('/');
    await employeePage.getByTestId('login-email').fill(EMPLOYEE_EMAIL);
    await employeePage.getByTestId('login-password').fill(EMPLOYEE_PASSWORD);
    await employeePage.getByTestId('login-submit-button').click();
    await expect(employeePage.getByTestId('dashboard-header')).toBeVisible();
    
    // Step 4: Employee checks notification inbox
    await employeePage.getByTestId('notifications-icon').click();
    
    // Verify notification is delivered within 5 seconds
    const notificationDeliveryTime = Date.now();
    const deliveryLatency = notificationDeliveryTime - assignmentTime;
    expect(deliveryLatency).toBeLessThanOrEqual(NOTIFICATION_TIMEOUT);
    
    // Verify notification with task details is visible
    const notification = employeePage.getByTestId('notification-item').filter({ hasText: taskTitle });
    await expect(notification).toBeVisible();
    await expect(notification).toContainText(taskTitle);
    await expect(notification).toContainText(taskDescription);
    await expect(notification).toContainText(taskDeadline);
    await expect(notification).toContainText(taskPriority);
    
    // Step 5: Employee acknowledges the notification
    await notification.getByTestId('acknowledge-button').click();
    await expect(employeePage.getByText('Notification acknowledged')).toBeVisible();
    
    // Step 6: Manager checks acknowledgment status
    await page.getByTestId('notifications-icon').click();
    await page.getByTestId('notification-history-link').click();
    
    const acknowledgmentStatus = page.getByTestId('notification-acknowledgment').filter({ hasText: taskTitle });
    await expect(acknowledgmentStatus).toContainText('Acknowledged');
    await expect(acknowledgmentStatus).toContainText(EMPLOYEE_EMAIL);
    
    await employeePage.close();
  });

  test('Verify notification content accuracy (happy-path)', async ({ page, context }) => {
    // Step 1: Manager creates a task with specific details
    await page.getByTestId('login-email').fill(MANAGER_EMAIL);
    await page.getByTestId('login-password').fill(MANAGER_PASSWORD);
    await page.getByTestId('login-submit-button').click();
    await expect(page.getByTestId('dashboard-header')).toBeVisible();
    
    await page.getByTestId('nav-tasks').click();
    await page.getByTestId('create-task-button').click();
    
    const taskTitle = 'Q4 Budget Review';
    const taskDescription = 'Review and approve Q4 budget allocations';
    const taskDeadline = '2024-12-31';
    const taskPriority = 'High';
    
    // Step 2: Manager assigns the task to the employee
    await page.getByTestId('task-title-input').fill(taskTitle);
    await page.getByTestId('task-description-input').fill(taskDescription);
    await page.getByTestId('task-deadline-input').fill(taskDeadline);
    await page.getByTestId('task-priority-select').selectOption(taskPriority);
    await page.getByTestId('task-assignee-select').selectOption(EMPLOYEE_EMAIL);
    await page.getByTestId('task-submit-button').click();
    
    await expect(page.getByText('Task created successfully')).toBeVisible();
    
    // Step 3: Employee receives and opens the task assignment notification
    const employeePage = await context.newPage();
    await employeePage.goto('/');
    await employeePage.getByTestId('login-email').fill(EMPLOYEE_EMAIL);
    await employeePage.getByTestId('login-password').fill(EMPLOYEE_PASSWORD);
    await employeePage.getByTestId('login-submit-button').click();
    await expect(employeePage.getByTestId('dashboard-header')).toBeVisible();
    
    await employeePage.getByTestId('notifications-icon').click();
    const notification = employeePage.getByTestId('notification-item').filter({ hasText: taskTitle }).first();
    await expect(notification).toBeVisible();
    await notification.click();
    
    // Step 4: Employee verifies the task title matches
    const notificationTitle = employeePage.getByTestId('notification-detail-title');
    await expect(notificationTitle).toHaveText(taskTitle);
    
    // Step 5: Employee verifies the task description matches
    const notificationDescription = employeePage.getByTestId('notification-detail-description');
    await expect(notificationDescription).toHaveText(taskDescription);
    
    // Step 6: Employee verifies the deadline matches
    const notificationDeadline = employeePage.getByTestId('notification-detail-deadline');
    await expect(notificationDeadline).toContainText(taskDeadline);
    
    // Step 7: Employee verifies the priority is marked as High
    const notificationPriority = employeePage.getByTestId('notification-detail-priority');
    await expect(notificationPriority).toHaveText(taskPriority);
    
    await employeePage.close();
  });

  test('Ensure high notification delivery success rate (boundary)', async ({ page, context }) => {
    // Step 1: Manager prepares and assigns 100 unique tasks
    await page.getByTestId('login-email').fill(MANAGER_EMAIL);
    await page.getByTestId('login-password').fill(MANAGER_PASSWORD);
    await page.getByTestId('login-submit-button').click();
    await expect(page.getByTestId('dashboard-header')).toBeVisible();
    
    const totalTasks = 100;
    const taskIds: string[] = [];
    const priorities = ['Low', 'Medium', 'High', 'Critical'];
    
    // Step 2: Manager assigns all 100 tasks in rapid succession
    for (let i = 0; i < totalTasks; i++) {
      await page.getByTestId('nav-tasks').click();
      await page.getByTestId('create-task-button').click();
      
      const taskTitle = `Bulk Task ${i + 1} - ${Date.now()}`;
      const taskDescription = `Description for bulk task ${i + 1}`;
      const taskDeadline = '2024-12-31';
      const taskPriority = priorities[i % priorities.length];
      const employeeEmail = `employee${(i % 10) + 1}@company.com`;
      
      await page.getByTestId('task-title-input').fill(taskTitle);
      await page.getByTestId('task-description-input').fill(taskDescription);
      await page.getByTestId('task-deadline-input').fill(taskDeadline);
      await page.getByTestId('task-priority-select').selectOption(taskPriority);
      await page.getByTestId('task-assignee-select').selectOption(employeeEmail);
      await page.getByTestId('task-submit-button').click();
      
      await expect(page.getByText('Task created successfully')).toBeVisible({ timeout: 3000 });
      taskIds.push(taskTitle);
    }
    
    // Step 3 & 4: Monitor notification service and check delivery status
    await page.getByTestId('nav-admin').click();
    await page.getByTestId('notification-logs-link').click();
    
    // Wait for all notifications to be processed
    await page.waitForTimeout(10000);
    
    // Step 5: Count successfully delivered notifications
    await page.getByTestId('filter-status-select').selectOption('delivered');
    await page.getByTestId('filter-apply-button').click();
    
    const deliveredNotifications = await page.getByTestId('notification-log-row').count();
    
    // Step 6: Calculate delivery success rate
    const successRate = (deliveredNotifications / totalTasks) * 100;
    
    // Verify at least 99% delivery success rate
    expect(successRate).toBeGreaterThanOrEqual(99);
    expect(deliveredNotifications).toBeGreaterThanOrEqual(99);
    
    // Step 7: Review any failed notifications
    if (deliveredNotifications < totalTasks) {
      await page.getByTestId('filter-status-select').selectOption('failed');
      await page.getByTestId('filter-apply-button').click();
      
      const failedCount = await page.getByTestId('notification-log-row').count();
      const failedNotifications = await page.getByTestId('notification-log-row').all();
      
      for (const failedNotification of failedNotifications) {
        const failureReason = await failedNotification.getByTestId('failure-reason').textContent();
        console.log(`Failed notification reason: ${failureReason}`);
      }
      
      expect(failedCount).toBeLessThanOrEqual(1);
    }
  });
});