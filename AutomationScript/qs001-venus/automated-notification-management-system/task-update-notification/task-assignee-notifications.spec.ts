import { test, expect } from '@playwright/test';

test.describe('Task Assignee Notification System', () => {
  let baseURL: string;
  let testTaskId: string;

  test.beforeEach(async ({ page }) => {
    baseURL = process.env.BASE_URL || 'http://localhost:3000';
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', 'testuser@example.com');
    await page.fill('[data-testid="password-input"]', 'TestPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate notification sent on task status update (happy-path)', async ({ page, context }) => {
    // Navigate to the task management module and select an existing task assigned to the test user
    await page.goto(`${baseURL}/tasks`);
    await page.waitForSelector('[data-testid="task-list"]');
    await page.click('[data-testid="task-item"]:first-child');
    await expect(page.locator('[data-testid="task-details-panel"]')).toBeVisible();
    
    // Store task ID for verification
    testTaskId = await page.locator('[data-testid="task-id"]').textContent() || '';
    
    // Update the task status from 'In Progress' to 'Completed' and save the changes
    await page.click('[data-testid="task-status-dropdown"]');
    await page.click('[data-testid="status-option-completed"]');
    await page.click('[data-testid="save-task-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Task updated successfully');
    
    // Check the user's email inbox for the task update notification
    await page.goto(`${baseURL}/email-inbox`);
    await page.waitForSelector('[data-testid="email-list"]');
    const emailNotification = page.locator(`[data-testid="email-item"]:has-text("Task ${testTaskId} updated")`);
    await expect(emailNotification).toBeVisible({ timeout: 10000 });
    await emailNotification.click();
    await expect(page.locator('[data-testid="email-body"]')).toContainText('Completed');
    await expect(page.locator('[data-testid="email-body"]')).toContainText(testTaskId);
    
    // Check the user's mobile device for SMS notification
    await page.goto(`${baseURL}/sms-inbox`);
    await page.waitForSelector('[data-testid="sms-list"]');
    const smsNotification = page.locator(`[data-testid="sms-item"]:has-text("Task ${testTaskId}")`);
    await expect(smsNotification).toBeVisible({ timeout: 10000 });
    await expect(smsNotification).toContainText('Completed');
    
    // Check the in-app notification center within the application
    await page.click('[data-testid="notification-bell-icon"]');
    await expect(page.locator('[data-testid="notification-dropdown"]')).toBeVisible();
    const inAppNotification = page.locator(`[data-testid="notification-item"]:has-text("Task ${testTaskId}")`);
    await expect(inAppNotification).toBeVisible();
    await expect(inAppNotification).toContainText('Completed');
    
    // Navigate to user profile settings and access notification preferences section
    await page.goto(`${baseURL}/profile/settings`);
    await page.click('[data-testid="notification-preferences-tab"]');
    await expect(page.locator('[data-testid="notification-preferences-section"]')).toBeVisible();
    
    // Disable SMS notifications for task updates and save the preferences
    await page.uncheck('[data-testid="sms-task-updates-checkbox"]');
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved');
    
    // Update the same task status from 'Completed' to 'In Review'
    await page.goto(`${baseURL}/tasks`);
    await page.click(`[data-testid="task-item"]:has-text("${testTaskId}")`);
    await page.click('[data-testid="task-status-dropdown"]');
    await page.click('[data-testid="status-option-in-review"]');
    await page.click('[data-testid="save-task-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Task updated successfully');
    
    // Check email, SMS, and in-app notifications for the second update
    await page.goto(`${baseURL}/email-inbox`);
    const secondEmailNotification = page.locator(`[data-testid="email-item"]:has-text("Task ${testTaskId} updated"):has-text("In Review")`);
    await expect(secondEmailNotification).toBeVisible({ timeout: 10000 });
    
    // Verify SMS was NOT sent due to disabled preference
    await page.goto(`${baseURL}/sms-inbox`);
    const secondSmsNotification = page.locator(`[data-testid="sms-item"]:has-text("Task ${testTaskId}"):has-text("In Review")`);
    await expect(secondSmsNotification).not.toBeVisible({ timeout: 5000 });
    
    // Verify in-app notification was sent
    await page.click('[data-testid="notification-bell-icon"]');
    const secondInAppNotification = page.locator(`[data-testid="notification-item"]:has-text("Task ${testTaskId}"):has-text("In Review")`);
    await expect(secondInAppNotification).toBeVisible();
  });

  test('Verify retry mechanism on notification failure (error-case)', async ({ page }) => {
    // Configure the test environment to simulate email notification delivery failure for the next notification attempt
    await page.goto(`${baseURL}/admin/test-config`);
    await page.click('[data-testid="notification-testing-tab"]');
    await page.check('[data-testid="simulate-email-failure-checkbox"]');
    await page.fill('[data-testid="failure-count-input"]', '2');
    await page.click('[data-testid="apply-test-config-button"]');
    await expect(page.locator('[data-testid="config-applied-message"]')).toContainText('Test configuration applied');
    
    // Update a task status from 'New' to 'In Progress' to trigger notification
    await page.goto(`${baseURL}/tasks`);
    await page.click('[data-testid="filter-status-dropdown"]');
    await page.click('[data-testid="filter-status-new"]');
    await page.click('[data-testid="task-item"]:first-child');
    testTaskId = await page.locator('[data-testid="task-id"]').textContent() || '';
    await page.click('[data-testid="task-status-dropdown"]');
    await page.click('[data-testid="status-option-in-progress"]');
    const updateTimestamp = new Date().toISOString();
    await page.click('[data-testid="save-task-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Task updated successfully');
    
    // Monitor the notification service logs in real-time during the retry attempts
    await page.goto(`${baseURL}/admin/notification-logs`);
    await page.fill('[data-testid="log-search-input"]', testTaskId);
    await page.click('[data-testid="search-logs-button"]');
    await page.waitForSelector('[data-testid="log-entries"]');
    
    // Continue monitoring as the system performs subsequent retry attempts
    await page.waitForTimeout(5000);
    await page.click('[data-testid="refresh-logs-button"]');
    
    // Access the notification logs dashboard and filter for the specific task update notification
    const logEntries = page.locator('[data-testid="log-entry"]');
    await expect(logEntries).toHaveCount(3, { timeout: 15000 });
    
    // Verify the log entry details including task ID, notification type, delivery channel, and retry count
    for (let i = 0; i < 3; i++) {
      const logEntry = logEntries.nth(i);
      await expect(logEntry.locator('[data-testid="log-task-id"]')).toContainText(testTaskId);
      await expect(logEntry.locator('[data-testid="log-notification-type"]')).toContainText('task-update');
      await expect(logEntry.locator('[data-testid="log-delivery-channel"]')).toContainText('email');
      await expect(logEntry.locator('[data-testid="log-retry-count"]')).toContainText(`${i + 1}`);
      await expect(logEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    }
    
    // Remove the failure simulation and update the task status again from 'In Progress' to 'Blocked'
    await page.goto(`${baseURL}/admin/test-config`);
    await page.uncheck('[data-testid="simulate-email-failure-checkbox"]');
    await page.click('[data-testid="apply-test-config-button"]');
    
    await page.goto(`${baseURL}/tasks`);
    await page.click(`[data-testid="task-item"]:has-text("${testTaskId}")`);
    await page.click('[data-testid="task-status-dropdown"]');
    await page.click('[data-testid="status-option-blocked"]');
    await page.click('[data-testid="save-task-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Task updated successfully');
    
    // Check the notification logs for the successful delivery
    await page.goto(`${baseURL}/admin/notification-logs`);
    await page.fill('[data-testid="log-search-input"]', testTaskId);
    await page.click('[data-testid="search-logs-button"]');
    const successfulLogEntry = page.locator('[data-testid="log-entry"]:has-text("Blocked")').first();
    await expect(successfulLogEntry).toBeVisible({ timeout: 10000 });
    await expect(successfulLogEntry.locator('[data-testid="log-status"]')).toContainText('delivered');
    await expect(successfulLogEntry.locator('[data-testid="log-retry-count"]')).toContainText('1');
  });

  test('Ensure immediate notification delivery (happy-path)', async ({ page }) => {
    const deliveryTimes: number[] = [];
    const taskUpdates: { taskId: string; updateTime: number; deliveryTime: number }[] = [];
    
    // Record the current system timestamp as the test start time
    const testStartTime = Date.now();
    
    // Navigate to tasks page
    await page.goto(`${baseURL}/tasks`);
    await page.waitForSelector('[data-testid="task-list"]');
    
    // Update the status of Task #1 from 'New' to 'In Progress' and record the exact update timestamp
    await page.click('[data-testid="task-item"]', { position: { x: 10, y: 10 } });
    const task1Id = await page.locator('[data-testid="task-id"]').textContent() || '';
    await page.click('[data-testid="task-status-dropdown"]');
    await page.click('[data-testid="status-option-in-progress"]');
    const task1UpdateTime = Date.now();
    await page.click('[data-testid="save-task-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Monitor notification delivery and record the timestamp when notification is received in the in-app notification center
    await page.click('[data-testid="notification-bell-icon"]');
    await page.waitForSelector(`[data-testid="notification-item"]:has-text("${task1Id}")`, { timeout: 5000 });
    const task1DeliveryTime = Date.now();
    await page.click('[data-testid="notification-bell-icon"]');
    
    // Calculate the time difference between task update and notification delivery for Task #1
    const task1Difference = task1DeliveryTime - task1UpdateTime;
    deliveryTimes.push(task1Difference);
    taskUpdates.push({ taskId: task1Id, updateTime: task1UpdateTime, deliveryTime: task1DeliveryTime });
    expect(task1Difference).toBeLessThan(3000);
    
    // Update the status of Task #2 from 'In Progress' to 'Completed' and record the update timestamp
    await page.goto(`${baseURL}/tasks`);
    await page.click('[data-testid="filter-status-dropdown"]');
    await page.click('[data-testid="filter-status-in-progress"]');
    await page.click('[data-testid="task-item"]:nth-child(2)');
    const task2Id = await page.locator('[data-testid="task-id"]').textContent() || '';
    await page.click('[data-testid="task-status-dropdown"]');
    await page.click('[data-testid="status-option-completed"]');
    const task2UpdateTime = Date.now();
    await page.click('[data-testid="save-task-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Monitor and record the notification delivery timestamp for Task #2
    await page.click('[data-testid="notification-bell-icon"]');
    await page.waitForSelector(`[data-testid="notification-item"]:has-text("${task2Id}")`, { timeout: 5000 });
    const task2DeliveryTime = Date.now();
    await page.click('[data-testid="notification-bell-icon"]');
    
    const task2Difference = task2DeliveryTime - task2UpdateTime;
    deliveryTimes.push(task2Difference);
    taskUpdates.push({ taskId: task2Id, updateTime: task2UpdateTime, deliveryTime: task2DeliveryTime });
    expect(task2Difference).toBeLessThan(3000);
    
    // Update the status of Task #3 from 'Completed' to 'Archived' and record the update timestamp
    await page.goto(`${baseURL}/tasks`);
    await page.click('[data-testid="filter-status-dropdown"]');
    await page.click('[data-testid="filter-status-completed"]');
    await page.click('[data-testid="task-item"]:nth-child(3)');
    const task3Id = await page.locator('[data-testid="task-id"]').textContent() || '';
    await page.click('[data-testid="task-status-dropdown"]');
    await page.click('[data-testid="status-option-archived"]');
    const task3UpdateTime = Date.now();
    await page.click('[data-testid="save-task-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Monitor and record the notification delivery timestamp for Task #3
    await page.click('[data-testid="notification-bell-icon"]');
    await page.waitForSelector(`[data-testid="notification-item"]:has-text("${task3Id}")`, { timeout: 5000 });
    const task3DeliveryTime = Date.now();
    await page.click('[data-testid="notification-bell-icon"]');
    
    const task3Difference = task3DeliveryTime - task3UpdateTime;
    deliveryTimes.push(task3Difference);
    taskUpdates.push({ taskId: task3Id, updateTime: task3UpdateTime, deliveryTime: task3DeliveryTime });
    expect(task3Difference).toBeLessThan(3000);
    
    // Access the system logs and filter for notification delivery events for all three task updates
    await page.goto(`${baseURL}/admin/notification-logs`);
    await page.click('[data-testid="filter-date-range"]');
    await page.fill('[data-testid="start-time-input"]', new Date(testStartTime).toISOString());
    await page.fill('[data-testid="end-time-input"]', new Date().toISOString());
    await page.click('[data-testid="apply-filter-button"]');
    
    // Review the logs for any errors, warnings, or delays in the notification processing pipeline
    for (const taskUpdate of taskUpdates) {
      await page.fill('[data-testid="log-search-input"]', taskUpdate.taskId);
      await page.click('[data-testid="search-logs-button"]');
      
      const logEntry = page.locator(`[data-testid="log-entry"]:has-text("${taskUpdate.taskId}")`).first();
      await expect(logEntry).toBeVisible();
      await expect(logEntry.locator('[data-testid="log-status"]')).toContainText('delivered');
      await expect(logEntry.locator('[data-testid="log-errors"]')).toHaveCount(0);
      await expect(logEntry.locator('[data-testid="log-warnings"]')).toHaveCount(0);
      
      await page.click('[data-testid="clear-search-button"]');
    }
    
    // Generate a performance report showing average delivery time across all three notifications
    const averageDeliveryTime = deliveryTimes.reduce((a, b) => a + b, 0) / deliveryTimes.length;
    console.log(`Average notification delivery time: ${averageDeliveryTime}ms`);
    console.log(`Task 1 delivery time: ${deliveryTimes[0]}ms`);
    console.log(`Task 2 delivery time: ${deliveryTimes[1]}ms`);
    console.log(`Task 3 delivery time: ${deliveryTimes[2]}ms`);
    
    // Verify average delivery time meets immediate delivery requirement (< 2 seconds)
    expect(averageDeliveryTime).toBeLessThan(2000);
    
    // Verify all individual delivery times meet requirement
    deliveryTimes.forEach((time, index) => {
      expect(time).toBeLessThan(3000);
    });
  });
});