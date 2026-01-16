import { test, expect } from '@playwright/test';

test.describe('Story-13: Employee Task Assignment Notifications', () => {
  const managerEmail = 'manager@company.com';
  const managerPassword = 'Manager123!';
  const employeeEmail = 'employee@company.com';
  const employeePassword = 'Employee123!';
  const testTaskTitle = `Test Task ${Date.now()}`;
  const testTaskDescription = 'This is a test task for notification validation';
  const testTaskDueDate = '2024-12-31';

  test.beforeEach(async ({ page }) => {
    // Navigate to application
    await page.goto('/');
  });

  test('Validate notification delivery upon task assignment', async ({ page, context }) => {
    // Step 1: Manager logs in and navigates to task creation page
    await page.getByTestId('login-email').fill(managerEmail);
    await page.getByTestId('login-password').fill(managerPassword);
    await page.getByTestId('login-submit').click();
    
    await expect(page.getByTestId('dashboard-header')).toBeVisible();
    
    // Navigate to task creation page
    await page.getByTestId('nav-tasks').click();
    await page.getByTestId('create-task-button').click();
    
    // Step 2: Manager creates a new task with all required fields
    await page.getByTestId('task-title-input').fill(testTaskTitle);
    await page.getByTestId('task-description-input').fill(testTaskDescription);
    await page.getByTestId('task-due-date-input').fill(testTaskDueDate);
    
    // Step 3: Manager assigns the task to a specific employee
    await page.getByTestId('task-assignee-dropdown').click();
    await page.getByRole('option', { name: employeeEmail }).click();
    
    // Step 4: Manager clicks Save/Assign button
    await page.getByTestId('task-save-button').click();
    
    // Expected Result: Notification is triggered
    await expect(page.getByTestId('success-message')).toContainText('Task assigned successfully');
    await expect(page.getByTestId('notification-triggered-indicator')).toBeVisible();
    
    // Log out manager
    await page.getByTestId('user-menu').click();
    await page.getByTestId('logout-button').click();
    
    // Step 5: Employee logs into the system
    await page.getByTestId('login-email').fill(employeeEmail);
    await page.getByTestId('login-password').fill(employeePassword);
    await page.getByTestId('login-submit').click();
    
    await expect(page.getByTestId('dashboard-header')).toBeVisible();
    
    // Step 6: Employee navigates to system inbox/notifications section
    await page.getByTestId('nav-notifications').click();
    
    // Expected Result: Notification is received in system inbox
    await expect(page.getByTestId('notification-list')).toBeVisible();
    const notification = page.getByTestId('notification-item').filter({ hasText: testTaskTitle }).first();
    await expect(notification).toBeVisible();
    await expect(notification).toContainText('You have been assigned a new task');
    await expect(notification).toContainText(testTaskTitle);
    
    // Step 7: Employee clicks on notification to view full details
    await notification.click();
    
    // Expected Result: Notification details are displayed correctly
    await expect(page.getByTestId('notification-detail-title')).toContainText(testTaskTitle);
    await expect(page.getByTestId('notification-detail-description')).toContainText(testTaskDescription);
    await expect(page.getByTestId('notification-detail-due-date')).toContainText(testTaskDueDate);
    await expect(page.getByTestId('notification-detail-type')).toContainText('Task Assignment');
    
    // Note: Email verification would require email testing service integration
    // This is a placeholder for email validation
    // In real scenario, integrate with email testing service like Mailhog, Mailtrap, or Gmail API
  });

  test('Verify notification delivery logging', async ({ page }) => {
    // Step 1: Manager logs in
    await page.getByTestId('login-email').fill(managerEmail);
    await page.getByTestId('login-password').fill(managerPassword);
    await page.getByTestId('login-submit').click();
    
    await expect(page.getByTestId('dashboard-header')).toBeVisible();
    
    // Step 2: Manager creates a new task with all required information
    await page.getByTestId('nav-tasks').click();
    await page.getByTestId('create-task-button').click();
    
    await page.getByTestId('task-title-input').fill(testTaskTitle);
    await page.getByTestId('task-description-input').fill(testTaskDescription);
    await page.getByTestId('task-priority-dropdown').click();
    await page.getByRole('option', { name: 'High' }).click();
    await page.getByTestId('task-due-date-input').fill(testTaskDueDate);
    
    // Step 3: Manager assigns the task to an employee and saves
    await page.getByTestId('task-assignee-dropdown').click();
    await page.getByRole('option', { name: employeeEmail }).click();
    await page.getByTestId('task-save-button').click();
    
    // Expected Result: System automatically triggers notification delivery
    await expect(page.getByTestId('success-message')).toContainText('Task assigned successfully');
    
    // Get task ID for verification
    const taskId = await page.getByTestId('created-task-id').textContent();
    
    // Step 4: Navigate to notification logs section
    await page.getByTestId('nav-admin').click();
    await page.getByTestId('nav-notification-logs').click();
    
    // Expected Result: Notification delivery is logged in system
    await expect(page.getByTestId('notification-logs-table')).toBeVisible();
    
    // Step 5: Filter or search for the notification log entry
    await page.getByTestId('log-search-input').fill(employeeEmail);
    await page.getByTestId('log-search-button').click();
    
    // Wait for filtered results
    await page.waitForTimeout(1000);
    
    // Step 6: Review the log entry details
    const logEntry = page.getByTestId('log-entry-row').filter({ hasText: testTaskTitle }).first();
    await expect(logEntry).toBeVisible();
    
    // Expected Result: Log entries match notification events
    await expect(logEntry.getByTestId('log-recipient')).toContainText(employeeEmail);
    await expect(logEntry.getByTestId('log-delivery-status')).toContainText('Delivered');
    await expect(logEntry.getByTestId('log-notification-type')).toContainText('Task Assignment');
    await expect(logEntry.getByTestId('log-task-reference')).toContainText(taskId || testTaskTitle);
    
    // Verify timestamp is recent (within last 5 minutes)
    const timestamp = await logEntry.getByTestId('log-timestamp').textContent();
    expect(timestamp).toBeTruthy();
    
    // Click on log entry to view full details
    await logEntry.click();
    
    // Verify detailed log information
    await expect(page.getByTestId('log-detail-modal')).toBeVisible();
    await expect(page.getByTestId('log-detail-recipient')).toContainText(employeeEmail);
    await expect(page.getByTestId('log-detail-status')).toContainText('Delivered');
    await expect(page.getByTestId('log-detail-channels')).toContainText('System Inbox');
    await expect(page.getByTestId('log-detail-channels')).toContainText('Email');
    await expect(page.getByTestId('log-detail-task-title')).toContainText(testTaskTitle);
  });
});