import { test, expect } from '@playwright/test';

test.describe('Task Status Notifications', () => {
  test.beforeEach(async ({ page }) => {
    // Login as employee user
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'employee@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate notification delivery on status update', async ({ page, context }) => {
    // Step 1: Navigate to the task details page for an assigned task
    await page.goto('/tasks');
    await page.click('[data-testid="task-item"]:has-text("Test Task")');
    await expect(page.locator('[data-testid="task-details-header"]')).toBeVisible();

    // Step 2: Update the task status from current status to a different status
    await page.click('[data-testid="task-status-dropdown"]');
    await page.click('[data-testid="status-option-in-progress"]');
    await page.click('[data-testid="update-status-button"]');
    
    // Expected Result: Status update is processed successfully
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Status updated successfully');
    await expect(page.locator('[data-testid="current-status"]')).toContainText('In Progress');

    // Step 3: Click on the notifications icon in the application header to view in-app notifications
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();

    // Expected Result: Notification appears with correct details
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toBeVisible();
    await expect(notification).toContainText('Test Task');
    await expect(notification).toContainText('In Progress');
    await expect(notification.locator('[data-testid="notification-timestamp"]')).toBeVisible();

    // Step 4: Open the email inbox associated with the user account
    // Open new tab for email verification
    const emailPage = await context.newPage();
    await emailPage.goto('/test-email-inbox');
    await emailPage.fill('[data-testid="email-search"]', 'employee@example.com');
    await emailPage.click('[data-testid="search-button"]');

    // Step 5: Verify the content accuracy of both in-app and email notifications
    // Expected Result: Email notification received with accurate content
    const emailNotification = emailPage.locator('[data-testid="email-item"]').first();
    await expect(emailNotification).toBeVisible();
    await expect(emailNotification).toContainText('Task Status Update');
    await emailNotification.click();
    await expect(emailPage.locator('[data-testid="email-body"]')).toContainText('Test Task');
    await expect(emailPage.locator('[data-testid="email-body"]')).toContainText('In Progress');
    await emailPage.close();
  });

  test('Verify notification preference settings', async ({ page }) => {
    // Step 1: Navigate to user profile settings and click on 'Notification Settings' or 'Preferences'
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-link"]');
    await expect(page).toHaveURL(/.*settings/);
    await page.click('[data-testid="notification-settings-tab"]');
    
    // Expected Result: Settings UI is displayed
    await expect(page.locator('[data-testid="notification-settings-panel"]')).toBeVisible();

    // Step 2: Locate the email notification toggle/checkbox for task status updates and disable it
    const emailToggle = page.locator('[data-testid="email-notifications-toggle"]');
    await expect(emailToggle).toBeVisible();
    
    // Check if currently enabled and disable it
    const isChecked = await emailToggle.isChecked();
    if (isChecked) {
      await emailToggle.click();
    }
    await expect(emailToggle).not.toBeChecked();

    // Step 3: Click the 'Save' or 'Update Preferences' button
    await page.click('[data-testid="save-preferences-button"]');
    
    // Expected Result: Preference is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');

    // Step 4: Navigate to a task assigned to the user and update its status to trigger a notification
    await page.goto('/tasks');
    await page.click('[data-testid="task-item"]:has-text("Test Task 2")');
    await page.click('[data-testid="task-status-dropdown"]');
    await page.click('[data-testid="status-option-completed"]');
    await page.click('[data-testid="update-status-button"]');
    
    // Expected Result: Status update processed
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Status updated successfully');

    // Step 5: Check the in-app notification panel for the status update notification
    await page.click('[data-testid="notifications-icon"]');
    
    // Expected Result: Notification sent only via in-app
    const inAppNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Test Task 2' });
    await expect(inAppNotification).toBeVisible();
    await expect(inAppNotification).toContainText('Completed');

    // Step 6: Check the email inbox for any notification related to the status update
    await page.goto('/test-email-inbox');
    await page.fill('[data-testid="email-search"]', 'employee@example.com');
    await page.click('[data-testid="search-button"]');
    
    // Expected Result: No email received
    const recentEmail = page.locator('[data-testid="email-item"]').filter({ hasText: 'Test Task 2' });
    await expect(recentEmail).toHaveCount(0);

    // Step 7: Verify notification delivery logs in the system
    await page.goto('/admin/notification-logs');
    await page.fill('[data-testid="log-search"]', 'Test Task 2');
    await page.click('[data-testid="search-logs-button"]');
    const logEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(logEntry).toContainText('in-app');
    await expect(logEntry).not.toContainText('email');
  });

  test('Ensure unauthorized users do not receive notifications', async ({ page, context }) => {
    // Step 1: As User A, navigate to the task details page for a task assigned only to User A
    await page.goto('/tasks');
    await page.click('[data-testid="task-item"]:has-text("User A Task")');
    await expect(page.locator('[data-testid="task-details-header"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-assignee"]')).toContainText('employee@example.com');

    // Step 2: Update the task status from current status to a different status
    await page.click('[data-testid="task-status-dropdown"]');
    await page.click('[data-testid="status-option-in-progress"]');
    await page.click('[data-testid="update-status-button"]');
    
    // Expected Result: Status update processed
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Status updated successfully');

    // Step 3: As User A, check the in-app notifications panel
    await page.click('[data-testid="notifications-icon"]');
    const userANotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'User A Task' });
    await expect(userANotification).toBeVisible();
    await expect(userANotification).toContainText('In Progress');

    // Step 4: Switch to User B's session and check the in-app notifications panel
    const userBPage = await context.newPage();
    await userBPage.goto('/login');
    await userBPage.fill('[data-testid="email-input"]', 'userb@example.com');
    await userBPage.fill('[data-testid="password-input"]', 'password123');
    await userBPage.click('[data-testid="login-button"]');
    await expect(userBPage).toHaveURL(/.*dashboard/);

    await userBPage.click('[data-testid="notifications-icon"]');
    
    // Expected Result: No notification received
    const userBNotification = userBPage.locator('[data-testid="notification-item"]').filter({ hasText: 'User A Task' });
    await expect(userBNotification).toHaveCount(0);

    // Step 5: Check User B's email inbox for any notifications about User A's task
    await userBPage.goto('/test-email-inbox');
    await userBPage.fill('[data-testid="email-search"]', 'userb@example.com');
    await userBPage.click('[data-testid="search-button"]');
    
    // Expected Result: No email notification for User B
    const userBEmail = userBPage.locator('[data-testid="email-item"]').filter({ hasText: 'User A Task' });
    await expect(userBEmail).toHaveCount(0);

    // Step 6: Access the notification service audit logs and filter by the task status update event
    await page.goto('/admin/notification-logs');
    await page.fill('[data-testid="log-search"]', 'User A Task');
    await page.click('[data-testid="search-logs-button"]');
    
    // Step 7: Verify the notification recipient list in the logs matches only authorized users
    // Expected Result: Notifications sent only to authorized users
    const logEntries = page.locator('[data-testid="log-entry"]');
    await expect(logEntries).toHaveCount(1);
    const recipientLog = logEntries.first();
    await expect(recipientLog).toContainText('employee@example.com');
    await expect(recipientLog).not.toContainText('userb@example.com');
    await expect(recipientLog.locator('[data-testid="log-status"]')).toContainText('delivered');

    await userBPage.close();
  });
});