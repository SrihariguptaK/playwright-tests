import { test, expect } from '@playwright/test';

test.describe('Task Status Update Notifications', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const employeeEmail = 'employee@example.com';
  const employeePassword = 'Password123!';
  const unauthorizedEmail = 'unauthorized@example.com';
  const unauthorizedPassword = 'Password123!';

  test.beforeEach(async ({ page }) => {
    await page.goto(baseURL);
  });

  test('Verify notification sent on task status update (happy-path)', async ({ page, context }) => {
    // Step 1: Log into the system as an employee
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to task details
    await page.click('[data-testid="tasks-menu"]');
    await page.click('[data-testid="task-list-item"]:first-child');
    await expect(page.locator('[data-testid="task-details-header"]')).toBeVisible();

    // Get current task details for verification
    const taskTitle = await page.locator('[data-testid="task-title"]').textContent();
    const currentStatus = await page.locator('[data-testid="task-status"]').textContent();

    // Step 3: Update task status
    await page.click('[data-testid="status-dropdown"]');
    await page.click('[data-testid="status-option-in-progress"]');
    await page.click('[data-testid="submit-status-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Step 4: Wait for notification processing (within 1 minute)
    await page.waitForTimeout(2000);

    // Step 5: Check in-app notification center
    await page.click('[data-testid="notification-icon"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();
    
    const notificationItem = page.locator('[data-testid="notification-item"]').first();
    await expect(notificationItem).toBeVisible();
    
    // Step 6: Click on notification to view details
    await notificationItem.click();
    await expect(page.locator('[data-testid="notification-details"]')).toBeVisible();

    // Step 7: Verify notification content accuracy
    const notificationTaskTitle = await page.locator('[data-testid="notification-task-title"]').textContent();
    const notificationStatus = await page.locator('[data-testid="notification-status"]').textContent();
    expect(notificationTaskTitle).toContain(taskTitle);
    expect(notificationStatus).toContain('In Progress');

    // Step 8: Verify notification is timely (within 1 minute)
    const notificationTime = await page.locator('[data-testid="notification-timestamp"]').textContent();
    expect(notificationTime).toContain('just now');
  });

  test('Test notification preference settings (happy-path)', async ({ page }) => {
    // Step 1: Log into the system
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to notification preferences
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-option"]');
    await page.click('[data-testid="notification-preferences-tab"]');
    await expect(page.locator('[data-testid="notification-preferences-section"]')).toBeVisible();

    // Step 3: Review current notification preferences
    const emailNotificationCheckbox = page.locator('[data-testid="email-notification-checkbox"]');
    const inAppNotificationCheckbox = page.locator('[data-testid="inapp-notification-checkbox"]');
    await expect(emailNotificationCheckbox).toBeVisible();
    await expect(inAppNotificationCheckbox).toBeVisible();

    // Step 4: Modify notification preferences - disable email, enable in-app
    if (await emailNotificationCheckbox.isChecked()) {
      await emailNotificationCheckbox.uncheck();
    }
    if (!await inAppNotificationCheckbox.isChecked()) {
      await inAppNotificationCheckbox.check();
    }

    // Step 5: Save preferences
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toBeVisible();

    // Step 6: Verify settings are saved
    await page.reload();
    await expect(emailNotificationCheckbox).not.toBeChecked();
    await expect(inAppNotificationCheckbox).toBeChecked();

    // Step 7: Trigger a task status update
    await page.click('[data-testid="tasks-menu"]');
    await page.click('[data-testid="task-list-item"]:first-child');
    await page.click('[data-testid="status-dropdown"]');
    await page.click('[data-testid="status-option-completed"]');
    await page.click('[data-testid="submit-status-button"]');

    // Step 8: Wait for notification processing
    await page.waitForTimeout(2000);

    // Step 9: Check for in-app notification
    await page.click('[data-testid="notification-icon"]');
    const notificationCount = await page.locator('[data-testid="notification-badge"]').textContent();
    expect(parseInt(notificationCount || '0')).toBeGreaterThan(0);
    await expect(page.locator('[data-testid="notification-item"]').first()).toBeVisible();

    // Step 10: Update preferences again - enable email, disable in-app
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-option"]');
    await page.click('[data-testid="notification-preferences-tab"]');
    await emailNotificationCheckbox.check();
    await inAppNotificationCheckbox.uncheck();
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toBeVisible();

    // Step 11: Trigger another task status update
    await page.click('[data-testid="tasks-menu"]');
    await page.click('[data-testid="task-list-item"]:nth-child(2)');
    await page.click('[data-testid="status-dropdown"]');
    await page.click('[data-testid="status-option-in-progress"]');
    await page.click('[data-testid="submit-status-button"]');
    await page.waitForTimeout(2000);

    // Step 12: Verify email notification would be sent (check preferences respected)
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-option"]');
    await page.click('[data-testid="notification-preferences-tab"]');
    await expect(emailNotificationCheckbox).toBeChecked();
    await expect(inAppNotificationCheckbox).not.toBeChecked();
  });

  test('Ensure no notifications sent to unauthorized users (error-case)', async ({ page, context }) => {
    // Step 1: Log in as authorized user and identify a task
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to task and note details
    await page.click('[data-testid="tasks-menu"]');
    await page.click('[data-testid="task-list-item"]:first-child');
    const taskId = await page.locator('[data-testid="task-id"]').textContent();
    const taskTitle = await page.locator('[data-testid="task-title"]').textContent();

    // Step 3: Update task status as authorized user
    await page.click('[data-testid="status-dropdown"]');
    await page.click('[data-testid="status-option-blocked"]');
    await page.click('[data-testid="submit-status-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Step 4: Wait for notification processing
    await page.waitForTimeout(2000);

    // Step 5: Log out and log in as unauthorized user
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="logout-option"]');
    await expect(page).toHaveURL(/.*login/);

    await page.fill('[data-testid="email-input"]', unauthorizedEmail);
    await page.fill('[data-testid="password-input"]', unauthorizedPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 6: Check in-app notification center for unauthorized user
    await page.click('[data-testid="notification-icon"]');
    const notificationPanel = page.locator('[data-testid="notification-panel"]');
    await expect(notificationPanel).toBeVisible();

    // Step 7: Verify no notification about the task update
    const notifications = page.locator('[data-testid="notification-item"]');
    const notificationCount = await notifications.count();
    
    if (notificationCount > 0) {
      // Check that none of the notifications are about the updated task
      for (let i = 0; i < notificationCount; i++) {
        const notificationText = await notifications.nth(i).textContent();
        expect(notificationText).not.toContain(taskTitle || '');
        expect(notificationText).not.toContain(taskId || '');
      }
    } else {
      // No notifications present - this is expected
      await expect(page.locator('[data-testid="no-notifications-message"]')).toBeVisible();
    }

    // Step 8: Verify unauthorized user cannot access the task
    await page.goto(`${baseURL}/tasks/${taskId}`);
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    
    // Step 9: Log back in as authorized user to verify they received notification
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="logout-option"]');
    
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    
    await page.click('[data-testid="notification-icon"]');
    const authorizedNotifications = page.locator('[data-testid="notification-item"]');
    const authorizedNotificationCount = await authorizedNotifications.count();
    expect(authorizedNotificationCount).toBeGreaterThan(0);
    
    // Verify authorized user has notification about the task
    const firstNotification = await authorizedNotifications.first().textContent();
    expect(firstNotification).toContain('Blocked');
  });
});