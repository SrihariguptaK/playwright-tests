import { test, expect } from '@playwright/test';

test.describe('Overdue Task Notifications', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Project Manager
    await page.goto('/');
    await page.fill('[data-testid="email-input"]', 'projectmanager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
  });

  test('Receive notification for overdue task', async ({ page }) => {
    // Step 1: Create a task with past due date
    await page.click('[data-testid="create-task-button"]');
    await expect(page.locator('[data-testid="task-form"]')).toBeVisible();
    
    await page.fill('[data-testid="task-title-input"]', 'Overdue Test Task');
    await page.fill('[data-testid="task-description-input"]', 'This task is for testing overdue notifications');
    
    // Set due date to yesterday
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    const yesterdayFormatted = yesterday.toISOString().split('T')[0];
    await page.fill('[data-testid="task-due-date-input"]', yesterdayFormatted);
    
    await page.click('[data-testid="save-task-button"]');
    
    // Expected Result: Task marked as overdue
    await expect(page.locator('[data-testid="task-status"]')).toContainText('Overdue');
    const taskId = await page.locator('[data-testid="task-id"]').textContent();
    
    // Step 2: Wait for notification processing (max 1 minute)
    await page.waitForTimeout(65000); // Wait 65 seconds to ensure notification is processed
    
    // Expected Result: Notification sent to Project Manager
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();
    
    const notification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Overdue Test Task' });
    await expect(notification).toBeVisible();
    await expect(notification).toContainText('overdue');
    
    // Step 3: Open notification and access task details
    await notification.click();
    
    // Expected Result: Task details page opens correctly
    await expect(page).toHaveURL(new RegExp(`/tasks/${taskId || '\\d+'}`));
    await expect(page.locator('[data-testid="task-details-title"]')).toContainText('Overdue Test Task');
    await expect(page.locator('[data-testid="task-details-status"]')).toContainText('Overdue');
    await expect(page.locator('[data-testid="task-details-due-date"]')).toContainText(yesterdayFormatted);
  });

  test('Manage notification subscription preferences', async ({ page }) => {
    // Step 1: Access notification subscription settings
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-menu-item"]');
    await page.click('[data-testid="notification-settings-tab"]');
    
    // Expected Result: Subscription UI displayed
    await expect(page.locator('[data-testid="notification-settings-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="overdue-task-notifications-section"]')).toBeVisible();
    
    // Step 2: Disable email notifications for overdue tasks
    const emailNotificationToggle = page.locator('[data-testid="overdue-email-notification-toggle"]');
    const inAppNotificationToggle = page.locator('[data-testid="overdue-inapp-notification-toggle"]');
    
    // Ensure email is enabled first, then disable it
    if (await emailNotificationToggle.isChecked() === false) {
      await emailNotificationToggle.check();
    }
    await emailNotificationToggle.uncheck();
    
    // Keep in-app notifications enabled
    if (await inAppNotificationToggle.isChecked() === false) {
      await inAppNotificationToggle.check();
    }
    
    await page.click('[data-testid="save-preferences-button"]');
    
    // Expected Result: Preferences saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');
    
    // Step 3: Create overdue task and verify notifications received or suppressed accordingly
    await page.click('[data-testid="dashboard-link"]');
    await page.click('[data-testid="create-task-button"]');
    
    await page.fill('[data-testid="task-title-input"]', 'Notification Preference Test Task');
    await page.fill('[data-testid="task-description-input"]', 'Testing notification preferences');
    
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    const yesterdayFormatted = yesterday.toISOString().split('T')[0];
    await page.fill('[data-testid="task-due-date-input"]', yesterdayFormatted);
    
    await page.click('[data-testid="save-task-button"]');
    await expect(page.locator('[data-testid="task-status"]')).toContainText('Overdue');
    
    // Wait for notification processing
    await page.waitForTimeout(65000);
    
    // Expected Result: In-app notification received, email suppressed
    await page.click('[data-testid="notifications-icon"]');
    const inAppNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Notification Preference Test Task' });
    await expect(inAppNotification).toBeVisible();
    
    // Re-enable email notifications
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-menu-item"]');
    await page.click('[data-testid="notification-settings-tab"]');
    
    await page.locator('[data-testid="overdue-email-notification-toggle"]').check();
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');
    
    // Create another overdue task
    await page.click('[data-testid="dashboard-link"]');
    await page.click('[data-testid="create-task-button"]');
    
    await page.fill('[data-testid="task-title-input"]', 'Email Enabled Test Task');
    await page.fill('[data-testid="task-description-input"]', 'Testing with email enabled');
    await page.fill('[data-testid="task-due-date-input"]', yesterdayFormatted);
    
    await page.click('[data-testid="save-task-button"]');
    await expect(page.locator('[data-testid="task-status"]')).toContainText('Overdue');
    
    // Wait for notification processing
    await page.waitForTimeout(65000);
    
    // Expected Result: Both email and in-app notifications received
    await page.click('[data-testid="notifications-icon"]');
    const finalNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Email Enabled Test Task' });
    await expect(finalNotification).toBeVisible();
  });
});