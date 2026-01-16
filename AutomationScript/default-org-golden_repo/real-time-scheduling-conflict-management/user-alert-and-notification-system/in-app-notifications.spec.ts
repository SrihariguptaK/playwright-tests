import { test, expect } from '@playwright/test';

test.describe('In-App Notifications for Scheduling Conflicts', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const userACredentials = { email: 'usera@example.com', password: 'Password123!' };
  const userBCredentials = { email: 'userb@example.com', password: 'Password123!' };

  test.beforeEach(async ({ page }) => {
    await page.goto(baseURL);
  });

  test('Validate real-time in-app notification delivery', async ({ page }) => {
    // Step 1: Verify user is logged in and the application dashboard is displayed with active connection indicator
    await page.fill('[data-testid="email-input"]', userACredentials.email);
    await page.fill('[data-testid="password-input"]', userACredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="connection-indicator"]')).toHaveAttribute('data-status', 'active');

    // Step 2: Create a scheduling conflict by adding an overlapping appointment
    await page.click('[data-testid="add-appointment-button"]');
    await page.fill('[data-testid="appointment-title"]', 'Team Meeting');
    await page.fill('[data-testid="appointment-date"]', '2024-02-15');
    await page.fill('[data-testid="appointment-start-time"]', '10:00');
    await page.fill('[data-testid="appointment-end-time"]', '11:00');
    await page.selectOption('[data-testid="resource-select"]', 'Conference Room A');
    await page.click('[data-testid="save-appointment-button"]');

    // Create overlapping appointment to trigger conflict
    await page.click('[data-testid="add-appointment-button"]');
    await page.fill('[data-testid="appointment-title"]', 'Client Presentation');
    await page.fill('[data-testid="appointment-date"]', '2024-02-15');
    await page.fill('[data-testid="appointment-start-time"]', '10:30');
    await page.fill('[data-testid="appointment-end-time"]', '11:30');
    await page.selectOption('[data-testid="resource-select"]', 'Conference Room A');
    await page.click('[data-testid="save-appointment-button"]');

    // Step 3: Observe the application interface for in-app notification appearance
    const notification = page.locator('[data-testid="in-app-notification"]');
    await expect(notification).toBeVisible({ timeout: 2000 });
    await expect(notification).toContainText('Scheduling Conflict');

    // Step 4: Click on the in-app notification to expand and read the full conflict details
    await notification.click();
    const notificationDetails = page.locator('[data-testid="notification-details"]');
    await expect(notificationDetails).toBeVisible();
    await expect(notificationDetails).toContainText('Conference Room A');
    await expect(notificationDetails).toContainText('10:00');
    await expect(notificationDetails).toContainText('11:30');

    // Step 5: Click the 'Acknowledge' button or action within the notification
    await page.click('[data-testid="acknowledge-notification-button"]');

    // Step 6: Verify the notification is moved to notification history or acknowledged items section
    await expect(notification).not.toBeVisible();
    await page.click('[data-testid="notification-history-button"]');
    const historyItem = page.locator('[data-testid="notification-history-item"]').first();
    await expect(historyItem).toBeVisible();
    await expect(historyItem).toHaveAttribute('data-status', 'acknowledged');
  });

  test('Verify notification persistence until addressed', async ({ page }) => {
    // Step 1: Trigger a scheduling conflict to generate an in-app notification
    await page.fill('[data-testid="email-input"]', userACredentials.email);
    await page.fill('[data-testid="password-input"]', userACredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    await page.click('[data-testid="add-appointment-button"]');
    await page.fill('[data-testid="appointment-title"]', 'Morning Standup');
    await page.fill('[data-testid="appointment-date"]', '2024-02-16');
    await page.fill('[data-testid="appointment-start-time"]', '09:00');
    await page.fill('[data-testid="appointment-end-time"]', '09:30');
    await page.selectOption('[data-testid="resource-select"]', 'Meeting Room B');
    await page.click('[data-testid="save-appointment-button"]');

    await page.click('[data-testid="add-appointment-button"]');
    await page.fill('[data-testid="appointment-title"]', 'Sprint Planning');
    await page.fill('[data-testid="appointment-date"]', '2024-02-16');
    await page.fill('[data-testid="appointment-start-time"]', '09:15');
    await page.fill('[data-testid="appointment-end-time"]', '10:00');
    await page.selectOption('[data-testid="resource-select"]', 'Meeting Room B');
    await page.click('[data-testid="save-appointment-button"]');

    const notification = page.locator('[data-testid="in-app-notification"]');
    await expect(notification).toBeVisible({ timeout: 2000 });

    // Step 2: View the notification but do not click any action buttons, then navigate to a different page
    await notification.click();
    await expect(page.locator('[data-testid="notification-details"]')).toBeVisible();
    await page.click('[data-testid="schedules-nav-link"]');
    await expect(page.locator('[data-testid="schedules-page"]')).toBeVisible();

    // Step 3: Log out of the application and then log back in with the same user credentials
    await page.click('[data-testid="user-menu-button"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    await page.fill('[data-testid="email-input"]', userACredentials.email);
    await page.fill('[data-testid="password-input"]', userACredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 4: Verify notification counter shows the correct number of pending notifications
    const notificationCounter = page.locator('[data-testid="notification-counter"]');
    await expect(notificationCounter).toBeVisible();
    await expect(notificationCounter).toHaveText('1');
    
    await page.click('[data-testid="notification-bell-icon"]');
    const persistedNotification = page.locator('[data-testid="in-app-notification"]');
    await expect(persistedNotification).toBeVisible();

    // Step 5: Click the 'Acknowledge' button on the persistent notification
    await page.click('[data-testid="acknowledge-notification-button"]');

    // Step 6: Verify the notification is removed from the active notifications list
    await expect(persistedNotification).not.toBeVisible();
    await expect(notificationCounter).not.toBeVisible();

    // Step 7: Refresh the page or navigate to another section and return to verify notification does not reappear
    await page.reload();
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-counter"]')).not.toBeVisible();
    
    await page.click('[data-testid="schedules-nav-link"]');
    await page.click('[data-testid="dashboard-nav-link"]');
    await expect(page.locator('[data-testid="notification-counter"]')).not.toBeVisible();
  });

  test('Ensure only authenticated users receive relevant notifications', async ({ page, context }) => {
    // Step 1: Log in to the application as User A who is assigned to Schedule X
    await page.fill('[data-testid="email-input"]', userACredentials.email);
    await page.fill('[data-testid="password-input"]', userACredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 2: Create a scheduling conflict in Schedule X that User A is responsible for
    await page.click('[data-testid="schedule-selector"]');
    await page.click('[data-testid="schedule-option-x"]');
    await expect(page.locator('[data-testid="active-schedule"]')).toContainText('Schedule X');

    await page.click('[data-testid="add-appointment-button"]');
    await page.fill('[data-testid="appointment-title"]', 'User A Meeting 1');
    await page.fill('[data-testid="appointment-date"]', '2024-02-17');
    await page.fill('[data-testid="appointment-start-time"]', '14:00');
    await page.fill('[data-testid="appointment-end-time"]', '15:00');
    await page.selectOption('[data-testid="resource-select"]', 'Resource Alpha');
    await page.click('[data-testid="save-appointment-button"]');

    await page.click('[data-testid="add-appointment-button"]');
    await page.fill('[data-testid="appointment-title"]', 'User A Meeting 2');
    await page.fill('[data-testid="appointment-date"]', '2024-02-17');
    await page.fill('[data-testid="appointment-start-time"]', '14:30');
    await page.fill('[data-testid="appointment-end-time"]', '15:30');
    await page.selectOption('[data-testid="resource-select"]', 'Resource Alpha');
    await page.click('[data-testid="save-appointment-button"]');

    // Step 3: Observe the in-app notification area for User A
    const userANotification = page.locator('[data-testid="in-app-notification"]');
    await expect(userANotification).toBeVisible({ timeout: 2000 });

    // Step 4: Verify notification details match User A's schedule assignments and permissions
    await userANotification.click();
    const notificationDetails = page.locator('[data-testid="notification-details"]');
    await expect(notificationDetails).toBeVisible();
    await expect(notificationDetails).toContainText('Schedule X');
    await expect(notificationDetails).toContainText('Resource Alpha');
    await expect(notificationDetails).toContainText('User A Meeting');

    // Step 5: Log out as User A and log in as User B who does not have access to Schedule X
    await page.click('[data-testid="user-menu-button"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    await page.fill('[data-testid="email-input"]', userBCredentials.email);
    await page.fill('[data-testid="password-input"]', userBCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 6: Check the in-app notification center for User B
    await page.click('[data-testid="notification-bell-icon"]');
    const notificationList = page.locator('[data-testid="notification-list"]');
    await expect(notificationList).toBeVisible();
    
    // Verify no notifications from Schedule X are present
    const scheduleXNotifications = page.locator('[data-testid="in-app-notification"]', { hasText: 'Schedule X' });
    await expect(scheduleXNotifications).toHaveCount(0);

    // Step 7: Create a new conflict in a schedule that User B is authorized to access
    await page.click('[data-testid="schedule-selector"]');
    await page.click('[data-testid="schedule-option-y"]');
    await expect(page.locator('[data-testid="active-schedule"]')).toContainText('Schedule Y');

    await page.click('[data-testid="add-appointment-button"]');
    await page.fill('[data-testid="appointment-title"]', 'User B Meeting 1');
    await page.fill('[data-testid="appointment-date"]', '2024-02-18');
    await page.fill('[data-testid="appointment-start-time"]', '11:00');
    await page.fill('[data-testid="appointment-end-time"]', '12:00');
    await page.selectOption('[data-testid="resource-select"]', 'Resource Beta');
    await page.click('[data-testid="save-appointment-button"]');

    await page.click('[data-testid="add-appointment-button"]');
    await page.fill('[data-testid="appointment-title"]', 'User B Meeting 2');
    await page.fill('[data-testid="appointment-date"]', '2024-02-18');
    await page.fill('[data-testid="appointment-start-time"]', '11:30');
    await page.fill('[data-testid="appointment-end-time"]', '12:30');
    await page.selectOption('[data-testid="resource-select"]', 'Resource Beta');
    await page.click('[data-testid="save-appointment-button"]');

    // Step 8: Verify that User B's notification does not contain any information about Schedule X
    const userBNotification = page.locator('[data-testid="in-app-notification"]');
    await expect(userBNotification).toBeVisible({ timeout: 2000 });
    await userBNotification.click();
    
    const userBNotificationDetails = page.locator('[data-testid="notification-details"]');
    await expect(userBNotificationDetails).toBeVisible();
    await expect(userBNotificationDetails).toContainText('Schedule Y');
    await expect(userBNotificationDetails).toContainText('Resource Beta');
    await expect(userBNotificationDetails).not.toContainText('Schedule X');
    await expect(userBNotificationDetails).not.toContainText('Resource Alpha');
    await expect(userBNotificationDetails).not.toContainText('User A Meeting');
  });
});