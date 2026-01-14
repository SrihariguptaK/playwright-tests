import { test, expect } from '@playwright/test';

test.describe('Schedule Change Notifications', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const EMPLOYEE_EMAIL = 'employee@example.com';
  const EMPLOYEE_PASSWORD = 'Password123!';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate display of schedule change notifications', async ({ page }) => {
    // Step 1: Log in as employee
    await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Schedule dashboard is displayed
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    await page.waitForLoadState('networkidle');

    // Get initial notification count
    const notificationBadge = page.locator('[data-testid="notification-badge"]');
    const initialCount = await notificationBadge.isVisible() ? await notificationBadge.textContent() : '0';

    // Step 2: Trigger a schedule change event
    // Simulate schedule change by calling API or triggering UI action
    await page.evaluate(() => {
      // Simulate real-time notification event
      window.dispatchEvent(new CustomEvent('scheduleChange', {
        detail: {
          type: 'shift_modified',
          message: 'Your shift on Monday has been changed from 9:00 AM to 10:00 AM',
          timestamp: new Date().toISOString()
        }
      }));
    });

    // Expected Result: Notification appears on dashboard in real-time
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toBeVisible({ timeout: 5000 });
    await expect(notification).toContainText('shift');
    
    // Verify notification content and visibility
    const notificationMessage = page.locator('[data-testid="notification-message"]').first();
    await expect(notificationMessage).toBeVisible();
    await expect(notificationMessage).toContainText(/shift.*changed|modified/i);

    // Step 3: Acknowledge notification
    const acknowledgeButton = page.locator('[data-testid="acknowledge-notification-button"]').first();
    await expect(acknowledgeButton).toBeVisible();
    await acknowledgeButton.click();

    // Expected Result: Notification is marked as acknowledged and removed from active list
    await expect(notification).not.toBeVisible({ timeout: 3000 });
    
    // Verify the notification counter updates
    const updatedBadge = page.locator('[data-testid="notification-badge"]');
    if (parseInt(initialCount) > 0) {
      const updatedCount = await updatedBadge.textContent();
      expect(parseInt(updatedCount || '0')).toBeLessThan(parseInt(initialCount));
    }
  });

  test('Verify notification history accessibility', async ({ page }) => {
    // Step 1: Log in as employee
    await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Schedule dashboard is displayed
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    await page.waitForLoadState('networkidle');

    // Verify the schedule dashboard loads completely
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();

    // Step 2: Navigate to notification history section
    const notificationHistoryLink = page.locator('[data-testid="notification-history-link"]');
    await expect(notificationHistoryLink).toBeVisible();
    
    const startTime = Date.now();
    await notificationHistoryLink.click();

    // Expected Result: Archived notifications are displayed
    await expect(page.locator('[data-testid="notification-history-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-history-header"]')).toContainText(/notification.*history|archived/i);

    // Verify archived notifications are displayed
    const archivedNotifications = page.locator('[data-testid="archived-notification-item"]');
    await expect(archivedNotifications.first()).toBeVisible({ timeout: 5000 });

    // Verify notification history loads within performance requirements (2 seconds)
    const loadTime = Date.now() - startTime;
    expect(loadTime).toBeLessThan(2000);

    // Verify only employee-specific notifications are shown
    const notificationCount = await archivedNotifications.count();
    expect(notificationCount).toBeGreaterThan(0);

    // Verify each notification contains expected employee-specific data
    for (let i = 0; i < Math.min(notificationCount, 3); i++) {
      const notification = archivedNotifications.nth(i);
      await expect(notification).toBeVisible();
      
      // Verify notification has timestamp
      const timestamp = notification.locator('[data-testid="notification-timestamp"]');
      await expect(timestamp).toBeVisible();
      
      // Verify notification has message content
      const message = notification.locator('[data-testid="notification-message"]');
      await expect(message).toBeVisible();
    }
  });

  test('Validate real-time notification updates without page refresh', async ({ page }) => {
    // Log in as employee
    await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    await page.waitForLoadState('networkidle');

    // Get initial notification count
    const notificationContainer = page.locator('[data-testid="notification-container"]');
    const initialNotifications = await page.locator('[data-testid="notification-item"]').count();

    // Trigger multiple schedule change events without page refresh
    await page.evaluate(() => {
      window.dispatchEvent(new CustomEvent('scheduleChange', {
        detail: {
          type: 'shift_added',
          message: 'New shift assigned for Tuesday 2:00 PM - 6:00 PM',
          timestamp: new Date().toISOString()
        }
      }));
    });

    // Wait for real-time update
    await page.waitForTimeout(1000);

    // Verify new notification appears without refresh
    const updatedNotifications = await page.locator('[data-testid="notification-item"]').count();
    expect(updatedNotifications).toBeGreaterThan(initialNotifications);

    // Verify notification content
    const latestNotification = page.locator('[data-testid="notification-item"]').first();
    await expect(latestNotification).toContainText(/shift.*assigned|added/i);
  });

  test('Verify notification dismiss functionality', async ({ page }) => {
    // Log in as employee
    await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    await page.waitForLoadState('networkidle');

    // Trigger a notification
    await page.evaluate(() => {
      window.dispatchEvent(new CustomEvent('scheduleChange', {
        detail: {
          type: 'shift_cancelled',
          message: 'Your shift on Friday has been cancelled',
          timestamp: new Date().toISOString()
        }
      }));
    });

    // Wait for notification to appear
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toBeVisible({ timeout: 5000 });

    // Dismiss notification
    const dismissButton = notification.locator('[data-testid="dismiss-notification-button"]');
    await expect(dismissButton).toBeVisible();
    await dismissButton.click();

    // Verify notification is removed
    await expect(notification).not.toBeVisible({ timeout: 3000 });
  });

  test('Verify notification load time performance', async ({ page }) => {
    // Log in as employee
    await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    
    const startTime = Date.now();
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Wait for notifications to load
    await page.locator('[data-testid="notification-container"]').waitFor({ state: 'visible' });
    
    const loadTime = Date.now() - startTime;
    
    // Verify notifications load within 2 seconds
    expect(loadTime).toBeLessThan(2000);
    
    // Verify notification container is visible
    await expect(page.locator('[data-testid="notification-container"]')).toBeVisible();
  });
});