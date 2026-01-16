import { test, expect } from '@playwright/test';

test.describe('Schedule Change Notifications', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const employeeACredentials = {
    username: 'employee.a@company.com',
    password: 'TestPass123!'
  };
  const employeeBCredentials = {
    username: 'employee.b@company.com',
    password: 'TestPass123!'
  };

  test.beforeEach(async ({ page }) => {
    await page.goto(`${baseURL}/login`);
  });

  test('Validate display of schedule change notifications on login', async ({ page }) => {
    // Step 1: Employee logs into the web portal with pending schedule changes
    await page.fill('[data-testid="username-input"]', employeeACredentials.username);
    await page.fill('[data-testid="password-input"]', employeeACredentials.password);
    await page.click('[data-testid="login-button"]');

    // Wait for navigation to dashboard
    await page.waitForURL('**/dashboard');

    // Expected Result: Notification banner appears with change details
    const notificationBanner = page.locator('[data-testid="notification-banner"]');
    await expect(notificationBanner).toBeVisible({ timeout: 5000 });
    await expect(notificationBanner).toContainText('Schedule Change');

    // Step 2: Employee views notification details
    await page.click('[data-testid="notification-banner"]');
    // Alternative: Click 'View Details' link if banner is not clickable
    const viewDetailsLink = page.locator('[data-testid="view-details-link"]');
    if (await viewDetailsLink.isVisible()) {
      await viewDetailsLink.click();
    }

    // Expected Result: Detailed information about schedule changes is displayed
    const notificationDetails = page.locator('[data-testid="notification-details"]');
    await expect(notificationDetails).toBeVisible();
    await expect(notificationDetails).toContainText(/shift|schedule|change/i);
    
    // Verify notification contains key information
    const notificationContent = await notificationDetails.textContent();
    expect(notificationContent).toBeTruthy();
    expect(notificationContent!.length).toBeGreaterThan(10);
  });

  test('Verify notification dismissal functionality', async ({ page }) => {
    // Login as employee with notifications
    await page.fill('[data-testid="username-input"]', employeeACredentials.username);
    await page.fill('[data-testid="password-input"]', employeeACredentials.password);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');

    // Step 1: Locate the visible schedule change notification on the dashboard
    const notification = page.locator('[data-testid="notification-banner"]').first();
    await expect(notification).toBeVisible();

    // Capture notification text for verification later
    const notificationText = await notification.textContent();

    // Step 2: Identify and click the dismiss button
    const dismissButton = notification.locator('[data-testid="dismiss-notification-button"]');
    const closeIcon = notification.locator('[data-testid="close-icon"]');
    
    if (await dismissButton.isVisible()) {
      await dismissButton.click();
    } else if (await closeIcon.isVisible()) {
      await closeIcon.click();
    } else {
      // Fallback to generic close button
      await notification.locator('button[aria-label="Dismiss"]').click();
    }

    // Expected Result: Notification is removed and not visible on current page
    await expect(notification).not.toBeVisible({ timeout: 3000 });

    // Step 3: Log out and log back in
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.waitForURL('**/login');

    // Log back in with same credentials
    await page.fill('[data-testid="username-input"]', employeeACredentials.username);
    await page.fill('[data-testid="password-input"]', employeeACredentials.password);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');

    // Expected Result: Previously dismissed notification does not reappear
    const notificationAfterLogin = page.locator('[data-testid="notification-banner"]');
    
    // Check if any notifications exist
    const notificationCount = await notificationAfterLogin.count();
    if (notificationCount > 0) {
      // If notifications exist, verify the dismissed one is not present
      const currentNotifications = await notificationAfterLogin.allTextContents();
      expect(currentNotifications).not.toContain(notificationText);
    } else {
      // No notifications should be visible
      await expect(notificationAfterLogin).not.toBeVisible();
    }

    // Step 4: Navigate to notification history if available
    const notificationHistoryLink = page.locator('[data-testid="notification-history-link"]');
    if (await notificationHistoryLink.isVisible()) {
      await notificationHistoryLink.click();
      const dismissedNotification = page.locator('[data-testid="notification-history-item"]', { hasText: notificationText || '' });
      // Verify dismissed notification appears in history
      await expect(dismissedNotification).toBeVisible();
    }
  });

  test('Test notification visibility restricted to affected employee', async ({ page }) => {
    // Step 1: Log in as Employee A who has pending schedule change notifications
    await page.fill('[data-testid="username-input"]', employeeACredentials.username);
    await page.fill('[data-testid="password-input"]', employeeACredentials.password);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');

    // Step 2: Note the specific details of Employee A's schedule change notifications
    const employeeANotifications = page.locator('[data-testid="notification-banner"]');
    const employeeANotificationCount = await employeeANotifications.count();
    const employeeANotificationDetails: string[] = [];

    if (employeeANotificationCount > 0) {
      for (let i = 0; i < employeeANotificationCount; i++) {
        const notificationText = await employeeANotifications.nth(i).textContent();
        if (notificationText) {
          employeeANotificationDetails.push(notificationText);
        }
      }
    }

    // Step 3: Log out of Employee A's account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.waitForURL('**/login');

    // Step 4: Log in as Employee B using their valid credentials
    await page.fill('[data-testid="username-input"]', employeeBCredentials.username);
    await page.fill('[data-testid="password-input"]', employeeBCredentials.password);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');

    // Step 5: Observe the dashboard for any schedule change notifications
    const employeeBNotifications = page.locator('[data-testid="notification-banner"]');
    const employeeBNotificationCount = await employeeBNotifications.count();

    // Expected Result: Employee B sees only their own notifications (if any exist)
    if (employeeBNotificationCount > 0) {
      // Verify Employee B's notifications do not contain Employee A's notification details
      for (let i = 0; i < employeeBNotificationCount; i++) {
        const notificationText = await employeeBNotifications.nth(i).textContent();
        if (notificationText) {
          // Ensure Employee A's specific notifications are not visible to Employee B
          for (const employeeANotification of employeeANotificationDetails) {
            expect(notificationText).not.toBe(employeeANotification);
          }
        }
      }
    }

    // Step 6: Attempt to access notification history or details section
    const notificationHistoryLink = page.locator('[data-testid="notification-history-link"]');
    if (await notificationHistoryLink.isVisible()) {
      await notificationHistoryLink.click();
      
      // Verify notification history only shows Employee B's notifications
      const historyItems = page.locator('[data-testid="notification-history-item"]');
      const historyCount = await historyItems.count();
      
      for (let i = 0; i < historyCount; i++) {
        const historyText = await historyItems.nth(i).textContent();
        if (historyText) {
          // Verify Employee A's notifications are not in Employee B's history
          for (const employeeANotification of employeeANotificationDetails) {
            expect(historyText).not.toContain(employeeANotification);
          }
        }
      }
    }

    // Step 7: Verify API call includes correct employeeId parameter for Employee B
    // Listen to API requests to verify correct employeeId is being used
    page.on('request', request => {
      const url = request.url();
      if (url.includes('/api/notifications/scheduleChanges')) {
        // Extract employeeId from URL parameters
        const urlObj = new URL(url);
        const employeeId = urlObj.searchParams.get('employeeId');
        
        // Verify employeeId is not Employee A's ID
        expect(employeeId).toBeTruthy();
        expect(employeeId).not.toBe('employee-a-id');
      }
    });

    // Refresh to trigger API call
    await page.reload();
    await page.waitForLoadState('networkidle');
  });
});