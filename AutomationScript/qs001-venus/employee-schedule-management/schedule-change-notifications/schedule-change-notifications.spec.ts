import { test, expect } from '@playwright/test';

test.describe('Schedule Change Notifications', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const EMPLOYEE_A_CREDENTIALS = {
    username: 'employee.a@company.com',
    password: 'TestPassword123!'
  };
  const EMPLOYEE_B_ID = '456';

  test('Validate display of schedule change notifications on login (happy-path)', async ({ page }) => {
    // Navigate to the schedule portal login page
    await page.goto(`${BASE_URL}/login`);
    await expect(page).toHaveURL(/.*login/);

    // Enter valid employee credentials (username and password)
    await page.fill('[data-testid="username-input"]', EMPLOYEE_A_CREDENTIALS.username);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_A_CREDENTIALS.password);

    // Click the login button
    await page.click('[data-testid="login-button"]');

    // Wait for navigation to dashboard
    await page.waitForURL(/.*dashboard/);

    // Observe the notification area on the dashboard - New schedule change notifications are displayed prominently
    const notificationArea = page.locator('[data-testid="notification-area"]');
    await expect(notificationArea).toBeVisible();
    
    const newNotifications = page.locator('[data-testid="new-notification"]');
    await expect(newNotifications.first()).toBeVisible();

    // Review the notification content
    const firstNotification = newNotifications.first();
    await expect(firstNotification).toContainText(/schedule change|shift/i);

    // Click on the notification to view full details
    await firstNotification.click();
    
    const notificationDetails = page.locator('[data-testid="notification-details"]');
    await expect(notificationDetails).toBeVisible();
    await expect(notificationDetails).toContainText(/date|shift|type/i);

    // Click the acknowledge button or mark as read option on the notification
    await page.click('[data-testid="acknowledge-notification-button"]');

    // Notification is marked as read and removed from new notifications list
    await expect(firstNotification).toHaveAttribute('data-status', 'read');
    
    // Verify the notification counter or badge
    const notificationBadge = page.locator('[data-testid="notification-badge"]');
    const badgeText = await notificationBadge.textContent();
    const notificationCount = parseInt(badgeText || '0');
    expect(notificationCount).toBeGreaterThanOrEqual(0);

    // Refresh the page or navigate away and return to dashboard
    await page.reload();
    await page.waitForLoadState('networkidle');
    
    // Verify notification remains marked as read after refresh
    const refreshedNotification = page.locator('[data-testid="notification-item"]').first();
    await expect(refreshedNotification).toHaveAttribute('data-status', 'read');
  });

  test('Verify notification history accessibility (happy-path)', async ({ page }) => {
    // Login first
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', EMPLOYEE_A_CREDENTIALS.username);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_A_CREDENTIALS.password);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL(/.*dashboard/);

    // Locate the notification icon or menu in the navigation bar
    const notificationIcon = page.locator('[data-testid="notification-icon"]');
    await expect(notificationIcon).toBeVisible();

    // Click on the notification icon or menu
    await notificationIcon.click();

    // Locate and click on 'View All Notifications' or 'Notification History' link
    const viewAllLink = page.locator('[data-testid="view-all-notifications"]');
    await expect(viewAllLink).toBeVisible();
    await viewAllLink.click();

    // Wait for navigation to notification history page
    await page.waitForURL(/.*notifications/);

    // All past notifications are displayed with accurate details
    const notificationHistoryPage = page.locator('[data-testid="notification-history-page"]');
    await expect(notificationHistoryPage).toBeVisible();

    // Verify the details displayed for each notification entry
    const notificationEntries = page.locator('[data-testid="notification-entry"]');
    await expect(notificationEntries.first()).toBeVisible();
    
    const firstEntry = notificationEntries.first();
    await expect(firstEntry).toContainText(/shift|schedule/i);
    await expect(firstEntry.locator('[data-testid="notification-date"]')).toBeVisible();
    await expect(firstEntry.locator('[data-testid="notification-type"]')).toBeVisible();

    // Check the visual distinction between read and unread notifications
    const readNotification = page.locator('[data-testid="notification-entry"][data-status="read"]').first();
    const unreadNotification = page.locator('[data-testid="notification-entry"][data-status="unread"]').first();
    
    if (await unreadNotification.count() > 0) {
      const readOpacity = await readNotification.evaluate(el => window.getComputedStyle(el).opacity);
      const unreadOpacity = await unreadNotification.evaluate(el => window.getComputedStyle(el).opacity);
      expect(readOpacity).not.toBe(unreadOpacity);
    }

    // Scroll through the notification history list
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await page.waitForTimeout(500);

    // Click on a specific historical notification to view full details
    await notificationEntries.first().click();
    const detailsModal = page.locator('[data-testid="notification-details-modal"]');
    await expect(detailsModal).toBeVisible();
    await expect(detailsModal).toContainText(/shift info|change type|date/i);

    // Verify the timestamp accuracy of notifications
    const timestamp = page.locator('[data-testid="notification-timestamp"]');
    await expect(timestamp).toBeVisible();
    const timestampText = await timestamp.textContent();
    expect(timestampText).toMatch(/\d{1,2}[:\/\-]\d{1,2}/);

    // Close modal
    await page.click('[data-testid="close-details-modal"]');

    // Apply any available filters (if present) such as date range or notification type
    const filterButton = page.locator('[data-testid="notification-filter"]');
    if (await filterButton.count() > 0) {
      await filterButton.click();
      const typeFilter = page.locator('[data-testid="filter-type-select"]');
      if (await typeFilter.count() > 0) {
        await typeFilter.selectOption('schedule_change');
        await page.click('[data-testid="apply-filter-button"]');
        await page.waitForLoadState('networkidle');
        
        const filteredEntries = page.locator('[data-testid="notification-entry"]');
        await expect(filteredEntries.first()).toBeVisible();
      }
    }
  });

  test('Test access control for notifications (error-case)', async ({ page, request }) => {
    // Login as Employee A
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', EMPLOYEE_A_CREDENTIALS.username);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_A_CREDENTIALS.password);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL(/.*dashboard/);

    // Navigate to the notification history page
    await page.goto(`${BASE_URL}/notifications`);
    await page.waitForLoadState('networkidle');

    // Note Employee A's employee ID from the URL or profile section
    const currentURL = page.url();
    const employeeAIdMatch = currentURL.match(/employeeId=(\d+)/);
    const employeeAId = employeeAIdMatch ? employeeAIdMatch[1] : '123';

    // Attempt to manually modify the URL to access Employee B's notifications
    const unauthorizedURL = `${BASE_URL}/notifications?employeeId=${EMPLOYEE_B_ID}`;
    await page.goto(unauthorizedURL);

    // Access denied error is shown
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText(/access denied|unauthorized|forbidden/i);

    // Verify that no notification data from Employee B is visible on the page
    const notificationEntries = page.locator('[data-testid="notification-entry"]');
    await expect(notificationEntries).toHaveCount(0);

    // Attempt to make a direct API call to GET /api/notifications
    const apiResponse = await request.get(`${BASE_URL}/api/notifications?scheduleChanges&employeeId=${EMPLOYEE_B_ID}`, {
      headers: {
        'Cookie': await page.context().cookies().then(cookies => 
          cookies.map(c => `${c.name}=${c.value}`).join('; ')
        )
      }
    });

    // Verify the response indicates access denied
    expect(apiResponse.status()).toBe(403);
    const responseBody = await apiResponse.json();
    expect(responseBody).toHaveProperty('error');
    expect(responseBody.error).toMatch(/access denied|unauthorized|forbidden/i);

    // Attempt to access notification details directly using a notification ID that belongs to Employee B
    const unauthorizedNotificationURL = `${BASE_URL}/notifications/999?employeeId=${EMPLOYEE_B_ID}`;
    await page.goto(unauthorizedNotificationURL);

    // Verify access is denied
    const detailsError = page.locator('[data-testid="error-message"]');
    await expect(detailsError).toBeVisible();
    await expect(detailsError).toContainText(/access denied|unauthorized|not found/i);

    // Return to Employee A's legitimate notification page
    await page.goto(`${BASE_URL}/notifications`);
    await page.waitForLoadState('networkidle');
    
    // Verify Employee A can access their own notifications
    const legitimateNotifications = page.locator('[data-testid="notification-history-page"]');
    await expect(legitimateNotifications).toBeVisible();
  });
});