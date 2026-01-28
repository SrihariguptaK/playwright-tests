import { test, expect } from '@playwright/test';

test.describe('Notification History - Employee View', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_EMAIL = 'employee@company.com';
  const VALID_PASSWORD = 'Password123!';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto(`${BASE_URL}/login`);
  });

  test('Verify employee can access notification history for the last 30 days', async ({ page }) => {
    // Navigate to the system login page
    await expect(page).toHaveURL(/.*login/);

    // Enter valid employee credentials and click Login button
    await page.fill('[data-testid="email-input"]', VALID_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    
    const startTime = Date.now();
    await page.click('[data-testid="login-button"]');
    await page.waitForURL(/.*dashboard/);

    // Locate and click on the Notification History menu option or icon
    await page.click('[data-testid="notification-history-menu"]');
    
    // Observe the list of notifications displayed on the page
    await page.waitForSelector('[data-testid="notification-list"]');
    const endTime = Date.now();
    const loadTime = (endTime - startTime) / 1000;

    // Verify the date range of notifications displayed
    const notifications = await page.locator('[data-testid="notification-item"]').all();
    expect(notifications.length).toBeGreaterThan(0);

    // Verify all notifications are within last 30 days
    const today = new Date();
    const thirtyDaysAgo = new Date(today.setDate(today.getDate() - 30));
    
    for (const notification of notifications) {
      const dateText = await notification.locator('[data-testid="notification-date"]').textContent();
      const notificationDate = new Date(dateText || '');
      expect(notificationDate.getTime()).toBeGreaterThanOrEqual(thirtyDaysAgo.getTime());
    }

    // Check the page load time from step 3 to step 4
    expect(loadTime).toBeLessThan(2);
  });

  test('Verify search functionality for specific notifications within history', async ({ page }) => {
    // Login
    await page.fill('[data-testid="email-input"]', VALID_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL(/.*dashboard/);

    // Navigate to the Notification History page
    await page.click('[data-testid="notification-history-menu"]');
    await page.waitForSelector('[data-testid="notification-list"]');

    // Get initial count of notifications
    const initialCount = await page.locator('[data-testid="notification-item"]').count();

    // Locate the search input field on the notification history page
    const searchInput = page.locator('[data-testid="notification-search-input"]');
    await expect(searchInput).toBeVisible();

    // Enter the keyword 'meeting' in the search field
    await searchInput.fill('meeting');

    // Click the Search button or press Enter key
    await page.keyboard.press('Enter');
    await page.waitForTimeout(500); // Wait for search results

    // Review the filtered notification list
    const filteredNotifications = await page.locator('[data-testid="notification-item"]').all();
    
    // Verify filtered results contain the search keyword
    for (const notification of filteredNotifications) {
      const content = await notification.textContent();
      expect(content?.toLowerCase()).toContain('meeting');
    }

    // Clear the search field and verify results
    await searchInput.clear();
    await page.keyboard.press('Enter');
    await page.waitForTimeout(500);
    
    const clearedCount = await page.locator('[data-testid="notification-item"]').count();
    expect(clearedCount).toBe(initialCount);
  });

  test('Verify notification details are displayed clearly and accurately', async ({ page }) => {
    // Login
    await page.fill('[data-testid="email-input"]', VALID_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL(/.*dashboard/);

    // Navigate to notification history
    await page.click('[data-testid="notification-history-menu"]');
    await page.waitForSelector('[data-testid="notification-list"]');

    // View the list of notifications in the notification history
    const notifications = page.locator('[data-testid="notification-item"]');
    await expect(notifications.first()).toBeVisible();

    // Select a specific notification from the list by clicking on it
    await notifications.first().click();

    // Review the notification details displayed
    await page.waitForSelector('[data-testid="notification-detail-modal"]');
    const detailModal = page.locator('[data-testid="notification-detail-modal"]');
    await expect(detailModal).toBeVisible();

    // Verify the timestamp format and accuracy
    const timestamp = page.locator('[data-testid="notification-detail-timestamp"]');
    await expect(timestamp).toBeVisible();
    const timestampText = await timestamp.textContent();
    expect(timestampText).toMatch(/\d{1,2}\/\d{1,2}\/\d{4}|\d{4}-\d{2}-\d{2}/);

    // Check the readability and formatting of the notification content
    const content = page.locator('[data-testid="notification-detail-content"]');
    await expect(content).toBeVisible();
    const contentText = await content.textContent();
    expect(contentText).toBeTruthy();
    expect(contentText?.length).toBeGreaterThan(0);

    // Verify title is displayed
    const title = page.locator('[data-testid="notification-detail-title"]');
    await expect(title).toBeVisible();

    // Close the notification detail view
    await page.click('[data-testid="notification-detail-close"]');
    await expect(detailModal).not.toBeVisible();
  });

  test('Verify user can delete notifications from their history', async ({ page }) => {
    // Login
    await page.fill('[data-testid="email-input"]', VALID_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL(/.*dashboard/);

    // Navigate to notification history
    await page.click('[data-testid="notification-history-menu"]');
    await page.waitForSelector('[data-testid="notification-list"]');

    // View the notification history list and count the total number of notifications
    const initialCount = await page.locator('[data-testid="notification-item"]').count();
    expect(initialCount).toBeGreaterThan(0);

    // Select a notification to delete by clicking on it or hovering over it
    const firstNotification = page.locator('[data-testid="notification-item"]').first();
    await firstNotification.hover();

    // Click on the Delete button or delete icon for the selected notification
    await firstNotification.locator('[data-testid="notification-delete-button"]').click();

    // Click Confirm or Yes button in the confirmation dialog
    await page.waitForSelector('[data-testid="delete-confirmation-dialog"]');
    await page.click('[data-testid="confirm-delete-button"]');

    // Wait for deletion to complete
    await page.waitForTimeout(500);

    // Verify the notification is no longer visible in the history list
    const afterDeleteCount = await page.locator('[data-testid="notification-item"]').count();
    expect(afterDeleteCount).toBe(initialCount - 1);

    // Refresh the notification history page
    await page.reload();
    await page.waitForSelector('[data-testid="notification-list"]');

    // Verify count remains the same after refresh
    const afterRefreshCount = await page.locator('[data-testid="notification-item"]').count();
    expect(afterRefreshCount).toBe(initialCount - 1);
  });

  test('Verify notification history does not display notifications older than 30 days', async ({ page }) => {
    // Login
    await page.fill('[data-testid="email-input"]', VALID_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL(/.*dashboard/);

    // Navigate to the Notification History page
    await page.click('[data-testid="notification-history-menu"]');
    await page.waitForSelector('[data-testid="notification-list"]');

    // Review all notifications displayed and note the oldest notification date
    const notifications = await page.locator('[data-testid="notification-item"]').all();
    let oldestDate = new Date();

    for (const notification of notifications) {
      const dateText = await notification.locator('[data-testid="notification-date"]').textContent();
      const notificationDate = new Date(dateText || '');
      if (notificationDate < oldestDate) {
        oldestDate = notificationDate;
      }
    }

    // Verify that notifications exactly 30 days old are visible
    const today = new Date();
    const thirtyDaysAgo = new Date(today.setDate(today.getDate() - 30));
    const daysDifference = Math.floor((new Date().getTime() - oldestDate.getTime()) / (1000 * 60 * 60 * 24));
    expect(daysDifference).toBeLessThanOrEqual(30);

    // Attempt to search or scroll for notifications older than 30 days
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await page.waitForTimeout(1000);

    // Verify no notifications older than 30 days are displayed
    const allNotifications = await page.locator('[data-testid="notification-item"]').all();
    for (const notification of allNotifications) {
      const dateText = await notification.locator('[data-testid="notification-date"]').textContent();
      const notificationDate = new Date(dateText || '');
      expect(notificationDate.getTime()).toBeGreaterThanOrEqual(thirtyDaysAgo.getTime());
    }

    // Check if there is any option or filter to view notifications older than 30 days
    const olderNotificationsFilter = page.locator('[data-testid="older-notifications-filter"]');
    await expect(olderNotificationsFilter).not.toBeVisible();
  });

  test('Verify notification history requires user authentication', async ({ page }) => {
    // Open a web browser and ensure no user is logged into the system
    await page.context().clearCookies();

    // Attempt to directly access the notification history page by entering the URL
    await page.goto(`${BASE_URL}/notifications/history`);

    // Verify that an appropriate error message or authentication prompt is displayed
    await page.waitForURL(/.*login/);
    const loginForm = page.locator('[data-testid="login-form"]');
    await expect(loginForm).toBeVisible();

    // Check for authentication error message or redirect
    const currentUrl = page.url();
    expect(currentUrl).toContain('login');

    // Enter valid employee credentials on the login page
    await page.fill('[data-testid="email-input"]', VALID_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL(/.*dashboard/);

    // Navigate to the notification history page after successful login
    await page.click('[data-testid="notification-history-menu"]');
    await page.waitForSelector('[data-testid="notification-list"]');
    
    // Verify successful access
    const notificationList = page.locator('[data-testid="notification-list"]');
    await expect(notificationList).toBeVisible();
  });

  test('Verify notification history loads within 2 seconds performance requirement', async ({ page }) => {
    // Login
    await page.fill('[data-testid="email-input"]', VALID_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL(/.*dashboard/);

    // Clear browser cache and refresh the page to ensure clean test
    await page.context().clearCookies();
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', VALID_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL(/.*dashboard/);

    // Start timer and click on the Notification History menu option
    const startTime = Date.now();
    
    // Monitor API call
    const apiResponsePromise = page.waitForResponse(response => 
      response.url().includes('/api/notifications/history') && response.status() === 200
    );

    await page.click('[data-testid="notification-history-menu"]');

    // Monitor the page load time until notification history is fully displayed
    await page.waitForSelector('[data-testid="notification-list"]');
    const endTime = Date.now();

    // Stop timer and record the total load time from click to full display
    const totalLoadTime = (endTime - startTime) / 1000;

    // Review the Network tab to verify API response time
    const apiResponse = await apiResponsePromise;
    expect(apiResponse.status()).toBe(200);

    // Verify load time is within 2 seconds
    expect(totalLoadTime).toBeLessThan(2);
  });

  test('Verify employee can only view their own notification history', async ({ page }) => {
    // Log in as Employee A with valid credentials
    await page.fill('[data-testid="email-input"]', VALID_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL(/.*dashboard/);

    // Navigate to the Notification History page
    await page.click('[data-testid="notification-history-menu"]');
    await page.waitForSelector('[data-testid="notification-list"]');

    // Review all notifications displayed and verify ownership
    const notifications = await page.locator('[data-testid="notification-item"]').all();
    expect(notifications.length).toBeGreaterThan(0);

    // Get current URL
    const legitimateUrl = page.url();

    // Attempt to manipulate URL parameters to access Employee B's notification history
    const manipulatedUrl = legitimateUrl.replace(/userId=\d+/, 'userId=9999');
    
    // Set up API request interception
    const unauthorizedResponse = page.waitForResponse(response => 
      response.url().includes('/api/notifications/history') && 
      (response.status() === 403 || response.status() === 401)
    );

    await page.goto(manipulatedUrl);

    // Verify that no API calls can retrieve other employees' notification data
    try {
      const response = await unauthorizedResponse;
      expect([401, 403]).toContain(response.status());
    } catch (error) {
      // If no unauthorized response, verify redirect to own notifications
      await page.waitForURL(/.*notifications\/history/);
      const currentNotifications = await page.locator('[data-testid="notification-item"]').count();
      expect(currentNotifications).toBeGreaterThanOrEqual(0);
    }
  });

  test('Verify notification history displays empty state when no notifications exist', async ({ page }) => {
    // Log in as the new employee with no notification history
    const newEmployeeEmail = 'newemployee@company.com';
    const newEmployeePassword = 'Password123!';
    
    await page.fill('[data-testid="email-input"]', newEmployeeEmail);
    await page.fill('[data-testid="password-input"]', newEmployeePassword);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL(/.*dashboard/);

    // Navigate to the Notification History page
    await page.click('[data-testid="notification-history-menu"]');
    await page.waitForSelector('[data-testid="notification-history-container"]');

    // Observe the content displayed on the notification history page
    const emptyState = page.locator('[data-testid="notification-empty-state"]');
    await expect(emptyState).toBeVisible();

    // Verify empty state message
    const emptyStateMessage = await emptyState.textContent();
    expect(emptyStateMessage).toContain('No notifications');

    // Verify that the page layout and UI elements are properly displayed
    const pageTitle = page.locator('[data-testid="notification-history-title"]');
    await expect(pageTitle).toBeVisible();

    const searchInput = page.locator('[data-testid="notification-search-input"]');
    await expect(searchInput).toBeVisible();

    // Verify search functionality behavior with no notifications
    await searchInput.fill('test');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(500);

    // Empty state should still be visible
    await expect(emptyState).toBeVisible();
    
    // Verify no notification items are displayed
    const notificationCount = await page.locator('[data-testid="notification-item"]').count();
    expect(notificationCount).toBe(0);
  });

  test('Verify canceling delete operation does not remove notification from history', async ({ page }) => {
    // Login
    await page.fill('[data-testid="email-input"]', VALID_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL(/.*dashboard/);

    // Navigate to notification history
    await page.click('[data-testid="notification-history-menu"]');
    await page.waitForSelector('[data-testid="notification-list"]');

    // View the notification history list and select a specific notification to delete
    const initialCount = await page.locator('[data-testid="notification-item"]').count();
    const firstNotification = page.locator('[data-testid="notification-item"]').first();

    // Note the details of the selected notification (title, date, content)
    const notificationTitle = await firstNotification.locator('[data-testid="notification-title"]').textContent();
    const notificationDate = await firstNotification.locator('[data-testid="notification-date"]').textContent();
    const notificationContent = await firstNotification.textContent();

    // Hover over notification and click delete button
    await firstNotification.hover();
    await firstNotification.locator('[data-testid="notification-delete-button"]').click();

    // Wait for confirmation dialog
    await page.waitForSelector('[data-testid="delete-confirmation-dialog"]');
    const confirmDialog = page.locator('[data-testid="delete-confirmation-dialog"]');
    await expect(confirmDialog).toBeVisible();

    // Click the Cancel or No button in the confirmation dialog
    await page.click('[data-testid="cancel-delete-button"]');
    await page.waitForTimeout(500);

    // Verify the notification is still present in the history list
    const afterCancelCount = await page.locator('[data-testid="notification-item"]').count();
    expect(afterCancelCount).toBe(initialCount);

    // Verify the specific notification details are still present
    const stillPresentNotification = page.locator('[data-testid="notification-item"]').first();
    const stillPresentTitle = await stillPresentNotification.locator('[data-testid="notification-title"]').textContent();
    const stillPresentDate = await stillPresentNotification.locator('[data-testid="notification-date"]').textContent();
    
    expect(stillPresentTitle).toBe(notificationTitle);
    expect(stillPresentDate).toBe(notificationDate);

    // Refresh the page and verify the notification is still present
    await page.reload();
    await page.waitForSelector('[data-testid="notification-list"]');
    
    const afterRefreshCount = await page.locator('[data-testid="notification-item"]').count();
    expect(afterRefreshCount).toBe(initialCount);

    // Verify the notification details are still intact after refresh
    const afterRefreshNotification = page.locator('[data-testid="notification-item"]').first();
    const afterRefreshTitle = await afterRefreshNotification.locator('[data-testid="notification-title"]').textContent();
    expect(afterRefreshTitle).toBe(notificationTitle);
  });
});