import { test, expect } from '@playwright/test';

test.describe('Schedule Change Notifications', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const MANAGER_EMAIL = 'manager@company.com';
  const MANAGER_PASSWORD = 'Manager123!';
  const EMPLOYEE_A_EMAIL = 'employeeA@company.com';
  const EMPLOYEE_A_PASSWORD = 'Employee123!';
  const EMPLOYEE_B_EMAIL = 'employeeB@company.com';
  const EMPLOYEE_B_PASSWORD = 'Employee123!';

  test('Validate notification generation and display for schedule changes (happy-path)', async ({ page, context }) => {
    // Log in as Manager/Admin with valid credentials
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the schedule management section
    await page.click('[data-testid="schedule-menu"]');
    await expect(page.locator('[data-testid="schedule-page"]')).toBeVisible();

    // Select the target employee's existing shift and modify the schedule
    await page.click(`[data-testid="employee-schedule-${EMPLOYEE_A_EMAIL}"]`);
    await page.click('[data-testid="edit-shift-button"]');
    
    // Change time, date, or location
    await page.fill('[data-testid="shift-start-time"]', '09:00');
    await page.fill('[data-testid="shift-end-time"]', '17:00');
    await page.selectOption('[data-testid="shift-location"]', 'Building B');
    
    // Save the schedule change
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule updated successfully');

    // Log out as Manager/Admin
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Log in as the affected employee using valid credentials
    await page.fill('[data-testid="email-input"]', EMPLOYEE_A_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_A_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the notifications section in the web interface
    await page.click('[data-testid="notifications-menu"]');
    await expect(page.locator('[data-testid="notifications-page"]')).toBeVisible();

    // Verify the new schedule change notification is displayed with details of the change
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toBeVisible();
    await expect(notification).toContainText('Schedule change');
    await expect(notification).toContainText('09:00');
    await expect(notification).toContainText('17:00');
    await expect(notification).toContainText('Building B');
    await expect(notification.locator('[data-testid="notification-status"]')).toContainText('unread');

    // Click on the notification to mark it as read
    await notification.click();
    await page.click('[data-testid="mark-as-read-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Notification marked as read');

    // Refresh the notifications page
    await page.reload();
    await expect(page.locator('[data-testid="notifications-page"]')).toBeVisible();

    // Verify notification status updated and reflected in UI
    const updatedNotification = page.locator('[data-testid="notification-item"]').first();
    await expect(updatedNotification.locator('[data-testid="notification-status"]')).toContainText('read');

    // Log out as employee
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);
  });

  test('Verify notification access control (error-case)', async ({ page }) => {
    // Log in as Employee A with valid credentials
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', EMPLOYEE_A_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_A_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the notifications section
    await page.click('[data-testid="notifications-menu"]');
    await expect(page.locator('[data-testid="notifications-page"]')).toBeVisible();

    // Get Employee A's current URL
    const employeeAUrl = page.url();

    // Attempt to access Employee B's notifications by manipulating the URL or API request
    const employeeBId = 'employee-b-id-12345';
    
    // Try URL manipulation
    await page.goto(`${BASE_URL}/notifications?employeeId=${employeeBId}`);
    
    // Verify that no notification data from Employee B is visible or accessible
    const unauthorizedMessage = page.locator('[data-testid="error-message"]');
    await expect(unauthorizedMessage).toBeVisible();
    await expect(unauthorizedMessage).toContainText('Access denied');

    // Check for API error response
    const apiResponse = await page.waitForResponse(response => 
      response.url().includes('/api/notifications') && response.status() === 403
    ).catch(() => null);

    if (apiResponse) {
      expect(apiResponse.status()).toBe(403);
    }

    // Verify Employee A is redirected or sees error
    await expect(page.locator('[data-testid="notifications-page"]')).not.toContainText('Employee B');

    // Check browser console for error response
    const consoleMessages: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleMessages.push(msg.text());
      }
    });

    // Log out as Employee A
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);
  });

  test('Test notification delivery timing (boundary)', async ({ page, context }) => {
    // Log in as Employee and navigate to the notifications section
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', EMPLOYEE_A_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_A_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    await page.click('[data-testid="notifications-menu"]');
    await expect(page.locator('[data-testid="notifications-page"]')).toBeVisible();

    // Note the current timestamp and number of existing notifications
    const initialNotificationCount = await page.locator('[data-testid="notification-item"]').count();
    
    // In a separate browser session, log in as Manager/Admin
    const managerPage = await context.newPage();
    await managerPage.goto(`${BASE_URL}/login`);
    await managerPage.fill('[data-testid="email-input"]', MANAGER_EMAIL);
    await managerPage.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await managerPage.click('[data-testid="login-button"]');
    await expect(managerPage).toHaveURL(/.*dashboard/);

    // Navigate to schedule management
    await managerPage.click('[data-testid="schedule-menu"]');
    await expect(managerPage.locator('[data-testid="schedule-page"]')).toBeVisible();

    // Record the exact timestamp and make a schedule change for the logged-in employee
    const scheduleChangeTimestamp = Date.now();
    
    await managerPage.click(`[data-testid="employee-schedule-${EMPLOYEE_A_EMAIL}"]`);
    await managerPage.click('[data-testid="edit-shift-button"]');
    await managerPage.fill('[data-testid="shift-start-time"]', '10:00');
    await managerPage.fill('[data-testid="shift-end-time"]', '18:00');
    await managerPage.click('[data-testid="save-schedule-button"]');
    await expect(managerPage.locator('[data-testid="success-message"]')).toContainText('Schedule updated successfully');

    // Return to the employee's browser session and refresh the notifications page every 10 seconds
    let notificationDelivered = false;
    let notificationDeliveryTimestamp = 0;
    const maxWaitTime = 65000; // 65 seconds to account for 1 minute + buffer
    const checkInterval = 10000; // 10 seconds
    const startTime = Date.now();

    while (!notificationDelivered && (Date.now() - startTime) < maxWaitTime) {
      await page.reload();
      await page.waitForTimeout(1000); // Wait for page to load
      
      const currentNotificationCount = await page.locator('[data-testid="notification-item"]').count();
      
      if (currentNotificationCount > initialNotificationCount) {
        notificationDelivered = true;
        notificationDeliveryTimestamp = Date.now();
        break;
      }
      
      await page.waitForTimeout(checkInterval);
    }

    // Record the timestamp when the new notification appears
    expect(notificationDelivered).toBeTruthy();

    // Calculate the time difference between schedule change (T0) and notification delivery (T1)
    const deliveryTimeInSeconds = (notificationDeliveryTimestamp - scheduleChangeTimestamp) / 1000;

    // Verify that the notification delivery time is within 1 minute (60 seconds)
    expect(deliveryTimeInSeconds).toBeLessThanOrEqual(60);
    expect(deliveryTimeInSeconds).toBeGreaterThan(0);

    // Verify the notification content
    const newNotification = page.locator('[data-testid="notification-item"]').first();
    await expect(newNotification).toContainText('Schedule change');
    await expect(newNotification).toContainText('10:00');
    await expect(newNotification).toContainText('18:00');

    // Log out from both employee and manager sessions
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    await managerPage.click('[data-testid="user-menu"]');
    await managerPage.click('[data-testid="logout-button"]');
    await expect(managerPage).toHaveURL(/.*login/);
    await managerPage.close();
  });
});