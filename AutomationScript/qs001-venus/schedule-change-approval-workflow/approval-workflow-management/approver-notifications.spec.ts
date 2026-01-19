import { test, expect } from '@playwright/test';

test.describe('Story-15: Approver Notifications for Schedule Change Requests', () => {
  const employeeEmail = 'employee@company.com';
  const employeePassword = 'Employee123!';
  const approverEmail = 'approver@company.com';
  const approverPassword = 'Approver123!';
  const adminEmail = 'admin@company.com';
  const adminPassword = 'Admin123!';

  test('Verify notification sent upon request assignment (happy-path)', async ({ page, context }) => {
    // Step 1: Log in as employee user and navigate to schedule change request submission page
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    await page.click('[data-testid="schedule-change-menu"]');
    await page.click('[data-testid="new-request-button"]');
    await expect(page).toHaveURL(/.*schedule-change-request/);

    // Step 2: Fill in schedule change request details
    const requestDate = new Date();
    requestDate.setDate(requestDate.getDate() + 1);
    const formattedDate = requestDate.toISOString().split('T')[0];
    
    await page.fill('[data-testid="request-date-input"]', formattedDate);
    await page.fill('[data-testid="reason-input"]', 'Medical appointment');
    await page.selectOption('[data-testid="current-time-select"]', '09:00');
    await page.selectOption('[data-testid="requested-time-select"]', '11:00');

    // Step 3: Click 'Submit Request' button
    await page.click('[data-testid="submit-request-button"]');
    
    // Verify submission success
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request submitted successfully');
    
    // Extract request ID from success message or confirmation page
    const requestId = await page.locator('[data-testid="request-id"]').textContent();
    expect(requestId).toBeTruthy();

    // Step 4: System automatically determines approver and assigns the request
    // Wait up to 1 minute for notification processing
    await page.waitForTimeout(60000);

    // Step 5: Log in as the assigned approver and check email inbox
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 6: Verify in-app notification by checking notification center
    await page.click('[data-testid="notification-bell"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();
    
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toBeVisible();

    // Step 7: Review notification content for accuracy
    await expect(notification).toContainText(requestId!);
    await expect(notification).toContainText('Medical appointment');
    await expect(notification).toContainText('09:00');
    await expect(notification).toContainText('11:00');

    // Step 8: Click on the direct link provided in the notification
    await notification.click();
    
    // Step 9: Verify the correct request is displayed with all details
    await expect(page).toHaveURL(new RegExp(`.*request/${requestId}`));
    await expect(page.locator('[data-testid="request-id-display"]')).toContainText(requestId!);
    await expect(page.locator('[data-testid="employee-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-schedule"]')).toContainText('09:00');
    await expect(page.locator('[data-testid="requested-schedule"]')).toContainText('11:00');
    await expect(page.locator('[data-testid="request-reason"]')).toContainText('Medical appointment');
    await expect(page.locator('[data-testid="submission-date"]')).toBeVisible();

    // Step 10: Check notification delivery logs in the admin system
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', adminEmail);
    await page.fill('[data-testid="password-input"]', adminPassword);
    await page.click('[data-testid="login-button"]');
    
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="notification-logs"]');
    
    await page.fill('[data-testid="log-search-input"]', requestId!);
    await page.click('[data-testid="search-button"]');
    
    const logEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(logEntry).toBeVisible();
    await expect(logEntry).toContainText(requestId!);
    await expect(logEntry).toContainText(approverEmail);
    await expect(logEntry).toContainText('delivered');
  });

  test('Test notification preference settings (happy-path)', async ({ page }) => {
    // Step 1: Log in as approver and navigate to user profile settings page
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="profile-settings"]');
    await expect(page).toHaveURL(/.*profile-settings/);

    // Step 2: Locate notification preferences section and view current settings
    await page.click('[data-testid="notification-preferences-tab"]');
    await expect(page.locator('[data-testid="notification-preferences-section"]')).toBeVisible();
    
    const emailNotificationCheckbox = page.locator('[data-testid="email-notifications-checkbox"]');
    const inAppNotificationCheckbox = page.locator('[data-testid="inapp-notifications-checkbox"]');
    
    await expect(emailNotificationCheckbox).toBeVisible();
    await expect(inAppNotificationCheckbox).toBeVisible();

    // Step 3: Uncheck the 'Email Notifications' checkbox to disable email alerts
    const isEmailChecked = await emailNotificationCheckbox.isChecked();
    if (isEmailChecked) {
      await emailNotificationCheckbox.uncheck();
    }
    
    // Ensure in-app notifications remain enabled
    const isInAppChecked = await inAppNotificationCheckbox.isChecked();
    if (!isInAppChecked) {
      await inAppNotificationCheckbox.check();
    }

    // Step 4: Click 'Save Preferences' button
    await page.click('[data-testid="save-preferences-button"]');
    
    // Step 5: Verify updated preferences are displayed correctly after save
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toContainText('Preferences saved successfully');
    
    await expect(emailNotificationCheckbox).not.toBeChecked();
    await expect(inAppNotificationCheckbox).toBeChecked();

    // Step 6: Log out from approver account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 7: Log in as employee user and navigate to schedule change request submission page
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    await page.click('[data-testid="schedule-change-menu"]');
    await page.click('[data-testid="new-request-button"]');

    // Step 8: Submit a new schedule change request
    const requestDate = new Date();
    requestDate.setDate(requestDate.getDate() + 1);
    const formattedDate = requestDate.toISOString().split('T')[0];
    
    await page.fill('[data-testid="request-date-input"]', formattedDate);
    await page.fill('[data-testid="reason-input"]', 'Personal appointment');
    await page.selectOption('[data-testid="current-time-select"]', '13:00');
    await page.selectOption('[data-testid="requested-time-select"]', '15:00');
    await page.click('[data-testid="submit-request-button"]');
    
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    const requestId = await page.locator('[data-testid="request-id"]').textContent();
    expect(requestId).toBeTruthy();

    // Step 9: Wait up to 1 minute for notification processing
    await page.waitForTimeout(60000);

    // Step 10: Log out and log in as approver to check notifications
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');

    // Step 11: Check in-app notification center
    await page.click('[data-testid="notification-bell"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();
    
    const notification = page.locator(`[data-testid="notification-item"]:has-text("${requestId}")`);
    await expect(notification).toBeVisible();
    await expect(notification).toContainText('Personal appointment');

    // Step 12: Verify notification delivery logs show only in-app notification was sent
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', adminEmail);
    await page.fill('[data-testid="password-input"]', adminPassword);
    await page.click('[data-testid="login-button"]');
    
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="notification-logs"]');
    
    await page.fill('[data-testid="log-search-input"]', requestId!);
    await page.click('[data-testid="search-button"]');
    
    const logEntries = page.locator('[data-testid="log-entry"]');
    await expect(logEntries).toHaveCount(1);
    
    const inAppLog = logEntries.first();
    await expect(inAppLog).toContainText('in-app');
    await expect(inAppLog).toContainText('delivered');
    await expect(inAppLog).not.toContainText('email');
  });
});