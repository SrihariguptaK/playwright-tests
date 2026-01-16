import { test, expect } from '@playwright/test';

test.describe('Schedule Notifications - Story 8', () => {
  test.beforeEach(async ({ page }) => {
    // Login as scheduler before each test
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Receive notification on schedule modification (happy-path)', async ({ page, context }) => {
    // Step 1: Navigate to the employee scheduling page
    await page.goto('/scheduling');
    await expect(page.locator('[data-testid="scheduling-page"]')).toBeVisible();

    // Step 2: Select an employee from the schedule list
    await page.click('[data-testid="employee-list-item"]:has-text("John Doe")');
    await expect(page.locator('[data-testid="employee-details"]')).toBeVisible();

    // Step 3: Click the 'Edit Schedule' button for the selected employee
    await page.click('[data-testid="edit-schedule-button"]');
    await expect(page.locator('[data-testid="edit-schedule-modal"]')).toBeVisible();

    // Step 4: Modify the schedule by changing the shift time
    const originalStartTime = await page.locator('[data-testid="shift-start-time"]').inputValue();
    const originalEndTime = await page.locator('[data-testid="shift-end-time"]').inputValue();
    
    await page.fill('[data-testid="shift-start-time"]', '10:00');
    await page.fill('[data-testid="shift-end-time"]', '18:00');
    
    // Expected Result: Schedule is updated
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule updated successfully');

    // Step 5: Open new tab to check employee's email
    const emailPage = await context.newPage();
    await emailPage.goto('/email-client');
    await emailPage.fill('[data-testid="email-username"]', 'john.doe@company.com');
    await emailPage.fill('[data-testid="email-password"]', 'employeepass');
    await emailPage.click('[data-testid="email-login-button"]');
    
    // Step 6: Check employee's email notifications
    await emailPage.waitForSelector('[data-testid="email-inbox"]');
    const emailNotification = emailPage.locator('[data-testid="email-item"]').filter({ hasText: 'Schedule Change Notification' }).first();
    await expect(emailNotification).toBeVisible({ timeout: 10000 });
    
    // Step 7: Open and review the email notification content
    await emailNotification.click();
    await expect(emailPage.locator('[data-testid="email-subject"]')).toContainText('Schedule Change');
    const emailBody = emailPage.locator('[data-testid="email-body"]');
    await expect(emailBody).toContainText('10:00');
    await expect(emailBody).toContainText('18:00');
    await emailPage.close();

    // Step 8: Log in as the affected employee to check in-app notifications
    await page.goto('/logout');
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'john.doe@company.com');
    await page.fill('[data-testid="password-input"]', 'employeepass');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 9: Navigate to notifications section
    await page.click('[data-testid="notification-bell-icon"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();
    
    // Expected Result: Notification about schedule change is received
    const inAppNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Schedule Modified' }).first();
    await expect(inAppNotification).toBeVisible();

    // Step 10: Click on the notification to view full details
    await inAppNotification.click();
    await expect(page.locator('[data-testid="notification-details-modal"]')).toBeVisible();
    
    // Step 11: Verify notification content accuracy
    // Expected Result: Notification contains correct schedule details
    const notificationContent = page.locator('[data-testid="notification-content"]');
    await expect(notificationContent).toContainText('John Doe');
    await expect(notificationContent).toContainText('10:00');
    await expect(notificationContent).toContainText('18:00');
    await expect(notificationContent).toContainText('Schedule has been modified');
  });

  test('Configure notification preferences (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the user profile or account settings page
    await page.goto('/profile/settings');
    await expect(page.locator('[data-testid="settings-page"]')).toBeVisible();

    // Step 2: Locate and click on 'Notification Settings' menu item
    await page.click('[data-testid="notification-settings-link"]');
    await expect(page.locator('[data-testid="notification-settings-section"]')).toBeVisible();
    
    // Expected Result: Settings UI is displayed
    await expect(page.locator('[data-testid="email-notification-toggle"]')).toBeVisible();
    await expect(page.locator('[data-testid="inapp-notification-toggle"]')).toBeVisible();

    // Step 3: Review the current state of email notification toggle
    const emailToggle = page.locator('[data-testid="email-notification-toggle"]');
    const initialEmailState = await emailToggle.isChecked();

    // Step 4: Click the email notification toggle to change its state
    await emailToggle.click();
    await expect(emailToggle).toHaveAttribute('aria-checked', String(!initialEmailState));

    // Step 5: Review the current state of in-app notification toggle
    const inAppToggle = page.locator('[data-testid="inapp-notification-toggle"]');
    const initialInAppState = await inAppToggle.isChecked();

    // Step 6: Click the in-app notification toggle to change its state
    await inAppToggle.click();
    await expect(inAppToggle).toHaveAttribute('aria-checked', String(!initialInAppState));

    // Step 7: Click the 'Save' button to save the changes
    await page.click('[data-testid="save-preferences-button"]');
    
    // Expected Result: Preferences are saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');

    // Step 8: Refresh the page to verify persistence
    await page.reload();
    await page.click('[data-testid="notification-settings-link"]');
    await expect(page.locator('[data-testid="email-notification-toggle"]')).toHaveAttribute('aria-checked', String(!initialEmailState));
    await expect(page.locator('[data-testid="inapp-notification-toggle"]')).toHaveAttribute('aria-checked', String(!initialInAppState));

    // Step 9: As a Scheduler user, modify the current user's schedule
    await page.goto('/logout');
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    
    await page.goto('/scheduling');
    await page.click('[data-testid="employee-list-item"]:has-text("scheduler@company.com")');
    await page.click('[data-testid="edit-schedule-button"]');
    await page.fill('[data-testid="shift-start-time"]', '11:00');
    await page.fill('[data-testid="shift-end-time"]', '19:00');
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Step 10: Verify email notifications according to preferences
    if (!initialEmailState) {
      // Email was ENABLED after toggle
      await page.goto('/email-client');
      await page.fill('[data-testid="email-username"]', 'scheduler@company.com');
      await page.fill('[data-testid="email-password"]', 'password123');
      await page.click('[data-testid="email-login-button"]');
      const emailNotification = page.locator('[data-testid="email-item"]').filter({ hasText: 'Schedule Change' }).first();
      await expect(emailNotification).toBeVisible({ timeout: 10000 });
    } else {
      // Email was DISABLED after toggle - verify no email received
      await page.goto('/email-client');
      await page.fill('[data-testid="email-username"]', 'scheduler@company.com');
      await page.fill('[data-testid="email-password"]', 'password123');
      await page.click('[data-testid="email-login-button"]');
      await page.waitForTimeout(3000);
      const emailCount = await page.locator('[data-testid="email-item"]').filter({ hasText: 'Schedule Change' }).count();
      expect(emailCount).toBe(0);
    }

    // Step 11: Verify in-app notifications according to preferences
    // Expected Result: Notifications are sent according to preferences
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    
    if (!initialInAppState) {
      // In-app was ENABLED after toggle
      await page.click('[data-testid="notification-bell-icon"]');
      const inAppNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Schedule Modified' }).first();
      await expect(inAppNotification).toBeVisible();
    } else {
      // In-app was DISABLED after toggle - verify no notification appears
      await page.click('[data-testid="notification-bell-icon"]');
      await page.waitForTimeout(2000);
      const notificationCount = await page.locator('[data-testid="notification-item"]').filter({ hasText: 'Schedule Modified' }).count();
      expect(notificationCount).toBe(0);
    }
  });
});