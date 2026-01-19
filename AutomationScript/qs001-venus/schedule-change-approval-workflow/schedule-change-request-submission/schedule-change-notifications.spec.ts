import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Notifications', () => {
  const approverEmail = 'approver@company.com';
  const approverPassword = 'ApproverPass123!';
  const employeeEmail = 'employee@company.com';
  const employeePassword = 'EmployeePass123!';
  const baseURL = 'https://app.example.com';

  test('Verify employee receives notification on status change', async ({ page, context }) => {
    // Step 1: Log in as an approver with appropriate permissions
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to the pending schedule change requests list
    await page.click('[data-testid="schedule-requests-menu"]');
    await page.click('[data-testid="pending-requests-link"]');
    await expect(page.locator('[data-testid="pending-requests-list"]')).toBeVisible();

    // Step 3: Select the employee's schedule change request from the list
    const requestRow = page.locator('[data-testid="request-row"]').filter({ hasText: employeeEmail }).first();
    await expect(requestRow).toBeVisible();
    const requestId = await requestRow.getAttribute('data-request-id');
    await requestRow.click();

    // Step 4: Change the schedule change request status to 'Approved' and submit the decision
    await expect(page.locator('[data-testid="request-details-modal"]')).toBeVisible();
    await page.selectOption('[data-testid="status-select"]', 'approved');
    await page.fill('[data-testid="approval-comments"]', 'Request approved - schedule change confirmed');
    await page.click('[data-testid="submit-decision-button"]');
    
    // Step 5: Verify notification is triggered and sent to the employee within 1 minute
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Status updated successfully');
    const notificationTimestamp = Date.now();
    
    // Step 6: Log out approver
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 7: Log in as the employee who submitted the request
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 8: Check in-app notifications by clicking on the notification icon
    await page.waitForTimeout(2000); // Allow notification processing
    const notificationBadge = page.locator('[data-testid="notification-badge"]');
    await expect(notificationBadge).toBeVisible();
    await expect(notificationBadge).toContainText(/[1-9]/);
    
    await page.click('[data-testid="notification-icon"]');
    await expect(page.locator('[data-testid="notification-dropdown"]')).toBeVisible();
    
    // Step 9: Verify notification content is clear and accurate
    const latestNotification = page.locator('[data-testid="notification-item"]').first();
    await expect(latestNotification).toContainText('Schedule Change Request Approved');
    await expect(latestNotification).toContainText(requestId || '');
    await expect(latestNotification).toContainText('approved');
    
    // Verify notification was sent within 1 minute
    const notificationTime = await latestNotification.getAttribute('data-timestamp');
    if (notificationTime) {
      const timeDiff = parseInt(notificationTime) - notificationTimestamp;
      expect(timeDiff).toBeLessThan(60000); // Less than 1 minute
    }

    // Step 10: Click on the notification link or navigate to schedule change requests section
    await latestNotification.click();
    
    // Step 11: View the schedule change request details in the system
    await expect(page.locator('[data-testid="request-details-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Approved');
    await expect(page.locator('[data-testid="request-id"]')).toContainText(requestId || '');
  });

  test('Test employee notification preference settings', async ({ page }) => {
    // Step 1: Log in as the employee
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to user profile settings by clicking on profile icon or settings menu
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="profile-settings-link"]');
    await expect(page).toHaveURL(/.*profile|settings/);

    // Step 3: Locate and click on 'Notification Preferences' or 'Notifications' section
    await page.click('[data-testid="notification-preferences-tab"]');
    await expect(page.locator('[data-testid="notification-preferences-section"]')).toBeVisible();

    // Step 4: Review current notification settings for schedule change requests
    const emailNotificationToggle = page.locator('[data-testid="email-notifications-toggle"]');
    await expect(emailNotificationToggle).toBeVisible();
    const initialEmailState = await emailNotificationToggle.isChecked();

    // Step 5: Uncheck or toggle off the 'Email Notifications' option for schedule change request updates
    if (initialEmailState) {
      await emailNotificationToggle.uncheck();
    }
    await expect(emailNotificationToggle).not.toBeChecked();

    // Step 6: Click 'Save' or 'Update Preferences' button to save the changes
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toContainText('Preferences saved successfully');

    // Step 7: Refresh the notification preferences page to verify persistence
    await page.reload();
    await expect(page.locator('[data-testid="notification-preferences-section"]')).toBeVisible();
    const emailToggleAfterRefresh = page.locator('[data-testid="email-notifications-toggle"]');
    await expect(emailToggleAfterRefresh).not.toBeChecked();

    // Step 8: Log out and log back in as an approver
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', approverPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 9: Navigate to the employee's schedule change request and change its status
    await page.click('[data-testid="schedule-requests-menu"]');
    await page.click('[data-testid="pending-requests-link"]');
    
    const requestRow = page.locator('[data-testid="request-row"]').filter({ hasText: employeeEmail }).first();
    await expect(requestRow).toBeVisible();
    const requestId = await requestRow.getAttribute('data-request-id');
    await requestRow.click();

    await expect(page.locator('[data-testid="request-details-modal"]')).toBeVisible();
    await page.selectOption('[data-testid="status-select"]', 'rejected');
    await page.fill('[data-testid="approval-comments"]', 'Request rejected - testing notification preferences');
    await page.click('[data-testid="submit-decision-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Status updated successfully');

    // Step 10: Wait for notification processing (up to 1 minute)
    await page.waitForTimeout(5000);

    // Step 11: Log back in as the employee
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 12: Check in-app notifications by clicking on the notification icon
    await page.waitForTimeout(2000);
    const notificationBadge = page.locator('[data-testid="notification-badge"]');
    await expect(notificationBadge).toBeVisible();
    
    await page.click('[data-testid="notification-icon"]');
    await expect(page.locator('[data-testid="notification-dropdown"]')).toBeVisible();
    
    const latestNotification = page.locator('[data-testid="notification-item"]').first();
    await expect(latestNotification).toContainText('Schedule Change Request');
    await expect(latestNotification).toContainText('rejected');

    // Step 13: Verify only in-app notification was received (email disabled)
    // Navigate to notification delivery logs or admin panel
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="profile-settings-link"]');
    await page.click('[data-testid="notification-history-tab"]');
    
    const recentNotificationLog = page.locator('[data-testid="notification-log-item"]').filter({ hasText: requestId || '' }).first();
    await expect(recentNotificationLog).toBeVisible();
    await expect(recentNotificationLog.locator('[data-testid="delivery-method"]')).toContainText('in-app');
    await expect(recentNotificationLog.locator('[data-testid="delivery-method"]')).not.toContainText('email');
    
    // Verify notification delivery status
    await expect(recentNotificationLog.locator('[data-testid="delivery-status"]')).toContainText('delivered');
  });
});