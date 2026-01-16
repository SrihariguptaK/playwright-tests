import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Notifications', () => {
  const employeeEmail = 'employee@company.com';
  const employeePassword = 'Employee123!';
  const managerEmail = 'manager@company.com';
  const managerPassword = 'Manager123!';

  test.beforeEach(async ({ page }) => {
    await page.goto('/login');
  });

  test('Validate notification delivery on request submission', async ({ page, context }) => {
    // Login as employee
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the schedule change request submission page
    await page.click('[data-testid="schedule-menu"]');
    await page.click('[data-testid="change-request-link"]');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Fill in all required fields for the schedule change request
    await page.fill('[data-testid="request-date-input"]', '2024-02-15');
    await page.fill('[data-testid="request-time-input"]', '09:00');
    await page.selectOption('[data-testid="request-type-select"]', 'shift-swap');
    await page.fill('[data-testid="request-reason-textarea"]', 'Personal appointment - need to swap shift');

    // Click the Submit button to submit the schedule change request
    await page.click('[data-testid="submit-request-button"]');

    // Expected Result: System sends email and in-app notification confirming submission
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule change request submitted successfully');
    
    // Wait for notification to be processed (within 1 minute)
    await page.waitForTimeout(2000);

    // Navigate to the in-app notification center
    await page.click('[data-testid="notification-bell-icon"]');
    await expect(page.locator('[data-testid="notification-dropdown"]')).toBeVisible();
    
    // Verify in-app notification exists
    const submissionNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Schedule change request submitted' });
    await expect(submissionNotification).toBeVisible();
    await expect(submissionNotification).toContainText('Personal appointment');

    // Navigate to the employee profile and access the notification history section
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="profile-link"]');
    await page.click('[data-testid="notification-history-tab"]');

    // Expected Result: Submission notification is listed with correct details
    const notificationHistory = page.locator('[data-testid="notification-history-list"]');
    await expect(notificationHistory).toBeVisible();
    
    const historyItem = notificationHistory.locator('[data-testid="notification-history-item"]').first();
    await expect(historyItem).toContainText('Schedule change request submitted');
    await expect(historyItem).toContainText('2024-02-15');
    await expect(historyItem).toContainText('Personal appointment');
  });

  test('Verify notification on approval and rejection', async ({ page, context }) => {
    // First, create a request as employee
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    await page.click('[data-testid="schedule-menu"]');
    await page.click('[data-testid="change-request-link"]');
    await page.fill('[data-testid="request-date-input"]', '2024-02-20');
    await page.fill('[data-testid="request-time-input"]', '14:00');
    await page.selectOption('[data-testid="request-type-select"]', 'time-off');
    await page.fill('[data-testid="request-reason-textarea"]', 'Medical appointment');
    await page.click('[data-testid="submit-request-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Logout employee
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Login as manager
    await page.fill('[data-testid="email-input"]', managerEmail);
    await page.fill('[data-testid="password-input"]', managerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Manager navigates to the pending schedule change requests queue
    await page.click('[data-testid="schedule-menu"]');
    await page.click('[data-testid="pending-requests-link"]');
    await expect(page.locator('[data-testid="pending-requests-table"]')).toBeVisible();

    // Manager selects the employee's schedule change request to review
    const requestRow = page.locator('[data-testid="request-row"]').filter({ hasText: 'Medical appointment' });
    await requestRow.click();
    await expect(page.locator('[data-testid="request-details-modal"]')).toBeVisible();

    // Manager clicks Approve button and adds optional approval comments
    await page.click('[data-testid="approve-button"]');
    await page.fill('[data-testid="approval-comments-textarea"]', 'Approved - please ensure coverage is arranged');
    
    // Manager confirms the approval action
    await page.click('[data-testid="confirm-approval-button"]');
    await expect(page.locator('[data-testid="approval-success-message"]')).toContainText('Request approved successfully');

    // Wait for notification to be sent (within 1 minute)
    await page.waitForTimeout(2000);

    // Logout manager and login as employee to check notification
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');

    // Expected Result: Employee receives corresponding notification promptly
    await page.click('[data-testid="notification-bell-icon"]');
    const approvalNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'approved' });
    await expect(approvalNotification).toBeVisible();
    await expect(approvalNotification).toContainText('Medical appointment');

    // Logout and test rejection flow
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Create another request as employee
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    await page.click('[data-testid="schedule-menu"]');
    await page.click('[data-testid="change-request-link"]');
    await page.fill('[data-testid="request-date-input"]', '2024-02-25');
    await page.fill('[data-testid="request-time-input"]', '10:00');
    await page.selectOption('[data-testid="request-type-select"]', 'shift-swap');
    await page.fill('[data-testid="request-reason-textarea"]', 'Family event');
    await page.click('[data-testid="submit-request-button"]');
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Login as manager for rejection
    await page.fill('[data-testid="email-input"]', managerEmail);
    await page.fill('[data-testid="password-input"]', managerPassword);
    await page.click('[data-testid="login-button"]');
    await page.click('[data-testid="schedule-menu"]');
    await page.click('[data-testid="pending-requests-link"]');

    // Manager navigates to another pending schedule change request
    const rejectionRequestRow = page.locator('[data-testid="request-row"]').filter({ hasText: 'Family event' });
    await rejectionRequestRow.click();

    // Manager clicks Reject button and enters mandatory rejection reason
    await page.click('[data-testid="reject-button"]');
    await page.fill('[data-testid="rejection-reason-textarea"]', 'Insufficient staffing coverage for requested date');
    
    // Manager confirms the rejection action
    await page.click('[data-testid="confirm-rejection-button"]');
    await expect(page.locator('[data-testid="rejection-success-message"]')).toContainText('Request rejected');

    await page.waitForTimeout(2000);

    // Logout manager and login as employee to check rejection notification
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');

    // Expected Result: Affected employee receives rejection notification
    await page.click('[data-testid="notification-bell-icon"]');
    const rejectionNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'rejected' });
    await expect(rejectionNotification).toBeVisible();
    await expect(rejectionNotification).toContainText('Family event');
    await expect(rejectionNotification).toContainText('Insufficient staffing coverage');
  });

  test('Ensure notification preferences are respected', async ({ page }) => {
    // Login as employee
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the employee profile or settings page
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-link"]');
    await expect(page.locator('[data-testid="settings-page"]')).toBeVisible();

    // Click on Notification Preferences or Notification Settings option
    await page.click('[data-testid="notification-preferences-tab"]');
    await expect(page.locator('[data-testid="notification-preferences-section"]')).toBeVisible();

    // Verify current notification preferences show both email and in-app notifications are enabled
    const emailToggle = page.locator('[data-testid="email-notification-toggle"]');
    const inAppToggle = page.locator('[data-testid="inapp-notification-toggle"]');
    await expect(emailToggle).toBeChecked();
    await expect(inAppToggle).toBeChecked();

    // Toggle the email notification preference to OFF or Disabled
    await emailToggle.click();
    await expect(emailToggle).not.toBeChecked();

    // Click Save or Update Preferences button
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toContainText('Preferences saved successfully');

    // Trigger a notification event by submitting a new schedule change request
    await page.click('[data-testid="schedule-menu"]');
    await page.click('[data-testid="change-request-link"]');
    await page.fill('[data-testid="request-date-input"]', '2024-03-01');
    await page.fill('[data-testid="request-time-input"]', '11:00');
    await page.selectOption('[data-testid="request-type-select"]', 'time-off');
    await page.fill('[data-testid="request-reason-textarea"]', 'Testing notification preferences');
    await page.click('[data-testid="submit-request-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    await page.waitForTimeout(2000);

    // Expected Result: System stops sending email notifications but continues in-app notifications
    // Navigate to the in-app notification center in the application
    await page.click('[data-testid="notification-bell-icon"]');
    const inAppNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Testing notification preferences' });
    await expect(inAppNotification).toBeVisible();

    // Navigate back to notification preferences and verify email notifications remain disabled
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-link"]');
    await page.click('[data-testid="notification-preferences-tab"]');
    await expect(page.locator('[data-testid="email-notification-toggle"]')).not.toBeChecked();
    await expect(page.locator('[data-testid="inapp-notification-toggle"]')).toBeChecked();

    // Check notification history in employee profile
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="profile-link"]');
    await page.click('[data-testid="notification-history-tab"]');
    const historyList = page.locator('[data-testid="notification-history-list"]');
    const latestHistoryItem = historyList.locator('[data-testid="notification-history-item"]').first();
    await expect(latestHistoryItem).toContainText('Testing notification preferences');
    await expect(latestHistoryItem).toContainText('In-App');
  });
});