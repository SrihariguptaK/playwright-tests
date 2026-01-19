import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Notifications', () => {
  test.beforeEach(async ({ page }) => {
    // Login as manager before each test
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'ManagerPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Receive notification upon request submission (happy-path)', async ({ page }) => {
    // Manager navigates to the schedule change request form
    await page.goto('/schedule-change-request');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Manager fills in all required fields (date, time, reason, etc.) for the schedule change request
    await page.fill('[data-testid="request-date-input"]', '2024-02-15');
    await page.fill('[data-testid="request-time-input"]', '09:00');
    await page.fill('[data-testid="request-reason-textarea"]', 'Medical appointment - need to adjust shift timing');
    await page.selectOption('[data-testid="shift-type-select"]', 'morning');
    await page.fill('[data-testid="alternative-date-input"]', '2024-02-16');

    // Manager clicks the 'Submit' button to submit the schedule change request
    await page.click('[data-testid="submit-request-button"]');

    // System processes the submission and triggers notification service
    await expect(page.locator('[data-testid="submission-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="submission-success-message"]')).toContainText('Schedule change request submitted successfully');

    // Manager checks their preferred notification channel (email or SMS)
    await page.goto('/notifications');
    await expect(page.locator('[data-testid="notifications-list"]')).toBeVisible();

    // Manager reviews the notification content
    const latestNotification = page.locator('[data-testid="notification-item"]').first();
    await expect(latestNotification).toBeVisible();
    await expect(latestNotification.locator('[data-testid="notification-type"]')).toContainText('Submission Confirmation');
    await expect(latestNotification.locator('[data-testid="notification-content"]')).toContainText('Medical appointment');
    await expect(latestNotification.locator('[data-testid="notification-date"]')).toContainText('2024-02-15');

    // Verify notification delivery is logged in the system
    await page.goto('/notification-logs');
    await expect(page.locator('[data-testid="notification-logs-table"]')).toBeVisible();
    const logEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(logEntry.locator('[data-testid="log-status"]')).toContainText('Delivered');
    await expect(logEntry.locator('[data-testid="log-type"]')).toContainText('Submission Confirmation');
  });

  test('Receive notification on approval and rejection (happy-path)', async ({ page, context }) => {
    // Setup: Create a pending request first
    await page.goto('/schedule-change-request');
    await page.fill('[data-testid="request-date-input"]', '2024-02-20');
    await page.fill('[data-testid="request-time-input"]', '14:00');
    await page.fill('[data-testid="request-reason-textarea"]', 'Personal appointment requiring schedule adjustment');
    await page.click('[data-testid="submit-request-button"]');
    await expect(page.locator('[data-testid="submission-success-message"]')).toBeVisible();
    const requestId = await page.locator('[data-testid="request-id"]').textContent();

    // Login as approver in new page
    const approverPage = await context.newPage();
    await approverPage.goto('/login');
    await approverPage.fill('[data-testid="username-input"]', 'approver@company.com');
    await approverPage.fill('[data-testid="password-input"]', 'ApproverPass123');
    await approverPage.click('[data-testid="login-button"]');

    // Approver navigates to the pending requests queue
    await approverPage.goto('/pending-requests');
    await expect(approverPage.locator('[data-testid="pending-requests-queue"]')).toBeVisible();

    // Approver selects the manager's schedule change request to review
    await approverPage.click(`[data-testid="request-row-${requestId}"]`);
    await expect(approverPage.locator('[data-testid="request-details-modal"]')).toBeVisible();

    // Approver adds comments in the comments field
    await approverPage.fill('[data-testid="approver-comments-textarea"]', 'Approved due to valid business reason');

    // Approver clicks 'Approve' button to approve the request
    await approverPage.click('[data-testid="approve-button"]');
    await expect(approverPage.locator('[data-testid="approval-success-message"]')).toBeVisible();

    // System triggers notification service for status update
    // Manager receives notification via preferred channel
    await page.goto('/notifications');
    await page.reload();
    await page.waitForTimeout(2000); // Wait for notification to be delivered

    const approvalNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Approved' }).first();
    await expect(approvalNotification).toBeVisible();

    // Verify notification is accurate and timely
    await expect(approvalNotification.locator('[data-testid="notification-type"]')).toContainText('Approval');
    await expect(approvalNotification.locator('[data-testid="notification-content"]')).toContainText('Approved due to valid business reason');
    await expect(approvalNotification.locator('[data-testid="notification-timestamp"]')).toBeVisible();

    // Repeat steps for rejection scenario
    // Create another request
    await page.goto('/schedule-change-request');
    await page.fill('[data-testid="request-date-input"]', '2024-02-25');
    await page.fill('[data-testid="request-time-input"]', '10:00');
    await page.fill('[data-testid="request-reason-textarea"]', 'Request for schedule change');
    await page.click('[data-testid="submit-request-button"]');
    await expect(page.locator('[data-testid="submission-success-message"]')).toBeVisible();
    const rejectionRequestId = await page.locator('[data-testid="request-id"]').textContent();

    // Approver selects another pending request and clicks 'Reject' with rejection reason
    await approverPage.goto('/pending-requests');
    await approverPage.click(`[data-testid="request-row-${rejectionRequestId}"]`);
    await expect(approverPage.locator('[data-testid="request-details-modal"]')).toBeVisible();
    await approverPage.fill('[data-testid="approver-comments-textarea"]', 'Rejected due to insufficient coverage');
    await approverPage.click('[data-testid="reject-button"]');
    await expect(approverPage.locator('[data-testid="rejection-success-message"]')).toBeVisible();

    // Manager receives rejection notification and reviews content
    await page.goto('/notifications');
    await page.reload();
    await page.waitForTimeout(2000);

    const rejectionNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Rejected' }).first();
    await expect(rejectionNotification).toBeVisible();
    await expect(rejectionNotification.locator('[data-testid="notification-type"]')).toContainText('Rejection');
    await expect(rejectionNotification.locator('[data-testid="notification-content"]')).toContainText('Rejected due to insufficient coverage');

    // Verify both approval and rejection notifications are logged
    await page.goto('/notification-logs');
    await expect(page.locator('[data-testid="notification-logs-table"]')).toBeVisible();
    const approvalLog = page.locator('[data-testid="log-entry"]').filter({ hasText: 'Approval' }).first();
    await expect(approvalLog.locator('[data-testid="log-status"]')).toContainText('Delivered');
    const rejectionLog = page.locator('[data-testid="log-entry"]').filter({ hasText: 'Rejection' }).first();
    await expect(rejectionLog.locator('[data-testid="log-status"]')).toContainText('Delivered');

    await approverPage.close();
  });

  test('Manage notification preferences (happy-path)', async ({ page }) => {
    // Manager navigates to user profile or settings section
    await page.goto('/profile');
    await expect(page.locator('[data-testid="profile-page"]')).toBeVisible();

    // Manager clicks on 'Notification Preferences' or 'Notification Settings' option
    await page.click('[data-testid="notification-preferences-link"]');
    await expect(page.locator('[data-testid="notification-preferences-section"]')).toBeVisible();

    // Manager reviews current notification channel preferences (email, SMS, or both)
    const emailCheckbox = page.locator('[data-testid="notification-channel-email"]');
    const smsCheckbox = page.locator('[data-testid="notification-channel-sms"]');
    await expect(emailCheckbox).toBeVisible();
    await expect(smsCheckbox).toBeVisible();

    const initialEmailState = await emailCheckbox.isChecked();
    const initialSmsState = await smsCheckbox.isChecked();

    // Manager updates notification channel preferences by selecting/deselecting email and SMS options
    if (!initialEmailState) {
      await emailCheckbox.check();
    }
    if (initialSmsState) {
      await smsCheckbox.uncheck();
    }

    // Manager selects specific notification types to receive
    await page.check('[data-testid="notification-type-submission"]');
    await page.check('[data-testid="notification-type-approval"]');
    await page.check('[data-testid="notification-type-rejection"]');
    await page.check('[data-testid="notification-type-escalation"]');

    // Manager clicks 'Save' or 'Update Preferences' button
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toContainText('Notification preferences updated successfully');

    // Manager verifies updated preferences are displayed correctly on the preferences page
    await page.reload();
    await expect(page.locator('[data-testid="notification-channel-email"]')).toBeChecked();
    await expect(page.locator('[data-testid="notification-channel-sms"]')).not.toBeChecked();
    await expect(page.locator('[data-testid="notification-type-submission"]')).toBeChecked();
    await expect(page.locator('[data-testid="notification-type-approval"]')).toBeChecked();
    await expect(page.locator('[data-testid="notification-type-rejection"]')).toBeChecked();
    await expect(page.locator('[data-testid="notification-type-escalation"]')).toBeChecked();

    // Manager submits a new schedule change request to test updated preferences
    await page.goto('/schedule-change-request');
    await page.fill('[data-testid="request-date-input"]', '2024-03-01');
    await page.fill('[data-testid="request-time-input"]', '11:00');
    await page.fill('[data-testid="request-reason-textarea"]', 'Testing notification preferences');
    await page.click('[data-testid="submit-request-button"]');
    await expect(page.locator('[data-testid="submission-success-message"]')).toBeVisible();

    // System sends notification according to updated preferences
    await page.goto('/notifications');
    await page.waitForTimeout(2000);

    // Manager checks the selected notification channels
    const testNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Testing notification preferences' }).first();
    await expect(testNotification).toBeVisible();
    await expect(testNotification.locator('[data-testid="notification-channel"]')).toContainText('Email');

    // Manager verifies no notifications are received on disabled channels
    await expect(testNotification.locator('[data-testid="notification-channel"]')).not.toContainText('SMS');

    // Verify preference changes are logged in the system
    await page.goto('/notification-logs');
    await expect(page.locator('[data-testid="notification-logs-table"]')).toBeVisible();
    const preferenceLog = page.locator('[data-testid="log-entry"]').filter({ hasText: 'Preferences Updated' }).first();
    await expect(preferenceLog).toBeVisible();
    await expect(preferenceLog.locator('[data-testid="log-details"]')).toContainText('Email: enabled');
    await expect(preferenceLog.locator('[data-testid="log-details"]')).toContainText('SMS: disabled');
  });
});