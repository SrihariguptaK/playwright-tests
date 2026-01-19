import { test, expect } from '@playwright/test';

test.describe('Schedule Notifications Management', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    // Login as Scheduling Manager
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', 'scheduling.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Send notification on schedule creation (happy-path)', async ({ page }) => {
    // Navigate to the schedule management interface
    await page.goto(`${baseURL}/schedules`);
    await expect(page.locator('[data-testid="schedule-management-page"]')).toBeVisible();
    
    // Click on 'Create New Schedule' button
    await page.click('[data-testid="create-schedule-button"]');
    await expect(page.locator('[data-testid="schedule-form"]')).toBeVisible();
    
    // Fill in schedule details including employee name, date, time, and shift information
    await page.fill('[data-testid="employee-name-input"]', 'John Doe');
    await page.selectOption('[data-testid="employee-select"]', { label: 'John Doe' });
    await page.fill('[data-testid="schedule-date-input"]', '2024-02-15');
    await page.fill('[data-testid="start-time-input"]', '09:00');
    await page.fill('[data-testid="end-time-input"]', '17:00');
    await page.selectOption('[data-testid="shift-select"]', { label: 'Morning Shift' });
    
    // Click 'Save' or 'Create Schedule' button
    await page.click('[data-testid="save-schedule-button"]');
    
    // Verify notification is triggered in the system logs or notification dashboard
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule created successfully');
    await expect(page.locator('[data-testid="notification-triggered-indicator"]')).toBeVisible();
    
    // Navigate to notification dashboard to verify notification was sent
    await page.click('[data-testid="notifications-menu"]');
    await page.click('[data-testid="notification-status-link"]');
    await expect(page).toHaveURL(/.*notifications/);
    
    // Check employee's email inbox for notification (verify in notification dashboard)
    const notificationRow = page.locator('[data-testid="notification-list"]').locator('tr').first();
    await expect(notificationRow.locator('[data-testid="recipient-name"]')).toContainText('John Doe');
    await expect(notificationRow.locator('[data-testid="notification-type"]')).toContainText('Schedule Created');
    await expect(notificationRow.locator('[data-testid="delivery-status"]')).toContainText('Sent');
    await expect(notificationRow.locator('[data-testid="channel"]')).toContainText('Email');
    
    // Check employee's app for push notification or in-app message
    await expect(notificationRow.locator('[data-testid="app-notification-status"]')).toContainText('Delivered');
    
    // Verify notification content includes all relevant schedule information
    await notificationRow.click();
    await expect(page.locator('[data-testid="notification-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-content"]')).toContainText('John Doe');
    await expect(page.locator('[data-testid="notification-content"]')).toContainText('2024-02-15');
    await expect(page.locator('[data-testid="notification-content"]')).toContainText('09:00');
    await expect(page.locator('[data-testid="notification-content"]')).toContainText('17:00');
    await expect(page.locator('[data-testid="notification-content"]')).toContainText('Morning Shift');
  });

  test('Track and resend failed notifications (error-case)', async ({ page }) => {
    // Navigate to the notification status dashboard or monitoring page
    await page.goto(`${baseURL}/notifications/status`);
    await expect(page.locator('[data-testid="notification-dashboard"]')).toBeVisible();
    
    // Simulate a notification failure by disabling email service or using invalid employee email address
    await page.goto(`${baseURL}/schedules`);
    await page.click('[data-testid="create-schedule-button"]');
    
    // Create or modify a schedule to trigger notification with invalid email
    await page.fill('[data-testid="employee-name-input"]', 'Jane Smith');
    await page.selectOption('[data-testid="employee-select"]', { label: 'Jane Smith' });
    await page.fill('[data-testid="schedule-date-input"]', '2024-02-16');
    await page.fill('[data-testid="start-time-input"]', '10:00');
    await page.fill('[data-testid="end-time-input"]', '18:00');
    await page.selectOption('[data-testid="shift-select"]', { label: 'Afternoon Shift' });
    
    // Override email with invalid address for testing
    await page.click('[data-testid="advanced-options-toggle"]');
    await page.fill('[data-testid="override-email-input"]', 'invalid-email@');
    
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Check the notification status dashboard for the failed notification
    await page.goto(`${baseURL}/notifications/status`);
    await page.click('[data-testid="filter-failed-notifications"]');
    
    const failedNotification = page.locator('[data-testid="notification-list"]').locator('tr', { hasText: 'Jane Smith' }).first();
    await expect(failedNotification).toBeVisible();
    
    // Verify failure details include error message and affected employee information
    await expect(failedNotification.locator('[data-testid="delivery-status"]')).toContainText('Failed');
    await expect(failedNotification.locator('[data-testid="recipient-name"]')).toContainText('Jane Smith');
    
    await failedNotification.click();
    await expect(page.locator('[data-testid="notification-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Invalid email address');
    await expect(page.locator('[data-testid="affected-employee"]')).toContainText('Jane Smith');
    
    // Resolve the issue causing failure (e.g., correct email address, re-enable service)
    await page.click('[data-testid="edit-recipient-button"]');
    await page.fill('[data-testid="correct-email-input"]', 'jane.smith@company.com');
    await page.click('[data-testid="save-email-button"]');
    await expect(page.locator('[data-testid="email-updated-message"]')).toContainText('Email address updated');
    
    // Select the failed notification from the list
    await page.goto(`${baseURL}/notifications/status`);
    await page.click('[data-testid="filter-failed-notifications"]');
    const updatedFailedNotification = page.locator('[data-testid="notification-list"]').locator('tr', { hasText: 'Jane Smith' }).first();
    await updatedFailedNotification.locator('[data-testid="notification-checkbox"]').check();
    
    // Click 'Resend Notification' or 'Retry' button
    await page.click('[data-testid="resend-notification-button"]');
    await expect(page.locator('[data-testid="resend-confirmation-dialog"]')).toBeVisible();
    await page.click('[data-testid="confirm-resend-button"]');
    
    // Monitor notification status for the resent notification
    await expect(page.locator('[data-testid="resend-success-message"]')).toContainText('Notification resent successfully');
    
    // Verify employee receives the resent notification via configured channel
    await page.waitForTimeout(2000); // Wait for notification processing
    await page.reload();
    
    const resentNotification = page.locator('[data-testid="notification-list"]').locator('tr', { hasText: 'Jane Smith' }).first();
    await expect(resentNotification.locator('[data-testid="delivery-status"]')).toContainText('Sent');
    await expect(resentNotification.locator('[data-testid="channel"]')).toContainText('Email');
    
    // Check notification history to confirm resend attempt is logged
    await resentNotification.click();
    await page.click('[data-testid="notification-history-tab"]');
    await expect(page.locator('[data-testid="notification-history"]')).toBeVisible();
    
    const historyEntries = page.locator('[data-testid="history-entry"]');
    await expect(historyEntries).toHaveCount(2); // Original failed attempt + resend
    await expect(historyEntries.first()).toContainText('Failed');
    await expect(historyEntries.last()).toContainText('Sent');
    await expect(historyEntries.last()).toContainText('Resent');
  });
});