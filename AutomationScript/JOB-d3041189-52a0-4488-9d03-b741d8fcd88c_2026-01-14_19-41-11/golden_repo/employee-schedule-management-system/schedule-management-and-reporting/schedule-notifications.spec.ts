import { test, expect } from '@playwright/test';

test.describe('Schedule Notification Management', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Scheduling Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduling.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Send notification on schedule creation', async ({ page }) => {
    // Navigate to the schedule management section
    await page.click('[data-testid="schedule-management-link"]');
    await expect(page.locator('[data-testid="schedule-management-header"]')).toBeVisible();

    // Click the 'Create New Schedule' button
    await page.click('[data-testid="create-schedule-button"]');
    await expect(page.locator('[data-testid="schedule-form"]')).toBeVisible();

    // Select an employee from the dropdown list
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-john-doe"]');
    await expect(page.locator('[data-testid="employee-dropdown"]')).toContainText('John Doe');

    // Enter schedule details including date, shift start time, shift end time, and position
    await page.fill('[data-testid="schedule-date-input"]', '2024-02-15');
    await page.fill('[data-testid="shift-start-time-input"]', '09:00');
    await page.fill('[data-testid="shift-end-time-input"]', '17:00');
    await page.click('[data-testid="position-dropdown"]');
    await page.click('[data-testid="position-option-cashier"]');

    // Click the 'Save' or 'Create Schedule' button
    await page.click('[data-testid="save-schedule-button"]');
    
    // Verify notification triggered
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule created and notification sent');
    await expect(page.locator('[data-testid="notification-triggered-indicator"]')).toBeVisible();

    // Navigate to the notification tracking section in the system
    await page.click('[data-testid="notification-tracking-link"]');
    await expect(page.locator('[data-testid="notification-tracking-header"]')).toBeVisible();

    // Locate the notification entry for the newly created schedule and check its delivery status
    const notificationRow = page.locator('[data-testid="notification-row"]').filter({ hasText: 'John Doe' }).first();
    await expect(notificationRow).toBeVisible();
    
    // Check notification delivery status in system - Status shows successful delivery
    await expect(notificationRow.locator('[data-testid="email-status"]')).toContainText('Delivered');
    await expect(notificationRow.locator('[data-testid="sms-status"]')).toContainText('Delivered');
    await expect(notificationRow.locator('[data-testid="delivery-timestamp"]')).toBeVisible();

    // Verify the notification content matches the created schedule details
    await notificationRow.click();
    await expect(page.locator('[data-testid="notification-detail-employee"]')).toContainText('John Doe');
    await expect(page.locator('[data-testid="notification-detail-date"]')).toContainText('2024-02-15');
    await expect(page.locator('[data-testid="notification-detail-shift-time"]')).toContainText('09:00 - 17:00');
    await expect(page.locator('[data-testid="notification-detail-position"]')).toContainText('Cashier');
  });

  test('Customize notification message and verify', async ({ page }) => {
    // Navigate to the notification settings or template management section
    await page.click('[data-testid="settings-menu"]');
    await page.click('[data-testid="notification-templates-link"]');
    await expect(page.locator('[data-testid="notification-templates-header"]')).toBeVisible();

    // Select the 'Schedule Update' notification template from the list
    await page.click('[data-testid="template-list-item-schedule-update"]');
    await expect(page.locator('[data-testid="template-editor"]')).toBeVisible();

    // Modify the notification template message by adding custom text
    const customMessage = 'IMPORTANT: Your schedule has been updated. Please review the changes below.';
    await page.fill('[data-testid="template-message-input"]', customMessage);
    
    // Verify that template variables are properly included
    await page.fill('[data-testid="template-message-input"]', `${customMessage}\n\nEmployee: {employee_name}\nShift Date: {shift_date}\nShift Time: {shift_time}`);
    await expect(page.locator('[data-testid="template-message-input"]')).toContainText('{employee_name}');
    await expect(page.locator('[data-testid="template-message-input"]')).toContainText('{shift_date}');
    await expect(page.locator('[data-testid="template-message-input"]')).toContainText('{shift_time}');

    // Click the 'Save Template' button
    await page.click('[data-testid="save-template-button"]');
    await expect(page.locator('[data-testid="template-saved-message"]')).toContainText('Template saved successfully');

    // Navigate to the schedule management section
    await page.click('[data-testid="schedule-management-link"]');
    await expect(page.locator('[data-testid="schedule-management-header"]')).toBeVisible();

    // Select an existing employee schedule and click 'Edit'
    const scheduleRow = page.locator('[data-testid="schedule-row"]').filter({ hasText: 'Jane Smith' }).first();
    await scheduleRow.click();
    await page.click('[data-testid="edit-schedule-button"]');
    await expect(page.locator('[data-testid="schedule-form"]')).toBeVisible();

    // Modify the schedule by changing the shift time or date
    await page.fill('[data-testid="schedule-date-input"]', '2024-02-20');
    await page.fill('[data-testid="shift-start-time-input"]', '10:00');
    await page.fill('[data-testid="shift-end-time-input"]', '18:00');

    // Click 'Save' to update the schedule
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule updated and notification sent');

    // Navigate to notification tracking to verify customized message
    await page.click('[data-testid="notification-tracking-link"]');
    await expect(page.locator('[data-testid="notification-tracking-header"]')).toBeVisible();

    // Locate the notification for Jane Smith
    const notificationRow = page.locator('[data-testid="notification-row"]').filter({ hasText: 'Jane Smith' }).first();
    await notificationRow.click();

    // Verify that the employee receives customized message
    const notificationContent = page.locator('[data-testid="notification-content"]');
    await expect(notificationContent).toContainText('IMPORTANT: Your schedule has been updated. Please review the changes below.');
    
    // Verify that all template variables are correctly replaced with actual data
    await expect(notificationContent).toContainText('Employee: Jane Smith');
    await expect(notificationContent).toContainText('Shift Date: 2024-02-20');
    await expect(notificationContent).toContainText('Shift Time: 10:00 - 18:00');
    await expect(notificationContent).not.toContainText('{employee_name}');
    await expect(notificationContent).not.toContainText('{shift_date}');
    await expect(notificationContent).not.toContainText('{shift_time}');

    // Verify delivery status
    await expect(page.locator('[data-testid="email-status"]')).toContainText('Delivered');
    await expect(page.locator('[data-testid="sms-status"]')).toContainText('Delivered');
  });
});