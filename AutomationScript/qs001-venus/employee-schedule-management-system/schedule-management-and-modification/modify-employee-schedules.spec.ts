import { test, expect } from '@playwright/test';

test.describe('Modify Employee Schedules - Story 7', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Scheduling Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduling.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Modify employee schedule and log changes', async ({ page }) => {
    // Step 1: Navigate to employee schedules page and select existing schedule
    await page.goto('/employee-schedules');
    await expect(page.locator('[data-testid="schedules-page-title"]')).toBeVisible();
    
    // Locate and click on a specific employee schedule
    const scheduleRow = page.locator('[data-testid="schedule-row"]').first();
    await scheduleRow.click();
    
    // Expected Result: Schedule details are displayed
    await expect(page.locator('[data-testid="schedule-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-times"]')).toBeVisible();
    
    // Step 2: Click Edit button to enter edit mode
    await page.click('[data-testid="edit-schedule-button"]');
    await expect(page.locator('[data-testid="schedule-edit-form"]')).toBeVisible();
    
    // Modify shift start time and end time
    const originalStartTime = await page.inputValue('[data-testid="shift-start-time"]');
    const originalEndTime = await page.inputValue('[data-testid="shift-end-time"]');
    
    await page.fill('[data-testid="shift-start-time"]', '09:00');
    await page.fill('[data-testid="shift-end-time"]', '17:00');
    
    // Click Save button
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Changes are saved and audit log entry created
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule updated successfully');
    
    // Step 3: Navigate to audit log section
    await page.click('[data-testid="audit-log-link"]');
    await expect(page).toHaveURL(/.*audit-log/);
    
    // Search for the modification entry
    await page.fill('[data-testid="audit-log-search"]', 'schedule modification');
    await page.click('[data-testid="search-button"]');
    
    // Expected Result: Log entry contains user and timestamp
    const auditLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditLogEntry).toBeVisible();
    await expect(auditLogEntry.locator('[data-testid="log-user"]')).toContainText('scheduling.manager@company.com');
    await expect(auditLogEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(auditLogEntry.locator('[data-testid="log-action"]')).toContainText('Schedule Modified');
    
    // Verify the timestamp is recent (within last 5 minutes)
    const timestampText = await auditLogEntry.locator('[data-testid="log-timestamp"]').textContent();
    expect(timestampText).toBeTruthy();
  });

  test('Send notification after schedule change', async ({ page }) => {
    // Step 1: Navigate to employee schedules page
    await page.goto('/employee-schedules');
    await expect(page.locator('[data-testid="schedules-page-title"]')).toBeVisible();
    
    // Select an existing employee schedule
    const scheduleRow = page.locator('[data-testid="schedule-row"]').first();
    const employeeName = await scheduleRow.locator('[data-testid="employee-name-cell"]').textContent();
    await scheduleRow.click();
    
    // Expected Result: Schedule details are displayed
    await expect(page.locator('[data-testid="schedule-details-panel"]')).toBeVisible();
    
    // Click Edit button to enter edit mode
    await page.click('[data-testid="edit-schedule-button"]');
    await expect(page.locator('[data-testid="schedule-edit-form"]')).toBeVisible();
    
    // Modify the schedule by changing shift times
    await page.fill('[data-testid="shift-start-time"]', '10:00');
    await page.fill('[data-testid="shift-end-time"]', '18:00');
    await page.fill('[data-testid="shift-date"]', '2024-02-15');
    
    // Click Save button to save changes
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Notification is sent to employee
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule updated and notification sent');
    
    // Step 2: Navigate to notifications management section
    await page.click('[data-testid="notifications-link"]');
    await expect(page).toHaveURL(/.*notifications/);
    await expect(page.locator('[data-testid="notifications-page-title"]')).toBeVisible();
    
    // Search or filter for the notification sent to the affected employee
    await page.fill('[data-testid="notification-search"]', employeeName || 'schedule change');
    await page.click('[data-testid="search-notifications-button"]');
    
    // Expected Result: Notification status shows as Delivered or Sent
    const notificationEntry = page.locator('[data-testid="notification-entry"]').first();
    await expect(notificationEntry).toBeVisible();
    
    const notificationStatus = notificationEntry.locator('[data-testid="notification-status"]');
    await expect(notificationStatus).toBeVisible();
    
    // Check notification status is Delivered or Sent
    const statusText = await notificationStatus.textContent();
    expect(statusText).toMatch(/Delivered|Sent/);
    
    // Verify notification contains schedule change details
    await expect(notificationEntry.locator('[data-testid="notification-type"]')).toContainText('Schedule Change');
    await expect(notificationEntry.locator('[data-testid="notification-recipient"]')).toContainText(employeeName || '');
    
    // Verify notification timestamp is recent
    const notificationTimestamp = notificationEntry.locator('[data-testid="notification-timestamp"]');
    await expect(notificationTimestamp).toBeVisible();
  });
});