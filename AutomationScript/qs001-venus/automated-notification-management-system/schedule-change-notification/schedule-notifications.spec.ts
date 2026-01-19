import { test, expect } from '@playwright/test';

test.describe('Schedule Change Notifications', () => {
  let testScheduleId: string;
  let modificationTimestamp: Date;

  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@test.com');
    await page.fill('[data-testid="password-input"]', 'Test@1234');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate notification sent on schedule change (happy-path)', async ({ page, context }) => {
    // Navigate to the scheduling module and select an existing schedule entry
    await page.goto('/scheduling');
    await page.waitForSelector('[data-testid="schedule-list"]');
    await page.click('[data-testid="schedule-entry-1"]');
    
    // Update a schedule entry by modifying the date, time, or resource assignment
    await page.click('[data-testid="edit-schedule-button"]');
    await page.fill('[data-testid="schedule-date-input"]', '2024-02-15');
    await page.fill('[data-testid="schedule-time-input"]', '14:30');
    await page.selectOption('[data-testid="resource-assignment-select"]', 'Resource-A');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Verify that the system detects the change and triggers notification process
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule updated successfully');
    await expect(page.locator('[data-testid="notification-triggered-indicator"]')).toBeVisible();
    
    // Check the in-app notification center within the application
    await page.click('[data-testid="notification-bell-icon"]');
    await page.waitForSelector('[data-testid="notification-center"]');
    
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toBeVisible();
    await expect(notification).toContainText('Schedule change');
    await expect(notification).toContainText('2024-02-15');
    await expect(notification).toContainText('14:30');
    await expect(notification).toContainText('Resource-A');
    
    // Click on the acknowledge button in the in-app notification
    await notification.locator('[data-testid="acknowledge-button"]').click();
    await expect(notification.locator('[data-testid="acknowledged-badge"]')).toBeVisible();
    
    // Navigate to notification logs or audit trail section
    await page.goto('/notifications/logs');
    await page.waitForSelector('[data-testid="notification-logs-table"]');
    
    const logEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(logEntry).toContainText('Schedule change');
    await expect(logEntry).toContainText('Acknowledged');
    await expect(logEntry.locator('[data-testid="delivery-status-email"]')).toContainText('Delivered');
    await expect(logEntry.locator('[data-testid="delivery-status-sms"]')).toContainText('Delivered');
    await expect(logEntry.locator('[data-testid="delivery-status-inapp"]')).toContainText('Delivered');
  });

  test('Verify retry mechanism on notification failure (error-case)', async ({ page }) => {
    // Configure the test environment to simulate notification delivery failure for email service
    await page.goto('/admin/settings');
    await page.click('[data-testid="notification-settings-tab"]');
    await page.check('[data-testid="simulate-email-failure-checkbox"]');
    await page.click('[data-testid="save-settings-button"]');
    await expect(page.locator('[data-testid="settings-saved-message"]')).toBeVisible();
    
    // Update a schedule entry to trigger notification
    await page.goto('/scheduling');
    await page.click('[data-testid="schedule-entry-2"]');
    await page.click('[data-testid="edit-schedule-button"]');
    await page.fill('[data-testid="schedule-date-input"]', '2024-02-20');
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Access notification logs from the system dashboard
    await page.goto('/notifications/logs');
    await page.waitForSelector('[data-testid="notification-logs-table"]');
    
    // Observe the retry mechanism activation and subsequent retry attempts
    const latestLog = page.locator('[data-testid="log-entry"]').first();
    await expect(latestLog.locator('[data-testid="retry-count"]')).toBeVisible();
    
    // Wait for retry attempts to complete (with timeout)
    await page.waitForTimeout(10000);
    await page.reload();
    
    // Verify all retry attempts are logged with timestamps
    await expect(latestLog.locator('[data-testid="retry-attempt-1"]')).toBeVisible();
    await expect(latestLog.locator('[data-testid="retry-attempt-2"]')).toBeVisible();
    await expect(latestLog.locator('[data-testid="retry-attempt-3"]')).toBeVisible();
    
    const retryTimestamp1 = await latestLog.locator('[data-testid="retry-timestamp-1"]').textContent();
    const retryTimestamp2 = await latestLog.locator('[data-testid="retry-timestamp-2"]').textContent();
    const retryTimestamp3 = await latestLog.locator('[data-testid="retry-timestamp-3"]').textContent();
    
    expect(retryTimestamp1).toBeTruthy();
    expect(retryTimestamp2).toBeTruthy();
    expect(retryTimestamp3).toBeTruthy();
    
    // Restore email service to normal operation
    await page.goto('/admin/settings');
    await page.click('[data-testid="notification-settings-tab"]');
    await page.uncheck('[data-testid="simulate-email-failure-checkbox"]');
    await page.click('[data-testid="save-settings-button"]');
    
    // Review final notification status in logs
    await page.goto('/notifications/logs');
    const finalStatus = page.locator('[data-testid="log-entry"]').first();
    const emailStatus = await finalStatus.locator('[data-testid="delivery-status-email"]').textContent();
    
    // Confirm notification delivery after retries or failure is logged
    expect(emailStatus).toMatch(/Failed|Delivered/);
    await expect(finalStatus.locator('[data-testid="final-status"]')).toBeVisible();
  });

  test('Ensure notifications are sent within SLA (boundary)', async ({ page }) => {
    const scheduleChanges: Array<{ id: string; timestamp: Date; deliveryTime?: Date }> = [];
    
    // Record the current system timestamp as test start time
    const testStartTime = new Date();
    
    await page.goto('/scheduling');
    await page.waitForSelector('[data-testid="schedule-list"]');
    
    // Update the first schedule entry and record the exact modification timestamp
    await page.click('[data-testid="schedule-entry-1"]');
    await page.click('[data-testid="edit-schedule-button"]');
    await page.fill('[data-testid="schedule-date-input"]', '2024-03-01');
    const timestamp1 = new Date();
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    scheduleChanges.push({ id: 'schedule-1', timestamp: timestamp1 });
    
    // Update the second schedule entry and record the exact modification timestamp
    await page.goto('/scheduling');
    await page.click('[data-testid="schedule-entry-2"]');
    await page.click('[data-testid="edit-schedule-button"]');
    await page.fill('[data-testid="schedule-date-input"]', '2024-03-02');
    const timestamp2 = new Date();
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    scheduleChanges.push({ id: 'schedule-2', timestamp: timestamp2 });
    
    // Update the third schedule entry and record the exact modification timestamp
    await page.goto('/scheduling');
    await page.click('[data-testid="schedule-entry-3"]');
    await page.click('[data-testid="edit-schedule-button"]');
    await page.fill('[data-testid="schedule-date-input"]', '2024-03-03');
    const timestamp3 = new Date();
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    scheduleChanges.push({ id: 'schedule-3', timestamp: timestamp3 });
    
    // Wait for notifications to be processed
    await page.waitForTimeout(6000);
    
    // Access system logs and filter for the test period
    await page.goto('/notifications/logs');
    await page.waitForSelector('[data-testid="notification-logs-table"]');
    
    // Filter logs by test period
    await page.fill('[data-testid="log-filter-start-time"]', testStartTime.toISOString());
    await page.click('[data-testid="apply-filter-button"]');
    await page.waitForSelector('[data-testid="log-entry"]');
    
    // Calculate the delivery time for each notification
    const logEntries = await page.locator('[data-testid="log-entry"]').all();
    
    for (let i = 0; i < Math.min(3, logEntries.length); i++) {
      const logEntry = logEntries[i];
      const deliveryTimeText = await logEntry.locator('[data-testid="delivery-timestamp"]').textContent();
      const deliveryTime = new Date(deliveryTimeText || '');
      
      const modificationTime = scheduleChanges[i].timestamp;
      const deliveryDuration = (deliveryTime.getTime() - modificationTime.getTime()) / 1000; // in seconds
      
      // Verify notification was delivered within 5 minutes (300 seconds)
      expect(deliveryDuration).toBeLessThanOrEqual(300);
      
      // Verify delivery status is successful
      await expect(logEntry.locator('[data-testid="delivery-status"]')).toContainText('Delivered');
    }
    
    // Review logs for any delays, errors, or warnings during the notification delivery process
    const errorLogs = page.locator('[data-testid="log-entry"][data-status="error"]');
    const errorCount = await errorLogs.count();
    expect(errorCount).toBe(0);
    
    const warningLogs = page.locator('[data-testid="log-entry"][data-status="warning"]');
    const warningCount = await warningLogs.count();
    
    // Generate performance report for the notification delivery times
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="performance-report"]');
    
    const avgDeliveryTime = await page.locator('[data-testid="avg-delivery-time"]').textContent();
    const maxDeliveryTime = await page.locator('[data-testid="max-delivery-time"]').textContent();
    const slaCompliance = await page.locator('[data-testid="sla-compliance-rate"]').textContent();
    
    expect(avgDeliveryTime).toBeTruthy();
    expect(maxDeliveryTime).toBeTruthy();
    expect(slaCompliance).toContain('100%');
  });
});