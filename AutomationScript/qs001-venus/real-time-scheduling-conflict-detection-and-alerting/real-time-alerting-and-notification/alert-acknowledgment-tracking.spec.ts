import { test, expect } from '@playwright/test';

test.describe('Alert Acknowledgment and Tracking', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate alert acknowledgment process (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the notification center or alert inbox where conflict alerts are displayed
    await page.click('[data-testid="notification-center-icon"]');
    await expect(page.locator('[data-testid="notification-center"]')).toBeVisible();
    
    // Verify alert is displayed to user
    const alertItem = page.locator('[data-testid="conflict-alert-item"]').first();
    await expect(alertItem).toBeVisible();
    const alertId = await alertItem.getAttribute('data-alert-id');
    
    // Step 2: Click on the alert to view full details
    await alertItem.click();
    await expect(page.locator('[data-testid="alert-details-panel"]')).toBeVisible();
    
    // Verify alert details are displayed
    await expect(page.locator('[data-testid="conflict-information"]')).toBeVisible();
    await expect(page.locator('[data-testid="affected-resources"]')).toBeVisible();
    await expect(page.locator('[data-testid="time-slots"]')).toBeVisible();
    
    // Step 3: Click the 'Acknowledge' button to acknowledge the alert
    const acknowledgeButton = page.locator('[data-testid="acknowledge-alert-button"]');
    await expect(acknowledgeButton).toBeEnabled();
    
    // Record the time before acknowledgment
    const acknowledgeTime = new Date();
    await acknowledgeButton.click();
    
    // Step 4: Observe the UI response after acknowledgment
    await expect(page.locator('[data-testid="acknowledgment-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="acknowledgment-success-message"]')).toContainText('Alert acknowledged successfully');
    
    // Verify acknowledgment status is updated in the UI
    await expect(page.locator('[data-testid="alert-status"]')).toContainText('Acknowledged');
    
    // Step 5: Navigate to the alert logs or audit trail section
    await page.click('[data-testid="alert-logs-link"]');
    await expect(page).toHaveURL(/.*alert-logs/);
    
    // Step 6: Search for the acknowledged alert by alert ID
    await page.fill('[data-testid="alert-search-input"]', alertId);
    await page.click('[data-testid="search-button"]');
    
    // Verify acknowledgment status in alert logs
    const logEntry = page.locator(`[data-testid="alert-log-entry"][data-alert-id="${alertId}"]`);
    await expect(logEntry).toBeVisible();
    
    // Verify status shows acknowledged with correct user and time
    await expect(logEntry.locator('[data-testid="log-status"]')).toContainText('Acknowledged');
    await expect(logEntry.locator('[data-testid="acknowledged-by"]')).toContainText('scheduler@example.com');
    
    // Verify the acknowledgment timestamp is within acceptable range (within 5 seconds)
    const timestampText = await logEntry.locator('[data-testid="acknowledgment-timestamp"]').textContent();
    const loggedTime = new Date(timestampText);
    const timeDifference = Math.abs(loggedTime.getTime() - acknowledgeTime.getTime());
    expect(timeDifference).toBeLessThan(5000);
  });

  test('Verify reminder notifications for unacknowledged alerts (happy-path)', async ({ page }) => {
    // Step 1: Generate a new conflict alert by creating a scheduling conflict
    await page.click('[data-testid="scheduling-menu"]');
    await page.click('[data-testid="create-schedule-button"]');
    
    // Create a scheduling conflict
    await page.fill('[data-testid="resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="start-time-input"]', '2024-01-15T10:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-15T11:00');
    await page.click('[data-testid="submit-schedule-button"]');
    
    // Create conflicting schedule
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="start-time-input"]', '2024-01-15T10:30');
    await page.fill('[data-testid="end-time-input"]', '2024-01-15T11:30');
    await page.click('[data-testid="submit-schedule-button"]');
    
    // Step 2: Verify the alert appears in the notification interface
    await page.click('[data-testid="notification-center-icon"]');
    const newAlert = page.locator('[data-testid="conflict-alert-item"]').first();
    await expect(newAlert).toBeVisible();
    
    // Note the delivery timestamp
    const deliveryTimestamp = await newAlert.locator('[data-testid="alert-timestamp"]').textContent();
    const alertId = await newAlert.getAttribute('data-alert-id');
    expect(deliveryTimestamp).toBeTruthy();
    
    // Step 3: Do not acknowledge the alert and wait for the configured reminder interval
    // Close notification center without acknowledging
    await page.click('[data-testid="close-notification-center"]');
    
    // Wait for the configured reminder interval (simulated with shorter wait for testing)
    // In production, this would be 30 minutes; for testing, we use API to trigger reminder
    await page.request.post(`/api/alerts/${alertId}/trigger-reminder`);
    
    // Step 4: After the reminder interval has elapsed, check for reminder notification
    await page.click('[data-testid="notification-center-icon"]');
    const reminderNotification = page.locator('[data-testid="reminder-notification"]').filter({ hasText: alertId });
    await expect(reminderNotification).toBeVisible();
    
    // Step 5: Verify the reminder notification content and metadata
    await expect(reminderNotification).toContainText('Reminder');
    await expect(reminderNotification).toContainText('unacknowledged');
    await expect(reminderNotification.locator('[data-testid="reminder-alert-id"]')).toContainText(alertId);
    
    // Step 6: Open the alert from the reminder notification and click 'Acknowledge'
    await reminderNotification.click();
    await expect(page.locator('[data-testid="alert-details-panel"]')).toBeVisible();
    
    const acknowledgeButton = page.locator('[data-testid="acknowledge-alert-button"]');
    await acknowledgeButton.click();
    
    // Verify acknowledgment recorded
    await expect(page.locator('[data-testid="acknowledgment-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-status"]')).toContainText('Acknowledged');
    
    // Step 7: Wait for another reminder interval period to verify reminders have stopped
    await page.click('[data-testid="close-alert-details"]');
    
    // Trigger another reminder check (should not send reminder for acknowledged alert)
    await page.request.post(`/api/alerts/${alertId}/trigger-reminder`);
    
    // Verify no new reminder notification appears
    await page.reload();
    await page.click('[data-testid="notification-center-icon"]');
    const newReminderCount = await page.locator('[data-testid="reminder-notification"]').filter({ hasText: alertId }).count();
    expect(newReminderCount).toBe(0);
    
    // Step 8: Check the alert logs to verify reminder delivery and acknowledgment sequence
    await page.click('[data-testid="alert-logs-link"]');
    await page.fill('[data-testid="alert-search-input"]', alertId);
    await page.click('[data-testid="search-button"]');
    
    const logEntry = page.locator(`[data-testid="alert-log-entry"][data-alert-id="${alertId}"]`);
    await expect(logEntry).toBeVisible();
    
    // Verify reminder delivery in logs
    const activityLog = logEntry.locator('[data-testid="activity-log"]');
    await expect(activityLog).toContainText('Reminder sent');
    await expect(activityLog).toContainText('Acknowledged');
    
    // Verify acknowledgment is the last action
    const lastActivity = activityLog.locator('[data-testid="activity-item"]').last();
    await expect(lastActivity).toContainText('Acknowledged');
  });

  test('Validate alert acknowledgment process - automated test case #1', async ({ page }) => {
    // Action: Receive conflict alert
    await page.goto('/notifications');
    const conflictAlert = page.locator('[data-testid="conflict-alert"]').first();
    
    // Expected Result: Alert is displayed to user
    await expect(conflictAlert).toBeVisible();
    const alertId = await conflictAlert.getAttribute('data-alert-id');
    
    // Action: User acknowledges alert
    await conflictAlert.click();
    const acknowledgeBtn = page.locator('[data-testid="acknowledge-button"]');
    await acknowledgeBtn.click();
    
    // Expected Result: Acknowledgment is recorded with timestamp
    await expect(page.locator('[data-testid="acknowledgment-confirmation"]')).toBeVisible();
    const acknowledgmentTime = await page.locator('[data-testid="acknowledgment-time"]').textContent();
    expect(acknowledgmentTime).toBeTruthy();
    
    // Action: Verify acknowledgment status in alert logs
    await page.goto('/alert-logs');
    await page.fill('[data-testid="log-search"]', alertId);
    await page.click('[data-testid="search-submit"]');
    
    const logRecord = page.locator(`[data-testid="log-record-${alertId}"]`);
    await expect(logRecord).toBeVisible();
    
    // Expected Result: Status shows acknowledged with correct user and time
    await expect(logRecord.locator('[data-testid="status"]')).toHaveText('Acknowledged');
    await expect(logRecord.locator('[data-testid="acknowledged-user"]')).toContainText('scheduler@example.com');
    await expect(logRecord.locator('[data-testid="acknowledged-time"]')).toBeVisible();
  });

  test('Verify reminder notifications for unacknowledged alerts - automated test case #2', async ({ page }) => {
    // Action: Generate alert without acknowledgment
    await page.goto('/scheduling');
    
    // Create conflict to generate alert
    await page.click('[data-testid="new-schedule"]');
    await page.fill('[data-testid="resource-name"]', 'Meeting Room B');
    await page.fill('[data-testid="schedule-start"]', '2024-02-01T14:00');
    await page.fill('[data-testid="schedule-end"]', '2024-02-01T15:00');
    await page.click('[data-testid="save-schedule"]');
    
    // Create overlapping schedule
    await page.click('[data-testid="new-schedule"]');
    await page.fill('[data-testid="resource-name"]', 'Meeting Room B');
    await page.fill('[data-testid="schedule-start"]', '2024-02-01T14:30');
    await page.fill('[data-testid="schedule-end"]', '2024-02-01T15:30');
    await page.click('[data-testid="save-schedule"]');
    
    // Expected Result: Alert remains unacknowledged
    await page.goto('/notifications');
    const unacknowledgedAlert = page.locator('[data-testid="unacknowledged-alert"]').first();
    await expect(unacknowledgedAlert).toBeVisible();
    const alertId = await unacknowledgedAlert.getAttribute('data-alert-id');
    
    // Action: Wait configured reminder interval (simulated via API)
    await page.request.post(`/api/alerts/${alertId}/simulate-reminder-interval`);
    
    // Expected Result: System sends reminder notification
    await page.reload();
    const reminderBadge = page.locator('[data-testid="reminder-badge"]');
    await expect(reminderBadge).toBeVisible();
    
    await page.click('[data-testid="notifications-icon"]');
    const reminderAlert = page.locator('[data-testid="reminder-alert"]').filter({ hasText: alertId });
    await expect(reminderAlert).toBeVisible();
    await expect(reminderAlert).toContainText('Reminder');
    
    // Action: User acknowledges alert after reminder
    await reminderAlert.click();
    await page.click('[data-testid="acknowledge-button"]');
    
    // Expected Result: Acknowledgment recorded and reminders stop
    await expect(page.locator('[data-testid="acknowledgment-success"]')).toBeVisible();
    
    // Verify reminders stop by checking no new reminders are generated
    await page.request.post(`/api/alerts/${alertId}/simulate-reminder-interval`);
    await page.reload();
    
    const newReminders = await page.locator('[data-testid="reminder-alert"]').filter({ hasText: alertId }).count();
    expect(newReminders).toBe(0);
  });
});