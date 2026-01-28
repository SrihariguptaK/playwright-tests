import { test, expect } from '@playwright/test';

test.describe('Story-6: Scheduling Conflict Alerts', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling application
    await page.goto('/scheduling');
    // Authenticate user
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
  });

  test('Validate alert delivery for detected conflicts', async ({ page }) => {
    // Step 1: Create or modify a schedule entry that conflicts with an existing schedule
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="schedule-resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="schedule-date-input"]', '2024-02-15');
    await page.fill('[data-testid="schedule-start-time-input"]', '10:00');
    await page.fill('[data-testid="schedule-end-time-input"]', '11:00');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Create conflicting schedule entry
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="schedule-resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="schedule-date-input"]', '2024-02-15');
    await page.fill('[data-testid="schedule-start-time-input"]', '10:30');
    await page.fill('[data-testid="schedule-end-time-input"]', '11:30');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Alert notification is prepared and dispatched
    const conflictDetectionTime = Date.now();
    
    // Step 2: System sends the alert to the user
    // Wait for alert to be dispatched (max 5 seconds as per requirements)
    await page.waitForSelector('[data-testid="alert-notification"]', { timeout: 5000 });
    
    // Step 3: User checks for received alerts
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-center"]')).toBeVisible();
    
    // Expected Result: User receives the alert with conflict details
    const alertNotification = page.locator('[data-testid="alert-notification"]').first();
    await expect(alertNotification).toBeVisible();
    await expect(alertNotification).toContainText('Scheduling Conflict');
    await expect(alertNotification).toContainText('Conference Room A');
    await expect(alertNotification).toContainText('2024-02-15');
    await expect(alertNotification).toContainText('10:30');
    
    // Verify the timestamp of alert delivery against the conflict detection time
    const alertTimestamp = await alertNotification.locator('[data-testid="alert-timestamp"]').textContent();
    const alertTime = new Date(alertTimestamp || '').getTime();
    const deliveryTime = alertTime - conflictDetectionTime;
    expect(deliveryTime).toBeLessThanOrEqual(5000);
  });

  test('Ensure alerts contain actionable insights', async ({ page }) => {
    // Step 1: System detects a scheduling conflict and triggers the alert generation process
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="schedule-resource-input"]', 'Meeting Room B');
    await page.fill('[data-testid="schedule-date-input"]', '2024-02-16');
    await page.fill('[data-testid="schedule-start-time-input"]', '14:00');
    await page.fill('[data-testid="schedule-end-time-input"]', '15:00');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Create conflicting entry
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="schedule-resource-input"]', 'Meeting Room B');
    await page.fill('[data-testid="schedule-date-input"]', '2024-02-16');
    await page.fill('[data-testid="schedule-start-time-input"]', '14:30');
    await page.fill('[data-testid="schedule-end-time-input"]', '15:30');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Step 2: System sends an alert notification for the scheduling conflict
    await page.waitForSelector('[data-testid="alert-notification"]', { timeout: 5000 });
    
    // Expected Result: Alert is dispatched
    await expect(page.locator('[data-testid="alert-notification"]')).toBeVisible();
    
    // Step 3: User receives and opens the alert notification
    await page.click('[data-testid="notifications-icon"]');
    const alertNotification = page.locator('[data-testid="alert-notification"]').first();
    await alertNotification.click();
    
    // Step 4: User reviews the alert content for conflict details
    const alertDetails = page.locator('[data-testid="alert-details-modal"]');
    await expect(alertDetails).toBeVisible();
    
    // Expected Result: Alert includes details and suggested actions
    await expect(alertDetails.locator('[data-testid="conflict-resource"]')).toContainText('Meeting Room B');
    await expect(alertDetails.locator('[data-testid="conflict-date"]')).toContainText('2024-02-16');
    await expect(alertDetails.locator('[data-testid="conflict-time"]')).toContainText('14:30');
    
    // Step 5: User examines the actionable insights section of the alert
    const actionableInsights = alertDetails.locator('[data-testid="actionable-insights-section"]');
    await expect(actionableInsights).toBeVisible();
    await expect(actionableInsights).toContainText('Suggested Actions');
    
    // Verify suggested actions are present
    const rescheduleAction = actionableInsights.locator('[data-testid="action-reschedule"]');
    const reassignAction = actionableInsights.locator('[data-testid="action-reassign"]');
    const cancelAction = actionableInsights.locator('[data-testid="action-cancel"]');
    
    await expect(rescheduleAction).toBeVisible();
    await expect(reassignAction).toBeVisible();
    await expect(cancelAction).toBeVisible();
    
    // Step 6: User selects one of the suggested actions from the alert
    await rescheduleAction.click();
    
    // Expected Result: User is navigated to the scheduling interface
    await expect(page.locator('[data-testid="reschedule-modal"]')).toBeVisible();
    
    // Step 7: User implements the suggested action to resolve the conflict
    await page.fill('[data-testid="reschedule-start-time-input"]', '15:30');
    await page.fill('[data-testid="reschedule-end-time-input"]', '16:30');
    await page.click('[data-testid="confirm-reschedule-button"]');
    
    // Step 8: System validates that the conflict has been resolved
    // Expected Result: User successfully resolves the conflict
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Conflict resolved successfully');
    
    // Verify no conflict alerts remain for this schedule
    await page.click('[data-testid="notifications-icon"]');
    const remainingConflicts = page.locator('[data-testid="alert-notification"]:has-text("Meeting Room B")');
    await expect(remainingConflicts).toHaveCount(0);
  });

  test('Validate alert delivery for detected conflicts - email channel', async ({ page }) => {
    // Step 1: Create conflicting schedule entry
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="schedule-resource-input"]', 'Lab Equipment 1');
    await page.fill('[data-testid="schedule-date-input"]', '2024-02-17');
    await page.fill('[data-testid="schedule-start-time-input"]', '09:00');
    await page.fill('[data-testid="schedule-end-time-input"]', '10:00');
    await page.click('[data-testid="save-schedule-button"]');
    
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="schedule-resource-input"]', 'Lab Equipment 1');
    await page.fill('[data-testid="schedule-date-input"]', '2024-02-17');
    await page.fill('[data-testid="schedule-start-time-input"]', '09:30');
    await page.fill('[data-testid="schedule-end-time-input"]', '10:30');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Alert notification is prepared
    await page.waitForSelector('[data-testid="alert-notification"]', { timeout: 5000 });
    
    // Step 2: System sends the alert to the user
    // Check email notification was sent
    await page.goto('/notifications/history');
    const emailNotification = page.locator('[data-testid="notification-history-item"]').filter({ hasText: 'Email' }).first();
    await expect(emailNotification).toBeVisible();
    await expect(emailNotification).toContainText('Lab Equipment 1');
    await expect(emailNotification).toContainText('Delivered');
    
    // Step 3: User checks for received alerts
    await page.click('[data-testid="notifications-icon"]');
    
    // Expected Result: User receives the alert with conflict details
    const inAppAlert = page.locator('[data-testid="alert-notification"]').filter({ hasText: 'Lab Equipment 1' });
    await expect(inAppAlert).toBeVisible();
    await expect(inAppAlert).toContainText('Scheduling Conflict');
    await expect(inAppAlert).toContainText('09:30');
  });

  test('Validate user can customize alert preferences', async ({ page }) => {
    // Navigate to alert preferences
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="settings-menu-item"]');
    await page.click('[data-testid="notifications-settings-tab"]');
    
    // Verify alert preference options are available
    await expect(page.locator('[data-testid="alert-preferences-section"]')).toBeVisible();
    
    // Customize alert channels
    const emailAlertToggle = page.locator('[data-testid="email-alert-toggle"]');
    const smsAlertToggle = page.locator('[data-testid="sms-alert-toggle"]');
    const inAppAlertToggle = page.locator('[data-testid="inapp-alert-toggle"]');
    
    await expect(emailAlertToggle).toBeVisible();
    await expect(smsAlertToggle).toBeVisible();
    await expect(inAppAlertToggle).toBeVisible();
    
    // Enable email alerts
    await emailAlertToggle.check();
    await expect(emailAlertToggle).toBeChecked();
    
    // Save preferences
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toBeVisible();
    
    // Verify preferences are persisted
    await page.reload();
    await expect(emailAlertToggle).toBeChecked();
  });
});