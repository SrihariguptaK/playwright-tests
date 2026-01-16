import { test, expect } from '@playwright/test';

test.describe('Scheduling Conflict Alerts', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling application
    await page.goto('/scheduler');
    // Wait for the page to be fully loaded
    await page.waitForLoadState('networkidle');
  });

  test('Receive in-app alert on conflict detection (happy-path)', async ({ page }) => {
    // Step 1: Create or modify a schedule entry that conflicts with an existing entry
    // First, create an initial schedule entry
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-input"]', 'Resource-A');
    await page.fill('[data-testid="start-time-input"]', '2024-01-15T09:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-15T11:00');
    await page.fill('[data-testid="task-name-input"]', 'Task 1');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Wait for the first entry to be saved
    await expect(page.locator('[data-testid="schedule-entry"]').filter({ hasText: 'Task 1' })).toBeVisible();
    
    // Create a conflicting schedule entry with same resource and overlapping time
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-input"]', 'Resource-A');
    await page.fill('[data-testid="start-time-input"]', '2024-01-15T10:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-15T12:00');
    await page.fill('[data-testid="task-name-input"]', 'Task 2');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: In-app alert is generated and displayed to the user within 1 second
    const alertNotification = page.locator('[data-testid="alert-notification"]');
    await expect(alertNotification).toBeVisible({ timeout: 1000 });
    await expect(alertNotification).toContainText('conflict', { ignoreCase: true });
    
    // Step 2: User views alert details
    await page.click('[data-testid="alert-notification"]');
    
    // Expected Result: Alert shows detailed conflict information
    const alertDetails = page.locator('[data-testid="alert-details-modal"]');
    await expect(alertDetails).toBeVisible();
    await expect(alertDetails).toContainText('Resource-A');
    await expect(alertDetails).toContainText('Task 1');
    await expect(alertDetails).toContainText('Task 2');
    await expect(alertDetails).toContainText('09:00');
    await expect(alertDetails).toContainText('10:00');
    
    // Step 3: User acknowledges and dismisses alert
    const acknowledgeButton = page.locator('[data-testid="acknowledge-alert-button"]');
    await expect(acknowledgeButton).toBeVisible();
    await acknowledgeButton.click();
    
    // Expected Result: Alert is removed from active notifications
    await expect(alertNotification).not.toBeVisible({ timeout: 2000 });
    
    // Verify alert is in dismissed/history section
    await page.click('[data-testid="notification-history-button"]');
    const dismissedAlerts = page.locator('[data-testid="dismissed-alerts-section"]');
    await expect(dismissedAlerts).toBeVisible();
    await expect(dismissedAlerts.locator('[data-testid="alert-item"]').first()).toContainText('Resource-A');
  });

  test('Alert delivery performance test (boundary)', async ({ page }) => {
    // Step 1: Prepare test data with 5-10 schedule entries that will create simultaneous conflicts
    const baseSchedules = [
      { resource: 'Resource-1', startTime: '2024-01-20T09:00', endTime: '2024-01-20T11:00', task: 'Base Task 1' },
      { resource: 'Resource-2', startTime: '2024-01-20T10:00', endTime: '2024-01-20T12:00', task: 'Base Task 2' },
      { resource: 'Resource-3', startTime: '2024-01-20T13:00', endTime: '2024-01-20T15:00', task: 'Base Task 3' },
      { resource: 'Resource-4', startTime: '2024-01-20T14:00', endTime: '2024-01-20T16:00', task: 'Base Task 4' },
      { resource: 'Resource-5', startTime: '2024-01-20T15:00', endTime: '2024-01-20T17:00', task: 'Base Task 5' }
    ];
    
    // Create base schedule entries
    for (const schedule of baseSchedules) {
      await page.click('[data-testid="create-schedule-button"]');
      await page.fill('[data-testid="resource-input"]', schedule.resource);
      await page.fill('[data-testid="start-time-input"]', schedule.startTime);
      await page.fill('[data-testid="end-time-input"]', schedule.endTime);
      await page.fill('[data-testid="task-name-input"]', schedule.task);
      await page.click('[data-testid="save-schedule-button"]');
      await page.waitForTimeout(200);
    }
    
    // Clear any existing notifications
    const existingAlerts = page.locator('[data-testid="alert-notification"]');
    const alertCount = await existingAlerts.count();
    if (alertCount > 0) {
      await page.click('[data-testid="clear-all-alerts-button"]');
    }
    
    // Step 2: Start performance monitoring timer
    const conflictingSchedules = [
      { resource: 'Resource-1', startTime: '2024-01-20T10:00', endTime: '2024-01-20T12:00', task: 'Conflict Task 1' },
      { resource: 'Resource-2', startTime: '2024-01-20T11:00', endTime: '2024-01-20T13:00', task: 'Conflict Task 2' },
      { resource: 'Resource-3', startTime: '2024-01-20T14:00', endTime: '2024-01-20T16:00', task: 'Conflict Task 3' },
      { resource: 'Resource-4', startTime: '2024-01-20T15:00', endTime: '2024-01-20T17:00', task: 'Conflict Task 4' },
      { resource: 'Resource-5', startTime: '2024-01-20T16:00', endTime: '2024-01-20T18:00', task: 'Conflict Task 5' }
    ];
    
    // Step 3: Trigger multiple conflicts simultaneously by batch updating
    await page.click('[data-testid="batch-create-button"]');
    
    const startTime = Date.now();
    
    // Fill batch create form with conflicting entries
    for (let i = 0; i < conflictingSchedules.length; i++) {
      const schedule = conflictingSchedules[i];
      await page.fill(`[data-testid="batch-resource-${i}"]`, schedule.resource);
      await page.fill(`[data-testid="batch-start-time-${i}"]`, schedule.startTime);
      await page.fill(`[data-testid="batch-end-time-${i}"]`, schedule.endTime);
      await page.fill(`[data-testid="batch-task-name-${i}"]`, schedule.task);
    }
    
    await page.click('[data-testid="batch-save-button"]');
    
    // Step 4: Observe and record the time taken for each alert to appear
    const alertNotifications = page.locator('[data-testid="alert-notification"]');
    
    // Wait for alerts to appear and measure time
    await expect(alertNotifications.first()).toBeVisible({ timeout: 1000 });
    const firstAlertTime = Date.now() - startTime;
    
    // Step 5: Verify the timestamp difference between conflict creation and alert display
    // Expected Result: All alerts are delivered within 1 second
    expect(firstAlertTime).toBeLessThanOrEqual(1000);
    
    // Wait for all alerts to be delivered
    await page.waitForTimeout(1000);
    const finalAlertTime = Date.now() - startTime;
    
    // Step 6: Count the total number of alerts displayed
    const totalAlerts = await alertNotifications.count();
    
    // Expected Result: Number of alerts matches number of conflicts created
    expect(totalAlerts).toBe(conflictingSchedules.length);
    
    // Verify all alerts were delivered within 1 second
    expect(finalAlertTime).toBeLessThanOrEqual(1000);
    
    // Step 7: Review system logs or monitoring dashboard for alert generation metrics
    // Verify each alert contains conflict information
    for (let i = 0; i < totalAlerts; i++) {
      const alert = alertNotifications.nth(i);
      await expect(alert).toBeVisible();
      await expect(alert).toContainText('conflict', { ignoreCase: true });
    }
    
    // Verify alert acknowledgment tracking
    await page.click('[data-testid="system-metrics-button"]');
    const metricsPanel = page.locator('[data-testid="metrics-panel"]');
    await expect(metricsPanel).toBeVisible();
    await expect(metricsPanel.locator('[data-testid="alert-delivery-latency"]')).toContainText('ms');
    
    const latencyText = await metricsPanel.locator('[data-testid="alert-delivery-latency"]').textContent();
    const latencyValue = parseInt(latencyText?.match(/\d+/)?.[0] || '0');
    expect(latencyValue).toBeLessThanOrEqual(1000);
  });
});