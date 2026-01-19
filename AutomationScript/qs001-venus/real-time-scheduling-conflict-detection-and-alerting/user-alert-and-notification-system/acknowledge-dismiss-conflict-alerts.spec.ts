import { test, expect } from '@playwright/test';

test.describe('Story-17: Acknowledge and Dismiss Conflict Alerts', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify user can acknowledge and dismiss conflict alerts (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the alerts section where conflict alerts are displayed
    await page.click('[data-testid="alerts-menu"]');
    await page.waitForSelector('[data-testid="alerts-section"]');
    
    // Step 2: Verify that the conflict alert is visible in the UI with all relevant details
    const conflictAlert = page.locator('[data-testid="conflict-alert"]').first();
    await expect(conflictAlert).toBeVisible();
    await expect(conflictAlert.locator('[data-testid="alert-resource"]')).toBeVisible();
    await expect(conflictAlert.locator('[data-testid="alert-time"]')).toBeVisible();
    await expect(conflictAlert.locator('[data-testid="alert-severity"]')).toBeVisible();
    
    // Step 3: Locate and click the 'Acknowledge' button on the conflict alert
    const acknowledgeButton = conflictAlert.locator('[data-testid="acknowledge-button"]');
    await expect(acknowledgeButton).toBeVisible();
    await acknowledgeButton.click();
    
    // Step 4: Verify the acknowledge action is reflected in the alert display
    await expect(conflictAlert.locator('[data-testid="alert-status"]')).toContainText('Acknowledged');
    await expect(conflictAlert).toHaveAttribute('data-acknowledged', 'true');
    
    // Step 5: Locate and click the 'Dismiss' button on the acknowledged alert
    const dismissButton = conflictAlert.locator('[data-testid="dismiss-button"]');
    await expect(dismissButton).toBeVisible();
    await dismissButton.click();
    
    // Step 6: Verify the alert is removed from UI
    await expect(conflictAlert).not.toBeVisible({ timeout: 2000 });
    
    // Step 7: Verify the dismissal action is logged by checking the audit log
    await page.click('[data-testid="audit-log-menu"]');
    await page.waitForSelector('[data-testid="audit-log-section"]');
    const latestLogEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(latestLogEntry).toContainText('Alert dismissed');
    await expect(latestLogEntry.locator('[data-testid="log-user"]')).toBeVisible();
    await expect(latestLogEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    
    // Step 8: Refresh the alerts page and verify alert persistence
    await page.click('[data-testid="alerts-menu"]');
    await page.reload();
    await page.waitForSelector('[data-testid="alerts-section"]');
    await expect(page.locator('[data-testid="conflict-alert"]').first()).not.toContainText('Acknowledged');
  });

  test('Ensure dismissed alerts do not reappear unless conflict persists (edge-case)', async ({ page }) => {
    // Step 1: Navigate to the alerts section and identify an active conflict alert
    await page.click('[data-testid="alerts-menu"]');
    await page.waitForSelector('[data-testid="alerts-section"]');
    const conflictAlert = page.locator('[data-testid="conflict-alert"]').first();
    await expect(conflictAlert).toBeVisible();
    
    // Capture alert details for later verification
    const alertId = await conflictAlert.getAttribute('data-alert-id');
    const alertResource = await conflictAlert.locator('[data-testid="alert-resource"]').textContent();
    
    // Step 2: Acknowledge the conflict alert by clicking the 'Acknowledge' button
    await conflictAlert.locator('[data-testid="acknowledge-button"]').click();
    await expect(conflictAlert.locator('[data-testid="alert-status"]')).toContainText('Acknowledged');
    
    // Step 3: Dismiss the alert by clicking the 'Dismiss' button
    await conflictAlert.locator('[data-testid="dismiss-button"]').click();
    await expect(conflictAlert).not.toBeVisible({ timeout: 2000 });
    
    // Step 4: Wait for 5 seconds without making any changes to the underlying conflict
    await page.waitForTimeout(5000);
    
    // Step 5: Refresh the alerts page
    await page.reload();
    await page.waitForSelector('[data-testid="alerts-section"]');
    
    // Step 6: Verify the alert remains dismissed
    const dismissedAlert = page.locator(`[data-testid="conflict-alert"][data-alert-id="${alertId}"]`);
    await expect(dismissedAlert).not.toBeVisible();
    
    // Check multiple times over a 2-minute period (checking every 30 seconds)
    for (let i = 0; i < 4; i++) {
      await page.waitForTimeout(30000);
      await page.reload();
      await page.waitForSelector('[data-testid="alerts-section"]');
      await expect(page.locator(`[data-testid="conflict-alert"][data-alert-id="${alertId}"]`)).not.toBeVisible();
    }
    
    // Step 7: Simulate a change in conflict status by resolving the underlying conflict
    await page.click('[data-testid="schedule-menu"]');
    await page.waitForSelector('[data-testid="schedule-section"]');
    const conflictingResource = page.locator(`[data-testid="resource-item"][data-resource-name="${alertResource}"]`);
    await conflictingResource.click();
    await page.click('[data-testid="resolve-conflict-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Conflict resolved');
    
    // Step 8: Recreate the same conflict condition that triggered the original alert
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-input"]', alertResource || '');
    await page.fill('[data-testid="start-time-input"]', '2024-01-15T10:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-15T11:00');
    await page.click('[data-testid="submit-booking-button"]');
    
    // Create overlapping booking to trigger conflict
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-input"]', alertResource || '');
    await page.fill('[data-testid="start-time-input"]', '2024-01-15T10:30');
    await page.fill('[data-testid="end-time-input"]', '2024-01-15T11:30');
    await page.click('[data-testid="submit-booking-button"]');
    
    // Step 9: Check the alerts dashboard for new alert generation
    await page.click('[data-testid="alerts-menu"]');
    await page.waitForSelector('[data-testid="alerts-section"]');
    const newAlert = page.locator('[data-testid="conflict-alert"]').first();
    await expect(newAlert).toBeVisible();
    
    // Step 10: Verify the new alert has a different alert ID and timestamp
    const newAlertId = await newAlert.getAttribute('data-alert-id');
    const newAlertTimestamp = await newAlert.locator('[data-testid="alert-timestamp"]').textContent();
    
    expect(newAlertId).not.toBe(alertId);
    expect(newAlertTimestamp).toBeTruthy();
    await expect(newAlert.locator('[data-testid="alert-resource"]')).toContainText(alertResource || '');
  });

  test('Verify user can acknowledge conflict alerts via the UI', async ({ page }) => {
    // Action: Scheduler receives conflict alert
    await page.click('[data-testid="alerts-menu"]');
    await page.waitForSelector('[data-testid="alerts-section"]');
    const conflictAlert = page.locator('[data-testid="conflict-alert"]').first();
    
    // Expected Result: Alert is displayed in UI
    await expect(conflictAlert).toBeVisible();
    await expect(conflictAlert.locator('[data-testid="alert-resource"]')).toBeVisible();
    
    // Action: Scheduler clicks acknowledge button
    const acknowledgeButton = conflictAlert.locator('[data-testid="acknowledge-button"]');
    await acknowledgeButton.click();
    
    // Expected Result: Alert is marked as acknowledged
    await expect(conflictAlert.locator('[data-testid="alert-status"]')).toContainText('Acknowledged');
    await expect(conflictAlert).toHaveAttribute('data-acknowledged', 'true');
  });

  test('Verify user can dismiss alerts and dismissed alerts are removed from interface', async ({ page }) => {
    // Setup: Navigate to alerts and acknowledge an alert
    await page.click('[data-testid="alerts-menu"]');
    await page.waitForSelector('[data-testid="alerts-section"]');
    const conflictAlert = page.locator('[data-testid="conflict-alert"]').first();
    await conflictAlert.locator('[data-testid="acknowledge-button"]').click();
    
    // Action: Scheduler dismisses the alert
    const dismissButton = conflictAlert.locator('[data-testid="dismiss-button"]');
    await dismissButton.click();
    
    // Expected Result: Alert is removed from UI and dismissal is logged
    await expect(conflictAlert).not.toBeVisible({ timeout: 2000 });
    
    // Verify dismissal is logged
    await page.click('[data-testid="audit-log-menu"]');
    await page.waitForSelector('[data-testid="audit-log-section"]');
    const latestLogEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(latestLogEntry).toContainText('Alert dismissed');
    await expect(latestLogEntry.locator('[data-testid="log-user"]')).toBeVisible();
    await expect(latestLogEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
  });

  test('Verify dismissed alerts do not reappear unless conflict persists', async ({ page }) => {
    // Action: Scheduler dismisses alert for a conflict
    await page.click('[data-testid="alerts-menu"]');
    await page.waitForSelector('[data-testid="alerts-section"]');
    const conflictAlert = page.locator('[data-testid="conflict-alert"]').first();
    const alertId = await conflictAlert.getAttribute('data-alert-id');
    
    await conflictAlert.locator('[data-testid="acknowledge-button"]').click();
    await conflictAlert.locator('[data-testid="dismiss-button"]').click();
    
    // Expected Result: Alert is removed
    await expect(conflictAlert).not.toBeVisible({ timeout: 2000 });
    
    // Action: No change in conflict status
    await page.waitForTimeout(3000);
    await page.reload();
    await page.waitForSelector('[data-testid="alerts-section"]');
    
    // Expected Result: Alert does not reappear
    await expect(page.locator(`[data-testid="conflict-alert"][data-alert-id="${alertId}"]`)).not.toBeVisible();
    
    // Action: Conflict status changes (resolved and reoccurs)
    // This would require system-level changes to simulate conflict reoccurrence
    // For automation purposes, we verify the system behavior when a new conflict is created
    await page.click('[data-testid="schedule-menu"]');
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="start-time-input"]', '2024-01-20T14:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-20T15:00');
    await page.click('[data-testid="submit-booking-button"]');
    
    // Create conflicting booking
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="start-time-input"]', '2024-01-20T14:30');
    await page.fill('[data-testid="end-time-input"]', '2024-01-20T15:30');
    await page.click('[data-testid="submit-booking-button"]');
    
    // Expected Result: New alert is generated and displayed
    await page.click('[data-testid="alerts-menu"]');
    await page.waitForSelector('[data-testid="alerts-section"]');
    const newAlert = page.locator('[data-testid="conflict-alert"]').first();
    await expect(newAlert).toBeVisible();
    
    const newAlertId = await newAlert.getAttribute('data-alert-id');
    expect(newAlertId).not.toBe(alertId);
  });
});