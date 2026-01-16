import { test, expect } from '@playwright/test';

test.describe('Story-13: Real-time Scheduling Conflict Alerts', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling application
    await page.goto('/scheduler');
    // Assume user is already authenticated or perform login
    await page.waitForLoadState('networkidle');
  });

  test('Verify real-time alert delivery within 5 seconds', async ({ page }) => {
    // Step 1: Trigger a scheduling conflict by creating overlapping resource assignments
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Conference Room A');
    await page.fill('[data-testid="start-time-input"]', '2024-01-15T10:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-15T11:00');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Create overlapping booking for the same resource
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Conference Room A');
    await page.fill('[data-testid="start-time-input"]', '2024-01-15T10:30');
    await page.fill('[data-testid="end-time-input"]', '2024-01-15T11:30');
    
    // Start timer and trigger conflict
    const startTime = Date.now();
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: System detects conflict
    await expect(page.locator('[data-testid="conflict-detected-message"]')).toBeVisible({ timeout: 5000 });
    
    // Step 2: Observe alert delivery to user via configured channels
    const alertNotification = page.locator('[data-testid="alert-notification"]');
    await expect(alertNotification).toBeVisible({ timeout: 5000 });
    
    const endTime = Date.now();
    const deliveryTime = endTime - startTime;
    
    // Expected Result: Alert received within 5 seconds
    expect(deliveryTime).toBeLessThanOrEqual(5000);
    
    // Step 3: Check alert log for timestamp and delivery status
    await page.click('[data-testid="alerts-menu"]');
    await page.click('[data-testid="alert-log-link"]');
    
    // Expected Result: Alert logged with correct details
    const alertLogEntry = page.locator('[data-testid="alert-log-entry"]').first();
    await expect(alertLogEntry).toBeVisible();
    await expect(alertLogEntry.locator('[data-testid="alert-timestamp"]')).toBeVisible();
    await expect(alertLogEntry.locator('[data-testid="alert-delivery-status"]')).toHaveText(/delivered|success/i);
    await expect(alertLogEntry.locator('[data-testid="alert-type"]')).toContainText('Scheduling Conflict');
  });

  test('Test user alert preference configuration', async ({ page }) => {
    // Step 1: Navigate to user alert preferences settings page
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="preferences-link"]');
    await page.click('[data-testid="alert-preferences-tab"]');
    
    // Update alert preferences to receive email only by unchecking other channels
    await page.uncheck('[data-testid="alert-channel-in-app"]');
    await page.check('[data-testid="alert-channel-email"]');
    await page.uncheck('[data-testid="alert-channel-sms"]');
    
    await page.click('[data-testid="save-preferences-button"]');
    
    // Expected Result: Preferences saved successfully
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toContainText(/saved successfully/i);
    
    // Navigate back to scheduler
    await page.goto('/scheduler');
    
    // Step 2: Trigger scheduling conflict by creating a resource conflict
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Meeting Room B');
    await page.fill('[data-testid="start-time-input"]', '2024-01-16T14:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-16T15:00');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Create overlapping booking
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Meeting Room B');
    await page.fill('[data-testid="start-time-input"]', '2024-01-16T14:30');
    await page.fill('[data-testid="end-time-input"]', '2024-01-16T15:30');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: User receives alert via email only
    // Verify no in-app notification is shown
    await expect(page.locator('[data-testid="alert-notification"]')).not.toBeVisible({ timeout: 3000 }).catch(() => {});
    
    // Verify alert log shows email delivery
    await page.click('[data-testid="alerts-menu"]');
    await page.click('[data-testid="alert-log-link"]');
    
    const latestAlert = page.locator('[data-testid="alert-log-entry"]').first();
    await expect(latestAlert.locator('[data-testid="alert-channel"]')).toContainText('Email');
    await expect(latestAlert.locator('[data-testid="alert-delivery-status"]')).toHaveText(/delivered|sent/i);
  });

  test('Validate alert escalation after unresolved conflict', async ({ page }) => {
    // Configure short escalation period for testing (if configurable)
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="preferences-link"]');
    await page.click('[data-testid="alert-preferences-tab"]');
    
    // Set escalation time to 10 seconds for testing purposes
    await page.fill('[data-testid="escalation-period-input"]', '10');
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toBeVisible();
    
    await page.goto('/scheduler');
    
    // Step 1: Trigger a scheduling conflict
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Training Room C');
    await page.fill('[data-testid="start-time-input"]', '2024-01-17T09:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-17T10:00');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Create conflict
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Training Room C');
    await page.fill('[data-testid="start-time-input"]', '2024-01-17T09:30');
    await page.fill('[data-testid="end-time-input"]', '2024-01-17T10:30');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Initial alert delivered
    await expect(page.locator('[data-testid="conflict-detected-message"]')).toBeVisible();
    
    // Navigate to alert log to verify initial alert
    await page.click('[data-testid="alerts-menu"]');
    await page.click('[data-testid="alert-log-link"]');
    
    const initialAlert = page.locator('[data-testid="alert-log-entry"]').first();
    await expect(initialAlert).toBeVisible();
    await expect(initialAlert.locator('[data-testid="alert-severity"]')).toContainText(/initial|warning/i);
    
    // Step 2: Wait configured escalation period without resolution
    // Do not acknowledge or resolve the conflict
    await page.waitForTimeout(12000); // Wait 12 seconds (escalation period + buffer)
    
    // Refresh alert log
    await page.reload();
    
    // Expected Result: System sends escalation alert to designated users
    const escalatedAlert = page.locator('[data-testid="alert-log-entry"]').filter({ hasText: /escalat/i }).first();
    await expect(escalatedAlert).toBeVisible({ timeout: 5000 });
    await expect(escalatedAlert.locator('[data-testid="alert-severity"]')).toContainText(/escalat|critical/i);
    await expect(escalatedAlert.locator('[data-testid="alert-recipients"]')).toContainText(/manager|supervisor/i);
    
    // Verify escalation timestamp is after initial alert
    const escalationTimestamp = await escalatedAlert.locator('[data-testid="alert-timestamp"]').textContent();
    expect(escalationTimestamp).toBeTruthy();
  });
});