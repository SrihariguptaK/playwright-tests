import { test, expect } from '@playwright/test';

test.describe('Real-time Scheduling Conflict Alerts', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling application
    await page.goto('/scheduler');
    // Login as scheduler user
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
  });

  test('Validate real-time alert delivery upon conflict detection', async ({ page }) => {
    // Step 1: Create a scheduling conflict by assigning the same resource to two overlapping time slots
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="start-time-input"]', '2024-01-15T10:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-15T12:00');
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Create overlapping schedule with same resource
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="start-time-input"]', '2024-01-15T11:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-15T13:00');
    
    // Start timer to measure alert delivery time
    const startTime = Date.now();
    await page.click('[data-testid="save-schedule-button"]');

    // Step 2: Observe alert dispatch - Alert is sent within 2 seconds via configured channels
    const alertNotification = page.locator('[data-testid="alert-notification"]');
    await expect(alertNotification).toBeVisible({ timeout: 2000 });
    const endTime = Date.now();
    const alertDeliveryTime = endTime - startTime;
    
    // Verify alert was delivered within 2 seconds
    expect(alertDeliveryTime).toBeLessThan(2000);

    // Step 3: User receives alert - Alert contains detailed conflict information
    const alertTitle = page.locator('[data-testid="alert-title"]');
    await expect(alertTitle).toContainText('Scheduling Conflict Detected');
    
    const alertDetails = page.locator('[data-testid="alert-details"]');
    await expect(alertDetails).toContainText('Conference Room A');
    await expect(alertDetails).toContainText('2024-01-15');
    await expect(alertDetails).toContainText('11:00');
    
    // Verify conflict information is present
    const conflictInfo = page.locator('[data-testid="conflict-info"]');
    await expect(conflictInfo).toBeVisible();
    await expect(conflictInfo).toContainText('overlapping');
  });

  test('Verify user alert preference configuration', async ({ page }) => {
    // Step 1: User accesses alert settings UI - Settings page is displayed
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="settings-link"]');
    await page.click('[data-testid="alert-preferences-tab"]');
    
    const settingsPage = page.locator('[data-testid="alert-settings-page"]');
    await expect(settingsPage).toBeVisible();
    await expect(page.locator('[data-testid="notification-settings-header"]')).toContainText('Alert Preferences');

    // Step 2: User selects preferred notification channels - Preferences are saved successfully
    await page.check('[data-testid="in-app-notification-checkbox"]');
    await page.check('[data-testid="email-notification-checkbox"]');
    await page.check('[data-testid="sms-notification-checkbox"]');
    
    // Configure additional settings
    await page.selectOption('[data-testid="alert-frequency-select"]', 'immediate');
    await page.fill('[data-testid="quiet-hours-start"]', '22:00');
    await page.fill('[data-testid="quiet-hours-end"]', '08:00');
    await page.selectOption('[data-testid="priority-level-select"]', 'high');
    
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toContainText('Preferences saved successfully');

    // Step 3: Trigger conflict alert - Alert is sent via user-selected channels
    await page.goto('/scheduler');
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-input"]', 'Meeting Room B');
    await page.fill('[data-testid="start-time-input"]', '2024-01-16T14:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-16T16:00');
    await page.click('[data-testid="save-schedule-button"]');

    // Create conflict
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-input"]', 'Meeting Room B');
    await page.fill('[data-testid="start-time-input"]', '2024-01-16T15:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-16T17:00');
    await page.click('[data-testid="save-schedule-button"]');

    // Verify in-app alert
    await expect(page.locator('[data-testid="alert-notification"]')).toBeVisible();
    
    // Verify alert channels indicator
    const alertChannels = page.locator('[data-testid="alert-channels-indicator"]');
    await expect(alertChannels).toContainText('in-app');
    await expect(alertChannels).toContainText('email');
    await expect(alertChannels).toContainText('sms');
  });

  test('Ensure alert delivery logging and acknowledgment tracking', async ({ page }) => {
    // Step 1: Trigger a scheduling conflict to generate an alert
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-input"]', 'Training Room C');
    await page.fill('[data-testid="start-time-input"]', '2024-01-17T09:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-17T11:00');
    await page.click('[data-testid="save-schedule-button"]');

    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-input"]', 'Training Room C');
    await page.fill('[data-testid="start-time-input"]', '2024-01-17T10:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-17T12:00');
    await page.click('[data-testid="save-schedule-button"]');

    // Wait for alert to be generated
    await expect(page.locator('[data-testid="alert-notification"]')).toBeVisible();

    // Step 2: Query the alert delivery logs - Alert delivery is logged in system
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="alert-logs-link"]');
    
    const alertLogViewer = page.locator('[data-testid="alert-log-viewer"]');
    await expect(alertLogViewer).toBeVisible();
    
    const latestAlertLog = page.locator('[data-testid="alert-log-entry"]').first();
    await expect(latestAlertLog).toBeVisible();
    await expect(latestAlertLog).toContainText('Training Room C');
    await expect(latestAlertLog).toContainText('Delivered');
    
    // Verify delivery timestamp is logged
    const deliveryTimestamp = latestAlertLog.locator('[data-testid="delivery-timestamp"]');
    await expect(deliveryTimestamp).toBeVisible();

    // Step 3: User acknowledges alert - Acknowledgment is recorded
    await page.goto('/scheduler');
    const alertNotification = page.locator('[data-testid="alert-notification"]');
    await expect(alertNotification).toBeVisible();
    
    await page.click('[data-testid="acknowledge-alert-button"]');
    await expect(page.locator('[data-testid="alert-acknowledged-message"]')).toBeVisible();

    // Refresh alert log viewer and verify acknowledgment
    await page.goto('/admin/alert-logs');
    await page.click('[data-testid="refresh-logs-button"]');
    
    const acknowledgedAlert = page.locator('[data-testid="alert-log-entry"]').first();
    await expect(acknowledgedAlert).toContainText('Acknowledged');
    
    const acknowledgmentTimestamp = acknowledgedAlert.locator('[data-testid="acknowledgment-timestamp"]');
    await expect(acknowledgmentTimestamp).toBeVisible();

    // Step 4: Generate report on alert delivery and acknowledgment - Report accurately reflects alert statuses
    await page.click('[data-testid="reporting-menu"]');
    await page.click('[data-testid="alert-reports-link"]');
    
    const reportingModule = page.locator('[data-testid="reporting-module"]');
    await expect(reportingModule).toBeVisible();
    
    // Set report date range to current date
    const today = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="report-start-date"]', today);
    await page.fill('[data-testid="report-end-date"]', today);
    
    await page.click('[data-testid="generate-report-button"]');
    
    const reportResults = page.locator('[data-testid="report-results"]');
    await expect(reportResults).toBeVisible();
    
    // Verify report accuracy
    const reportTable = page.locator('[data-testid="alert-report-table"]');
    await expect(reportTable).toBeVisible();
    
    const reportRow = reportTable.locator('[data-testid="report-row"]').first();
    await expect(reportRow).toContainText('Training Room C');
    await expect(reportRow).toContainText('Delivered');
    await expect(reportRow).toContainText('Acknowledged');
    
    // Verify delivery success rate metric
    const deliverySuccessRate = page.locator('[data-testid="delivery-success-rate"]');
    await expect(deliverySuccessRate).toBeVisible();
    const successRateText = await deliverySuccessRate.textContent();
    const successRate = parseFloat(successRateText || '0');
    expect(successRate).toBeGreaterThanOrEqual(98);
    
    // Verify acknowledgment rate metric
    const acknowledgmentRate = page.locator('[data-testid="acknowledgment-rate"]');
    await expect(acknowledgmentRate).toBeVisible();
    const ackRateText = await acknowledgmentRate.textContent();
    const ackRate = parseFloat(ackRateText || '0');
    expect(ackRate).toBeGreaterThanOrEqual(85);
  });
});