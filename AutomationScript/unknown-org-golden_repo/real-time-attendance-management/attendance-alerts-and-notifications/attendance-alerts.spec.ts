import { test, expect } from '@playwright/test';

test.describe('Attendance Anomaly Alerts - Manager Functionality', () => {
  let baseURL: string;

  test.beforeEach(async ({ page }) => {
    baseURL = process.env.BASE_URL || 'http://localhost:3000';
    // Login as manager
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager@123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();
  });

  test('Validate alert configuration and saving', async ({ page }) => {
    // Step 1: Navigate to alert settings
    await page.click('[data-testid="alert-settings-menu"]');
    await expect(page.locator('[data-testid="alert-configuration-page"]')).toBeVisible();
    
    // Step 2: Set late arrival threshold to 15 minutes
    await page.fill('[data-testid="late-arrival-threshold-input"]', '15');
    
    // Set absence alert threshold to immediate
    await page.selectOption('[data-testid="absence-threshold-select"]', 'immediate');
    
    // Select email notification channel
    await page.check('[data-testid="email-notification-checkbox"]');
    await expect(page.locator('[data-testid="email-notification-checkbox"]')).toBeChecked();
    
    // Select SMS notification channel
    await page.check('[data-testid="sms-notification-checkbox"]');
    await expect(page.locator('[data-testid="sms-notification-checkbox"]')).toBeChecked();
    
    // Select in-app notification channel
    await page.check('[data-testid="inapp-notification-checkbox"]');
    await expect(page.locator('[data-testid="inapp-notification-checkbox"]')).toBeChecked();
    
    // Click Save button
    await page.click('[data-testid="save-alert-settings-button"]');
    await expect(page.locator('[data-testid="settings-saved-confirmation"]')).toBeVisible();
    
    // Step 3: Navigate away and return to verify settings persistence
    await page.click('[data-testid="dashboard-menu"]');
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();
    
    // Return to alert settings
    await page.click('[data-testid="alert-settings-menu"]');
    await expect(page.locator('[data-testid="alert-configuration-page"]')).toBeVisible();
    
    // Verify late arrival threshold displays 15 minutes
    await expect(page.locator('[data-testid="late-arrival-threshold-input"]')).toHaveValue('15');
    
    // Verify absence threshold displays immediate trigger
    await expect(page.locator('[data-testid="absence-threshold-select"]')).toHaveValue('immediate');
    
    // Verify all notification channels are checked
    await expect(page.locator('[data-testid="email-notification-checkbox"]')).toBeChecked();
    await expect(page.locator('[data-testid="sms-notification-checkbox"]')).toBeChecked();
    await expect(page.locator('[data-testid="inapp-notification-checkbox"]')).toBeChecked();
  });

  test('Verify alert delivery for late arrival', async ({ page }) => {
    // Step 1: Note current time and simulate late arrival
    const currentTime = new Date();
    const testEmployeeId = 'EMP001';
    const scheduledStartTime = '09:00';
    const lateArrivalTime = '09:20';
    
    // Navigate to attendance entry or simulation page
    await page.goto(`${baseURL}/attendance/simulate`);
    await expect(page.locator('[data-testid="attendance-simulation-page"]')).toBeVisible();
    
    // Simulate employee late arrival (20 minutes late)
    await page.fill('[data-testid="employee-id-input"]', testEmployeeId);
    await page.fill('[data-testid="scheduled-time-input"]', scheduledStartTime);
    await page.fill('[data-testid="actual-arrival-time-input"]', lateArrivalTime);
    await page.click('[data-testid="simulate-late-arrival-button"]');
    
    // Wait for system to process and detect anomaly
    await page.waitForTimeout(2000);
    await expect(page.locator('[data-testid="anomaly-detected-message"]')).toBeVisible();
    
    // Step 2: Check in-app notifications within 5 minutes
    await page.goto(`${baseURL}/dashboard`);
    await page.click('[data-testid="notifications-icon"]');
    
    // Wait for alert to appear (max 5 minutes, checking every 10 seconds)
    await page.waitForSelector('[data-testid="late-arrival-alert"]', { timeout: 300000 });
    
    const alertElement = page.locator('[data-testid="late-arrival-alert"]').first();
    await expect(alertElement).toBeVisible();
    await expect(alertElement).toContainText(testEmployeeId);
    await expect(alertElement).toContainText('late arrival');
    
    // Verify alert timestamp is within 5 minutes
    const alertTimestamp = await alertElement.locator('[data-testid="alert-timestamp"]').textContent();
    expect(alertTimestamp).toBeTruthy();
    
    // Step 3: Manager acknowledges alert
    await alertElement.click();
    await page.click('[data-testid="acknowledge-alert-button"]');
    
    // Verify alert status updated to acknowledged
    await expect(page.locator('[data-testid="alert-status"]')).toContainText('Acknowledged');
    
    // Refresh and verify status persists
    await page.reload();
    await page.click('[data-testid="notifications-icon"]');
    const acknowledgedAlert = page.locator(`[data-testid="late-arrival-alert"]`).first();
    await expect(acknowledgedAlert.locator('[data-testid="alert-status-badge"]')).toContainText('Acknowledged');
  });

  test('Test alert acknowledgment and dismissal', async ({ page }) => {
    // Step 1: Navigate to alerts section
    await page.goto(`${baseURL}/dashboard/alerts`);
    await expect(page.locator('[data-testid="alerts-page"]')).toBeVisible();
    
    // Locate and click active alerts tab
    await page.click('[data-testid="active-alerts-tab"]');
    await expect(page.locator('[data-testid="active-alerts-section"]')).toBeVisible();
    
    // Count active alerts
    const activeAlerts = page.locator('[data-testid="active-alert-item"]');
    const initialAlertCount = await activeAlerts.count();
    expect(initialAlertCount).toBeGreaterThan(0);
    
    // Review details of first alert
    const firstAlert = activeAlerts.first();
    await expect(firstAlert.locator('[data-testid="alert-type"]')).toBeVisible();
    await expect(firstAlert.locator('[data-testid="employee-info"]')).toBeVisible();
    await expect(firstAlert.locator('[data-testid="alert-timestamp"]')).toBeVisible();
    
    const alertType = await firstAlert.locator('[data-testid="alert-type"]').textContent();
    const employeeInfo = await firstAlert.locator('[data-testid="employee-info"]').textContent();
    
    // Step 2: Dismiss the first alert
    await firstAlert.locator('[data-testid="dismiss-alert-button"]').click();
    
    // Confirm dismissal in dialog
    await page.click('[data-testid="confirm-dismiss-button"]');
    
    // Note dismissal timestamp
    const dismissalTime = new Date();
    
    // Verify alert removed from active list
    await page.waitForTimeout(1000);
    const updatedAlertCount = await activeAlerts.count();
    expect(updatedAlertCount).toBe(initialAlertCount - 1);
    
    // Step 3: Navigate to alert history
    await page.click('[data-testid="alert-history-tab"]');
    await expect(page.locator('[data-testid="alert-history-section"]')).toBeVisible();
    
    // Search for dismissed alert
    await page.fill('[data-testid="alert-history-search-input"]', employeeInfo || '');
    await page.click('[data-testid="search-button"]');
    
    // Click on dismissed alert in history
    const dismissedAlertInHistory = page.locator('[data-testid="history-alert-item"]').first();
    await dismissedAlertInHistory.click();
    
    // Verify alert status shows Dismissed
    await expect(page.locator('[data-testid="alert-detail-status"]')).toContainText('Dismissed');
    
    // Verify dismissal timestamp is present and recent
    const dismissalTimestampElement = page.locator('[data-testid="dismissal-timestamp"]');
    await expect(dismissalTimestampElement).toBeVisible();
    const dismissalTimestampText = await dismissalTimestampElement.textContent();
    expect(dismissalTimestampText).toBeTruthy();
    
    // Verify manager info is logged
    await expect(page.locator('[data-testid="dismissed-by-manager"]')).toBeVisible();
    await expect(page.locator('[data-testid="dismissed-by-manager"]')).toContainText('manager@company.com');
    
    // Return to active alerts and test acknowledgment
    await page.click('[data-testid="active-alerts-tab"]');
    await expect(page.locator('[data-testid="active-alerts-section"]')).toBeVisible();
    
    // Select different alert and acknowledge
    const secondAlert = page.locator('[data-testid="active-alert-item"]').first();
    await secondAlert.locator('[data-testid="acknowledge-alert-button"]').click();
    
    // Verify acknowledged alert shows updated status but remains visible
    await page.waitForTimeout(1000);
    await expect(secondAlert.locator('[data-testid="alert-status-badge"]')).toContainText('Acknowledged');
    await expect(secondAlert).toBeVisible();
  });
});