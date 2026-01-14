import { test, expect } from '@playwright/test';

test.describe('Late Arrival Alerts Management', () => {
  test.beforeEach(async ({ page }) => {
    // Login as manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate detection and alerting of late arrivals', async ({ page }) => {
    // Step 1: Navigate to Alert Configuration section and configure late arrival threshold to 9:00 AM
    await page.goto('/alerts/configuration');
    await page.click('[data-testid="alert-config-section"]');
    
    await page.fill('[data-testid="late-arrival-threshold-input"]', '09:00');
    await page.click('[data-testid="save-threshold-button"]');
    
    // Expected Result: Configuration saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Configuration saved successfully');
    await expect(page.locator('[data-testid="late-arrival-threshold-display"]')).toContainText('09:00');

    // Step 2: Simulate employee check-in at 9:15 AM (15 minutes after threshold)
    await page.goto('/admin/simulate-checkin');
    await page.selectOption('[data-testid="employee-select"]', { label: 'John Doe' });
    await page.fill('[data-testid="checkin-time-input"]', '09:15');
    await page.click('[data-testid="simulate-checkin-button"]');
    
    // Expected Result: System detects late arrival and triggers alert
    await expect(page.locator('[data-testid="checkin-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="late-arrival-detected-indicator"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-triggered-message"]')).toContainText('Late arrival alert triggered');

    // Step 3: Verify alert received via email by checking manager's email inbox
    await page.goto('/admin/email-inbox');
    await page.waitForSelector('[data-testid="email-list"]');
    const emailAlert = page.locator('[data-testid="email-item"]').filter({ hasText: 'Late Arrival Alert' }).first();
    await expect(emailAlert).toBeVisible();
    await emailAlert.click();
    
    // Expected Result: Alert contains correct employee and time details
    await expect(page.locator('[data-testid="email-subject"]')).toContainText('Late Arrival Alert');
    await expect(page.locator('[data-testid="email-body"]')).toContainText('John Doe');
    await expect(page.locator('[data-testid="email-body"]')).toContainText('9:15 AM');
    await expect(page.locator('[data-testid="email-body"]')).toContainText('15 minutes late');

    // Verify alert received via SMS by checking manager's mobile device
    await page.goto('/admin/sms-inbox');
    await page.waitForSelector('[data-testid="sms-list"]');
    const smsAlert = page.locator('[data-testid="sms-item"]').filter({ hasText: 'Late Arrival' }).first();
    await expect(smsAlert).toBeVisible();
    await expect(smsAlert).toContainText('John Doe');
    await expect(smsAlert).toContainText('9:15');

    // Verify alert displayed in dashboard by navigating to Alerts/Notifications section
    await page.goto('/alerts/dashboard');
    await page.waitForSelector('[data-testid="alerts-list"]');
    const dashboardAlert = page.locator('[data-testid="alert-item"]').filter({ hasText: 'John Doe' }).first();
    await expect(dashboardAlert).toBeVisible();
    await expect(dashboardAlert).toContainText('Late Arrival');
    await expect(dashboardAlert).toContainText('John Doe');
    await expect(dashboardAlert).toContainText('9:15');
    await expect(dashboardAlert).toContainText('15 minutes late');
  });

  test('Verify alert configuration UI and validation', async ({ page }) => {
    // Step 1: Navigate to Alert Configuration section
    await page.goto('/alerts/configuration');
    await expect(page.locator('[data-testid="alert-config-section"]')).toBeVisible();

    // Step 2: Attempt to set invalid threshold time by entering text characters (e.g., 'ABC') in the time field
    await page.fill('[data-testid="late-arrival-threshold-input"]', 'ABC');
    await page.click('[data-testid="save-threshold-button"]');
    
    // Expected Result: System displays validation error and prevents save
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Invalid time format');

    // Step 3: Attempt to set threshold time with invalid format (e.g., '25:00' or '9:70')
    await page.fill('[data-testid="late-arrival-threshold-input"]', '25:00');
    await page.click('[data-testid="save-threshold-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Invalid time');

    await page.fill('[data-testid="late-arrival-threshold-input"]', '9:70');
    await page.click('[data-testid="save-threshold-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Invalid time');

    // Step 4: Leave threshold time field empty and attempt to save
    await page.fill('[data-testid="late-arrival-threshold-input"]', '');
    await page.click('[data-testid="save-threshold-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Time is required');

    // Step 5: Enter valid threshold time (e.g., '09:00') and click Save
    await page.fill('[data-testid="late-arrival-threshold-input"]', '09:00');
    await page.click('[data-testid="save-threshold-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Configuration saved successfully');
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
  });

  test('Test alert acknowledgment and logging', async ({ page }) => {
    // Setup: Create a late arrival alert first
    await page.goto('/admin/simulate-checkin');
    await page.selectOption('[data-testid="employee-select"]', { label: 'Jane Smith' });
    await page.fill('[data-testid="checkin-time-input"]', '09:30');
    await page.click('[data-testid="simulate-checkin-button"]');
    await expect(page.locator('[data-testid="alert-triggered-message"]')).toBeVisible();

    // Step 1: Navigate to the Alerts Dashboard section
    await page.goto('/alerts/dashboard');
    await page.waitForSelector('[data-testid="alerts-list"]');
    await expect(page.locator('[data-testid="alerts-list"]')).toBeVisible();

    // Step 2: Locate the specific late arrival alert and click on it to view details
    const targetAlert = page.locator('[data-testid="alert-item"]').filter({ hasText: 'Jane Smith' }).first();
    await expect(targetAlert).toBeVisible();
    await targetAlert.click();
    
    await expect(page.locator('[data-testid="alert-details-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-employee-name"]')).toContainText('Jane Smith');
    await expect(page.locator('[data-testid="alert-checkin-time"]')).toContainText('9:30');

    // Step 3: Click the 'Acknowledge' button on the alert
    await page.click('[data-testid="acknowledge-alert-button"]');
    
    // Expected Result: Alert status updated and logged
    await expect(page.locator('[data-testid="acknowledgment-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="acknowledgment-success-message"]')).toContainText('Alert acknowledged successfully');

    // Step 4: Verify the alert status is updated in the dashboard list view
    await page.click('[data-testid="close-alert-details"]');
    const acknowledgedAlert = page.locator('[data-testid="alert-item"]').filter({ hasText: 'Jane Smith' }).first();
    await expect(acknowledgedAlert.locator('[data-testid="alert-status"]')).toContainText('Acknowledged');
    await expect(acknowledgedAlert.locator('[data-testid="alert-status-badge"]')).toHaveClass(/acknowledged/);

    // Step 5: Navigate to Alert History/Logs section
    await page.goto('/alerts/history');
    await page.waitForSelector('[data-testid="alert-history-list"]');
    await expect(page.locator('[data-testid="alert-history-list"]')).toBeVisible();

    // Step 6: Verify the acknowledged alert is moved to appropriate section or filtered view
    const historyEntry = page.locator('[data-testid="history-item"]').filter({ hasText: 'Jane Smith' }).first();
    await expect(historyEntry).toBeVisible();
    await expect(historyEntry).toContainText('Acknowledged');
    await expect(historyEntry.locator('[data-testid="acknowledgment-timestamp"]')).toBeVisible();
    await expect(historyEntry.locator('[data-testid="acknowledged-by"]')).toContainText('manager@company.com');
  });
});