import { test, expect } from '@playwright/test';

test.describe('Attendance Anomaly Alerts - Story 21', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const managerEmail = 'manager@company.com';
  const managerPassword = 'Manager@123';
  const unauthorizedEmail = 'employee@company.com';
  const unauthorizedPassword = 'Employee@123';

  test.beforeEach(async ({ page }) => {
    await page.goto(baseURL);
  });

  test('Validate detection and alerting of attendance anomalies (happy-path)', async ({ page, context }) => {
    // Login as manager
    await page.fill('[data-testid="email-input"]', managerEmail);
    await page.fill('[data-testid="password-input"]', managerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to attendance management
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="manage-attendance-link"]');
    await expect(page.locator('[data-testid="attendance-page"]')).toBeVisible();

    // Simulate an attendance anomaly by creating an absence record
    await page.click('[data-testid="create-attendance-record-button"]');
    await page.fill('[data-testid="employee-search-input"]', 'John Doe');
    await page.click('[data-testid="employee-option-john-doe"]');
    await page.selectOption('[data-testid="attendance-status-select"]', 'absent');
    await page.fill('[data-testid="scheduled-date-input"]', new Date().toISOString().split('T')[0]);
    await page.click('[data-testid="save-attendance-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance record created');

    // Wait for the system to process the attendance data and detect the anomaly
    await page.waitForTimeout(2000);

    // Verify that an alert notification is generated in the system
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();
    const alertNotification = page.locator('[data-testid="alert-notification"]').first();
    await expect(alertNotification).toBeVisible();
    await expect(alertNotification).toContainText('Attendance Anomaly Detected');

    // Check the system notifications panel in the manager's dashboard
    await page.click('[data-testid="dashboard-link"]');
    await expect(page.locator('[data-testid="notifications-badge"]')).toBeVisible();
    await expect(page.locator('[data-testid="notifications-badge"]')).toContainText('1');

    // Click on the system notification to view alert details
    await page.click('[data-testid="notifications-icon"]');
    await page.click('[data-testid="alert-notification"]');
    await expect(page.locator('[data-testid="alert-detail-modal"]')).toBeVisible();

    // Review the alert details for accuracy
    await expect(page.locator('[data-testid="alert-employee-name"]')).toContainText('John Doe');
    await expect(page.locator('[data-testid="alert-type"]')).toContainText('Absence');
    await expect(page.locator('[data-testid="alert-date"]')).toBeVisible();

    // Click the 'Acknowledge' button in the alert detail modal
    await page.click('[data-testid="acknowledge-alert-button"]');
    await expect(page.locator('[data-testid="acknowledgment-form"]')).toBeVisible();

    // Enter acknowledgment comment and confirm
    await page.fill('[data-testid="acknowledgment-comment-input"]', 'Reviewed and will follow up with employee');
    await page.click('[data-testid="confirm-acknowledgment-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Alert acknowledged successfully');

    // Navigate to the alerts history page
    await page.click('[data-testid="alerts-menu"]');
    await page.click('[data-testid="alerts-history-link"]');
    await expect(page.locator('[data-testid="alerts-history-page"]')).toBeVisible();

    // Verify the alert log entry in the system
    const alertLogEntry = page.locator('[data-testid="alert-log-entry"]').first();
    await expect(alertLogEntry).toBeVisible();
    await expect(alertLogEntry).toContainText('John Doe');
    await expect(alertLogEntry).toContainText('Absence');
    await expect(alertLogEntry).toContainText('Acknowledged');
    await expect(alertLogEntry).toContainText('Reviewed and will follow up with employee');
  });

  test('Verify alert access control (error-case)', async ({ page }) => {
    // Log into the system using unauthorized user credentials
    await page.fill('[data-testid="email-input"]', unauthorizedEmail);
    await page.fill('[data-testid="password-input"]', unauthorizedPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Check if alerts or notifications panel is visible in the unauthorized user's dashboard
    const alertsMenu = page.locator('[data-testid="alerts-menu"]');
    await expect(alertsMenu).not.toBeVisible();

    // Attempt to navigate to the alerts module by entering the URL directly
    await page.goto(`${baseURL}/alerts`);
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');

    // Attempt to access alerts API endpoint directly
    const response = await page.request.get(`${baseURL}/api/attendance/alerts`);
    expect(response.status()).toBe(403);

    // Verify that no attendance alert emails were sent to unauthorized user
    // This would typically be verified through email service integration or test email inbox

    // Log out from the unauthorized user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Log into the system using authorized Attendance Manager credentials
    await page.fill('[data-testid="email-input"]', managerEmail);
    await page.fill('[data-testid="password-input"]', managerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Click on the alerts/notifications icon in the dashboard
    await page.click('[data-testid="alerts-menu"]');
    await expect(page.locator('[data-testid="alerts-page"]')).toBeVisible();

    // Verify that all alerts are accessible and actionable
    await expect(page.locator('[data-testid="alerts-list"]')).toBeVisible();
    const alertsList = page.locator('[data-testid="alert-item"]');
    await expect(alertsList.first()).toBeVisible();

    // Select an unacknowledged alert from the list
    const unacknowledgedAlert = page.locator('[data-testid="alert-item"][data-status="unacknowledged"]').first();
    await unacknowledgedAlert.click();
    await expect(page.locator('[data-testid="alert-detail-modal"]')).toBeVisible();

    // Click 'Acknowledge' button and add comment
    await page.click('[data-testid="acknowledge-alert-button"]');
    await page.fill('[data-testid="acknowledgment-comment-input"]', 'Investigating the issue');
    await page.click('[data-testid="confirm-acknowledgment-button"]');

    // Verify the acknowledgment is recorded in the system
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Alert acknowledged successfully');
    await page.click('[data-testid="close-modal-button"]');
    const acknowledgedAlert = page.locator('[data-testid="alert-item"][data-status="acknowledged"]').first();
    await expect(acknowledgedAlert).toBeVisible();
  });

  test('Ensure alert delivery latency within SLA (boundary)', async ({ page }) => {
    // Login as manager
    await page.fill('[data-testid="email-input"]', managerEmail);
    await page.fill('[data-testid="password-input"]', managerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Note the current system time before triggering the anomaly
    const anomalyTriggerTime = Date.now();

    // Navigate to attendance management
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="manage-attendance-link"]');

    // Trigger an attendance anomaly event by creating a late arrival record
    await page.click('[data-testid="create-attendance-record-button"]');
    await page.fill('[data-testid="employee-search-input"]', 'Jane Smith');
    await page.click('[data-testid="employee-option-jane-smith"]');
    await page.selectOption('[data-testid="attendance-status-select"]', 'late');
    await page.fill('[data-testid="scheduled-time-input"]', '09:00');
    await page.fill('[data-testid="actual-time-input"]', '09:30');
    await page.fill('[data-testid="scheduled-date-input"]', new Date().toISOString().split('T')[0]);
    await page.click('[data-testid="save-attendance-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance record created');

    // Monitor the system's anomaly detection process in real-time
    // Wait and observe when the alert is generated
    await page.waitForTimeout(5000);

    // Check the system notifications panel for the alert
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();
    const alertNotification = page.locator('[data-testid="alert-notification"]').first();
    await expect(alertNotification).toBeVisible();
    const alertReceivedTime = Date.now();

    // Click on the system notification to view alert details
    await alertNotification.click();
    await expect(page.locator('[data-testid="alert-detail-modal"]')).toBeVisible();

    // Verify the alert details include accurate timestamp information
    const alertTimestamp = await page.locator('[data-testid="alert-timestamp"]').textContent();
    expect(alertTimestamp).toBeTruthy();

    // Navigate to the alerts log/history section
    await page.click('[data-testid="close-modal-button"]');
    await page.click('[data-testid="alerts-menu"]');
    await page.click('[data-testid="alerts-history-link"]');
    await expect(page.locator('[data-testid="alerts-history-page"]')).toBeVisible();

    // Verify the alert log entry contains all required timestamps
    const alertLogEntry = page.locator('[data-testid="alert-log-entry"]').first();
    await expect(alertLogEntry).toBeVisible();
    await expect(alertLogEntry.locator('[data-testid="alert-created-timestamp"]')).toBeVisible();
    await expect(alertLogEntry.locator('[data-testid="alert-detected-timestamp"]')).toBeVisible();

    // Calculate and verify the total latency from anomaly occurrence to alert delivery
    const totalLatency = alertReceivedTime - anomalyTriggerTime;
    const latencyInSeconds = totalLatency / 1000;
    
    // Verify alert delivery within 1 minute (60 seconds) SLA
    expect(latencyInSeconds).toBeLessThanOrEqual(60);

    // Review system performance logs for alert processing time
    await page.click('[data-testid="system-menu"]');
    await page.click('[data-testid="performance-logs-link"]');
    await expect(page.locator('[data-testid="performance-logs-page"]')).toBeVisible();
    
    const alertProcessingLog = page.locator('[data-testid="log-entry"]').filter({ hasText: 'Alert Processing' }).first();
    await expect(alertProcessingLog).toBeVisible();
    const processingTime = await alertProcessingLog.locator('[data-testid="processing-time"]').textContent();
    expect(processingTime).toBeTruthy();
  });
});