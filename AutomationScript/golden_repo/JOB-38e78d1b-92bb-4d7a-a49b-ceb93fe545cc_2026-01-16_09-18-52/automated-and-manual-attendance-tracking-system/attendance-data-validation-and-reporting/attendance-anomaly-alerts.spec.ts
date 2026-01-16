import { test, expect } from '@playwright/test';

test.describe('Attendance Anomaly Alerts Management', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const managerEmail = 'attendance.manager@company.com';
  const managerPassword = 'Manager@123';
  const unauthorizedEmail = 'regular.employee@company.com';
  const unauthorizedPassword = 'Employee@123';

  test.beforeEach(async ({ page }) => {
    await page.goto(baseURL);
  });

  test('Validate anomaly detection and alert generation (happy-path)', async ({ page }) => {
    // Login as attendance manager
    await page.fill('[data-testid="email-input"]', managerEmail);
    await page.fill('[data-testid="password-input"]', managerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Inject attendance data with known anomalies
    await page.goto(`${baseURL}/admin/test-data`);
    await page.click('[data-testid="inject-anomaly-data-button"]');
    await page.selectOption('[data-testid="anomaly-type-select"]', 'missing-punch-out');
    await page.fill('[data-testid="employee-id-input"]', 'EMP001');
    await page.fill('[data-testid="date-input"]', '2024-01-15');
    await page.click('[data-testid="inject-data-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Anomaly data injected successfully');

    // Inject duplicate entry anomaly
    await page.selectOption('[data-testid="anomaly-type-select"]', 'duplicate-entry');
    await page.fill('[data-testid="employee-id-input"]', 'EMP002');
    await page.fill('[data-testid="date-input"]', '2024-01-15');
    await page.click('[data-testid="inject-data-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Anomaly data injected successfully');

    // Trigger anomaly detection process
    await page.goto(`${baseURL}/admin/anomaly-detection`);
    await page.click('[data-testid="run-detection-button"]');
    await expect(page.locator('[data-testid="detection-status"]')).toContainText('Detection completed', { timeout: 30000 });
    await expect(page.locator('[data-testid="anomalies-detected-count"]')).toContainText('2');

    // Navigate to manager dashboard and verify alerts
    await page.goto(`${baseURL}/attendance/alerts`);
    await expect(page.locator('[data-testid="alerts-dashboard"]')).toBeVisible();
    
    // Verify alerts are visible with correct details
    const alertsList = page.locator('[data-testid="alert-item"]');
    await expect(alertsList).toHaveCount(2, { timeout: 10000 });

    // Check first alert details - missing punch-out
    const firstAlert = alertsList.first();
    await expect(firstAlert.locator('[data-testid="alert-type"]')).toContainText('Missing Punch-Out');
    await expect(firstAlert.locator('[data-testid="alert-employee"]')).toContainText('EMP001');
    await expect(firstAlert.locator('[data-testid="alert-date"]')).toContainText('2024-01-15');
    await expect(firstAlert.locator('[data-testid="alert-status"]')).toContainText('Unacknowledged');

    // Click on individual alert to view detailed information
    await firstAlert.click();
    await expect(page.locator('[data-testid="alert-details-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-detail-type"]')).toContainText('Missing Punch-Out');
    await expect(page.locator('[data-testid="alert-detail-employee-id"]')).toContainText('EMP001');
    await expect(page.locator('[data-testid="alert-detail-description"]')).toContainText('Employee punched in but did not punch out');
    await page.click('[data-testid="close-modal-button"]');

    // Check email notifications (simulated via email log)
    await page.goto(`${baseURL}/admin/email-log`);
    await page.fill('[data-testid="email-search-input"]', managerEmail);
    await page.click('[data-testid="search-button"]');
    
    const emailEntries = page.locator('[data-testid="email-entry"]');
    await expect(emailEntries).toHaveCountGreaterThanOrEqual(2);
    
    // Verify first email content
    const firstEmail = emailEntries.first();
    await expect(firstEmail.locator('[data-testid="email-subject"]')).toContainText('Attendance Anomaly Alert');
    await expect(firstEmail.locator('[data-testid="email-recipient"]')).toContainText(managerEmail);
    await firstEmail.click();
    await expect(page.locator('[data-testid="email-body"]')).toContainText('Missing Punch-Out');
    await expect(page.locator('[data-testid="email-body"]')).toContainText('EMP001');
    await expect(page.locator('[data-testid="email-body"]')).toContainText('2024-01-15');
  });

  test('Test alert acknowledgment and resolution (happy-path)', async ({ page }) => {
    // Login as attendance manager
    await page.fill('[data-testid="email-input"]', managerEmail);
    await page.fill('[data-testid="password-input"]', managerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to alert dashboard
    await page.goto(`${baseURL}/attendance/alerts`);
    await expect(page.locator('[data-testid="alerts-dashboard"]')).toBeVisible();

    // Locate an unacknowledged alert
    const unacknowledgedAlert = page.locator('[data-testid="alert-item"]').filter({ has: page.locator('[data-testid="alert-status"]:has-text("Unacknowledged")') }).first();
    await expect(unacknowledgedAlert).toBeVisible();
    
    // Get alert ID for later verification
    const alertId = await unacknowledgedAlert.locator('[data-testid="alert-id"]').textContent();

    // Click on alert to open details page
    await unacknowledgedAlert.click();
    await expect(page.locator('[data-testid="alert-details-modal"]')).toBeVisible();

    // Click the Acknowledge button
    await page.click('[data-testid="acknowledge-button"]');
    await expect(page.locator('[data-testid="success-notification"]')).toContainText('Alert acknowledged successfully');
    await expect(page.locator('[data-testid="alert-status-badge"]')).toContainText('Acknowledged');

    // Close modal and verify status in dashboard list view
    await page.click('[data-testid="close-modal-button"]');
    await page.waitForTimeout(1000);
    const acknowledgedAlert = page.locator(`[data-testid="alert-item"][data-alert-id="${alertId}"]`);
    await expect(acknowledgedAlert.locator('[data-testid="alert-status"]')).toContainText('Acknowledged');

    // Return to alert details and review recommended corrective actions
    await acknowledgedAlert.click();
    await expect(page.locator('[data-testid="alert-details-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="corrective-actions"]')).toBeVisible();
    await expect(page.locator('[data-testid="corrective-actions"]')).toContainText('Review employee time records');

    // Mark alert as resolved
    await page.click('[data-testid="mark-resolved-button"]');
    await expect(page.locator('[data-testid="resolution-form"]')).toBeVisible();
    
    // Add resolution notes
    await page.fill('[data-testid="resolution-notes-textarea"]', 'Contacted employee. Missing punch-out was at 5:00 PM. Manual entry added to correct the record.');
    await page.click('[data-testid="save-resolution-button"]');
    
    await expect(page.locator('[data-testid="success-notification"]')).toContainText('Alert resolved successfully');
    await expect(page.locator('[data-testid="alert-status-badge"]')).toContainText('Resolved');
    await page.click('[data-testid="close-modal-button"]');

    // Navigate to audit log section
    await page.goto(`${baseURL}/admin/audit-log`);
    await expect(page.locator('[data-testid="audit-log-page"]')).toBeVisible();

    // Search for the alert ID
    await page.fill('[data-testid="audit-search-input"]', alertId || '');
    await page.click('[data-testid="audit-search-button"]');

    // Verify audit log contains acknowledgment entry
    const auditEntries = page.locator('[data-testid="audit-entry"]');
    await expect(auditEntries).toHaveCountGreaterThanOrEqual(2);
    
    const acknowledgmentEntry = auditEntries.filter({ hasText: 'Alert Acknowledged' }).first();
    await expect(acknowledgmentEntry).toBeVisible();
    await expect(acknowledgmentEntry.locator('[data-testid="audit-action"]')).toContainText('Alert Acknowledged');
    await expect(acknowledgmentEntry.locator('[data-testid="audit-user"]')).toContainText(managerEmail);
    await expect(acknowledgmentEntry.locator('[data-testid="audit-entity-id"]')).toContainText(alertId || '');

    // Verify audit log contains resolution entry
    const resolutionEntry = auditEntries.filter({ hasText: 'Alert Resolved' }).first();
    await expect(resolutionEntry).toBeVisible();
    await expect(resolutionEntry.locator('[data-testid="audit-action"]')).toContainText('Alert Resolved');
    await expect(resolutionEntry.locator('[data-testid="audit-user"]')).toContainText(managerEmail);
    await expect(resolutionEntry.locator('[data-testid="audit-details"]')).toContainText('Contacted employee');
  });

  test('Ensure access control for alert management (error-case)', async ({ page }) => {
    // Login as unauthorized user (regular employee)
    await page.fill('[data-testid="email-input"]', unauthorizedEmail);
    await page.fill('[data-testid="password-input"]', unauthorizedPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Attempt to navigate to alert dashboard by entering URL directly
    await page.goto(`${baseURL}/attendance/alerts`);
    
    // Verify access is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    await expect(page.locator('[data-testid="error-description"]')).toContainText('You do not have permission to access this resource');

    // Verify alert dashboard is not accessible
    await expect(page.locator('[data-testid="alerts-dashboard"]')).not.toBeVisible();

    // Attempt to access alert notifications
    await page.goto(`${baseURL}/notifications`);
    const notificationsList = page.locator('[data-testid="notification-item"]');
    const alertNotifications = notificationsList.filter({ hasText: 'Attendance Anomaly' });
    await expect(alertNotifications).toHaveCount(0);

    // Attempt to access specific alert by direct URL
    await page.goto(`${baseURL}/attendance/alerts/ALT001`);
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();

    // Logout from unauthorized user
    await page.click('[data-testid="user-menu-button"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Login as authorized attendance manager
    await page.fill('[data-testid="email-input"]', managerEmail);
    await page.fill('[data-testid="password-input"]', managerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to alert dashboard from main menu
    await page.click('[data-testid="main-menu-button"]');
    await page.click('[data-testid="menu-attendance"]');
    await page.click('[data-testid="menu-alerts"]');
    await expect(page.locator('[data-testid="alerts-dashboard"]')).toBeVisible();

    // Verify alert notifications are visible in dashboard notification area
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notifications-dropdown"]')).toBeVisible();
    const managerNotifications = page.locator('[data-testid="notification-item"]');
    const managerAlertNotifications = managerNotifications.filter({ hasText: 'Attendance Anomaly' });
    await expect(managerAlertNotifications.first()).toBeVisible();

    // Verify access to all alert management features
    const firstAlert = page.locator('[data-testid="alert-item"]').first();
    await firstAlert.click();
    await expect(page.locator('[data-testid="alert-details-modal"]')).toBeVisible();
    
    // Verify acknowledge button is accessible
    await expect(page.locator('[data-testid="acknowledge-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="acknowledge-button"]')).toBeEnabled();
    
    // Verify resolve button is accessible
    await expect(page.locator('[data-testid="mark-resolved-button"]')).toBeVisible();
    
    // Verify comment function is accessible
    await expect(page.locator('[data-testid="add-comment-button"]')).toBeVisible();
    await page.click('[data-testid="add-comment-button"]');
    await expect(page.locator('[data-testid="comment-textarea"]')).toBeVisible();
    await page.fill('[data-testid="comment-textarea"]', 'Test comment for verification');
    await page.click('[data-testid="submit-comment-button"]');
    await expect(page.locator('[data-testid="comment-list"]')).toContainText('Test comment for verification');

    // Check email notifications are being received (via email log)
    await page.goto(`${baseURL}/admin/email-log`);
    await page.fill('[data-testid="email-search-input"]', managerEmail);
    await page.click('[data-testid="search-button"]');
    const emailEntries = page.locator('[data-testid="email-entry"]');
    await expect(emailEntries.first()).toBeVisible();
    await expect(emailEntries.first().locator('[data-testid="email-recipient"]')).toContainText(managerEmail);
  });
});