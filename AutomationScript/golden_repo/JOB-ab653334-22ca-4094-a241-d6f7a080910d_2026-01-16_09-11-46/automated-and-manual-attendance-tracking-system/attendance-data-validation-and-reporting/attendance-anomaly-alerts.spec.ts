import { test, expect } from '@playwright/test';

test.describe('Attendance Anomaly Alerts Management', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const managerEmail = 'attendance.manager@company.com';
  const managerPassword = 'Manager@123';
  const unauthorizedEmail = 'employee@company.com';
  const unauthorizedPassword = 'Employee@123';

  test.beforeEach(async ({ page }) => {
    await page.goto(baseURL);
  });

  test('Validate anomaly detection and alert generation (happy-path)', async ({ page, context }) => {
    // Step 1: Inject attendance data with known anomalies
    await page.goto(`${baseURL}/admin/test-data`);
    await page.fill('[data-testid="employee-id-input"]', 'EMP001');
    await page.selectOption('[data-testid="anomaly-type-select"]', 'missing-clock-out');
    await page.click('[data-testid="inject-anomaly-button"]');
    await expect(page.locator('[data-testid="injection-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="injection-success-message"]')).toContainText('Anomaly data injected successfully');

    // Inject duplicate clock-in anomaly
    await page.fill('[data-testid="employee-id-input"]', 'EMP002');
    await page.selectOption('[data-testid="anomaly-type-select"]', 'duplicate-clock-in');
    await page.click('[data-testid="inject-anomaly-button"]');
    await expect(page.locator('[data-testid="injection-success-message"]')).toBeVisible();

    // Inject attendance on holiday anomaly
    await page.fill('[data-testid="employee-id-input"]', 'EMP003');
    await page.selectOption('[data-testid="anomaly-type-select"]', 'attendance-on-holiday');
    await page.click('[data-testid="inject-anomaly-button"]');
    await expect(page.locator('[data-testid="injection-success-message"]')).toBeVisible();

    // Trigger anomaly detection process
    await page.click('[data-testid="trigger-detection-button"]');
    await expect(page.locator('[data-testid="detection-running-message"]')).toBeVisible();
    await page.waitForSelector('[data-testid="detection-complete-message"]', { timeout: 30000 });
    await expect(page.locator('[data-testid="detection-complete-message"]')).toContainText('Anomaly detection completed');

    // Step 2: Login as Attendance Manager
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', managerEmail);
    await page.fill('[data-testid="password-input"]', managerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(`${baseURL}/dashboard`);

    // Step 3: Navigate to alert dashboard
    await page.click('[data-testid="alerts-menu"]');
    await expect(page).toHaveURL(`${baseURL}/alerts`);

    // Verify alerts appear in manager dashboard
    await expect(page.locator('[data-testid="alert-list"]')).toBeVisible();
    const alertItems = page.locator('[data-testid="alert-item"]');
    await expect(alertItems).toHaveCount(3);

    // Verify alert details for missing clock-out
    const firstAlert = alertItems.first();
    await expect(firstAlert.locator('[data-testid="alert-type"]')).toContainText('Missing Clock-Out');
    await expect(firstAlert.locator('[data-testid="employee-id"]')).toContainText('EMP001');
    await expect(firstAlert.locator('[data-testid="alert-status"]')).toContainText('New');

    // Click on alert to view detailed information
    await firstAlert.click();
    await expect(page.locator('[data-testid="alert-detail-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-detail-description"]')).toContainText('Employee clocked in but did not clock out');
    await page.click('[data-testid="close-modal-button"]');

    // Step 4: Check email notifications
    // Open new page to check email (simulated email client)
    const emailPage = await context.newPage();
    await emailPage.goto(`${baseURL}/test/email-inbox?email=${managerEmail}`);
    await expect(emailPage.locator('[data-testid="email-list"]')).toBeVisible();
    
    const emailItems = emailPage.locator('[data-testid="email-item"]');
    await expect(emailItems).toHaveCountGreaterThanOrEqual(3);
    
    const firstEmail = emailItems.first();
    await expect(firstEmail.locator('[data-testid="email-subject"]')).toContainText('Attendance Anomaly Alert');
    await firstEmail.click();
    await expect(emailPage.locator('[data-testid="email-body"]')).toContainText('Missing Clock-Out');
    await expect(emailPage.locator('[data-testid="email-body"]')).toContainText('EMP001');
    await emailPage.close();
  });

  test('Test alert acknowledgment and resolution (happy-path)', async ({ page }) => {
    // Login as Attendance Manager
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', managerEmail);
    await page.fill('[data-testid="password-input"]', managerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(`${baseURL}/dashboard`);

    // Step 1: Navigate to alert dashboard
    await page.click('[data-testid="alerts-menu"]');
    await expect(page).toHaveURL(`${baseURL}/alerts`);

    // Step 2: Select an alert with 'New' status
    const newAlerts = page.locator('[data-testid="alert-item"][data-status="new"]');
    await expect(newAlerts.first()).toBeVisible();
    const alertId = await newAlerts.first().getAttribute('data-alert-id');
    await newAlerts.first().click();

    // Step 3: Click the 'Acknowledge' button
    await expect(page.locator('[data-testid="alert-detail-modal"]')).toBeVisible();
    await page.click('[data-testid="acknowledge-button"]');
    
    // Confirm acknowledgment action
    await expect(page.locator('[data-testid="confirm-acknowledge-dialog"]')).toBeVisible();
    await page.click('[data-testid="confirm-acknowledge-yes-button"]');
    
    // Verify alert status changes to acknowledged
    await expect(page.locator('[data-testid="alert-status"]')).toContainText('Acknowledged');
    await expect(page.locator('[data-testid="acknowledgment-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="acknowledgment-success-message"]')).toContainText('Alert acknowledged successfully');

    // Step 4: Review alert details and take corrective action
    await expect(page.locator('[data-testid="alert-detail-description"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-details"]')).toBeVisible();

    // Step 5: Mark alert as resolved
    await page.click('[data-testid="mark-resolved-button"]');
    await expect(page.locator('[data-testid="resolution-dialog"]')).toBeVisible();
    
    // Enter resolution notes
    await page.fill('[data-testid="resolution-notes-textarea"]', 'Contacted employee and corrected attendance record. Missing clock-out time added as 17:30.');
    await page.click('[data-testid="confirm-resolution-button"]');
    
    // Verify alert status changes to resolved
    await expect(page.locator('[data-testid="alert-status"]')).toContainText('Resolved');
    await expect(page.locator('[data-testid="resolution-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="resolution-success-message"]')).toContainText('Alert resolved successfully');
    await page.click('[data-testid="close-modal-button"]');

    // Step 6: Navigate to audit log section
    await page.click('[data-testid="reports-menu"]');
    await page.click('[data-testid="audit-log-submenu"]');
    await expect(page).toHaveURL(`${baseURL}/reports/audit-log`);

    // Search for audit log entries related to the resolved alert
    await page.fill('[data-testid="audit-search-input"]', alertId || '');
    await page.click('[data-testid="audit-search-button"]');
    
    // Verify audit log contains acknowledgment entry
    const auditEntries = page.locator('[data-testid="audit-log-entry"]');
    await expect(auditEntries).toHaveCountGreaterThanOrEqual(2);
    
    const acknowledgmentEntry = auditEntries.filter({ hasText: 'Alert Acknowledged' });
    await expect(acknowledgmentEntry).toBeVisible();
    await expect(acknowledgmentEntry.locator('[data-testid="audit-action"]')).toContainText('Alert Acknowledged');
    await expect(acknowledgmentEntry.locator('[data-testid="audit-user"]')).toContainText(managerEmail);
    await expect(acknowledgmentEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
    
    // Verify audit log contains resolution entry
    const resolutionEntry = auditEntries.filter({ hasText: 'Alert Resolved' });
    await expect(resolutionEntry).toBeVisible();
    await expect(resolutionEntry.locator('[data-testid="audit-action"]')).toContainText('Alert Resolved');
    await expect(resolutionEntry.locator('[data-testid="audit-user"]')).toContainText(managerEmail);
    await expect(resolutionEntry.locator('[data-testid="audit-details"]')).toContainText('Contacted employee and corrected attendance record');
    await expect(resolutionEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
  });

  test('Ensure access control for alert management (error-case)', async ({ page }) => {
    // Step 1: Login as unauthorized user
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', unauthorizedEmail);
    await page.fill('[data-testid="password-input"]', unauthorizedPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(`${baseURL}/dashboard`);

    // Step 2: Attempt to access alert dashboard via menu
    const alertsMenu = page.locator('[data-testid="alerts-menu"]');
    if (await alertsMenu.isVisible()) {
      await alertsMenu.click();
      // Should show access denied message or redirect
      await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
      await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    } else {
      // Menu should not be visible for unauthorized users
      await expect(alertsMenu).not.toBeVisible();
    }

    // Step 3: Attempt to access alert dashboard directly via URL
    await page.goto(`${baseURL}/alerts`);
    // Should be redirected or show access denied
    const currentURL = page.url();
    if (currentURL.includes('/alerts')) {
      await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
      await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('You do not have permission to access this page');
    } else {
      // Should be redirected to dashboard or error page
      expect(currentURL).not.toContain('/alerts');
    }

    // Step 4: Verify no alert-related functionality is accessible
    await page.goto(`${baseURL}/dashboard`);
    await expect(page.locator('[data-testid="alert-notifications"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="alerts-menu"]')).not.toBeVisible();

    // Step 5: Logout from unauthorized user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(`${baseURL}/login`);

    // Step 6: Login as authorized attendance manager
    await page.fill('[data-testid="email-input"]', managerEmail);
    await page.fill('[data-testid="password-input"]', managerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(`${baseURL}/dashboard`);

    // Step 7: Verify access to alert dashboard
    await expect(page.locator('[data-testid="alerts-menu"]')).toBeVisible();
    await page.click('[data-testid="alerts-menu"]');
    await expect(page).toHaveURL(`${baseURL}/alerts`);
    await expect(page.locator('[data-testid="alert-list"]')).toBeVisible();

    // Step 8: Verify alert notifications are accessible
    await page.goto(`${baseURL}/dashboard`);
    await expect(page.locator('[data-testid="alert-notifications"]')).toBeVisible();
    const notificationBadge = page.locator('[data-testid="alert-notification-badge"]');
    if (await notificationBadge.isVisible()) {
      await expect(notificationBadge).toHaveText(/\d+/);
    }

    // Step 9: Verify full access to alert management features
    await page.click('[data-testid="alerts-menu"]');
    await expect(page.locator('[data-testid="alert-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="filter-alerts-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-alerts-button"]')).toBeVisible();
    
    // Click on an alert to verify detail access
    const firstAlert = page.locator('[data-testid="alert-item"]').first();
    if (await firstAlert.isVisible()) {
      await firstAlert.click();
      await expect(page.locator('[data-testid="alert-detail-modal"]')).toBeVisible();
      await expect(page.locator('[data-testid="acknowledge-button"]')).toBeVisible();
      await expect(page.locator('[data-testid="mark-resolved-button"]')).toBeVisible();
    }
  });
});