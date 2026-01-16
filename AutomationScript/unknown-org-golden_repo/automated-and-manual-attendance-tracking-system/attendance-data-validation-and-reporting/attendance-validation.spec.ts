import { test, expect } from '@playwright/test';

test.describe('Attendance Data Validation', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login');
  });

  test('Validate daily attendance data and generate report', async ({ page }) => {
    // Login as attendance manager
    await page.fill('[data-testid="username-input"]', 'attendance.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager@123');
    await page.click('[data-testid="login-button"]');
    
    // Wait for dashboard to load
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();
    
    // Action: Trigger daily validation job
    await page.click('[data-testid="validation-menu"]');
    await page.click('[data-testid="trigger-validation-button"]');
    
    // Expected Result: Validation completes without errors
    await expect(page.locator('[data-testid="validation-status"]')).toContainText('Validation completed successfully', { timeout: 30000 });
    await expect(page.locator('[data-testid="validation-error-count"]')).toContainText('0 errors');
    
    // Action: Access validation report via dashboard
    await page.click('[data-testid="view-validation-report-button"]');
    
    // Expected Result: Report displays anomalies and summary
    await expect(page.locator('[data-testid="validation-report-title"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-summary-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="anomalies-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="missing-punches-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="duplicate-entries-count"]')).toBeVisible();
    
    // Action: Verify notification sent to attendance manager
    await page.click('[data-testid="notifications-icon"]');
    
    // Expected Result: Notification received promptly
    await expect(page.locator('[data-testid="notification-list"]')).toBeVisible();
    const latestNotification = page.locator('[data-testid="notification-item"]').first();
    await expect(latestNotification).toContainText('Daily validation completed');
    await expect(latestNotification).toContainText('Attendance validation report is ready');
    
    // Verify notification timestamp is recent (within last 5 minutes)
    const notificationTime = await latestNotification.locator('[data-testid="notification-timestamp"]').textContent();
    expect(notificationTime).toBeTruthy();
  });

  test('Restrict validation report access to authorized users', async ({ page }) => {
    // Action: Login as unauthorized user
    await page.fill('[data-testid="username-input"]', 'regular.employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Employee@123');
    await page.click('[data-testid="login-button"]');
    
    // Wait for dashboard to load
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();
    
    // Expected Result: Access to validation report denied
    const validationMenuExists = await page.locator('[data-testid="validation-menu"]').count();
    expect(validationMenuExists).toBe(0);
    
    // Attempt direct URL access
    await page.goto('/attendance/validation-report');
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    await expect(page.locator('[data-testid="error-description"]')).toContainText('You do not have permission to access this resource');
    
    // Logout
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Action: Login as attendance manager
    await page.fill('[data-testid="username-input"]', 'attendance.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager@123');
    await page.click('[data-testid="login-button"]');
    
    // Wait for dashboard to load
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();
    
    // Expected Result: Access granted to validation report
    await expect(page.locator('[data-testid="validation-menu"]')).toBeVisible();
    await page.click('[data-testid="validation-menu"]');
    await page.click('[data-testid="view-validation-report-button"]');
    
    await expect(page.locator('[data-testid="validation-report-title"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-summary-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-data-table"]')).toBeVisible();
  });

  test('Review audit logs for attendance data changes (happy-path)', async ({ page }) => {
    // Navigate to the audit portal login page
    await page.goto('/audit/login');
    
    // Enter valid system auditor credentials and click Login button
    await page.fill('[data-testid="username-input"]', 'system.auditor@company.com');
    await page.fill('[data-testid="password-input"]', 'Auditor@123');
    await page.click('[data-testid="login-button"]');
    
    // Verify audit log interface displays available search criteria
    await expect(page.locator('[data-testid="audit-log-interface"]')).toBeVisible();
    await expect(page.locator('[data-testid="user-filter-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-filter-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="action-type-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="timestamp-filter"]')).toBeVisible();
    
    // Enter specific user name in the user filter field
    await page.fill('[data-testid="user-filter-field"]', 'john.doe@company.com');
    
    // Select a date range using the date filter (e.g., last 7 days)
    await page.click('[data-testid="date-filter-field"]');
    await page.click('[data-testid="date-range-preset-7days"]');
    
    // Click Search or Apply Filters button
    await page.click('[data-testid="apply-filters-button"]');
    
    // Review the displayed audit records for completeness
    await expect(page.locator('[data-testid="audit-records-table"]')).toBeVisible();
    const auditRecords = page.locator('[data-testid="audit-record-row"]');
    await expect(auditRecords.first()).toBeVisible();
    
    // Verify all required fields are present
    await expect(page.locator('[data-testid="audit-record-user"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="audit-record-date"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="audit-record-action"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="audit-record-timestamp"]').first()).toBeVisible();
    
    // Click on Export button and select export format
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-format-menu"]')).toBeVisible();
    
    // Select CSV format and confirm export
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-option"]');
    const download = await downloadPromise;
    
    // Verify download initiated
    expect(download.suggestedFilename()).toContain('.csv');
    
    // Save and verify file
    const path = await download.path();
    expect(path).toBeTruthy();
  });

  test('Prevent unauthorized access to audit logs (error-case)', async ({ page }) => {
    // Navigate to the audit portal login page
    await page.goto('/audit/login');
    
    // Enter valid non-auditor user credentials
    await page.fill('[data-testid="username-input"]', 'regular.employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Employee@123');
    
    // Click Login button
    await page.click('[data-testid="login-button"]');
    
    // Verify user is not redirected to audit log interface
    await page.waitForLoadState('networkidle');
    const currentUrl = page.url();
    expect(currentUrl).not.toContain('/audit/logs');
    expect(currentUrl).not.toContain('/audit/interface');
    
    // Verify audit log interface is not visible
    const auditInterfaceExists = await page.locator('[data-testid="audit-log-interface"]').count();
    expect(auditInterfaceExists).toBe(0);
    
    // Attempt to access audit log URL directly by typing the endpoint URL in browser
    await page.goto('/audit/logs');
    
    // Verify no audit log data is visible or accessible
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    
    const auditDataExists = await page.locator('[data-testid="audit-records-table"]').count();
    expect(auditDataExists).toBe(0);
    
    const auditRecordsExists = await page.locator('[data-testid="audit-record-row"]').count();
    expect(auditRecordsExists).toBe(0);
    
    // Verify error message or redirect to unauthorized page
    const unauthorizedIndicators = [
      page.locator('[data-testid="unauthorized-page"]'),
      page.locator('text=Unauthorized'),
      page.locator('text=403'),
      page.locator('[data-testid="permission-error"]')
    ];
    
    let foundUnauthorizedIndicator = false;
    for (const indicator of unauthorizedIndicators) {
      const count = await indicator.count();
      if (count > 0) {
        foundUnauthorizedIndicator = true;
        break;
      }
    }
    
    expect(foundUnauthorizedIndicator).toBe(true);
  });
});