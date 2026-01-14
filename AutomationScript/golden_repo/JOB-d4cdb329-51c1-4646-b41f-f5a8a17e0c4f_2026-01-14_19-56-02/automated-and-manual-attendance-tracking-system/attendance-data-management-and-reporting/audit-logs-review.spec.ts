import { test, expect } from '@playwright/test';

test.describe('Story-5: Audit Logs Review and Compliance', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const AUDITOR_EMAIL = 'auditor@company.com';
  const AUDITOR_PASSWORD = 'AuditorPass123!';
  const NON_AUDITOR_EMAIL = 'hranalyst@company.com';
  const NON_AUDITOR_PASSWORD = 'HRPass123!';
  const MANUAL_ENTRY_USER_EMAIL = 'supervisor@company.com';
  const MANUAL_ENTRY_USER_PASSWORD = 'SupervisorPass123!';
  const TEST_EMPLOYEE_ID = 'EMP12345';
  const TEST_EMPLOYEE_NAME = 'John Doe';

  test('Verify audit logging of attendance events (happy-path)', async ({ page }) => {
    // Step 1: Perform a biometric attendance capture
    await page.goto(`${BASE_URL}/biometric-capture`);
    await page.fill('[data-testid="employee-id-input"]', TEST_EMPLOYEE_ID);
    await page.click('[data-testid="simulate-fingerprint-scan"]');
    await expect(page.locator('[data-testid="capture-success-message"]')).toBeVisible();
    const biometricTimestamp = new Date().toISOString();

    // Step 2: Login as System Auditor and navigate to audit log interface
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', AUDITOR_EMAIL);
    await page.fill('[data-testid="password-input"]', AUDITOR_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 3: Navigate to audit logs
    await page.click('[data-testid="audit-logs-menu"]');
    await expect(page.locator('[data-testid="audit-log-interface"]')).toBeVisible();

    // Step 4: Search for the most recent biometric attendance audit log
    await page.fill('[data-testid="employee-filter"]', TEST_EMPLOYEE_ID);
    await page.selectOption('[data-testid="action-type-filter"]', 'biometric_capture');
    await page.click('[data-testid="search-button"]');
    await page.waitForSelector('[data-testid="audit-log-results"]');

    // Step 5: Verify audit log entry contains required metadata
    const firstLogEntry = page.locator('[data-testid="audit-log-row"]').first();
    await expect(firstLogEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(firstLogEntry.locator('[data-testid="log-employee-id"]')).toContainText(TEST_EMPLOYEE_ID);
    await expect(firstLogEntry.locator('[data-testid="log-action-type"]')).toContainText('biometric_capture');
    await expect(firstLogEntry.locator('[data-testid="log-ip-address"]')).toBeVisible();
    await expect(firstLogEntry.locator('[data-testid="log-device-info"]')).toBeVisible();

    // Step 6: Logout and login as manual attendance entry user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', MANUAL_ENTRY_USER_EMAIL);
    await page.fill('[data-testid="password-input"]', MANUAL_ENTRY_USER_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Step 7: Add manual attendance entry
    await page.click('[data-testid="manual-attendance-menu"]');
    await page.click('[data-testid="add-manual-entry-button"]');
    await page.fill('[data-testid="manual-employee-id"]', TEST_EMPLOYEE_ID);
    await page.fill('[data-testid="manual-date"]', '2024-01-15');
    await page.fill('[data-testid="manual-checkin-time"]', '09:00');
    await page.fill('[data-testid="manual-reason"]', 'Biometric device malfunction');
    await page.click('[data-testid="save-manual-entry"]');
    await expect(page.locator('[data-testid="success-notification"]')).toBeVisible();

    // Step 8: Login again as System Auditor
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', AUDITOR_EMAIL);
    await page.fill('[data-testid="password-input"]', AUDITOR_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Step 9: Search for manual attendance entry audit log
    await page.click('[data-testid="audit-logs-menu"]');
    await page.fill('[data-testid="employee-filter"]', TEST_EMPLOYEE_ID);
    await page.selectOption('[data-testid="action-type-filter"]', 'manual_entry_created');
    await page.click('[data-testid="search-button"]');
    await page.waitForSelector('[data-testid="audit-log-results"]');
    const manualEntryLog = page.locator('[data-testid="audit-log-row"]').first();
    await expect(manualEntryLog.locator('[data-testid="log-action-type"]')).toContainText('manual_entry_created');
    await expect(manualEntryLog.locator('[data-testid="log-user-id"]')).toBeVisible();

    // Step 10: Logout and login as manual entry user to edit entry
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', MANUAL_ENTRY_USER_EMAIL);
    await page.fill('[data-testid="password-input"]', MANUAL_ENTRY_USER_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Step 11: Edit manual attendance entry
    await page.click('[data-testid="manual-attendance-menu"]');
    await page.fill('[data-testid="search-employee"]', TEST_EMPLOYEE_ID);
    await page.click('[data-testid="search-entries-button"]');
    await page.locator('[data-testid="edit-entry-button"]').first().click();
    await page.fill('[data-testid="manual-checkin-time"]', '09:15');
    await page.click('[data-testid="save-manual-entry"]');
    await expect(page.locator('[data-testid="success-notification"]')).toBeVisible();

    // Step 12: Login as auditor and verify modification log
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', AUDITOR_EMAIL);
    await page.fill('[data-testid="password-input"]', AUDITOR_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.click('[data-testid="audit-logs-menu"]');
    await page.fill('[data-testid="employee-filter"]', TEST_EMPLOYEE_ID);
    await page.selectOption('[data-testid="action-type-filter"]', 'manual_entry_modified');
    await page.click('[data-testid="search-button"]');
    await page.waitForSelector('[data-testid="audit-log-results"]');

    // Step 13: Verify all three audit log entries contain complete traceability
    await page.selectOption('[data-testid="action-type-filter"]', 'all');
    await page.click('[data-testid="search-button"]');
    const allLogs = page.locator('[data-testid="audit-log-row"]');
    await expect(allLogs).toHaveCount(3, { timeout: 10000 });
    
    for (let i = 0; i < 3; i++) {
      const logRow = allLogs.nth(i);
      await expect(logRow.locator('[data-testid="log-timestamp"]')).toBeVisible();
      await expect(logRow.locator('[data-testid="log-employee-id"]')).toContainText(TEST_EMPLOYEE_ID);
      await expect(logRow.locator('[data-testid="log-action-type"]')).toBeVisible();
    }
  });

  test('Search and export audit logs (happy-path)', async ({ page }) => {
    // Step 1: Open audit portal and login as System Auditor
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', AUDITOR_EMAIL);
    await page.fill('[data-testid="password-input"]', AUDITOR_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Step 2: Verify access granted to audit log interface
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    await page.click('[data-testid="audit-logs-menu"]');
    await expect(page.locator('[data-testid="audit-log-interface"]')).toBeVisible();

    // Step 3: Select specific employee from filter dropdown
    await page.click('[data-testid="employee-filter-dropdown"]');
    await page.fill('[data-testid="employee-search-input"]', TEST_EMPLOYEE_NAME);
    await page.click(`[data-testid="employee-option-${TEST_EMPLOYEE_ID}"]`);

    // Step 4: Enter date range filter
    await page.fill('[data-testid="start-date-filter"]', '2024-01-01');
    await page.fill('[data-testid="end-date-filter"]', '2024-01-31');

    // Step 5: Click search and measure response time
    const searchStartTime = Date.now();
    await page.click('[data-testid="search-button"]');
    await page.waitForSelector('[data-testid="audit-log-results"]', { state: 'visible' });
    const searchEndTime = Date.now();
    const searchDuration = searchEndTime - searchStartTime;

    // Step 6: Verify search results display within 5 seconds
    expect(searchDuration).toBeLessThan(5000);

    // Step 7: Verify search results match filters
    const resultRows = page.locator('[data-testid="audit-log-row"]');
    await expect(resultRows.first()).toBeVisible();
    const firstResult = resultRows.first();
    await expect(firstResult.locator('[data-testid="log-employee-id"]')).toContainText(TEST_EMPLOYEE_ID);

    // Step 8: Review displayed audit log entries for completeness
    await expect(firstResult.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(firstResult.locator('[data-testid="log-action-type"]')).toBeVisible();
    await expect(firstResult.locator('[data-testid="log-user-id"]')).toBeVisible();
    await expect(firstResult.locator('[data-testid="log-details"]')).toBeVisible();

    // Step 9: Export to CSV
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-button"]');
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.csv');

    // Step 10: Verify CSV file downloaded and contains correct data
    const path = await download.path();
    expect(path).toBeTruthy();
    
    // Read and verify CSV content
    const fs = require('fs');
    const csvContent = fs.readFileSync(path, 'utf-8');
    expect(csvContent).toContain('timestamp');
    expect(csvContent).toContain('event type');
    expect(csvContent).toContain('user ID');
    expect(csvContent).toContain('employee ID');
    expect(csvContent).toContain('action details');
    expect(csvContent).toContain('IP address');
    expect(csvContent).toContain('device info');
    expect(csvContent).toContain(TEST_EMPLOYEE_ID);
  });

  test('Restrict audit log access to authorized users (error-case)', async ({ page, context }) => {
    // Step 1: Login as non-auditor user
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', NON_AUDITOR_EMAIL);
    await page.fill('[data-testid="password-input"]', NON_AUDITOR_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 2: Verify no audit log menu option visible
    const auditLogMenu = page.locator('[data-testid="audit-logs-menu"]');
    await expect(auditLogMenu).not.toBeVisible();

    // Step 3: Attempt to navigate directly to audit logs URL
    await page.goto(`${BASE_URL}/audit-logs`);
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('text=Access Denied')).toBeVisible();

    // Step 4: Attempt to access audit log API endpoint directly
    const apiResponse = await page.request.get(`${BASE_URL}/api/audit/logs`);
    expect(apiResponse.status()).toBe(403);
    const responseBody = await apiResponse.json();
    expect(responseBody.error).toContain('Unauthorized');

    // Step 5: Attempt API access with parameters
    const apiResponseWithParams = await page.request.get(`${BASE_URL}/api/audit/logs?employee=123&date=2024-01-01`);
    expect(apiResponseWithParams.status()).toBe(403);
    const responseBodyWithParams = await apiResponseWithParams.json();
    expect(responseBodyWithParams.error).toContain('Unauthorized');

    // Step 6: Logout and login as System Auditor
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', AUDITOR_EMAIL);
    await page.fill('[data-testid="password-input"]', AUDITOR_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Step 7: Verify System Auditor can access audit logs
    await page.click('[data-testid="audit-logs-menu"]');
    await expect(page.locator('[data-testid="audit-log-interface"]')).toBeVisible();

    // Step 8: Verify auditor can search audit logs
    await page.fill('[data-testid="employee-filter"]', TEST_EMPLOYEE_ID);
    await page.click('[data-testid="search-button"]');
    await expect(page.locator('[data-testid="audit-log-results"]')).toBeVisible();

    // Step 9: Verify API access works for auditor
    const auditorApiResponse = await page.request.get(`${BASE_URL}/api/audit/logs`);
    expect(auditorApiResponse.status()).toBe(200);
    const auditorResponseBody = await auditorApiResponse.json();
    expect(auditorResponseBody.logs).toBeDefined();
    expect(Array.isArray(auditorResponseBody.logs)).toBe(true);

    // Step 10: Check system logs for unauthorized access attempts
    await page.fill('[data-testid="employee-filter"]', '');
    await page.selectOption('[data-testid="action-type-filter"]', 'unauthorized_access_attempt');
    await page.fill('[data-testid="start-date-filter"]', new Date().toISOString().split('T')[0]);
    await page.click('[data-testid="search-button"]');
    
    const unauthorizedAttempts = page.locator('[data-testid="audit-log-row"]');
    await expect(unauthorizedAttempts.first()).toBeVisible({ timeout: 10000 });
    const firstAttempt = unauthorizedAttempts.first();
    await expect(firstAttempt.locator('[data-testid="log-user-id"]')).toContainText(NON_AUDITOR_EMAIL);
    await expect(firstAttempt.locator('[data-testid="log-action-type"]')).toContainText('unauthorized_access');
  });
});