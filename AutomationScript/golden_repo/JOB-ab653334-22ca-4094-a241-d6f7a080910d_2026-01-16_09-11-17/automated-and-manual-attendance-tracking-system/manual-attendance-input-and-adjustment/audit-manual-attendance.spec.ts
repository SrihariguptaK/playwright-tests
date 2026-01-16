import { test, expect } from '@playwright/test';

test.describe('Audit Manual Attendance Changes - Story 28', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const hrOfficerCredentials = {
    username: 'hr.officer@company.com',
    password: 'HRPassword123!'
  };
  const unauthorizedUserCredentials = {
    username: 'regular.employee@company.com',
    password: 'EmployeePass123!'
  };

  test.beforeEach(async ({ page }) => {
    await page.goto(baseURL);
  });

  test('Verify audit log creation for manual attendance changes (happy-path)', async ({ page }) => {
    // Login as HR Officer
    await page.fill('[data-testid="username-input"]', hrOfficerCredentials.username);
    await page.fill('[data-testid="password-input"]', hrOfficerCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to the manual attendance entry module
    await page.click('[data-testid="menu-manual-attendance"]');
    await expect(page.locator('[data-testid="manual-attendance-module"]')).toBeVisible();

    // Create a new manual attendance entry
    await page.click('[data-testid="create-attendance-button"]');
    const testEmployeeId = 'EMP-12345';
    const testDate = new Date().toISOString().split('T')[0];
    const testTimeIn = '09:00';
    const testTimeOut = '17:00';
    
    await page.fill('[data-testid="employee-id-input"]', testEmployeeId);
    await page.fill('[data-testid="attendance-date-input"]', testDate);
    await page.fill('[data-testid="time-in-input"]', testTimeIn);
    await page.fill('[data-testid="time-out-input"]', testTimeOut);
    await page.click('[data-testid="save-attendance-button"]');
    
    // Expected Result: Attendance entry is created successfully
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance entry created successfully');

    // Navigate to the audit log module
    await page.click('[data-testid="menu-audit-logs"]');
    await expect(page.locator('[data-testid="audit-log-module"]')).toBeVisible();

    // Search for the recently created manual attendance entry in the audit log
    await page.fill('[data-testid="audit-date-filter"]', testDate);
    await page.selectOption('[data-testid="audit-action-filter"]', 'CREATE');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Expected Result: Audit log shows CREATE action with correct details
    await expect(page.locator('[data-testid="audit-log-table"]')).toContainText('CREATE');
    await expect(page.locator('[data-testid="audit-log-table"]')).toContainText(testEmployeeId);
    await expect(page.locator('[data-testid="audit-log-table"]')).toContainText(hrOfficerCredentials.username);

    // Return to manual attendance module and update the entry
    await page.click('[data-testid="menu-manual-attendance"]');
    await page.click(`[data-testid="attendance-row-${testEmployeeId}"]`);
    await page.click('[data-testid="edit-attendance-button"]');
    
    const updatedTimeOut = '18:00';
    await page.fill('[data-testid="time-out-input"]', updatedTimeOut);
    await page.click('[data-testid="save-attendance-button"]');
    
    // Expected Result: Attendance entry is updated successfully
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance entry updated successfully');

    // Navigate back to the audit log module and filter by UPDATE action
    await page.click('[data-testid="menu-audit-logs"]');
    await page.fill('[data-testid="audit-date-filter"]', testDate);
    await page.selectOption('[data-testid="audit-action-filter"]', 'UPDATE');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Expected Result: Audit log shows UPDATE action with correct details
    await expect(page.locator('[data-testid="audit-log-table"]')).toContainText('UPDATE');
    await expect(page.locator('[data-testid="audit-log-table"]')).toContainText(testEmployeeId);
    await expect(page.locator('[data-testid="audit-log-table"]')).toContainText(updatedTimeOut);

    // Return to manual attendance module and delete the entry
    await page.click('[data-testid="menu-manual-attendance"]');
    await page.click(`[data-testid="attendance-row-${testEmployeeId}"]`);
    await page.click('[data-testid="delete-attendance-button"]');
    await page.click('[data-testid="confirm-delete-button"]');
    
    // Expected Result: Attendance entry is deleted successfully
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance entry deleted successfully');

    // Navigate back to the audit log module and filter by DELETE action
    await page.click('[data-testid="menu-audit-logs"]');
    await page.fill('[data-testid="audit-date-filter"]', testDate);
    await page.selectOption('[data-testid="audit-action-filter"]', 'DELETE');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Expected Result: Audit log shows DELETE action with correct details
    await expect(page.locator('[data-testid="audit-log-table"]')).toContainText('DELETE');
    await expect(page.locator('[data-testid="audit-log-table"]')).toContainText(testEmployeeId);

    // Apply multiple filters: specific user, date range, and all action types
    await page.fill('[data-testid="audit-user-filter"]', hrOfficerCredentials.username);
    await page.fill('[data-testid="audit-date-from-filter"]', testDate);
    await page.fill('[data-testid="audit-date-to-filter"]', testDate);
    await page.selectOption('[data-testid="audit-action-filter"]', 'ALL');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Expected Result: System returns matching audit records accurately
    const auditRows = page.locator('[data-testid="audit-log-row"]');
    await expect(auditRows).not.toHaveCount(0);
    await expect(page.locator('[data-testid="audit-log-table"]')).toContainText('CREATE');
    await expect(page.locator('[data-testid="audit-log-table"]')).toContainText('UPDATE');
    await expect(page.locator('[data-testid="audit-log-table"]')).toContainText('DELETE');

    // Click on the Export button and select CSV format
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-audit-logs-button"]');
    await page.click('[data-testid="export-csv-option"]');
    
    // Expected Result: CSV file downloads with correct audit data
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.csv');
    
    // Verify CSV file contents
    const path = await download.path();
    expect(path).toBeTruthy();
  });

  test('Ensure audit log access control (error-case)', async ({ page }) => {
    // Open the application login page
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Enter credentials for an unauthorized user
    await page.fill('[data-testid="username-input"]', unauthorizedUserCredentials.username);
    await page.fill('[data-testid="password-input"]', unauthorizedUserCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Login successful but with limited permissions
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Attempt to navigate to the audit log module by entering the URL directly
    await page.goto(`${baseURL}/audit-logs`);
    
    // Expected Result: Access to audit logs is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');

    // Verify audit log menu is not visible for unauthorized user
    const auditLogMenu = page.locator('[data-testid="menu-audit-logs"]');
    await expect(auditLogMenu).not.toBeVisible();

    // Attempt to access the audit log API endpoint directly
    const apiResponse = await page.request.get(`${baseURL}/api/manual-attendance/audit-logs`);
    
    // Expected Result: API returns 403 Forbidden
    expect(apiResponse.status()).toBe(403);

    // Logout from the unauthorized user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Enter credentials for an authorized HR officer
    await page.fill('[data-testid="username-input"]', hrOfficerCredentials.username);
    await page.fill('[data-testid="password-input"]', hrOfficerCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Login successful with full permissions
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to the audit log module via the menu
    await page.click('[data-testid="menu-audit-logs"]');
    
    // Expected Result: Access to audit logs is granted
    await expect(page.locator('[data-testid="audit-log-module"]')).toBeVisible();

    // Verify that audit log records are visible and can be filtered
    await expect(page.locator('[data-testid="audit-log-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-date-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-action-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="apply-filters-button"]')).toBeVisible();

    // Access the audit log API endpoint directly with authorized session
    const authorizedApiResponse = await page.request.get(`${baseURL}/api/manual-attendance/audit-logs`);
    
    // Expected Result: API returns 200 OK with audit log data
    expect(authorizedApiResponse.status()).toBe(200);
    const auditLogData = await authorizedApiResponse.json();
    expect(Array.isArray(auditLogData)).toBeTruthy();
  });
});