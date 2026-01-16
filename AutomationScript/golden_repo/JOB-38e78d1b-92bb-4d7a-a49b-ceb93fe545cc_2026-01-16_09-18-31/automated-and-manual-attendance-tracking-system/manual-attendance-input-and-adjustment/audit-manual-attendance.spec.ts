import { test, expect } from '@playwright/test';

test.describe('Audit Manual Attendance Changes', () => {
  let testEmployeeId: string;
  let testAttendanceId: string;
  let testDate: string;

  test.beforeEach(async ({ page }) => {
    testDate = new Date().toISOString().split('T')[0];
    testEmployeeId = 'EMP001';
  });

  test('Verify audit log creation for manual attendance changes (happy-path)', async ({ page }) => {
    // Login as authorized HR officer
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'hr.officer@company.com');
    await page.fill('[data-testid="password-input"]', 'HRPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the manual attendance entry module
    await page.click('[data-testid="menu-manual-attendance"]');
    await expect(page.locator('[data-testid="manual-attendance-page"]')).toBeVisible();

    // Create a new manual attendance entry for an employee
    await page.click('[data-testid="create-attendance-button"]');
    await page.fill('[data-testid="employee-id-input"]', testEmployeeId);
    await page.fill('[data-testid="attendance-date-input"]', testDate);
    await page.fill('[data-testid="time-in-input"]', '09:00');
    await page.fill('[data-testid="time-out-input"]', '17:00');
    await page.click('[data-testid="save-attendance-button"]');
    
    // Wait for success message and capture attendance ID
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    const attendanceRow = page.locator(`[data-testid="attendance-row-${testEmployeeId}"]`).first();
    testAttendanceId = await attendanceRow.getAttribute('data-attendance-id') || '';

    // Navigate to the audit log module
    await page.click('[data-testid="menu-audit-logs"]');
    await expect(page.locator('[data-testid="audit-log-page"]')).toBeVisible();

    // Search for the recently created manual attendance entry in the audit log
    await page.fill('[data-testid="filter-date-input"]', testDate);
    await page.selectOption('[data-testid="filter-action-select"]', 'CREATE');
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForTimeout(1000);

    // Expected Result: Audit logs are generated for CREATE action with correct details
    const createLogRow = page.locator('[data-testid="audit-log-row"]').filter({ hasText: 'CREATE' }).first();
    await expect(createLogRow).toBeVisible();
    await expect(createLogRow).toContainText(testEmployeeId);
    await expect(createLogRow).toContainText(testDate);
    await expect(createLogRow).toContainText('hr.officer@company.com');

    // Return to manual attendance module and update the previously created attendance entry
    await page.click('[data-testid="menu-manual-attendance"]');
    await page.locator(`[data-testid="edit-attendance-${testAttendanceId}"]`).click();
    await page.fill('[data-testid="time-out-input"]', '18:00');
    await page.click('[data-testid="save-attendance-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Navigate back to the audit log module and filter by UPDATE action
    await page.click('[data-testid="menu-audit-logs"]');
    await page.fill('[data-testid="filter-date-input"]', testDate);
    await page.selectOption('[data-testid="filter-action-select"]', 'UPDATE');
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForTimeout(1000);

    // Expected Result: Audit logs are generated for UPDATE action with correct details
    const updateLogRow = page.locator('[data-testid="audit-log-row"]').filter({ hasText: 'UPDATE' }).first();
    await expect(updateLogRow).toBeVisible();
    await expect(updateLogRow).toContainText(testEmployeeId);
    await expect(updateLogRow).toContainText('18:00');

    // Return to manual attendance module and delete the previously created attendance entry
    await page.click('[data-testid="menu-manual-attendance"]');
    await page.locator(`[data-testid="delete-attendance-${testAttendanceId}"]`).click();
    await page.click('[data-testid="confirm-delete-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Navigate back to the audit log module and filter by DELETE action
    await page.click('[data-testid="menu-audit-logs"]');
    await page.fill('[data-testid="filter-date-input"]', testDate);
    await page.selectOption('[data-testid="filter-action-select"]', 'DELETE');
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForTimeout(1000);

    // Expected Result: Audit logs are generated for DELETE action with correct details
    const deleteLogRow = page.locator('[data-testid="audit-log-row"]').filter({ hasText: 'DELETE' }).first();
    await expect(deleteLogRow).toBeVisible();
    await expect(deleteLogRow).toContainText(testEmployeeId);

    // Apply multiple filters in the audit log
    await page.fill('[data-testid="filter-user-input"]', 'hr.officer@company.com');
    await page.fill('[data-testid="filter-date-from-input"]', testDate);
    await page.fill('[data-testid="filter-date-to-input"]', testDate);
    await page.selectOption('[data-testid="filter-action-select"]', 'ALL');
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForTimeout(1000);

    // Expected Result: System returns matching audit records accurately
    const allLogRows = page.locator('[data-testid="audit-log-row"]');
    await expect(allLogRows).toHaveCount(3);
    await expect(page.locator('[data-testid="audit-log-row"]').filter({ hasText: 'CREATE' })).toBeVisible();
    await expect(page.locator('[data-testid="audit-log-row"]').filter({ hasText: 'UPDATE' })).toBeVisible();
    await expect(page.locator('[data-testid="audit-log-row"]').filter({ hasText: 'DELETE' })).toBeVisible();

    // Click on the Export button and select CSV format
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-csv-option"]');
    const download = await downloadPromise;

    // Expected Result: CSV file downloads with correct audit data
    expect(download.suggestedFilename()).toContain('.csv');
    const path = await download.path();
    expect(path).toBeTruthy();
  });

  test('Ensure audit log access control (error-case)', async ({ page }) => {
    // Open the application login page
    await page.goto('/login');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Enter credentials for an unauthorized user (regular employee)
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Attempt to navigate to the audit log module via menu
    const auditLogMenuItem = page.locator('[data-testid="menu-audit-logs"]');
    
    // Expected Result: Access to audit logs is denied (menu item not visible or disabled)
    if (await auditLogMenuItem.isVisible()) {
      await expect(auditLogMenuItem).toBeDisabled();
    } else {
      await expect(auditLogMenuItem).not.toBeVisible();
    }

    // Attempt to access the audit log URL directly
    await page.goto('/audit-logs');
    
    // Expected Result: Access denied - redirected or error message shown
    const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
    const unauthorizedMessage = page.locator('text=/unauthorized|access denied|forbidden/i');
    
    if (await accessDeniedMessage.isVisible()) {
      await expect(accessDeniedMessage).toBeVisible();
    } else if (await unauthorizedMessage.isVisible()) {
      await expect(unauthorizedMessage).toBeVisible();
    } else {
      await expect(page).not.toHaveURL(/.*audit-logs/);
    }

    // Attempt to access the audit log API endpoint directly
    const apiResponse = await page.request.get('/api/manual-attendance/audit-logs');
    
    // Expected Result: API returns 403 Forbidden or 401 Unauthorized
    expect([401, 403]).toContain(apiResponse.status());

    // Log out from the unauthorized user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Enter credentials for an authorized HR officer
    await page.fill('[data-testid="username-input"]', 'hr.officer@company.com');
    await page.fill('[data-testid="password-input"]', 'HRPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the audit log module via the menu
    await page.click('[data-testid="menu-audit-logs"]');
    
    // Expected Result: Access to audit logs is granted
    await expect(page.locator('[data-testid="audit-log-page"]')).toBeVisible();
    await expect(page).toHaveURL(/.*audit-logs/);

    // Verify that audit log records are visible and can be filtered
    await expect(page.locator('[data-testid="filter-date-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="filter-user-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="filter-action-select"]')).toBeVisible();
    
    // Apply filters to verify functionality
    await page.fill('[data-testid="filter-date-input"]', testDate);
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForTimeout(1000);
    
    // Verify audit log records are displayed
    const auditLogTable = page.locator('[data-testid="audit-log-table"]');
    await expect(auditLogTable).toBeVisible();

    // Access the audit log API endpoint directly with authorized session
    const authorizedApiResponse = await page.request.get('/api/manual-attendance/audit-logs');
    
    // Expected Result: API returns 200 OK with audit log data
    expect(authorizedApiResponse.status()).toBe(200);
    const responseBody = await authorizedApiResponse.json();
    expect(Array.isArray(responseBody) || responseBody.data).toBeTruthy();
  });
});