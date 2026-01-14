import { test, expect } from '@playwright/test';

test.describe('Audit Attendance Data Changes', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const attendanceManagerCredentials = {
    username: 'attendance.manager@company.com',
    password: 'AttendanceManager123!'
  };
  const unauthorizedUserCredentials = {
    username: 'regular.employee@company.com',
    password: 'Employee123!'
  };

  test('Verify audit logging of attendance data changes (happy-path)', async ({ page }) => {
    // Login as Attendance Manager
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', attendanceManagerCredentials.username);
    await page.fill('[data-testid="password-input"]', attendanceManagerCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the manual attendance entry page
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="manual-entry-link"]');
    await expect(page.locator('[data-testid="manual-attendance-form"]')).toBeVisible();

    // Create a new manual attendance entry
    const employeeName = 'John Doe';
    const todayDate = new Date().toISOString().split('T')[0];
    await page.click('[data-testid="employee-select"]');
    await page.click(`[data-testid="employee-option-${employeeName}"]`);
    await page.fill('[data-testid="attendance-date-input"]', todayDate);
    await page.fill('[data-testid="check-in-time-input"]', '09:00');
    await page.fill('[data-testid="check-out-time-input"]', '17:00');
    await page.click('[data-testid="save-attendance-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance entry created successfully');

    // Navigate to the audit log interface and search for the most recent create action
    await page.click('[data-testid="audit-menu"]');
    await page.click('[data-testid="audit-logs-link"]');
    await expect(page.locator('[data-testid="audit-log-interface"]')).toBeVisible();
    await page.fill('[data-testid="search-employee-input"]', employeeName);
    await page.selectOption('[data-testid="action-type-filter"]', 'CREATE');
    await page.click('[data-testid="search-button"]');
    await page.waitForTimeout(1000);
    
    // Expected Result: Audit log entry created with create action
    const createLogEntry = page.locator('[data-testid="audit-log-row"]').first();
    await expect(createLogEntry).toBeVisible();
    await expect(createLogEntry.locator('[data-testid="action-type"]')).toContainText('CREATE');
    await expect(createLogEntry.locator('[data-testid="user-id"]')).toBeVisible();
    await expect(createLogEntry.locator('[data-testid="username"]')).toContainText(attendanceManagerCredentials.username);
    await expect(createLogEntry.locator('[data-testid="ip-address"]')).toBeVisible();
    await expect(createLogEntry.locator('[data-testid="session-id"]')).toBeVisible();

    // Navigate back to attendance records and update the entry
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="attendance-records-link"]');
    await page.fill('[data-testid="search-employee-input"]', employeeName);
    await page.click('[data-testid="search-button"]');
    const attendanceRow = page.locator('[data-testid="attendance-row"]').first();
    await attendanceRow.locator('[data-testid="edit-button"]').click();
    await page.fill('[data-testid="check-out-time-input"]', '18:00');
    await page.click('[data-testid="save-attendance-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance entry updated successfully');

    // Return to the audit log interface and search for the most recent update action
    await page.click('[data-testid="audit-menu"]');
    await page.click('[data-testid="audit-logs-link"]');
    await page.fill('[data-testid="search-employee-input"]', employeeName);
    await page.selectOption('[data-testid="action-type-filter"]', 'UPDATE');
    await page.click('[data-testid="search-button"]');
    await page.waitForTimeout(1000);
    
    // Expected Result: Audit log entry created with update action
    const updateLogEntry = page.locator('[data-testid="audit-log-row"]').first();
    await expect(updateLogEntry).toBeVisible();
    await expect(updateLogEntry.locator('[data-testid="action-type"]')).toContainText('UPDATE');
    await expect(updateLogEntry.locator('[data-testid="user-id"]')).toBeVisible();
    await expect(updateLogEntry.locator('[data-testid="username"]')).toContainText(attendanceManagerCredentials.username);
    await expect(updateLogEntry.locator('[data-testid="ip-address"]')).toBeVisible();
    await expect(updateLogEntry.locator('[data-testid="session-id"]')).toBeVisible();

    // Navigate back to attendance records and delete the entry
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="attendance-records-link"]');
    await page.fill('[data-testid="search-employee-input"]', employeeName);
    await page.click('[data-testid="search-button"]');
    const attendanceRowToDelete = page.locator('[data-testid="attendance-row"]').first();
    await attendanceRowToDelete.locator('[data-testid="delete-button"]').click();
    await page.click('[data-testid="confirm-delete-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance entry deleted successfully');

    // Return to the audit log interface and search for the most recent delete action
    await page.click('[data-testid="audit-menu"]');
    await page.click('[data-testid="audit-logs-link"]');
    await page.fill('[data-testid="search-employee-input"]', employeeName);
    await page.selectOption('[data-testid="action-type-filter"]', 'DELETE');
    await page.click('[data-testid="search-button"]');
    await page.waitForTimeout(1000);
    
    // Expected Result: Audit log entry created with delete action
    const deleteLogEntry = page.locator('[data-testid="audit-log-row"]').first();
    await expect(deleteLogEntry).toBeVisible();
    await expect(deleteLogEntry.locator('[data-testid="action-type"]')).toContainText('DELETE');
    await expect(deleteLogEntry.locator('[data-testid="user-id"]')).toBeVisible();
    await expect(deleteLogEntry.locator('[data-testid="username"]')).toContainText(attendanceManagerCredentials.username);
    await expect(deleteLogEntry.locator('[data-testid="ip-address"]')).toBeVisible();
    await expect(deleteLogEntry.locator('[data-testid="session-id"]')).toBeVisible();

    // Verify all three audit log entries contain complete metadata
    await page.selectOption('[data-testid="action-type-filter"]', 'ALL');
    await page.click('[data-testid="search-button"]');
    await page.waitForTimeout(1000);
    const allLogEntries = page.locator('[data-testid="audit-log-row"]');
    await expect(allLogEntries).toHaveCount(3);
  });

  test('Search and export attendance audit logs (happy-path)', async ({ page }) => {
    // Navigate to the system login page and login as Attendance Manager
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', attendanceManagerCredentials.username);
    await page.fill('[data-testid="password-input"]', attendanceManagerCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access granted to audit log interface
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="welcome-message"]')).toBeVisible();

    // From the main navigation menu, click on 'Audit' or 'Audit Logs' section
    await page.click('[data-testid="audit-menu"]');
    await page.click('[data-testid="audit-logs-link"]');
    await expect(page.locator('[data-testid="audit-log-interface"]')).toBeVisible();

    // Verify the audit log interface displays filter options
    await expect(page.locator('[data-testid="user-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-range-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="action-type-filter"]')).toBeVisible();

    // Select a specific user from the User filter dropdown
    await page.click('[data-testid="user-filter"]');
    await page.click('[data-testid="user-option-first"]');

    // Set the date range filter
    const today = new Date();
    const sevenDaysAgo = new Date(today);
    sevenDaysAgo.setDate(today.getDate() - 7);
    const startDate = sevenDaysAgo.toISOString().split('T')[0];
    const endDate = today.toISOString().split('T')[0];
    await page.fill('[data-testid="start-date-input"]', startDate);
    await page.fill('[data-testid="end-date-input"]', endDate);

    // Click the 'Search' button and start a timer
    const startTime = Date.now();
    await page.click('[data-testid="search-button"]');
    await page.waitForSelector('[data-testid="audit-log-row"]', { timeout: 10000 });
    const endTime = Date.now();
    const searchDuration = (endTime - startTime) / 1000;

    // Expected Result: Filtered logs displayed within 5 seconds
    expect(searchDuration).toBeLessThan(5);

    // Verify the displayed audit log entries contain required columns
    const logTable = page.locator('[data-testid="audit-log-table"]');
    await expect(logTable.locator('[data-testid="column-timestamp"]')).toBeVisible();
    await expect(logTable.locator('[data-testid="column-user"]')).toBeVisible();
    await expect(logTable.locator('[data-testid="column-action-type"]')).toBeVisible();
    await expect(logTable.locator('[data-testid="column-record-id"]')).toBeVisible();
    await expect(logTable.locator('[data-testid="column-details"]')).toBeVisible();
    await expect(logTable.locator('[data-testid="column-ip-address"]')).toBeVisible();
    await expect(logTable.locator('[data-testid="column-status"]')).toBeVisible();

    // Change the Action Type filter to 'UPDATE' and search again
    await page.selectOption('[data-testid="action-type-filter"]', 'UPDATE');
    await page.click('[data-testid="search-button"]');
    await page.waitForTimeout(1000);
    const updateRows = page.locator('[data-testid="audit-log-row"]');
    const updateRowCount = await updateRows.count();
    for (let i = 0; i < updateRowCount; i++) {
      await expect(updateRows.nth(i).locator('[data-testid="action-type"]')).toContainText('UPDATE');
    }

    // Click the 'Export' button
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-button"]');
    const download = await downloadPromise;
    
    // Expected Result: CSV file downloaded with correct data
    expect(download.suggestedFilename()).toContain('.csv');
    const downloadPath = await download.path();
    expect(downloadPath).toBeTruthy();

    // Clear all filters and view all audit logs
    await page.click('[data-testid="clear-filters-button"]');
    await page.click('[data-testid="search-button"]');
    await page.waitForTimeout(1000);
    await expect(page.locator('[data-testid="audit-log-row"]')).toHaveCount(await page.locator('[data-testid="audit-log-row"]').count());
  });

  test('Restrict audit log access to authorized users (error-case)', async ({ page, request }) => {
    // Navigate to the system login page and login as unauthorized user
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', unauthorizedUserCredentials.username);
    await page.fill('[data-testid="password-input"]', unauthorizedUserCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Attempt to navigate to the audit log interface by entering the URL directly
    await page.goto(`${baseURL}/audit/attendance`);
    
    // Expected Result: Access to audit logs denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/access denied|unauthorized|forbidden/i);

    // Check the main navigation menu for any audit menu items
    const auditMenu = page.locator('[data-testid="audit-menu"]');
    await expect(auditMenu).not.toBeVisible();

    // Attempt to make a direct GET request to the audit log API endpoint
    const apiResponse1 = await page.request.get(`${baseURL}/api/audit/attendance`);
    
    // Expected Result: Authorization error returned
    expect(apiResponse1.status()).toBe(403);
    const responseBody1 = await apiResponse1.json();
    expect(responseBody1.error).toMatch(/unauthorized|forbidden|access denied/i);

    // Attempt to access audit logs with query parameters
    const apiResponse2 = await page.request.get(`${baseURL}/api/audit/attendance?userId=123&startDate=2024-01-01&endDate=2024-01-31`);
    
    // Expected Result: Authorization error returned
    expect(apiResponse2.status()).toBe(403);
    const responseBody2 = await apiResponse2.json();
    expect(responseBody2.error).toMatch(/unauthorized|forbidden|access denied/i);

    // Attempt to export audit logs
    const apiResponse3 = await page.request.get(`${baseURL}/api/audit/attendance/export?format=csv`);
    
    // Expected Result: Authorization error returned
    expect(apiResponse3.status()).toBe(403);
    const responseBody3 = await apiResponse3.json();
    expect(responseBody3.error).toMatch(/unauthorized|forbidden|access denied/i);

    // Verify error messages do not expose sensitive information
    expect(responseBody1.error).not.toContain('database');
    expect(responseBody1.error).not.toContain('SQL');
    expect(responseBody1.error).not.toContain('stack trace');
    expect(responseBody2.error).not.toContain('internal');
    expect(responseBody3.error).not.toContain('server path');

    // Log out the unauthorized user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Log in with valid Attendance Manager credentials
    await page.fill('[data-testid="username-input"]', attendanceManagerCredentials.username);
    await page.fill('[data-testid="password-input"]', attendanceManagerCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the audit log interface from the main menu
    await page.click('[data-testid="audit-menu"]');
    await page.click('[data-testid="audit-logs-link"]');
    await expect(page.locator('[data-testid="audit-log-interface"]')).toBeVisible();

    // Make a GET request to the audit log API endpoint using the Attendance Manager session
    const authorizedApiResponse = await page.request.get(`${baseURL}/api/audit/attendance`);
    
    // Expected Result: Access granted and data returned
    expect(authorizedApiResponse.status()).toBe(200);
    const authorizedResponseBody = await authorizedApiResponse.json();
    expect(authorizedResponseBody).toHaveProperty('data');
    expect(Array.isArray(authorizedResponseBody.data)).toBe(true);
  });
});