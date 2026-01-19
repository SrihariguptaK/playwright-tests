import { test, expect } from '@playwright/test';

test.describe('Audit Attendance Data Changes', () => {
  test.beforeEach(async ({ page }) => {
    // Login as HR Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'hr.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate audit log recording of attendance changes', async ({ page }) => {
    // Navigate to the attendance management module from the main dashboard
    await page.click('[data-testid="attendance-management-menu"]');
    await expect(page).toHaveURL(/.*attendance/);
    await expect(page.locator('[data-testid="attendance-module-header"]')).toBeVisible();

    // Select an existing attendance record for an employee
    const employeeName = 'John Doe';
    await page.click(`[data-testid="attendance-record-${employeeName.replace(' ', '-').toLowerCase()}"]`);
    await expect(page.locator('[data-testid="attendance-record-details"]')).toBeVisible();

    // Modify the attendance record by changing the time in from original value to a new value
    const originalTimeIn = await page.inputValue('[data-testid="time-in-input"]');
    const newTimeIn = '09:15';
    await page.fill('[data-testid="time-in-input"]', newTimeIn);
    await expect(page.locator('[data-testid="time-in-input"]')).toHaveValue(newTimeIn);

    // Click the 'Save' button to commit the changes
    await page.click('[data-testid="save-attendance-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Change is saved successfully');

    // Navigate to the audit log interface by clicking on 'Audit Logs' menu option
    await page.click('[data-testid="audit-logs-menu"]');
    await expect(page).toHaveURL(/.*audit/);
    await expect(page.locator('[data-testid="audit-log-interface"]')).toBeVisible();

    // Search for the recently modified attendance record using employee name or record ID
    await page.fill('[data-testid="audit-search-input"]', employeeName);
    await page.click('[data-testid="audit-search-button"]');
    await page.waitForSelector('[data-testid="audit-log-results"]');

    // Review the audit log entry details
    const auditEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditEntry).toBeVisible();
    await expect(auditEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
    await expect(auditEntry.locator('[data-testid="audit-user"]')).toContainText('hr.manager@company.com');
    await expect(auditEntry.locator('[data-testid="audit-field-changed"]')).toContainText('time in');
    await expect(auditEntry.locator('[data-testid="audit-old-value"]')).toContainText(originalTimeIn);
    await expect(auditEntry.locator('[data-testid="audit-new-value"]')).toContainText(newTimeIn);
    await expect(auditEntry).toContainText('Audit log entry for the change is present with details');
  });

  test('Verify audit log search and export functionality', async ({ page }) => {
    // Navigate to the audit log interface from the main menu
    await page.click('[data-testid="audit-logs-menu"]');
    await expect(page).toHaveURL(/.*audit/);
    await expect(page.locator('[data-testid="audit-log-interface"]')).toBeVisible();

    // Enter a specific user name in the 'User' filter field
    const searchUser = 'hr.manager@company.com';
    await page.fill('[data-testid="user-filter-input"]', searchUser);
    await expect(page.locator('[data-testid="user-filter-input"]')).toHaveValue(searchUser);

    // Select a date range using the date picker (e.g., last 7 days)
    const today = new Date();
    const sevenDaysAgo = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
    const formatDate = (date: Date) => date.toISOString().split('T')[0];
    
    await page.click('[data-testid="date-range-picker"]');
    await page.fill('[data-testid="start-date-input"]', formatDate(sevenDaysAgo));
    await page.fill('[data-testid="end-date-input"]', formatDate(today));

    // Click the 'Search' or 'Apply Filters' button
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForSelector('[data-testid="audit-log-results"]', { timeout: 5000 });

    // Verify that only audit entries matching the specified user and date range are displayed
    const auditEntries = page.locator('[data-testid="audit-log-entry"]');
    const entriesCount = await auditEntries.count();
    expect(entriesCount).toBeGreaterThan(0);
    await expect(page.locator('[data-testid="audit-results-message"]')).toContainText('Relevant audit entries are displayed');

    // Review the search results to confirm relevant audit entries are present
    for (let i = 0; i < Math.min(entriesCount, 3); i++) {
      const entry = auditEntries.nth(i);
      await expect(entry.locator('[data-testid="audit-user"]')).toContainText(searchUser);
      await expect(entry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
    }

    // Click the 'Export' or 'Download Report' button
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-report-button"]');

    // Select the desired export format (e.g., Excel) and confirm the export action
    await page.click('[data-testid="export-format-excel"]');
    await page.click('[data-testid="confirm-export-button"]');

    // Verify the download is initiated
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/audit.*\.(xlsx|xls|csv)/);
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('Report generated and downloadable');

    // Save the downloaded file
    const filePath = await download.path();
    expect(filePath).toBeTruthy();
  });

  test('Verify audit log access restricted to authorized HR personnel', async ({ page }) => {
    // Logout as HR Manager
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Login as non-HR user
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'regular.employee@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Attempt to access audit logs
    const auditLogsMenu = page.locator('[data-testid="audit-logs-menu"]');
    
    // Verify audit logs menu is not visible or accessible
    if (await auditLogsMenu.isVisible()) {
      await auditLogsMenu.click();
      await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
      await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('System restricts audit log access to authorized HR personnel');
    } else {
      // Menu should not be visible for non-HR users
      await expect(auditLogsMenu).not.toBeVisible();
    }
  });

  test('Verify audit search results returned within 5 seconds', async ({ page }) => {
    // Navigate to the audit log interface
    await page.click('[data-testid="audit-logs-menu"]');
    await expect(page).toHaveURL(/.*audit/);

    // Perform a search and measure response time
    const startTime = Date.now();
    await page.fill('[data-testid="audit-search-input"]', 'attendance');
    await page.click('[data-testid="audit-search-button"]');
    await page.waitForSelector('[data-testid="audit-log-results"]');
    const endTime = Date.now();
    const responseTime = (endTime - startTime) / 1000;

    // Verify results returned within 5 seconds
    expect(responseTime).toBeLessThan(5);
    await expect(page.locator('[data-testid="audit-log-results"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toBeVisible();
  });

  test('Verify 100% audit log coverage for attendance changes', async ({ page }) => {
    // Navigate to attendance management
    await page.click('[data-testid="attendance-management-menu"]');
    
    // Make multiple changes to different attendance records
    const employees = ['Jane Smith', 'Bob Johnson', 'Alice Williams'];
    const changes = [];
    
    for (const employee of employees) {
      await page.click(`[data-testid="attendance-record-${employee.replace(' ', '-').toLowerCase()}"]`);
      const originalValue = await page.inputValue('[data-testid="time-out-input"]');
      const newValue = '17:30';
      await page.fill('[data-testid="time-out-input"]', newValue);
      await page.click('[data-testid="save-attendance-button"]');
      await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
      changes.push({ employee, field: 'time out', oldValue: originalValue, newValue });
      await page.click('[data-testid="back-to-list-button"]');
    }

    // Navigate to audit logs and verify all changes are recorded
    await page.click('[data-testid="audit-logs-menu"]');
    
    for (const change of changes) {
      await page.fill('[data-testid="audit-search-input"]', change.employee);
      await page.click('[data-testid="audit-search-button"]');
      await page.waitForSelector('[data-testid="audit-log-results"]');
      
      const auditEntry = page.locator('[data-testid="audit-log-entry"]').first();
      await expect(auditEntry).toBeVisible();
      await expect(auditEntry.locator('[data-testid="audit-field-changed"]')).toContainText(change.field);
      await expect(auditEntry.locator('[data-testid="audit-new-value"]')).toContainText(change.newValue);
    }
    
    // Verify 100% coverage
    expect(changes.length).toBe(employees.length);
  });
});