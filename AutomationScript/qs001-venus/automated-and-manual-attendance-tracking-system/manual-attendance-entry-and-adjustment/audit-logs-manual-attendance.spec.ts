import { test, expect } from '@playwright/test';

test.describe('Audit Logs for Manual Attendance Changes', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const AUDIT_LOG_TIMEOUT = 60000; // 1 minute as per requirements

  test.beforeEach(async ({ page }) => {
    // Login as HR Officer
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'hr.officer@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate audit logging of manual attendance additions', async ({ page }) => {
    // Navigate to manual attendance management page
    await page.goto(`${BASE_URL}/attendance/manual`);
    await expect(page.locator('[data-testid="manual-attendance-page"]')).toBeVisible();

    // Click 'Add New Entry' button
    await page.click('[data-testid="add-new-entry-button"]');
    await expect(page.locator('[data-testid="add-attendance-modal"]')).toBeVisible();

    // Add a manual attendance entry
    const employeeName = 'John Doe';
    const attendanceDate = '2024-01-15';
    const checkInTime = '09:00';
    const checkOutTime = '17:30';
    const reason = 'Biometric system malfunction';
    
    await page.fill('[data-testid="employee-name-input"]', employeeName);
    await page.fill('[data-testid="attendance-date-input"]', attendanceDate);
    await page.fill('[data-testid="check-in-time-input"]', checkInTime);
    await page.fill('[data-testid="check-out-time-input"]', checkOutTime);
    await page.fill('[data-testid="reason-input"]', reason);

    // Note the timestamp before submission
    const operationTimestamp = new Date();
    
    // Submit the form
    await page.click('[data-testid="submit-attendance-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Navigate to audit log interface
    await page.goto(`${BASE_URL}/audit/manual-attendance`);
    await expect(page.locator('[data-testid="audit-log-page"]')).toBeVisible();

    // Retrieve audit logs and search for the newly added entry
    await page.waitForSelector('[data-testid="audit-log-table"]');
    
    // Search for the specific entry
    await page.fill('[data-testid="search-input"]', employeeName);
    await page.click('[data-testid="search-button"]');

    // Verify the audit log entry exists
    const auditLogRow = page.locator('[data-testid="audit-log-row"]').first();
    await expect(auditLogRow).toBeVisible();

    // Verify all required audit fields are present and accurate
    await expect(auditLogRow.locator('[data-testid="operation-type"]')).toContainText('Addition');
    await expect(auditLogRow.locator('[data-testid="employee-name"]')).toContainText(employeeName);
    await expect(auditLogRow.locator('[data-testid="user-identity"]')).toContainText('hr.officer@company.com');
    await expect(auditLogRow.locator('[data-testid="timestamp"]')).toBeVisible();
    await expect(auditLogRow.locator('[data-testid="change-details"]')).toContainText(reason);
  });

  test('Verify audit log filtering and export', async ({ page }) => {
    // Navigate to audit log interface for manual attendance
    await page.goto(`${BASE_URL}/audit/manual-attendance`);
    await expect(page.locator('[data-testid="audit-log-page"]')).toBeVisible();

    // Apply filter by selecting a specific user from the user dropdown filter
    await page.click('[data-testid="user-filter-dropdown"]');
    await page.click('[data-testid="user-option-hr-officer"]');
    await expect(page.locator('[data-testid="user-filter-dropdown"]')).toContainText('hr.officer@company.com');

    // Apply additional filter by selecting a date range (last 7 days)
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="last-7-days-option"]');
    
    // Click apply filters button
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForSelector('[data-testid="audit-log-table"]');

    // Verify the filtered results show correct data matching the filter criteria
    const filteredRows = page.locator('[data-testid="audit-log-row"]');
    const rowCount = await filteredRows.count();
    expect(rowCount).toBeGreaterThan(0);

    // Verify each row matches the filter criteria
    for (let i = 0; i < Math.min(rowCount, 5); i++) {
      const row = filteredRows.nth(i);
      await expect(row.locator('[data-testid="user-identity"]')).toContainText('hr.officer@company.com');
    }

    // Click on 'Export' or 'Download CSV' button
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-button"]');
    const download = await downloadPromise;

    // Verify the download occurred
    expect(download.suggestedFilename()).toContain('.csv');
    
    // Save and verify CSV contents
    const path = await download.path();
    expect(path).toBeTruthy();
  });

  test('Ensure audit logs are available within 1 minute', async ({ page }) => {
    // Note the current system time before performing the operation
    const operationStartTime = new Date();

    // Navigate to manual attendance management page
    await page.goto(`${BASE_URL}/attendance/manual`);
    await expect(page.locator('[data-testid="manual-attendance-page"]')).toBeVisible();

    // Select an existing entry to edit
    await page.click('[data-testid="attendance-row"]', { timeout: 5000 });
    await page.click('[data-testid="edit-entry-button"]');
    await expect(page.locator('[data-testid="edit-attendance-modal"]')).toBeVisible();

    // Perform manual attendance edit by modifying check-in time
    const newCheckInTime = '08:45';
    await page.fill('[data-testid="check-in-time-input"]', newCheckInTime);
    
    // Save changes
    await page.click('[data-testid="save-changes-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    const operationEndTime = new Date();

    // Immediately navigate to audit log interface
    await page.goto(`${BASE_URL}/audit/manual-attendance`);
    await expect(page.locator('[data-testid="audit-log-page"]')).toBeVisible();

    // Refresh audit logs and search for the edit operation
    await page.click('[data-testid="refresh-button"]');
    await page.waitForSelector('[data-testid="audit-log-table"]');

    // Search for the most recent edit operation
    const auditLogRow = page.locator('[data-testid="audit-log-row"]').first();
    await expect(auditLogRow).toBeVisible({ timeout: AUDIT_LOG_TIMEOUT });

    // Verify the operation type is 'Edit'
    await expect(auditLogRow.locator('[data-testid="operation-type"]')).toContainText('Edit');

    // Compare the audit log entry timestamp with the operation timestamp
    const auditTimestampText = await auditLogRow.locator('[data-testid="timestamp"]').textContent();
    const auditTimestamp = new Date(auditTimestampText || '');
    
    // Verify the audit log was created within 1 minute
    const timeDifferenceMs = auditTimestamp.getTime() - operationStartTime.getTime();
    expect(timeDifferenceMs).toBeLessThanOrEqual(60000); // 1 minute in milliseconds

    // Verify the audit log contains complete details of the edit operation
    await expect(auditLogRow.locator('[data-testid="change-details"]')).toContainText(newCheckInTime);
    await expect(auditLogRow.locator('[data-testid="user-identity"]')).toContainText('hr.officer@company.com');
  });

  test('Validate audit logging of manual attendance edits and deletions', async ({ page }) => {
    // Navigate to manual attendance management page
    await page.goto(`${BASE_URL}/attendance/manual`);
    await expect(page.locator('[data-testid="manual-attendance-page"]')).toBeVisible();

    // Select an entry to edit
    const firstRow = page.locator('[data-testid="attendance-row"]').first();
    await firstRow.click();
    await page.click('[data-testid="edit-entry-button"]');
    await expect(page.locator('[data-testid="edit-attendance-modal"]')).toBeVisible();

    // Modify the check-in time and save the changes
    const editedCheckInTime = '09:15';
    await page.fill('[data-testid="check-in-time-input"]', editedCheckInTime);
    await page.click('[data-testid="save-changes-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Access audit log interface and search for the edit operation
    await page.goto(`${BASE_URL}/audit/manual-attendance`);
    await expect(page.locator('[data-testid="audit-log-page"]')).toBeVisible();
    
    // Verify edit operation in audit log
    const editAuditRow = page.locator('[data-testid="audit-log-row"]').first();
    await expect(editAuditRow.locator('[data-testid="operation-type"]')).toContainText('Edit');
    await expect(editAuditRow.locator('[data-testid="change-details"]')).toContainText(editedCheckInTime);
    await expect(editAuditRow.locator('[data-testid="user-identity"]')).toBeVisible();
    await expect(editAuditRow.locator('[data-testid="timestamp"]')).toBeVisible();

    // Return to manual attendance management page
    await page.goto(`${BASE_URL}/attendance/manual`);
    await expect(page.locator('[data-testid="manual-attendance-page"]')).toBeVisible();

    // Select a different entry to delete
    const secondRow = page.locator('[data-testid="attendance-row"]').nth(1);
    const employeeNameToDelete = await secondRow.locator('[data-testid="employee-name"]').textContent();
    await secondRow.click();
    await page.click('[data-testid="delete-entry-button"]');

    // Confirm deletion of the manual attendance entry
    await expect(page.locator('[data-testid="delete-confirmation-modal"]')).toBeVisible();
    await page.click('[data-testid="confirm-delete-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Access audit log interface and search for the deletion operation
    await page.goto(`${BASE_URL}/audit/manual-attendance`);
    await expect(page.locator('[data-testid="audit-log-page"]')).toBeVisible();
    await page.click('[data-testid="refresh-button"]');

    // Search for deletion operation
    await page.fill('[data-testid="search-input"]', employeeNameToDelete || '');
    await page.click('[data-testid="search-button"]');

    // Verify deletion operation in audit log
    const deleteAuditRow = page.locator('[data-testid="audit-log-row"]').first();
    await expect(deleteAuditRow.locator('[data-testid="operation-type"]')).toContainText('Deletion');
    await expect(deleteAuditRow.locator('[data-testid="employee-name"]')).toContainText(employeeNameToDelete || '');
    await expect(deleteAuditRow.locator('[data-testid="user-identity"]')).toBeVisible();
    await expect(deleteAuditRow.locator('[data-testid="timestamp"]')).toBeVisible();
    await expect(deleteAuditRow.locator('[data-testid="change-details"]')).toBeVisible();
  });
});