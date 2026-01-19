import { test, expect } from '@playwright/test';

test.describe('Audit Manual Attendance Changes', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login');
  });

  test('Validate audit logging on manual attendance changes (happy-path)', async ({ page }) => {
    // Manager logs in
    await page.fill('[data-testid="username-input"]', 'attendance.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager@123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Manager navigates to the attendance records list
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="attendance-records-link"]');
    await expect(page.locator('[data-testid="attendance-records-list"]')).toBeVisible();

    // Manager selects an existing manual attendance record to edit
    await page.click('[data-testid="attendance-record-row"]:first-child [data-testid="edit-button"]');
    await expect(page.locator('[data-testid="edit-attendance-modal"]')).toBeVisible();

    // Manager modifies the attendance time
    const originalCheckIn = await page.inputValue('[data-testid="check-in-time-input"]');
    await page.fill('[data-testid="check-in-time-input"]', '09:30');

    // System prompts manager to provide a reason for the change
    await expect(page.locator('[data-testid="reason-for-change-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="reason-for-change-input"]')).toHaveAttribute('required', '');

    // Manager enters a valid reason for the change
    await page.fill('[data-testid="reason-for-change-input"]', 'Correcting biometric failure entry');

    // Manager clicks Save button to save the changes
    await page.click('[data-testid="save-attendance-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance record updated successfully');
    await expect(page.locator('[data-testid="edit-attendance-modal"]')).not.toBeVisible();

    // Manager logs out
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Authorized user with audit access logs into the system
    await page.fill('[data-testid="username-input"]', 'audit.user@company.com');
    await page.fill('[data-testid="password-input"]', 'AuditUser@123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Authorized user navigates to the audit logs section
    await page.click('[data-testid="audit-menu"]');
    await page.click('[data-testid="audit-logs-link"]');
    await expect(page.locator('[data-testid="audit-logs-table"]')).toBeVisible();

    // Authorized user searches for the recently modified attendance record
    await page.fill('[data-testid="audit-search-input"]', 'Correcting biometric failure entry');
    await page.click('[data-testid="search-button"]');

    // Authorized user views the audit log entry for the modified record
    const auditLogRow = page.locator('[data-testid="audit-log-row"]').first();
    await expect(auditLogRow).toBeVisible();
    await expect(auditLogRow.locator('[data-testid="audit-user"]')).toContainText('attendance.manager@company.com');
    await expect(auditLogRow.locator('[data-testid="audit-reason"]')).toContainText('Correcting biometric failure entry');
    await expect(auditLogRow.locator('[data-testid="audit-timestamp"]')).toBeVisible();
    await expect(auditLogRow.locator('[data-testid="audit-action"]')).toContainText('Modified');

    // Authorized user logs out
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Unauthorized user attempts to log in
    await page.fill('[data-testid="username-input"]', 'regular.employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Employee@123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Unauthorized user attempts to access the audit logs section by navigating to the URL
    await page.goto('/audit/logs');
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');

    // Unauthorized user verifies that audit logs menu option is not visible
    await page.goto('/dashboard');
    await expect(page.locator('[data-testid="audit-menu"]')).not.toBeVisible();
  });

  test('Ensure reason for change is mandatory (error-case)', async ({ page }) => {
    // Manager logs in
    await page.fill('[data-testid="username-input"]', 'attendance.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager@123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Manager navigates to the attendance records list
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="attendance-records-link"]');
    await expect(page.locator('[data-testid="attendance-records-list"]')).toBeVisible();

    // Manager selects an existing manual attendance record to edit
    await page.click('[data-testid="attendance-record-row"]:first-child [data-testid="edit-button"]');
    await expect(page.locator('[data-testid="edit-attendance-modal"]')).toBeVisible();

    // Manager modifies the attendance time (check-out time)
    const originalCheckOut = await page.inputValue('[data-testid="check-out-time-input"]');
    await page.fill('[data-testid="check-out-time-input"]', '18:00');

    // System displays the reason for change field marked as mandatory
    await expect(page.locator('[data-testid="reason-for-change-input"]')).toBeVisible();
    const reasonField = page.locator('[data-testid="reason-for-change-input"]');
    await expect(reasonField).toHaveAttribute('required', '');
    await expect(page.locator('label[for="reason-for-change-input"]')).toContainText('*');

    // Manager leaves the reason for change field empty and attempts to click Save button
    await page.fill('[data-testid="reason-for-change-input"]', '');
    await page.click('[data-testid="save-attendance-button"]');

    // System prevents save and displays error message
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Reason for change is required');
    await expect(page.locator('[data-testid="edit-attendance-modal"]')).toBeVisible();

    // Manager verifies that the attendance record has not been saved
    await page.click('[data-testid="cancel-button"]');
    await expect(page.locator('[data-testid="edit-attendance-modal"]')).not.toBeVisible();
    const recordCheckOut = await page.locator('[data-testid="attendance-record-row"]:first-child [data-testid="check-out-time"]').textContent();
    expect(recordCheckOut).not.toContain('18:00');

    // Manager opens the edit modal again
    await page.click('[data-testid="attendance-record-row"]:first-child [data-testid="edit-button"]');
    await expect(page.locator('[data-testid="edit-attendance-modal"]')).toBeVisible();

    // Manager modifies the check-out time again
    await page.fill('[data-testid="check-out-time-input"]', '18:00');

    // Manager enters a valid reason for the change
    await page.fill('[data-testid="reason-for-change-input"]', 'Employee worked overtime');

    // Manager clicks Save button again with the reason provided
    await page.click('[data-testid="save-attendance-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance record updated successfully');
    await expect(page.locator('[data-testid="edit-attendance-modal"]')).not.toBeVisible();

    // Manager verifies the updated record appears in the attendance list with the new values
    const updatedCheckOut = await page.locator('[data-testid="attendance-record-row"]:first-child [data-testid="check-out-time"]').textContent();
    expect(updatedCheckOut).toContain('18:00');

    // Manager or authorized user checks the audit log for this change
    await page.click('[data-testid="audit-menu"]');
    await page.click('[data-testid="audit-logs-link"]');
    await expect(page.locator('[data-testid="audit-logs-table"]')).toBeVisible();

    await page.fill('[data-testid="audit-search-input"]', 'Employee worked overtime');
    await page.click('[data-testid="search-button"]');

    const auditLogRow = page.locator('[data-testid="audit-log-row"]').first();
    await expect(auditLogRow).toBeVisible();
    await expect(auditLogRow.locator('[data-testid="audit-user"]')).toContainText('attendance.manager@company.com');
    await expect(auditLogRow.locator('[data-testid="audit-reason"]')).toContainText('Employee worked overtime');
    await expect(auditLogRow.locator('[data-testid="audit-timestamp"]')).toBeVisible();
    await expect(auditLogRow.locator('[data-testid="audit-action"]')).toContainText('Modified');
  });
});