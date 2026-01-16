import { test, expect } from '@playwright/test';

test.describe('Manual Attendance Entry - Story 24', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const MANUAL_ATTENDANCE_URL = `${BASE_URL}/manual-attendance`;
  const AUDIT_LOG_URL = `${BASE_URL}/audit-log`;

  test.beforeEach(async ({ page }) => {
    // Login as HR Officer before each test
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'hr.officer@company.com');
    await page.fill('[data-testid="password-input"]', 'HRPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate manual attendance creation with valid data (happy-path)', async ({ page }) => {
    // Step 1: Navigate to manual attendance entry page
    await page.goto(MANUAL_ATTENDANCE_URL);
    await expect(page.locator('[data-testid="manual-attendance-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-dropdown"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-picker"]')).toBeVisible();
    await expect(page.locator('[data-testid="time-in-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="time-out-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="status-dropdown"]')).toBeVisible();

    // Step 2: Select an employee from the employee dropdown list
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-john-doe"]');
    await expect(page.locator('[data-testid="employee-dropdown"]')).toContainText('John Doe');

    // Step 3: Select a valid date using the date picker
    await page.fill('[data-testid="date-picker"]', '2024-01-25');

    // Step 4: Enter valid time in (e.g., 09:00 AM) and time out (e.g., 05:00 PM)
    await page.fill('[data-testid="time-in-input"]', '09:00 AM');
    await page.fill('[data-testid="time-out-input"]', '05:00 PM');

    // Step 5: Select attendance status (e.g., Present, Half-day)
    await page.click('[data-testid="status-dropdown"]');
    await page.click('[data-testid="status-option-present"]');
    await expect(page.locator('[data-testid="status-dropdown"]')).toContainText('Present');

    // Step 6: Add optional remarks or notes in the remarks field
    await page.fill('[data-testid="remarks-input"]', 'Regular working hours');

    // Step 7: Click the Submit button to save the manual attendance entry
    const startTime = Date.now();
    await page.click('[data-testid="submit-button"]');

    // Step 8: Verify the submission response time
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 3000 });
    const endTime = Date.now();
    const responseTime = endTime - startTime;
    expect(responseTime).toBeLessThan(3000);

    // Verify confirmation message
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Manual attendance entry created successfully');
  });

  test('Verify validation prevents overlapping attendance records (error-case)', async ({ page }) => {
    // Step 1: Navigate to manual attendance entry page
    await page.goto(MANUAL_ATTENDANCE_URL);
    await expect(page.locator('[data-testid="manual-attendance-form"]')).toBeVisible();

    // Step 2: Select employee 'John Doe' from the employee dropdown
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-john-doe"]');

    // Step 3: Select date '2024-01-15' which already has an attendance record
    await page.fill('[data-testid="date-picker"]', '2024-01-15');

    // Step 4: Enter overlapping time in as 10:00 AM and time out as 06:00 PM
    await page.fill('[data-testid="time-in-input"]', '10:00 AM');
    await page.fill('[data-testid="time-out-input"]', '06:00 PM');

    // Select status
    await page.click('[data-testid="status-dropdown"]');
    await page.click('[data-testid="status-option-present"]');

    // Step 5: Click Submit button to attempt creating the overlapping attendance record
    await page.click('[data-testid="submit-button"]');

    // Verify validation error is displayed
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('overlapping attendance');
    await expect(page.locator('[data-testid="error-message"]')).toContainText('already exists');

    // Verify submission was blocked
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();

    // Step 6: Change the date to '2024-01-16' which has no existing attendance record
    await page.fill('[data-testid="date-picker"]', '2024-01-16');

    // Step 7: Keep the same time in (10:00 AM) and time out (06:00 PM) values
    await expect(page.locator('[data-testid="time-in-input"]')).toHaveValue('10:00 AM');
    await expect(page.locator('[data-testid="time-out-input"]')).toHaveValue('06:00 PM');

    // Step 8: Click Submit button to resubmit with corrected non-overlapping data
    await page.click('[data-testid="submit-button"]');

    // Verify submission succeeds with confirmation
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Manual attendance entry created successfully');
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
  });

  test('Ensure audit trail logs manual attendance changes (happy-path)', async ({ page }) => {
    // Step 1: Navigate to manual attendance entry page
    await page.goto(MANUAL_ATTENDANCE_URL);
    await expect(page.locator('[data-testid="manual-attendance-form"]')).toBeVisible();

    // Step 2: Select employee 'Jane Smith', date '2024-01-20', time in '08:30 AM', time out '04:30 PM', and status 'Present'
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-jane-smith"]');
    await page.fill('[data-testid="date-picker"]', '2024-01-20');
    await page.fill('[data-testid="time-in-input"]', '08:30 AM');
    await page.fill('[data-testid="time-out-input"]', '04:30 PM');
    await page.click('[data-testid="status-dropdown"]');
    await page.click('[data-testid="status-option-present"]');

    // Step 3: Click Submit button to create the manual attendance entry
    await page.click('[data-testid="submit-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Step 4: Access the audit log table or audit trail report for manual attendance
    await page.goto(AUDIT_LOG_URL);
    await expect(page.locator('[data-testid="audit-log-table"]')).toBeVisible();

    // Verify CREATE audit log entry
    const createLogEntry = page.locator('[data-testid="audit-log-row"]').filter({ hasText: 'Jane Smith' }).filter({ hasText: '2024-01-20' }).filter({ hasText: 'CREATE' }).first();
    await expect(createLogEntry).toBeVisible();
    await expect(createLogEntry.locator('[data-testid="audit-action"]')).toContainText('CREATE');
    await expect(createLogEntry.locator('[data-testid="audit-user"]')).toContainText('hr.officer@company.com');
    await expect(createLogEntry.locator('[data-testid="audit-timestamp"]')).not.toBeEmpty();

    // Step 5: Navigate to the attendance records list and locate the created entry for Jane Smith on 2024-01-20
    await page.goto(`${BASE_URL}/attendance-records`);
    await expect(page.locator('[data-testid="attendance-records-table"]')).toBeVisible();
    const attendanceRecord = page.locator('[data-testid="attendance-record-row"]').filter({ hasText: 'Jane Smith' }).filter({ hasText: '2024-01-20' });
    await expect(attendanceRecord).toBeVisible();

    // Step 6: Click Edit button on the attendance record
    await attendanceRecord.locator('[data-testid="edit-button"]').click();
    await expect(page.locator('[data-testid="edit-attendance-form"]')).toBeVisible();

    // Step 7: Modify the time out from '04:30 PM' to '05:00 PM' and add remarks 'Extended work hours'
    await page.fill('[data-testid="time-out-input"]', '05:00 PM');
    await page.fill('[data-testid="remarks-input"]', 'Extended work hours');

    // Step 8: Click Update button to save the modifications
    await page.click('[data-testid="update-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('updated successfully');

    // Step 9: Access the audit log table or audit trail report again
    await page.goto(AUDIT_LOG_URL);
    await expect(page.locator('[data-testid="audit-log-table"]')).toBeVisible();

    // Verify UPDATE audit log entry
    const updateLogEntry = page.locator('[data-testid="audit-log-row"]').filter({ hasText: 'Jane Smith' }).filter({ hasText: '2024-01-20' }).filter({ hasText: 'UPDATE' }).first();
    await expect(updateLogEntry).toBeVisible();
    await expect(updateLogEntry.locator('[data-testid="audit-action"]')).toContainText('UPDATE');
    await expect(updateLogEntry.locator('[data-testid="audit-user"]')).toContainText('hr.officer@company.com');
    await expect(updateLogEntry.locator('[data-testid="audit-timestamp"]')).not.toBeEmpty();
    await expect(updateLogEntry.locator('[data-testid="audit-details"]')).toContainText('Extended work hours');

    // Step 10: Navigate back to the attendance records list and locate the entry for Jane Smith on 2024-01-20
    await page.goto(`${BASE_URL}/attendance-records`);
    const attendanceRecordForDelete = page.locator('[data-testid="attendance-record-row"]').filter({ hasText: 'Jane Smith' }).filter({ hasText: '2024-01-20' });
    await expect(attendanceRecordForDelete).toBeVisible();

    // Step 11: Click Delete button on the attendance record
    await attendanceRecordForDelete.locator('[data-testid="delete-button"]').click();

    // Step 12: Click Confirm or Yes to proceed with deletion
    await expect(page.locator('[data-testid="delete-confirmation-dialog"]')).toBeVisible();
    await page.click('[data-testid="confirm-delete-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('deleted successfully');

    // Step 13: Access the audit log table or audit trail report once more
    await page.goto(AUDIT_LOG_URL);
    await expect(page.locator('[data-testid="audit-log-table"]')).toBeVisible();

    // Step 14: Verify that all three audit log entries (CREATE, UPDATE, DELETE) are present and contain complete information
    const allLogEntries = page.locator('[data-testid="audit-log-row"]').filter({ hasText: 'Jane Smith' }).filter({ hasText: '2024-01-20' });
    await expect(allLogEntries).toHaveCount(3);

    // Verify DELETE audit log entry
    const deleteLogEntry = page.locator('[data-testid="audit-log-row"]').filter({ hasText: 'Jane Smith' }).filter({ hasText: '2024-01-20' }).filter({ hasText: 'DELETE' }).first();
    await expect(deleteLogEntry).toBeVisible();
    await expect(deleteLogEntry.locator('[data-testid="audit-action"]')).toContainText('DELETE');
    await expect(deleteLogEntry.locator('[data-testid="audit-user"]')).toContainText('hr.officer@company.com');
    await expect(deleteLogEntry.locator('[data-testid="audit-timestamp"]')).not.toBeEmpty();

    // Verify all audit entries have complete information
    for (let i = 0; i < 3; i++) {
      const logEntry = allLogEntries.nth(i);
      await expect(logEntry.locator('[data-testid="audit-user"]')).not.toBeEmpty();
      await expect(logEntry.locator('[data-testid="audit-timestamp"]')).not.toBeEmpty();
      await expect(logEntry.locator('[data-testid="audit-action"]')).not.toBeEmpty();
    }
  });
});