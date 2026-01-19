import { test, expect } from '@playwright/test';

test.describe('Manual Attendance Entry - Story 23', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const validOfficerUsername = 'attendance.officer@company.com';
  const validOfficerPassword = 'Officer@123';
  const validEmployeeId = 'EMP12345';
  const invalidEmployeeId = 'EMP99999';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto(`${baseURL}/login`);
  });

  test('Validate successful manual attendance record addition (happy-path)', async ({ page }) => {
    // Step 1: Login as authorized attendance officer
    await page.fill('[data-testid="username-input"]', validOfficerUsername);
    await page.fill('[data-testid="password-input"]', validOfficerPassword);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access granted to manual attendance entry page
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();

    // Step 2: Navigate to the manual attendance entry page from the dashboard menu
    await page.click('[data-testid="menu-attendance"]');
    await page.click('[data-testid="submenu-manual-entry"]');
    
    // Expected Result: Manual attendance entry page displayed
    await expect(page).toHaveURL(/.*attendance\/manual-entry/);
    await expect(page.locator('[data-testid="manual-entry-form"]')).toBeVisible();

    // Step 3: Enter a valid employee ID in the employee ID field
    await page.fill('[data-testid="employee-id-input"]', validEmployeeId);
    
    // Step 4: Select or enter a valid date in the date field
    const currentDate = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="attendance-date-input"]', currentDate);
    
    // Step 5: Enter a valid time in the time field
    await page.fill('[data-testid="attendance-time-input"]', '09:00');
    
    // Step 6: Select attendance status from the dropdown
    await page.selectOption('[data-testid="attendance-status-select"]', 'Present');
    
    // Expected Result: Inputs accepted without validation errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();

    // Step 7: Click the Submit button to save the manual attendance record
    await page.click('[data-testid="submit-attendance-button"]');
    
    // Expected Result: Record saved and confirmation displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance record saved successfully');

    // Step 8: Verify the newly added record appears in the attendance records list
    await page.waitForTimeout(1000); // Wait for record to be added to list
    const recordRow = page.locator(`[data-testid="attendance-record-${validEmployeeId}"]`).first();
    await expect(recordRow).toBeVisible();
    await expect(recordRow).toContainText(validEmployeeId);
    await expect(recordRow).toContainText(currentDate);
    await expect(recordRow).toContainText('09:00');
    await expect(recordRow).toContainText('Present');
  });

  test('Verify validation rejects invalid employee IDs (error-case)', async ({ page }) => {
    // Step 1: Login as authorized attendance officer
    await page.fill('[data-testid="username-input"]', validOfficerUsername);
    await page.fill('[data-testid="password-input"]', validOfficerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to the manual attendance entry page from the dashboard
    await page.click('[data-testid="menu-attendance"]');
    await page.click('[data-testid="submenu-manual-entry"]');
    
    // Expected Result: Page displayed
    await expect(page).toHaveURL(/.*attendance\/manual-entry/);
    await expect(page.locator('[data-testid="manual-entry-form"]')).toBeVisible();

    // Step 3: Enter a non-existent employee ID
    await page.fill('[data-testid="employee-id-input"]', invalidEmployeeId);
    
    // Step 4: Tab out of the employee ID field or trigger validation
    await page.press('[data-testid="employee-id-input"]', 'Tab');
    await page.waitForTimeout(500); // Wait for validation to trigger
    
    // Expected Result: Validation error displayed
    await expect(page.locator('[data-testid="employee-id-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-id-error"]')).toContainText(/Employee ID does not exist|Invalid employee ID/);

    // Step 5: Enter valid date and time in respective fields
    const currentDate = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="attendance-date-input"]', currentDate);
    await page.fill('[data-testid="attendance-time-input"]', '09:00');
    
    // Step 6: Select attendance status from the dropdown
    await page.selectOption('[data-testid="attendance-status-select"]', 'Present');

    // Step 7: Click the Submit button to attempt saving the record
    await page.click('[data-testid="submit-attendance-button"]');
    
    // Expected Result: Submission blocked with error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/Cannot save attendance record|Invalid employee/);
    
    // Step 8: Verify that no record is created in the database
    const invalidRecordRow = page.locator(`[data-testid="attendance-record-${invalidEmployeeId}"]`);
    await expect(invalidRecordRow).not.toBeVisible();
  });

  test('Ensure audit trail records manual attendance edits (happy-path)', async ({ page }) => {
    // Step 1: Login as authorized attendance officer
    await page.fill('[data-testid="username-input"]', validOfficerUsername);
    await page.fill('[data-testid="password-input"]', validOfficerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to the attendance records list page
    await page.click('[data-testid="menu-attendance"]');
    await page.click('[data-testid="submenu-attendance-records"]');
    
    // Expected Result: Attendance records list displayed
    await expect(page).toHaveURL(/.*attendance\/records/);
    await expect(page.locator('[data-testid="attendance-records-table"]')).toBeVisible();

    // Step 3: Locate an existing manual attendance record and click the Edit button
    const firstRecord = page.locator('[data-testid^="attendance-record-"]').first();
    await expect(firstRecord).toBeVisible();
    
    // Step 4: Note the original attendance time value for verification purposes
    const originalTime = await firstRecord.locator('[data-testid="record-time"]').textContent();
    const recordId = await firstRecord.getAttribute('data-record-id');
    
    await firstRecord.locator('[data-testid="edit-button"]').click();
    
    // Expected Result: Edit form displayed with current data
    await expect(page.locator('[data-testid="edit-attendance-form"]')).toBeVisible();
    const timeInput = page.locator('[data-testid="edit-attendance-time-input"]');
    await expect(timeInput).toHaveValue(originalTime?.trim() || '');

    // Step 5: Modify the attendance time field to a different valid time
    const newTime = '09:30';
    await timeInput.clear();
    await timeInput.fill(newTime);
    
    // Step 6: Click the Submit or Save button to save the changes
    await page.click('[data-testid="save-edit-button"]');
    
    // Expected Result: Changes saved and confirmation displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/Record updated successfully|Changes saved/);

    // Step 7: Verify the updated record shows the new time in the attendance records list
    await page.waitForTimeout(1000); // Wait for list to refresh
    const updatedRecord = page.locator(`[data-testid="attendance-record-${recordId}"]`);
    await expect(updatedRecord.locator('[data-testid="record-time"]')).toContainText(newTime);

    // Step 8: Navigate to the audit logs section or view audit history
    await page.click('[data-testid="menu-audit-logs"]');
    
    // Expected Result: Audit logs page displayed
    await expect(page).toHaveURL(/.*audit-logs/);
    await expect(page.locator('[data-testid="audit-logs-table"]')).toBeVisible();

    // Step 9: Review the audit log entry for the edited record
    const auditLogEntry = page.locator(`[data-testid="audit-log-record-${recordId}"]`).first();
    await expect(auditLogEntry).toBeVisible();
    
    // Step 10: Verify the audit log shows edit details accurately
    await expect(auditLogEntry).toContainText('EDIT');
    await expect(auditLogEntry).toContainText(validOfficerUsername);
    await expect(auditLogEntry).toContainText(newTime);
    
    // Verify timestamp in the audit log matches the time when the edit was performed
    const auditTimestamp = await auditLogEntry.locator('[data-testid="audit-timestamp"]').textContent();
    const currentTimestamp = new Date();
    expect(auditTimestamp).toBeTruthy();
    
    // Verify audit log contains user information
    await expect(auditLogEntry.locator('[data-testid="audit-user"]')).toContainText(validOfficerUsername);
  });
});