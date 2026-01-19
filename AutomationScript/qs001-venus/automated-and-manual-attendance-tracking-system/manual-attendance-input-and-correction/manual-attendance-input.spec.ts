import { test, expect } from '@playwright/test';

test.describe('Manual Attendance Input - Story 19', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const managerCredentials = {
    username: 'attendance.manager@company.com',
    password: 'Manager@123'
  };
  const nonAuthorizedCredentials = {
    username: 'regular.employee@company.com',
    password: 'Employee@123'
  };
  const adminCredentials = {
    username: 'admin@company.com',
    password: 'Admin@123'
  };

  test.beforeEach(async ({ page }) => {
    await page.goto(baseURL);
  });

  test('Validate successful manual attendance record creation (happy-path)', async ({ page }) => {
    // Manager logs in
    await page.fill('[data-testid="username-input"]', managerCredentials.username);
    await page.fill('[data-testid="password-input"]', managerCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Manager navigates to manual attendance input page by clicking on 'Manual Attendance' menu option
    await page.click('[data-testid="manual-attendance-menu"]');
    await expect(page.locator('[data-testid="manual-attendance-form"]')).toBeVisible();

    // Manager selects a valid employee from the dropdown list
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-1001"]');
    const selectedEmployee = await page.locator('[data-testid="employee-dropdown"]').textContent();
    expect(selectedEmployee).toContain('John Doe');

    // Manager enters valid date in the date field (e.g., current date)
    const currentDate = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="attendance-date-input"]', currentDate);

    // Manager enters valid check-in time (e.g., 09:00 AM) and check-out time (e.g., 05:00 PM)
    await page.fill('[data-testid="checkin-time-input"]', '09:00');
    await page.fill('[data-testid="checkout-time-input"]', '17:00');

    // Manager enters any additional attendance details or notes in the remarks field
    await page.fill('[data-testid="remarks-input"]', 'Manual entry - biometric system was down');

    // Manager clicks the 'Submit' button to save the attendance record
    await page.click('[data-testid="submit-attendance-button"]');

    // Verify confirmation message is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance record saved successfully');

    // Manager verifies the newly created record appears in the attendance list
    await page.click('[data-testid="attendance-list-link"]');
    await page.fill('[data-testid="search-employee-input"]', 'John Doe');
    await page.fill('[data-testid="search-date-input"]', currentDate);
    await page.click('[data-testid="search-button"]');
    
    const attendanceRecord = page.locator('[data-testid="attendance-record-row"]').first();
    await expect(attendanceRecord).toBeVisible();
    await expect(attendanceRecord.locator('[data-testid="employee-name"]')).toContainText('John Doe');
    await expect(attendanceRecord.locator('[data-testid="checkin-time"]')).toContainText('09:00');
    await expect(attendanceRecord.locator('[data-testid="checkout-time"]')).toContainText('17:00');
  });

  test('Verify audit logging on manual attendance edits (happy-path)', async ({ page }) => {
    // Manager logs in
    await page.fill('[data-testid="username-input"]', managerCredentials.username);
    await page.fill('[data-testid="password-input"]', managerCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Manager navigates to the attendance records list and selects an existing attendance record to edit
    await page.click('[data-testid="attendance-records-menu"]');
    await expect(page.locator('[data-testid="attendance-records-list"]')).toBeVisible();
    
    const existingRecord = page.locator('[data-testid="attendance-record-row"]').first();
    await existingRecord.click();
    await page.click('[data-testid="edit-attendance-button"]');
    await expect(page.locator('[data-testid="edit-attendance-form"]')).toBeVisible();

    // Verify edit form is displayed with current data
    const currentCheckinTime = await page.locator('[data-testid="checkin-time-input"]').inputValue();
    expect(currentCheckinTime).toBeTruthy();

    // Manager modifies the check-in time from the original value to a new valid time
    await page.fill('[data-testid="checkin-time-input"]', '09:15');

    // Manager clicks the 'Save' or 'Update' button to submit the changes
    await page.click('[data-testid="update-attendance-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance record updated successfully');

    // Manager logs out
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Admin user logs into the system
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Admin navigates to the audit logs section and filters for the edited attendance record
    await page.click('[data-testid="audit-logs-menu"]');
    await expect(page.locator('[data-testid="audit-logs-page"]')).toBeVisible();
    
    await page.selectOption('[data-testid="audit-type-filter"]', 'attendance_edit');
    await page.click('[data-testid="apply-filter-button"]');

    // Admin verifies all audit details are complete and accurate
    const auditLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditLogEntry).toBeVisible();
    await expect(auditLogEntry.locator('[data-testid="audit-user"]')).toContainText(managerCredentials.username);
    await expect(auditLogEntry.locator('[data-testid="audit-action"]')).toContainText('Updated');
    await expect(auditLogEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
    await expect(auditLogEntry.locator('[data-testid="audit-changes"]')).toContainText('check-in time');
    await expect(auditLogEntry.locator('[data-testid="audit-changes"]')).toContainText('09:15');
  });

  test('Ensure access control for manual attendance input (error-case)', async ({ page }) => {
    // Non-authorized user logs into the system
    await page.fill('[data-testid="username-input"]', nonAuthorizedCredentials.username);
    await page.fill('[data-testid="password-input"]', nonAuthorizedCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Non-authorized user attempts to access the manual attendance input page
    const manualAttendanceMenu = page.locator('[data-testid="manual-attendance-menu"]');
    
    // Verify that manual attendance input menu option is not visible or is disabled
    const isMenuVisible = await manualAttendanceMenu.isVisible().catch(() => false);
    if (isMenuVisible) {
      const isMenuDisabled = await manualAttendanceMenu.isDisabled();
      expect(isMenuDisabled).toBeTruthy();
    } else {
      expect(isMenuVisible).toBeFalsy();
    }

    // Attempt direct URL navigation
    await page.goto(`${baseURL}/attendance/manual-input`);
    
    // Verify access denied message is displayed
    const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
    await expect(accessDeniedMessage).toBeVisible();
    await expect(accessDeniedMessage).toContainText('Access denied');

    // Non-authorized user logs out of the system
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Authorized manager logs into the system with valid credentials
    await page.fill('[data-testid="username-input"]', managerCredentials.username);
    await page.fill('[data-testid="password-input"]', managerCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Authorized manager navigates to the manual attendance input page
    await page.click('[data-testid="manual-attendance-menu"]');
    await expect(page.locator('[data-testid="manual-attendance-form"]')).toBeVisible();

    // Manager selects an employee, enters valid date and time details
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-1002"]');
    
    const currentDate = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="attendance-date-input"]', currentDate);
    await page.fill('[data-testid="checkin-time-input"]', '08:30');
    await page.fill('[data-testid="checkout-time-input"]', '16:30');
    await page.fill('[data-testid="remarks-input"]', 'Access control test - authorized manager');

    // Manager clicks 'Submit'
    await page.click('[data-testid="submit-attendance-button"]');

    // Manager verifies the record is saved by checking the attendance list
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance record saved successfully');
    
    await page.click('[data-testid="attendance-list-link"]');
    await page.fill('[data-testid="search-date-input"]', currentDate);
    await page.click('[data-testid="search-button"]');
    
    const savedRecord = page.locator('[data-testid="attendance-record-row"]').first();
    await expect(savedRecord).toBeVisible();
  });
});