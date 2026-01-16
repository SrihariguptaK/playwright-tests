import { test, expect } from '@playwright/test';

test.describe('Manual Attendance Entry - Story 24', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    // Login as HR Officer
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'hr.officer@company.com');
    await page.fill('[data-testid="password-input"]', 'HRPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate manual attendance creation with valid data (happy-path)', async ({ page }) => {
    // Step 1: Navigate to manual attendance entry page
    await page.goto(`${BASE_URL}/manual-attendance`);
    await expect(page.locator('[data-testid="manual-attendance-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-dropdown"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-picker"]')).toBeVisible();
    await expect(page.locator('[data-testid="time-in-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="time-out-input"]')).toBeVisible();
    
    // Step 2: Select an employee from the employee dropdown list
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-john-doe"]');
    await expect(page.locator('[data-testid="employee-dropdown"]')).toContainText('John Doe');
    
    // Select a valid date using the date picker
    await page.click('[data-testid="date-picker"]');
    await page.fill('[data-testid="date-picker"]', '2024-01-25');
    
    // Enter valid time in (e.g., 09:00 AM)
    await page.fill('[data-testid="time-in-input"]', '09:00');
    await page.selectOption('[data-testid="time-in-period"]', 'AM');
    
    // Enter valid time out (e.g., 05:00 PM)
    await page.fill('[data-testid="time-out-input"]', '05:00');
    await page.selectOption('[data-testid="time-out-period"]', 'PM');
    
    // Select attendance status (e.g., Present)
    await page.selectOption('[data-testid="attendance-status-dropdown"]', 'Present');
    
    // Step 3: Click the Submit button
    const startTime = Date.now();
    await page.click('[data-testid="submit-attendance-button"]');
    
    // Verify entry is saved and confirmation is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance entry created successfully');
    
    // Verify the response time of the submission (should be under 3 seconds)
    const endTime = Date.now();
    const responseTime = endTime - startTime;
    expect(responseTime).toBeLessThan(3000);
  });

  test('Verify validation prevents overlapping attendance records (error-case)', async ({ page }) => {
    // Step 1: Navigate to manual attendance entry page
    await page.goto(`${BASE_URL}/manual-attendance`);
    await expect(page.locator('[data-testid="manual-attendance-form"]')).toBeVisible();
    
    // Select employee 'John Doe' from the dropdown
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-john-doe"]');
    
    // Select date '2024-01-15' which already has an attendance record
    await page.fill('[data-testid="date-picker"]', '2024-01-15');
    
    // Enter overlapping time period (e.g., 10:00 AM to 06:00 PM)
    await page.fill('[data-testid="time-in-input"]', '10:00');
    await page.selectOption('[data-testid="time-in-period"]', 'AM');
    await page.fill('[data-testid="time-out-input"]', '06:00');
    await page.selectOption('[data-testid="time-out-period"]', 'PM');
    await page.selectOption('[data-testid="attendance-status-dropdown"]', 'Present');
    
    // Click the Submit button
    await page.click('[data-testid="submit-attendance-button"]');
    
    // System displays validation error and blocks submission
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/overlapping|conflict|already exists/i);
    
    // Step 2: Change the date to '2024-01-16' which has no existing record
    await page.fill('[data-testid="date-picker"]', '2024-01-16');
    
    // Keep the same time values (10:00 AM to 06:00 PM) and click Submit
    await page.click('[data-testid="submit-attendance-button"]');
    
    // Submission succeeds with confirmation
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance entry created successfully');
  });

  test('Ensure audit trail logs manual attendance changes (happy-path)', async ({ page }) => {
    // Step 1: Navigate to manual attendance entry page and create a new attendance entry
    await page.goto(`${BASE_URL}/manual-attendance`);
    await expect(page.locator('[data-testid="manual-attendance-form"]')).toBeVisible();
    
    // Create entry for employee 'Jane Smith' on '2024-01-20' with time 08:00 AM to 04:00 PM
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-jane-smith"]');
    await page.fill('[data-testid="date-picker"]', '2024-01-20');
    await page.fill('[data-testid="time-in-input"]', '08:00');
    await page.selectOption('[data-testid="time-in-period"]', 'AM');
    await page.fill('[data-testid="time-out-input"]', '04:00');
    await page.selectOption('[data-testid="time-out-period"]', 'PM');
    await page.selectOption('[data-testid="attendance-status-dropdown"]', 'Present');
    await page.click('[data-testid="submit-attendance-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Step 2: Access the audit log table or audit trail interface and search for the latest entry
    await page.goto(`${BASE_URL}/audit-log`);
    await page.fill('[data-testid="audit-search-input"]', 'Jane Smith');
    await page.click('[data-testid="audit-search-button"]');
    
    // Audit log records user and timestamp for CREATE action
    const createAuditRow = page.locator('[data-testid="audit-row"]').filter({ hasText: 'CREATE' }).first();
    await expect(createAuditRow).toBeVisible();
    await expect(createAuditRow).toContainText('Jane Smith');
    await expect(createAuditRow).toContainText('2024-01-20');
    await expect(createAuditRow).toContainText(/hr.officer/i);
    
    // Verify timestamp is present
    const timestampElement = createAuditRow.locator('[data-testid="audit-timestamp"]');
    await expect(timestampElement).toBeVisible();
    
    // Step 3: Navigate to the attendance records list and select the newly created entry
    await page.goto(`${BASE_URL}/attendance-records`);
    await page.fill('[data-testid="records-search-input"]', 'Jane Smith');
    await page.click('[data-testid="records-search-button"]');
    
    const attendanceRecord = page.locator('[data-testid="attendance-record-row"]').filter({ hasText: 'Jane Smith' }).filter({ hasText: '2024-01-20' }).first();
    await expect(attendanceRecord).toBeVisible();
    
    // Click Edit button and modify the time out from 04:00 PM to 05:00 PM
    await attendanceRecord.locator('[data-testid="edit-button"]').click();
    await expect(page.locator('[data-testid="edit-attendance-modal"]')).toBeVisible();
    
    await page.fill('[data-testid="edit-time-out-input"]', '05:00');
    await page.selectOption('[data-testid="edit-time-out-period"]', 'PM');
    await page.click('[data-testid="save-changes-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance updated successfully');
    
    // Step 4: Access the audit log and search for modification records
    await page.goto(`${BASE_URL}/audit-log`);
    await page.fill('[data-testid="audit-search-input"]', 'Jane Smith');
    await page.click('[data-testid="audit-search-button"]');
    
    // Audit log records modification details for UPDATE action
    const updateAuditRow = page.locator('[data-testid="audit-row"]').filter({ hasText: 'UPDATE' }).first();
    await expect(updateAuditRow).toBeVisible();
    await expect(updateAuditRow).toContainText('Jane Smith');
    await expect(updateAuditRow).toContainText(/04:00 PM.*05:00 PM|time out.*modified/i);
    await expect(updateAuditRow).toContainText(/hr.officer/i);
    
    // Step 5: Navigate back to the attendance records list and delete the entry
    await page.goto(`${BASE_URL}/attendance-records`);
    await page.fill('[data-testid="records-search-input"]', 'Jane Smith');
    await page.click('[data-testid="records-search-button"]');
    
    const recordToDelete = page.locator('[data-testid="attendance-record-row"]').filter({ hasText: 'Jane Smith' }).filter({ hasText: '2024-01-20' }).first();
    await recordToDelete.locator('[data-testid="delete-button"]').click();
    
    // Confirm the deletion
    await expect(page.locator('[data-testid="delete-confirmation-modal"]')).toBeVisible();
    await page.click('[data-testid="confirm-delete-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance deleted successfully');
    
    // Step 6: Access the audit log and search for deletion records
    await page.goto(`${BASE_URL}/audit-log`);
    await page.fill('[data-testid="audit-search-input"]', 'Jane Smith');
    await page.click('[data-testid="audit-search-button"]');
    
    // Audit log records deletion event for DELETE action
    const deleteAuditRow = page.locator('[data-testid="audit-row"]').filter({ hasText: 'DELETE' }).first();
    await expect(deleteAuditRow).toBeVisible();
    await expect(deleteAuditRow).toContainText('Jane Smith');
    await expect(deleteAuditRow).toContainText('2024-01-20');
    await expect(deleteAuditRow).toContainText(/hr.officer/i);
    
    // Step 7: Verify all three audit entries (CREATE, UPDATE, DELETE) are present
    const allAuditRows = page.locator('[data-testid="audit-row"]').filter({ hasText: 'Jane Smith' });
    const auditCount = await allAuditRows.count();
    expect(auditCount).toBeGreaterThanOrEqual(3);
    
    // Verify CREATE entry contains complete information
    await expect(createAuditRow.locator('[data-testid="audit-action"]')).toContainText('CREATE');
    await expect(createAuditRow.locator('[data-testid="audit-user"]')).toBeVisible();
    await expect(createAuditRow.locator('[data-testid="audit-timestamp"]')).toBeVisible();
    
    // Verify UPDATE entry contains complete information
    await expect(updateAuditRow.locator('[data-testid="audit-action"]')).toContainText('UPDATE');
    await expect(updateAuditRow.locator('[data-testid="audit-user"]')).toBeVisible();
    await expect(updateAuditRow.locator('[data-testid="audit-timestamp"]')).toBeVisible();
    
    // Verify DELETE entry contains complete information
    await expect(deleteAuditRow.locator('[data-testid="audit-action"]')).toContainText('DELETE');
    await expect(deleteAuditRow.locator('[data-testid="audit-user"]')).toBeVisible();
    await expect(deleteAuditRow.locator('[data-testid="audit-timestamp"]')).toBeVisible();
  });
});