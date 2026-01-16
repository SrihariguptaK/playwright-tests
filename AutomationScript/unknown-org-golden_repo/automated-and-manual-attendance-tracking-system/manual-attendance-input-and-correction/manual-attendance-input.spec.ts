import { test, expect } from '@playwright/test';

test.describe('Manual Attendance Input - Story 3', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const HR_OFFICER_USERNAME = 'hr.officer@company.com';
  const HR_OFFICER_PASSWORD = 'HRPassword123!';
  const UNAUTHORIZED_USERNAME = 'employee@company.com';
  const UNAUTHORIZED_PASSWORD = 'EmployeePass123!';

  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE_URL}/login`);
  });

  test('Add manual attendance record with valid data', async ({ page }) => {
    // Step 1: Login as authorized HR officer
    await page.fill('[data-testid="username-input"]', HR_OFFICER_USERNAME);
    await page.fill('[data-testid="password-input"]', HR_OFFICER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access granted to manual attendance input page
    await expect(page).toHaveURL(/.*dashboard/);
    await page.waitForSelector('[data-testid="manual-attendance-link"]');
    await page.click('[data-testid="manual-attendance-link"]');
    await expect(page).toHaveURL(/.*manual-attendance/);
    await expect(page.locator('[data-testid="manual-attendance-form"]')).toBeVisible();

    // Step 2: Enter valid employee ID, date, and time
    const employeeId = 'EMP001';
    const attendanceDate = '2024-01-15';
    const attendanceTime = '09:00';
    
    await page.fill('[data-testid="employee-id-input"]', employeeId);
    await page.fill('[data-testid="attendance-date-input"]', attendanceDate);
    await page.fill('[data-testid="attendance-time-input"]', attendanceTime);
    
    // Expected Result: Input accepted without validation errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();

    // Step 3: Submit manual attendance record
    await page.click('[data-testid="submit-attendance-button"]');
    
    // Expected Result: Record saved and confirmation displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Record saved successfully');
    
    // Verify record appears in the list
    await expect(page.locator(`[data-testid="attendance-record-${employeeId}"]`)).toBeVisible();
  });

  test('Prevent duplicate manual attendance entry', async ({ page }) => {
    // Login as authorized HR officer
    await page.fill('[data-testid="username-input"]', HR_OFFICER_USERNAME);
    await page.fill('[data-testid="password-input"]', HR_OFFICER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForSelector('[data-testid="manual-attendance-link"]');
    await page.click('[data-testid="manual-attendance-link"]');

    // Step 1: Attempt to add manual attendance record matching existing biometric entry
    const duplicateEmployeeId = 'EMP002';
    const duplicateDate = '2024-01-15';
    const duplicateTime = '08:30'; // Assume this matches existing biometric entry
    
    await page.fill('[data-testid="employee-id-input"]', duplicateEmployeeId);
    await page.fill('[data-testid="attendance-date-input"]', duplicateDate);
    await page.fill('[data-testid="attendance-time-input"]', duplicateTime);
    await page.click('[data-testid="submit-attendance-button"]');
    
    // Expected Result: System displays error preventing duplicate entry
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('duplicate');

    // Step 2: Modify entry to a unique time
    const uniqueTime = '14:30';
    await page.fill('[data-testid="attendance-time-input"]', uniqueTime);
    await page.click('[data-testid="submit-attendance-button"]');
    
    // Expected Result: System accepts and saves the record
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Record saved successfully');
  });

  test('Restrict manual attendance input to authorized users', async ({ page }) => {
    // Step 1: Login as unauthorized user
    await page.fill('[data-testid="username-input"]', UNAUTHORIZED_USERNAME);
    await page.fill('[data-testid="password-input"]', UNAUTHORIZED_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access to manual attendance input page denied
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Attempt to navigate to manual attendance page
    await page.goto(`${BASE_URL}/manual-attendance`);
    
    // Verify access is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');
    
    // Logout
    await page.click('[data-testid="logout-button"]');
    await page.waitForURL(/.*login/);

    // Step 2: Login as authorized HR officer
    await page.fill('[data-testid="username-input"]', HR_OFFICER_USERNAME);
    await page.fill('[data-testid="password-input"]', HR_OFFICER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access granted
    await page.waitForSelector('[data-testid="manual-attendance-link"]');
    await page.click('[data-testid="manual-attendance-link"]');
    await expect(page).toHaveURL(/.*manual-attendance/);
    await expect(page.locator('[data-testid="manual-attendance-form"]')).toBeVisible();
  });

  test('Delete manual attendance record with confirmation (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the application login page and enter valid HR officer credentials
    await page.fill('[data-testid="username-input"]', HR_OFFICER_USERNAME);
    await page.fill('[data-testid="password-input"]', HR_OFFICER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to the manual attendance records section from the main menu
    await page.waitForSelector('[data-testid="manual-attendance-link"]');
    await page.click('[data-testid="manual-attendance-link"]');
    await expect(page).toHaveURL(/.*manual-attendance/);

    // Step 3: Locate the specific manual attendance record to be deleted using search or browse functionality
    const recordToDelete = 'EMP003';
    await page.fill('[data-testid="search-employee-input"]', recordToDelete);
    await page.click('[data-testid="search-button"]');
    await expect(page.locator(`[data-testid="attendance-record-${recordToDelete}"]`)).toBeVisible();

    // Step 4: Click on the delete button/icon associated with the selected manual attendance record
    await page.click(`[data-testid="delete-button-${recordToDelete}"]`);

    // Step 5: Review the record details displayed in the confirmation prompt and click the 'Confirm' button
    await expect(page.locator('[data-testid="delete-confirmation-dialog"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-record-details"]')).toContainText(recordToDelete);
    await page.click('[data-testid="confirm-delete-button"]');

    // Step 6: Verify the deleted record no longer appears in the manual attendance records list
    await expect(page.locator('[data-testid="delete-success-message"]')).toBeVisible();
    await page.fill('[data-testid="search-employee-input"]', recordToDelete);
    await page.click('[data-testid="search-button"]');
    await expect(page.locator(`[data-testid="attendance-record-${recordToDelete}"]`)).not.toBeVisible();
    await expect(page.locator('[data-testid="no-records-message"]')).toBeVisible();

    // Step 7: Check the audit log for the deletion entry
    await page.click('[data-testid="audit-log-link"]');
    await expect(page).toHaveURL(/.*audit-log/);
    await page.fill('[data-testid="audit-search-input"]', recordToDelete);
    await page.click('[data-testid="audit-search-button"]');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('DELETE');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText(recordToDelete);
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText(HR_OFFICER_USERNAME);
  });

  test('Prevent unauthorized deletion attempts (error-case)', async ({ page, request }) => {
    // Step 1: Navigate to the application login page and enter credentials for an unauthorized user
    await page.fill('[data-testid="username-input"]', UNAUTHORIZED_USERNAME);
    await page.fill('[data-testid="password-input"]', UNAUTHORIZED_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Attempt to navigate to the manual attendance records section or access the delete functionality through the UI
    await page.goto(`${BASE_URL}/manual-attendance`);
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();

    // Step 3: Open API testing tool and construct a DELETE request to /api/attendance/manual/{id} endpoint
    // Get the unauthorized user's authentication token from cookies or local storage
    const cookies = await page.context().cookies();
    const authToken = cookies.find(cookie => cookie.name === 'auth_token')?.value || '';
    
    const recordIdToDelete = 'manual-record-123';

    // Step 4: Execute the DELETE API request with the unauthorized user's credentials
    const apiResponse = await request.delete(`${BASE_URL}/api/attendance/manual/${recordIdToDelete}`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      }
    });

    // Verify the API returns 403 Forbidden or 401 Unauthorized
    expect(apiResponse.status()).toBeGreaterThanOrEqual(401);
    expect(apiResponse.status()).toBeLessThanOrEqual(403);

    // Logout unauthorized user
    await page.click('[data-testid="logout-button"]');
    await page.waitForURL(/.*login/);

    // Step 5: Verify the manual attendance record still exists in the database by querying through an authorized account
    await page.fill('[data-testid="username-input"]', HR_OFFICER_USERNAME);
    await page.fill('[data-testid="password-input"]', HR_OFFICER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForSelector('[data-testid="manual-attendance-link"]');
    await page.click('[data-testid="manual-attendance-link"]');
    
    await page.fill('[data-testid="search-employee-input"]', recordIdToDelete);
    await page.click('[data-testid="search-button"]');
    await expect(page.locator(`[data-testid="attendance-record-${recordIdToDelete}"]`)).toBeVisible();

    // Step 6: Check the audit log for any unauthorized access attempts
    await page.click('[data-testid="audit-log-link"]');
    await expect(page).toHaveURL(/.*audit-log/);
    await page.fill('[data-testid="audit-search-input"]', 'unauthorized');
    await page.selectOption('[data-testid="audit-filter-type"]', 'UNAUTHORIZED_ACCESS');
    await page.click('[data-testid="audit-search-button"]');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('UNAUTHORIZED_ACCESS');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText(UNAUTHORIZED_USERNAME);
  });
});