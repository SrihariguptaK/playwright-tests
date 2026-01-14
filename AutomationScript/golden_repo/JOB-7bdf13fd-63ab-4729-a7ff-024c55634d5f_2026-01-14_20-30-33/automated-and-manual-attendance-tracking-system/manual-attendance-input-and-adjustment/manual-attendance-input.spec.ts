import { test, expect } from '@playwright/test';

test.describe('Manual Attendance Input - Story 14', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const HR_USERNAME = 'hr.officer@company.com';
  const HR_PASSWORD = 'HRPassword123!';
  const NON_HR_USERNAME = 'employee@company.com';
  const NON_HR_PASSWORD = 'EmployeePass123!';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('Validate manual attendance record creation (happy-path)', async ({ page }) => {
    // Step 1: Login as authorized HR officer
    await page.fill('input[data-testid="username-input"]', HR_USERNAME);
    await page.fill('input[data-testid="password-input"]', HR_PASSWORD);
    await page.click('button[data-testid="login-button"]');
    
    // Expected Result: Access granted to manual attendance input page
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="manual-attendance-link"]')).toBeVisible();

    // Step 2: Navigate to manual attendance input page
    await page.click('[data-testid="manual-attendance-link"]');
    await expect(page).toHaveURL(/.*manual-attendance/);
    await expect(page.locator('h1:has-text("Manual Attendance Input")')).toBeVisible();

    // Step 3: Select a valid employee from dropdown
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-1"]');
    const selectedEmployee = await page.locator('[data-testid="employee-dropdown"]').textContent();
    expect(selectedEmployee).toBeTruthy();

    // Step 4: Enter valid date
    const currentDate = new Date();
    const formattedDate = `${currentDate.getDate().toString().padStart(2, '0')}/${(currentDate.getMonth() + 1).toString().padStart(2, '0')}/${currentDate.getFullYear()}`;
    await page.fill('[data-testid="date-input"]', formattedDate);

    // Step 5: Enter valid time-in timestamp
    await page.fill('[data-testid="time-in-input"]', '09:00 AM');

    // Step 6: Enter valid time-out timestamp
    await page.fill('[data-testid="time-out-input"]', '05:00 PM');

    // Step 7: Submit the manual attendance record
    await page.click('[data-testid="submit-button"]');

    // Expected Result: Manual attendance record is saved and confirmation displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Manual attendance record saved successfully');

    // Step 8: Navigate to audit logs page
    await page.click('[data-testid="audit-logs-link"]');
    await expect(page).toHaveURL(/.*audit-logs/);

    // Step 9: Search for the newly created record in audit logs
    await page.fill('[data-testid="audit-search-input"]', selectedEmployee || '');
    await page.click('[data-testid="audit-search-button"]');

    // Expected Result: Audit log contains correct details
    const auditLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditLogEntry).toBeVisible();
    await expect(auditLogEntry).toContainText('Manual attendance created');
    await expect(auditLogEntry).toContainText(formattedDate);
  });

  test('Verify prevention of overlapping manual attendance entries (error-case)', async ({ page }) => {
    // Login as HR officer
    await page.fill('input[data-testid="username-input"]', HR_USERNAME);
    await page.fill('input[data-testid="password-input"]', HR_PASSWORD);
    await page.click('button[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to manual attendance input page
    await page.click('[data-testid="manual-attendance-link"]');
    await expect(page).toHaveURL(/.*manual-attendance/);

    // Step 1: Select employee with existing attendance record
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-1"]');

    // Step 2: Enter the same date as existing record
    await page.fill('[data-testid="date-input"]', '15/01/2024');

    // Step 3: Enter overlapping time-in value
    await page.fill('[data-testid="time-in-input"]', '10:00 AM');

    // Step 4: Enter time-out value
    await page.fill('[data-testid="time-out-input"]', '06:00 PM');

    // Step 5: Attempt to submit overlapping record
    await page.click('[data-testid="submit-button"]');

    // Expected Result: System displays validation error
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('overlapping attendance');

    // Expected Result: Form remains visible with entered data
    await expect(page.locator('[data-testid="date-input"]')).toHaveValue('15/01/2024');
    await expect(page.locator('[data-testid="time-in-input"]')).toHaveValue('10:00 AM');
    await expect(page.locator('[data-testid="time-out-input"]')).toHaveValue('06:00 PM');

    // Verify no duplicate record was created
    await page.click('[data-testid="view-records-link"]');
    const recordsForDate = page.locator('[data-testid="attendance-record"][data-date="15/01/2024"]');
    const recordCount = await recordsForDate.count();
    expect(recordCount).toBe(1);
  });

  test('Ensure unauthorized users cannot perform manual attendance operations (error-case)', async ({ page, request }) => {
    // Step 1: Login as non-HR user
    await page.fill('input[data-testid="username-input"]', NON_HR_USERNAME);
    await page.fill('input[data-testid="password-input"]', NON_HR_PASSWORD);
    await page.click('button[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Attempt to navigate to manual attendance input page
    const manualAttendanceLink = page.locator('[data-testid="manual-attendance-link"]');
    await expect(manualAttendanceLink).not.toBeVisible();

    // Attempt direct URL navigation
    await page.goto(`${BASE_URL}/manual-attendance`);
    
    // Expected Result: Access denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access to manual attendance input page is denied');

    // Step 3: Attempt POST request to manual attendance API
    const postResponse = await request.post(`${BASE_URL}/api/manual-attendance`, {
      data: {
        employeeId: '12345',
        date: '15/01/2024',
        timeIn: '09:00 AM',
        timeOut: '05:00 PM'
      },
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('authToken'))}`
      }
    });

    // Expected Result: Authorization error
    expect(postResponse.status()).toBe(403);
    const postBody = await postResponse.json();
    expect(postBody.error).toContain('Authorization error');

    // Step 4: Attempt PUT request to edit existing record
    const putResponse = await request.put(`${BASE_URL}/api/manual-attendance/1`, {
      data: {
        timeOut: '06:00 PM'
      },
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('authToken'))}`
      }
    });

    // Expected Result: Authorization error
    expect(putResponse.status()).toBe(403);
    const putBody = await putResponse.json();
    expect(putBody.error).toContain('Authorization error');

    // Step 5: Attempt DELETE request
    const deleteResponse = await request.delete(`${BASE_URL}/api/manual-attendance/1`, {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('authToken'))}`
      }
    });

    // Expected Result: Authorization error
    expect(deleteResponse.status()).toBe(403);
    const deleteBody = await deleteResponse.json();
    expect(deleteBody.error).toContain('Authorization error');

    // Step 6: Verify no unauthorized changes in audit logs
    await page.goto(`${BASE_URL}/logout`);
    await page.fill('input[data-testid="username-input"]', HR_USERNAME);
    await page.fill('input[data-testid="password-input"]', HR_PASSWORD);
    await page.click('button[data-testid="login-button"]');
    
    await page.click('[data-testid="audit-logs-link"]');
    await page.fill('[data-testid="audit-search-input"]', NON_HR_USERNAME);
    await page.click('[data-testid="audit-search-button"]');

    const unauthorizedAttempts = page.locator('[data-testid="audit-log-entry"]:has-text("unauthorized access attempt")');
    await expect(unauthorizedAttempts.first()).toBeVisible();
  });
});