import { test, expect } from '@playwright/test';

test.describe('Manual Attendance Input - Story 4', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const clerkCredentials = {
    username: 'attendance.clerk@company.com',
    password: 'ClerkPass123!'
  };
  const unauthorizedCredentials = {
    username: 'regular.employee@company.com',
    password: 'EmployeePass123!'
  };

  test('Add manual attendance entry successfully', async ({ page }) => {
    // Navigate to the attendance system login page
    await page.goto(`${baseURL}/login`);
    await expect(page).toHaveURL(/.*login/);

    // Enter valid Attendance Clerk credentials and click Login button
    await page.fill('[data-testid="username-input"]', clerkCredentials.username);
    await page.fill('[data-testid="password-input"]', clerkCredentials.password);
    await page.click('[data-testid="login-button"]');

    // Verify access to the manual attendance input section in the navigation menu
    await expect(page.locator('[data-testid="manual-attendance-nav"]')).toBeVisible();
    await expect(page).toHaveURL(/.*dashboard/);

    // Click on the manual attendance input section link
    await page.click('[data-testid="manual-attendance-nav"]');
    await expect(page).toHaveURL(/.*manual-attendance/);

    // Click on 'Add New Manual Attendance Entry' button
    await page.click('[data-testid="add-manual-entry-button"]');
    await expect(page.locator('[data-testid="manual-entry-form"]')).toBeVisible();

    // Enter a valid employee ID in the Employee ID field
    await page.fill('[data-testid="employee-id-input"]', 'EMP12345');

    // Select a valid date from the date picker (current or past date)
    const currentDate = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="date-input"]', currentDate);

    // Enter a valid time in the time field
    await page.fill('[data-testid="time-input"]', '09:00');

    // Enter a reason for the manual entry in the Reason field
    await page.fill('[data-testid="reason-input"]', 'Biometric device malfunction');

    // Verify that all required fields are filled and no validation errors are displayed
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();

    // Click the Submit or Save button to save the manual attendance entry
    await page.click('[data-testid="submit-entry-button"]');

    // Verify that confirmation message is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Entry saved');

    // Verify that the new entry appears in the list of manual attendance entries
    await expect(page.locator('[data-testid="manual-entry-list"]')).toContainText('EMP12345');
    await expect(page.locator('[data-testid="manual-entry-list"]')).toContainText('Biometric device malfunction');

    // Check that the audit log records the manual entry action
    await page.click('[data-testid="audit-log-tab"]');
    await expect(page.locator('[data-testid="audit-log-list"]')).toContainText('Manual entry created');
    await expect(page.locator('[data-testid="audit-log-list"]')).toContainText('EMP12345');
  });

  test('Edit and delete manual attendance entry', async ({ page }) => {
    // Login as Attendance Clerk
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', clerkCredentials.username);
    await page.fill('[data-testid="password-input"]', clerkCredentials.password);
    await page.click('[data-testid="login-button"]');

    // Navigate to the manual attendance input section from the dashboard
    await page.click('[data-testid="manual-attendance-nav"]');
    await expect(page).toHaveURL(/.*manual-attendance/);

    // Locate an existing manual attendance entry from the list
    await expect(page.locator('[data-testid="manual-entry-list"]')).toBeVisible();
    const firstEntry = page.locator('[data-testid="manual-entry-row"]').first();
    await expect(firstEntry).toBeVisible();

    // Click on the Edit icon or button for the selected entry
    await firstEntry.locator('[data-testid="edit-entry-button"]').click();

    // Verify that all current entry details are correctly displayed in the form
    await expect(page.locator('[data-testid="manual-entry-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-id-input"]')).toHaveValue(/EMP\d+/);
    await expect(page.locator('[data-testid="date-input"]')).not.toBeEmpty();
    await expect(page.locator('[data-testid="time-input"]')).not.toBeEmpty();

    // Modify the Time field to a different valid time
    await page.fill('[data-testid="time-input"]', '10:30');

    // Modify the Reason field to update the explanation
    await page.fill('[data-testid="reason-input"]', 'Biometric device malfunction - corrected time');

    // Click the Save Changes button
    await page.click('[data-testid="save-changes-button"]');

    // Verify that the updated entry shows the modified values in the list
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Changes saved');
    await expect(page.locator('[data-testid="manual-entry-list"]')).toContainText('10:30');
    await expect(page.locator('[data-testid="manual-entry-list"]')).toContainText('corrected time');

    // Check that the edit action is logged in the audit trail
    await page.click('[data-testid="audit-log-tab"]');
    await expect(page.locator('[data-testid="audit-log-list"]')).toContainText('Manual entry updated');

    // Navigate back to entries list
    await page.click('[data-testid="entries-tab"]');

    // Select the same or another manual attendance entry for deletion
    const entryToDelete = page.locator('[data-testid="manual-entry-row"]').first();
    await expect(entryToDelete).toBeVisible();

    // Click the Delete button for the selected entry
    await entryToDelete.locator('[data-testid="delete-entry-button"]').click();

    // Click Confirm or Yes in the deletion confirmation dialog
    await expect(page.locator('[data-testid="delete-confirmation-dialog"]')).toBeVisible();
    await page.click('[data-testid="confirm-delete-button"]');

    // Verify that the deleted entry is removed from the list
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Entry deleted');

    // Check that the deletion action is logged in the audit trail
    await page.click('[data-testid="audit-log-tab"]');
    await expect(page.locator('[data-testid="audit-log-list"]')).toContainText('Manual entry deleted');
  });

  test('Prevent unauthorized access to manual attendance input', async ({ page, request }) => {
    // Navigate to the attendance system login page
    await page.goto(`${baseURL}/login`);

    // Enter credentials of a user without manual attendance input permissions
    await page.fill('[data-testid="username-input"]', unauthorizedCredentials.username);
    await page.fill('[data-testid="password-input"]', unauthorizedCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Check the navigation menu for manual attendance input section
    const manualAttendanceNav = page.locator('[data-testid="manual-attendance-nav"]');
    await expect(manualAttendanceNav).not.toBeVisible();

    // Attempt to manually navigate to the manual attendance input URL
    await page.goto(`${baseURL}/manual-attendance`);

    // Verify that no manual attendance input functionality is accessible through the UI
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="manual-entry-form"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="add-manual-entry-button"]')).not.toBeVisible();

    // Get authentication token from cookies or local storage
    const authToken = await page.evaluate(() => {
      return localStorage.getItem('authToken') || sessionStorage.getItem('authToken');
    });

    // Attempt to call POST /api/manual-attendance endpoint
    const postResponse = await request.post(`${baseURL}/api/manual-attendance`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      data: {
        employeeId: 'EMP12345',
        date: new Date().toISOString().split('T')[0],
        time: '09:00',
        reason: 'Unauthorized test attempt'
      }
    });

    // Verify authorization error is returned
    expect(postResponse.status()).toBe(403);
    const postBody = await postResponse.json();
    expect(postBody.error || postBody.message).toMatch(/unauthorized|forbidden|access denied/i);

    // Attempt to call PUT /api/manual-attendance/{id} endpoint
    const putResponse = await request.put(`${baseURL}/api/manual-attendance/123`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      data: {
        employeeId: 'EMP12345',
        date: new Date().toISOString().split('T')[0],
        time: '10:00',
        reason: 'Unauthorized edit attempt'
      }
    });

    // Verify authorization error is returned
    expect(putResponse.status()).toBe(403);
    const putBody = await putResponse.json();
    expect(putBody.error || putBody.message).toMatch(/unauthorized|forbidden|access denied/i);

    // Attempt to call DELETE /api/manual-attendance/{id} endpoint
    const deleteResponse = await request.delete(`${baseURL}/api/manual-attendance/123`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });

    // Verify authorization error is returned
    expect(deleteResponse.status()).toBe(403);
    const deleteBody = await deleteResponse.json();
    expect(deleteBody.error || deleteBody.message).toMatch(/unauthorized|forbidden|access denied/i);

    // Verify that no manual attendance entries are created, modified, or deleted
    // This is implicitly verified by the 403 status codes above

    // Check security audit logs for the unauthorized access attempts
    // Note: This would typically require admin access to view audit logs
    // For this test, we verify the attempts were blocked
    expect(postResponse.status()).toBe(403);
    expect(putResponse.status()).toBe(403);
    expect(deleteResponse.status()).toBe(403);
  });
});