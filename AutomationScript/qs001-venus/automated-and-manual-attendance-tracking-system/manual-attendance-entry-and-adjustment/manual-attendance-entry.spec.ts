import { test, expect } from '@playwright/test';

test.describe('Manual Attendance Entry - Story 3', () => {
  test.beforeEach(async ({ page }) => {
    // HR officer logs into attendance system
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'hr.officer@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate adding manual attendance entry (happy-path)', async ({ page }) => {
    // Step 1: Navigate to manual attendance entry page from the main dashboard or menu
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="manual-attendance-link"]');
    
    // Expected Result: Manual attendance form is displayed
    await expect(page.locator('[data-testid="manual-attendance-form"]')).toBeVisible();
    await expect(page.locator('h1, h2')).toContainText(/manual attendance/i);

    // Step 2: Enter valid employee ID in the employee ID field
    await page.fill('[data-testid="employee-id-input"]', 'EMP12345');
    
    // Step 3: Select a valid date from the date picker
    await page.fill('[data-testid="attendance-date-input"]', '2024-01-15');
    
    // Step 4: Enter valid time in the time field (e.g., 09:00 AM)
    await page.fill('[data-testid="attendance-time-input"]', '09:00');
    
    // Step 5: Enter a reason for manual entry in the reason field
    await page.fill('[data-testid="attendance-reason-input"]', 'Missed biometric scan');
    
    // Step 6: Click the Submit or Save button
    await page.click('[data-testid="submit-attendance-button"]');
    
    // Expected Result: Entry is saved and confirmation message displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/successfully added|saved/i);
    
    // Step 7: Navigate to attendance reports section
    await page.click('[data-testid="attendance-reports-link"]');
    await expect(page).toHaveURL(/.*reports/);
    
    // Step 8: Search for the newly added manual attendance entry using employee ID and date
    await page.fill('[data-testid="search-employee-id"]', 'EMP12345');
    await page.fill('[data-testid="search-date"]', '2024-01-15');
    await page.click('[data-testid="search-button"]');
    
    // Expected Result: Manual attendance entry is listed correctly
    await expect(page.locator('[data-testid="attendance-record-row"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-record-row"]')).toContainText('EMP12345');
    await expect(page.locator('[data-testid="attendance-record-row"]')).toContainText('09:00');
    await expect(page.locator('[data-testid="attendance-record-row"]')).toContainText('Missed biometric scan');
  });

  test('Verify duplicate detection for manual entries (error-case)', async ({ page }) => {
    // Step 1: Navigate to manual attendance entry page
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="manual-attendance-link"]');
    await expect(page.locator('[data-testid="manual-attendance-form"]')).toBeVisible();
    
    // Step 2: Enter employee ID that has an existing biometric attendance record
    await page.fill('[data-testid="employee-id-input"]', 'EMP67890');
    
    // Step 3: Select the same date as the existing biometric record
    await page.fill('[data-testid="attendance-date-input"]', '2024-01-15');
    
    // Step 4: Enter the same time as the existing biometric record
    await page.fill('[data-testid="attendance-time-input"]', '08:30');
    
    // Step 5: Enter a reason and click Submit
    await page.fill('[data-testid="attendance-reason-input"]', 'Manual correction');
    await page.click('[data-testid="submit-attendance-button"]');
    
    // Expected Result: System rejects entry with duplicate warning
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/duplicate|already exists/i);
    
    // Step 6: Modify the time field to a unique time that does not conflict with existing records
    await page.fill('[data-testid="attendance-time-input"]', '09:30');
    
    // Step 7: Click Submit button again
    await page.click('[data-testid="submit-attendance-button"]');
    
    // Expected Result: Entry is accepted successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/successfully added|saved/i);
    
    // Step 8: Verify the entry appears in attendance records
    await page.click('[data-testid="attendance-reports-link"]');
    await page.fill('[data-testid="search-employee-id"]', 'EMP67890');
    await page.fill('[data-testid="search-date"]', '2024-01-15');
    await page.click('[data-testid="search-button"]');
    await expect(page.locator('[data-testid="attendance-record-row"]')).toContainText('09:30');
  });

  test('Ensure audit logging of manual attendance changes (happy-path)', async ({ page }) => {
    // Step 1: Navigate to manual attendance management page
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="manual-attendance-management-link"]');
    await expect(page.locator('[data-testid="manual-attendance-list"]')).toBeVisible();
    
    // Step 2: Select an existing manual attendance entry and click Edit button
    const firstEntry = page.locator('[data-testid="attendance-entry-row"]').first();
    const originalTime = await firstEntry.locator('[data-testid="entry-time"]').textContent();
    await firstEntry.locator('[data-testid="edit-entry-button"]').click();
    await expect(page.locator('[data-testid="edit-attendance-form"]')).toBeVisible();
    
    // Step 3: Modify the time field to a different valid time
    await page.fill('[data-testid="attendance-time-input"]', '10:15');
    
    // Step 4: Click Save or Update button
    await page.click('[data-testid="update-attendance-button"]');
    
    // Expected Result: Change is saved and audit log updated
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/updated|saved/i);
    
    // Step 5: Navigate to audit logs section or access audit trail for the edited entry
    await page.click('[data-testid="audit-logs-link"]');
    await expect(page).toHaveURL(/.*audit/);
    
    // Verify edit action is recorded with complete information
    const editLogEntry = page.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'EDIT' }).first();
    await expect(editLogEntry).toBeVisible();
    await expect(editLogEntry).toContainText(/edit|update/i);
    await expect(editLogEntry).toContainText('10:15');
    await expect(editLogEntry).toContainText(/hr.officer/i);
    
    // Step 6: Return to manual attendance management page and select a manual attendance entry
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="manual-attendance-management-link"]');
    await expect(page.locator('[data-testid="manual-attendance-list"]')).toBeVisible();
    
    // Step 7: Click Delete button and confirm the deletion
    const entryToDelete = page.locator('[data-testid="attendance-entry-row"]').first();
    const employeeIdToDelete = await entryToDelete.locator('[data-testid="entry-employee-id"]').textContent();
    await entryToDelete.locator('[data-testid="delete-entry-button"]').click();
    await page.locator('[data-testid="confirm-delete-button"]').click();
    
    // Expected Result: Deletion is recorded in audit logs
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/deleted|removed/i);
    
    // Step 8: Navigate to audit logs section and search for the deletion record
    await page.click('[data-testid="audit-logs-link"]');
    
    // Step 9: Verify that both edit and delete actions are recorded with complete information
    const deleteLogEntry = page.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'DELETE' }).first();
    await expect(deleteLogEntry).toBeVisible();
    await expect(deleteLogEntry).toContainText(/delete|removed/i);
    await expect(deleteLogEntry).toContainText(employeeIdToDelete || '');
    await expect(deleteLogEntry).toContainText(/hr.officer/i);
    
    // Verify timestamp is present in audit logs
    await expect(deleteLogEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
    await expect(editLogEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
  });
});