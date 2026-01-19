import { test, expect } from '@playwright/test';

test.describe('Edit Manual Attendance Entries', () => {
  test.beforeEach(async ({ page }) => {
    // Login as HR Officer
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'hr.officer@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful manual attendance entry edit', async ({ page }) => {
    // Action: Navigate to manual attendance management page
    await page.click('[data-testid="menu-attendance"]');
    await page.click('[data-testid="submenu-manual-attendance"]');
    await expect(page).toHaveURL(/.*manual-attendance/);
    
    // Expected Result: List of manual entries is displayed
    await expect(page.locator('[data-testid="manual-attendance-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-entry-row"]').first()).toBeVisible();
    
    // Locate a specific manual attendance entry using search
    await page.fill('[data-testid="search-employee-input"]', 'EMP001');
    await page.click('[data-testid="search-button"]');
    await page.waitForTimeout(1000);
    
    // Click the Edit button for the selected entry
    const firstEntry = page.locator('[data-testid="attendance-entry-row"]').first();
    await firstEntry.locator('[data-testid="edit-button"]').click();
    
    // Expected Result: Edit form is displayed with current details
    await expect(page.locator('[data-testid="edit-attendance-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-time-input"]')).toBeVisible();
    
    // Action: Modify attendance time
    const currentTime = await page.locator('[data-testid="attendance-time-input"]').inputValue();
    await page.fill('[data-testid="attendance-time-input"]', '10:30');
    await page.fill('[data-testid="reason-input"]', 'Corrected entry - actual check-in time');
    
    // Action: Submit changes
    await page.click('[data-testid="submit-edit-button"]');
    
    // Expected Result: Entry is updated and confirmation displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('successfully updated');
    
    // Verify the updated entry in the manual attendance list
    await page.waitForTimeout(1000);
    await expect(firstEntry.locator('[data-testid="attendance-time"]')).toContainText('10:30');
    
    // Navigate to attendance reports section
    await page.click('[data-testid="menu-reports"]');
    await page.click('[data-testid="submenu-attendance-reports"]');
    await expect(page).toHaveURL(/.*attendance-reports/);
    
    // Search for the edited entry in the attendance report
    await page.fill('[data-testid="report-employee-search"]', 'EMP001');
    await page.fill('[data-testid="report-date-input"]', new Date().toISOString().split('T')[0]);
    await page.click('[data-testid="report-search-button"]');
    await page.waitForTimeout(2000);
    
    // Verify the entry appears in the report with updated time
    const reportEntry = page.locator('[data-testid="report-entry-row"]').first();
    await expect(reportEntry).toContainText('10:30');
  });

  test('Verify prevention of duplicate attendance entries on edit', async ({ page }) => {
    // Navigate to manual attendance management page
    await page.click('[data-testid="menu-attendance"]');
    await page.click('[data-testid="submenu-manual-attendance"]');
    await expect(page).toHaveURL(/.*manual-attendance/);
    
    // Select a manual attendance entry for an employee with existing biometric record
    await page.fill('[data-testid="search-employee-input"]', 'EMP002');
    await page.click('[data-testid="search-button"]');
    await page.waitForTimeout(1000);
    
    // Click Edit button for the selected entry
    const targetEntry = page.locator('[data-testid="attendance-entry-row"]').first();
    await targetEntry.locator('[data-testid="edit-button"]').click();
    await expect(page.locator('[data-testid="edit-attendance-modal"]')).toBeVisible();
    
    // Action: Attempt to edit entry to match existing biometric record
    await page.fill('[data-testid="attendance-time-input"]', '09:00');
    await page.click('[data-testid="submit-edit-button"]');
    
    // Expected Result: System rejects edit with duplicate warning
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('duplicate');
    
    // Verify the entry remains unchanged in the list
    await page.click('[data-testid="cancel-edit-button"]');
    await page.waitForTimeout(500);
    const originalTime = await targetEntry.locator('[data-testid="attendance-time"]').textContent();
    expect(originalTime).not.toContain('09:00');
    
    // Click Edit button again for the same entry
    await targetEntry.locator('[data-testid="edit-button"]').click();
    await expect(page.locator('[data-testid="edit-attendance-modal"]')).toBeVisible();
    
    // Action: Modify entry to a unique time and submit
    await page.fill('[data-testid="attendance-time-input"]', '11:45');
    await page.fill('[data-testid="reason-input"]', 'Corrected to unique time');
    await page.click('[data-testid="submit-edit-button"]');
    
    // Expected Result: Edit is accepted successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('successfully updated');
    
    // Verify the updated entry appears in the list with the new unique time
    await page.waitForTimeout(1000);
    await expect(targetEntry.locator('[data-testid="attendance-time"]')).toContainText('11:45');
  });

  test('Ensure audit logging of manual attendance edits', async ({ page }) => {
    // Navigate to manual attendance management page
    await page.click('[data-testid="menu-attendance"]');
    await page.click('[data-testid="submenu-manual-attendance"]');
    await expect(page).toHaveURL(/.*manual-attendance/);
    
    // Search for specific manual attendance entry
    await page.fill('[data-testid="search-employee-input"]', 'EMP003');
    await page.click('[data-testid="search-button"]');
    await page.waitForTimeout(1000);
    
    // Note the current details of the entry
    const targetEntry = page.locator('[data-testid="attendance-entry-row"]').first();
    const employeeId = await targetEntry.locator('[data-testid="employee-id"]').textContent();
    const originalTime = await targetEntry.locator('[data-testid="attendance-time"]').textContent();
    const originalReason = await targetEntry.locator('[data-testid="reason"]').textContent();
    const entryDate = await targetEntry.locator('[data-testid="entry-date"]').textContent();
    
    // Click Edit button for the selected entry
    await targetEntry.locator('[data-testid="edit-button"]').click();
    await expect(page.locator('[data-testid="edit-attendance-modal"]')).toBeVisible();
    
    // Action: Modify the time and reason fields
    await page.fill('[data-testid="attendance-time-input"]', '09:45');
    await page.fill('[data-testid="reason-input"]', 'Time correction based on manager approval');
    
    // Record timestamp before submission
    const editTimestamp = new Date();
    
    // Click Submit button
    await page.click('[data-testid="submit-edit-button"]');
    
    // Expected Result: Entry is updated and confirmation displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await page.waitForTimeout(1000);
    
    // Navigate to audit logs section
    await page.click('[data-testid="menu-admin"]');
    await page.click('[data-testid="submenu-audit-logs"]');
    await expect(page).toHaveURL(/.*audit-logs/);
    
    // Search for audit records related to the edited entry
    await page.fill('[data-testid="audit-search-employee"]', employeeId?.trim() || 'EMP003');
    await page.fill('[data-testid="audit-search-date"]', entryDate?.trim() || new Date().toISOString().split('T')[0]);
    await page.selectOption('[data-testid="audit-action-filter"]', 'UPDATE');
    await page.click('[data-testid="audit-search-button"]');
    await page.waitForTimeout(1500);
    
    // Expected Result: Audit log records the change with user and timestamp
    const auditEntry = page.locator('[data-testid="audit-log-row"]').first();
    await expect(auditEntry).toBeVisible();
    
    // Verify audit log contains action type
    await expect(auditEntry.locator('[data-testid="audit-action"]')).toContainText(/UPDATE|EDIT/);
    
    // Verify user who made the change
    await expect(auditEntry.locator('[data-testid="audit-user"]')).toContainText('hr.officer');
    
    // Verify timestamp is present and recent
    const auditTimestamp = await auditEntry.locator('[data-testid="audit-timestamp"]').textContent();
    expect(auditTimestamp).toBeTruthy();
    
    // Verify old values are logged
    await auditEntry.locator('[data-testid="audit-details-button"]').click();
    await expect(page.locator('[data-testid="audit-details-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-old-time"]')).toContainText(originalTime?.trim() || '');
    
    // Verify new values are logged
    await expect(page.locator('[data-testid="audit-new-time"]')).toContainText('09:45');
    await expect(page.locator('[data-testid="audit-new-reason"]')).toContainText('Time correction based on manager approval');
    
    // Verify entry ID is present
    const auditEntryId = await page.locator('[data-testid="audit-entry-id"]').textContent();
    expect(auditEntryId).toBeTruthy();
    
    // Close details modal
    await page.click('[data-testid="close-audit-details"]');
    
    // Verify audit log entry is immutable (no edit/delete buttons present)
    await expect(auditEntry.locator('[data-testid="edit-audit-button"]')).not.toBeVisible();
    await expect(auditEntry.locator('[data-testid="delete-audit-button"]')).not.toBeVisible();
  });
});