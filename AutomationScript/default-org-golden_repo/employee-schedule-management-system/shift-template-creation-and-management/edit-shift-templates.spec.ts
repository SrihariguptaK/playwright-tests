import { test, expect } from '@playwright/test';

test.describe('Edit Shift Templates - Story 2', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful shift template editing with versioning', async ({ page }) => {
    // Step 1: Navigate to shift template list
    await page.click('[data-testid="shift-templates-menu"]');
    await expect(page.locator('[data-testid="template-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="template-list-item"]')).toHaveCount(await page.locator('[data-testid="template-list-item"]').count());

    // Step 2: Locate and edit 'Morning Shift - Standard' template
    const morningShiftTemplate = page.locator('[data-testid="template-list-item"]', { hasText: 'Morning Shift - Standard' });
    await expect(morningShiftTemplate).toBeVisible();
    await morningShiftTemplate.locator('[data-testid="edit-template-button"]').click();
    
    // Wait for edit form to load
    await expect(page.locator('[data-testid="edit-template-form"]')).toBeVisible();
    
    // Modify start time from 08:00 AM to 09:00 AM
    await page.fill('[data-testid="start-time-input"]', '09:00');
    await expect(page.locator('[data-testid="start-time-input"]')).toHaveValue('09:00');
    
    // Modify end time from 04:00 PM to 05:00 PM
    await page.fill('[data-testid="end-time-input"]', '17:00');
    await expect(page.locator('[data-testid="end-time-input"]')).toHaveValue('17:00');
    
    // Edit break period from 12:00 PM - 12:30 PM to 12:30 PM - 01:00 PM
    await page.fill('[data-testid="break-start-time-input"]', '12:30');
    await page.fill('[data-testid="break-end-time-input"]', '13:00');
    await expect(page.locator('[data-testid="break-start-time-input"]')).toHaveValue('12:30');
    await expect(page.locator('[data-testid="break-end-time-input"]')).toHaveValue('13:00');
    
    // Add additional role 'Senior Agent'
    await page.click('[data-testid="add-role-button"]');
    await page.fill('[data-testid="role-input"]', 'Senior Agent');
    await expect(page.locator('[data-testid="role-input"]')).toHaveValue('Senior Agent');
    
    // Enter version notes
    await page.fill('[data-testid="version-notes-input"]', 'Updated shift timing and added senior agent role');
    await expect(page.locator('[data-testid="version-notes-input"]')).toHaveValue('Updated shift timing and added senior agent role');
    
    // Verify no validation errors
    await expect(page.locator('[data-testid="validation-error"]')).toHaveCount(0);
    
    // Step 3: Save changes
    await page.click('[data-testid="save-changes-button"]');
    
    // Verify confirmation message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('New version is created');
    
    // Navigate back to template list
    await page.click('[data-testid="back-to-list-button"]');
    await expect(page.locator('[data-testid="template-list"]')).toBeVisible();
    
    // View version history
    const updatedTemplate = page.locator('[data-testid="template-list-item"]', { hasText: 'Morning Shift - Standard' });
    await updatedTemplate.locator('[data-testid="version-history-button"]').click();
    
    // Verify version history shows both versions
    await expect(page.locator('[data-testid="version-history-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="version-item"]', { hasText: 'v1.0' })).toBeVisible();
    await expect(page.locator('[data-testid="version-item"]', { hasText: 'v2.0' })).toBeVisible();
    
    // Verify previous version is still accessible
    await page.click('[data-testid="version-item"]', { hasText: 'v1.0' });
    await expect(page.locator('[data-testid="version-details"]')).toBeVisible();
  });

  test('Reject edits with invalid break overlaps', async ({ page }) => {
    // Step 1: Navigate to shift template list and select template
    await page.click('[data-testid="shift-templates-menu"]');
    await expect(page.locator('[data-testid="template-list"]')).toBeVisible();
    
    const afternoonShiftTemplate = page.locator('[data-testid="template-list-item"]', { hasText: 'Afternoon Shift' });
    await afternoonShiftTemplate.locator('[data-testid="edit-template-button"]').click();
    await expect(page.locator('[data-testid="edit-template-form"]')).toBeVisible();
    
    // Add first break with time 04:00 PM - 04:30 PM (assuming already exists)
    // Add second break with overlapping time: 04:15 PM - 04:45 PM
    await page.click('[data-testid="add-break-button"]');
    await page.fill('[data-testid="break-2-start-time-input"]', '16:15');
    await page.fill('[data-testid="break-2-end-time-input"]', '16:45');
    
    // Verify validation error appears
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('overlapping');
    await expect(page.locator('[data-testid="break-conflict-indicator"]')).toBeVisible();
    
    // Attempt to add another break with complete overlap: 04:00 PM - 04:30 PM
    await page.click('[data-testid="add-break-button"]');
    await page.fill('[data-testid="break-3-start-time-input"]', '16:00');
    await page.fill('[data-testid="break-3-end-time-input"]', '16:30');
    
    // Verify additional validation errors
    await expect(page.locator('[data-testid="validation-error"]')).toHaveCount(2);
    
    // Modify shift end time while overlapping breaks exist
    await page.fill('[data-testid="end-time-input"]', '22:00');
    
    // Step 2: Attempt to save with validation errors
    await page.click('[data-testid="save-changes-button"]');
    
    // Verify save is blocked
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Save is blocked until errors are resolved');
    
    // Verify no API call was made by checking we're still on edit page
    await expect(page.locator('[data-testid="edit-template-form"]')).toBeVisible();
    
    // Correct the overlapping break
    await page.fill('[data-testid="break-2-start-time-input"]', '17:00');
    await page.fill('[data-testid="break-2-end-time-input"]', '17:30');
    
    // Remove the third break
    await page.click('[data-testid="remove-break-3-button"]');
    
    // Verify validation errors are cleared
    await expect(page.locator('[data-testid="validation-error"]')).toHaveCount(0);
    
    // Save changes after correcting errors
    await page.click('[data-testid="save-changes-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
  });

  test('Verify audit trail records template edits', async ({ page }) => {
    // Note current timestamp before making edits
    const timestampBeforeEdit = new Date().toISOString();
    
    // Step 1: Navigate to shift template list
    await page.click('[data-testid="shift-templates-menu"]');
    await expect(page.locator('[data-testid="template-list"]')).toBeVisible();
    
    // Select 'Night Shift - Audit Test' template
    const nightShiftTemplate = page.locator('[data-testid="template-list-item"]', { hasText: 'Night Shift - Audit Test' });
    await nightShiftTemplate.locator('[data-testid="edit-template-button"]').click();
    await expect(page.locator('[data-testid="edit-template-form"]')).toBeVisible();
    
    // Change break period from 02:00 AM - 02:30 AM to 01:30 AM - 02:00 AM
    await page.fill('[data-testid="break-start-time-input"]', '01:30');
    await page.fill('[data-testid="break-end-time-input"]', '02:00');
    
    // Add additional role 'Security Officer'
    await page.click('[data-testid="add-role-button"]');
    await page.fill('[data-testid="role-input"]', 'Security Officer');
    
    // Enter version notes
    await page.fill('[data-testid="version-notes-input"]', 'Adjusted break time and added security officer role');
    
    // Save changes
    await page.click('[data-testid="save-changes-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    const timestampAfterEdit = new Date().toISOString();
    
    // Step 2: Navigate to audit trail logs
    await page.click('[data-testid="audit-logs-menu"]');
    await expect(page.locator('[data-testid="audit-logs-page"]')).toBeVisible();
    
    // Filter audit logs by action type and entity type
    await page.selectOption('[data-testid="action-type-filter"]', 'Template Edit');
    await page.selectOption('[data-testid="entity-type-filter"]', 'ShiftTemplate');
    
    // Apply timestamp range filter
    await page.fill('[data-testid="timestamp-from-filter"]', timestampBeforeEdit);
    await page.fill('[data-testid="timestamp-to-filter"]', timestampAfterEdit);
    await page.click('[data-testid="apply-filters-button"]');
    
    // Locate audit entry for 'Night Shift - Audit Test'
    const auditEntry = page.locator('[data-testid="audit-log-entry"]', { hasText: 'Night Shift - Audit Test' });
    await expect(auditEntry).toBeVisible();
    
    // Verify audit entry contains detailed change information
    await auditEntry.click();
    await expect(page.locator('[data-testid="audit-entry-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-change-details"]')).toContainText('break-start-time');
    await expect(page.locator('[data-testid="audit-change-details"]')).toContainText('01:30');
    await expect(page.locator('[data-testid="audit-change-details"]')).toContainText('Security Officer');
    
    // Verify audit entry includes user identification
    await expect(page.locator('[data-testid="audit-user-info"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-user-info"]')).toContainText('scheduler@example.com');
    
    // Verify timestamp accuracy
    const auditTimestamp = await page.locator('[data-testid="audit-timestamp"]').textContent();
    expect(auditTimestamp).toBeTruthy();
    
    // Verify audit entry is immutable
    await expect(page.locator('[data-testid="edit-audit-entry-button"]')).toHaveCount(0);
    await expect(page.locator('[data-testid="delete-audit-entry-button"]')).toHaveCount(0);
    
    // Verify audit entry is permanently stored
    await expect(page.locator('[data-testid="audit-entry-status"]')).toContainText('Permanent');
  });
});