import { test, expect } from '@playwright/test';

test.describe('Attendance Conflict Resolution', () => {
  test.beforeEach(async ({ page }) => {
    // Login as Attendance Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'attendance.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate automatic conflict detection', async ({ page }) => {
    // Step 1: Create overlapping biometric and manual attendance entries
    const employeeId = 'EMP-12345';
    const conflictDate = new Date().toISOString().split('T')[0];
    
    // Create biometric entry at 9:00 AM
    await page.goto('/attendance/biometric/entry');
    await page.fill('[data-testid="employee-id-input"]', employeeId);
    await page.fill('[data-testid="date-input"]', conflictDate);
    await page.fill('[data-testid="time-input"]', '09:00');
    await page.selectOption('[data-testid="entry-type-select"]', 'check-in');
    await page.click('[data-testid="submit-biometric-entry"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Create manual entry at 9:05 AM for same employee and date
    await page.goto('/attendance/manual/entry');
    await page.fill('[data-testid="employee-id-input"]', employeeId);
    await page.fill('[data-testid="date-input"]', conflictDate);
    await page.fill('[data-testid="time-input"]', '09:05');
    await page.selectOption('[data-testid="entry-type-select"]', 'check-in');
    await page.click('[data-testid="submit-manual-entry"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Step 2: Navigate to conflict resolution interface
    await page.goto('/attendance/conflicts');
    await page.waitForSelector('[data-testid="conflicts-dashboard"]');
    
    // Expected Result: System detects conflict and lists it in dashboard
    const conflictRow = page.locator(`[data-testid="conflict-row"][data-employee-id="${employeeId}"]`).first();
    await expect(conflictRow).toBeVisible();
    
    // Expected Result: Conflict details are displayed correctly
    await conflictRow.click();
    await expect(page.locator('[data-testid="conflict-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="biometric-entry-time"]')).toContainText('09:00');
    await expect(page.locator('[data-testid="manual-entry-time"]')).toContainText('09:05');
    await expect(page.locator('[data-testid="conflict-employee-id"]')).toContainText(employeeId);
  });

  test('Verify conflict resolution actions', async ({ page }) => {
    // Navigate to conflict resolution interface
    await page.goto('/attendance/conflicts');
    await page.waitForSelector('[data-testid="conflicts-list"]');
    
    // Step 1: Accept conflicting entry
    const firstConflict = page.locator('[data-testid="conflict-row"]').first();
    const firstConflictId = await firstConflict.getAttribute('data-conflict-id');
    await firstConflict.click();
    await page.click('[data-testid="accept-button"]');
    await page.click('[data-testid="confirm-accept-button"]');
    
    // Expected Result: Attendance record updated and conflict removed
    await expect(page.locator('[data-testid="success-notification"]')).toContainText('Conflict resolved successfully');
    await page.reload();
    await expect(page.locator(`[data-testid="conflict-row"][data-conflict-id="${firstConflictId}"]`)).not.toBeVisible();
    
    // Step 2: Reject conflicting entry
    const secondConflict = page.locator('[data-testid="conflict-row"]').first();
    const secondConflictId = await secondConflict.getAttribute('data-conflict-id');
    await secondConflict.click();
    await page.click('[data-testid="reject-button"]');
    await page.fill('[data-testid="rejection-reason-input"]', 'Duplicate entry detected');
    await page.click('[data-testid="confirm-reject-button"]');
    
    // Expected Result: Entry marked as rejected and excluded from reports
    await expect(page.locator('[data-testid="success-notification"]')).toContainText('Entry rejected successfully');
    await page.goto('/attendance/reports');
    await page.fill('[data-testid="search-conflict-id"]', secondConflictId || '');
    await page.click('[data-testid="search-button"]');
    await expect(page.locator('[data-testid="entry-status"]')).toContainText('Rejected');
    
    // Step 3: Modify conflicting entry
    await page.goto('/attendance/conflicts');
    const thirdConflict = page.locator('[data-testid="conflict-row"]').first();
    await thirdConflict.click();
    await page.click('[data-testid="modify-button"]');
    
    // Make changes to attendance time
    await page.fill('[data-testid="modify-time-input"]', '09:10');
    await page.selectOption('[data-testid="modify-status-select"]', 'Present');
    await page.click('[data-testid="save-modifications-button"]');
    
    // Expected Result: Changes saved and conflict resolved
    await expect(page.locator('[data-testid="success-notification"]')).toContainText('Modifications saved successfully');
    await expect(page.locator('[data-testid="conflict-details-panel"]')).not.toBeVisible();
    await page.reload();
    await expect(page.locator('[data-testid="conflicts-list"]')).not.toContainText(await thirdConflict.getAttribute('data-conflict-id') || '');
  });

  test('Ensure audit logging of conflict resolutions', async ({ page }) => {
    // Navigate to conflict resolution dashboard
    await page.goto('/attendance/conflicts');
    await page.waitForSelector('[data-testid="conflicts-list"]');
    
    // Step 1: Select a conflict from the dashboard
    const conflictToResolve = page.locator('[data-testid="conflict-row"]').first();
    const conflictId = await conflictToResolve.getAttribute('data-conflict-id');
    const employeeId = await conflictToResolve.getAttribute('data-employee-id');
    await conflictToResolve.click();
    
    // Step 2: Choose a resolution action (accept)
    await page.click('[data-testid="accept-button"]');
    await page.click('[data-testid="confirm-accept-button"]');
    await expect(page.locator('[data-testid="success-notification"]')).toBeVisible();
    
    // Step 3: Navigate to audit logs section
    await page.goto('/attendance/audit-logs');
    await page.waitForSelector('[data-testid="audit-logs-table"]');
    
    // Filter by conflict ID or employee ID
    await page.fill('[data-testid="audit-search-input"]', conflictId || employeeId || '');
    await page.click('[data-testid="audit-search-button"]');
    
    // Expected Result: Resolution action is logged with user and timestamp
    const auditLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditLogEntry).toBeVisible();
    await expect(auditLogEntry.locator('[data-testid="audit-action"]')).toContainText('Conflict Resolved - Accepted');
    await expect(auditLogEntry.locator('[data-testid="audit-user"]')).toContainText('attendance.manager@company.com');
    await expect(auditLogEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
    await expect(auditLogEntry.locator('[data-testid="audit-conflict-id"]')).toContainText(conflictId || '');
    
    // Verify timestamp is recent (within last 5 minutes)
    const timestampText = await auditLogEntry.locator('[data-testid="audit-timestamp"]').textContent();
    const logTimestamp = new Date(timestampText || '');
    const currentTime = new Date();
    const timeDifference = (currentTime.getTime() - logTimestamp.getTime()) / 1000 / 60; // in minutes
    expect(timeDifference).toBeLessThan(5);
  });
});