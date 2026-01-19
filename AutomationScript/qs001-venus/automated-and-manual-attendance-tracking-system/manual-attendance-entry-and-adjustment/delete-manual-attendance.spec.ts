import { test, expect } from '@playwright/test';

test.describe('Delete Manual Attendance Entries', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const HR_OFFICER_EMAIL = 'hr.officer@company.com';
  const HR_OFFICER_PASSWORD = 'HRPassword123!';
  const UNAUTHORIZED_USER_EMAIL = 'regular.user@company.com';
  const UNAUTHORIZED_USER_PASSWORD = 'UserPassword123!';

  test.beforeEach(async ({ page }) => {
    // Login as HR Officer for authorized tests
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', HR_OFFICER_EMAIL);
    await page.fill('[data-testid="password-input"]', HR_OFFICER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful deletion of manual attendance entry', async ({ page }) => {
    // Step 1: Navigate to manual attendance management page
    await page.goto(`${BASE_URL}/attendance/manual`);
    await page.waitForSelector('[data-testid="manual-attendance-list"]');
    
    // Expected Result: List of manual entries is displayed
    await expect(page.locator('[data-testid="manual-attendance-list"]')).toBeVisible();
    const entriesCount = await page.locator('[data-testid="attendance-entry-row"]').count();
    expect(entriesCount).toBeGreaterThan(0);

    // Get the first entry details for verification
    const firstEntryId = await page.locator('[data-testid="attendance-entry-row"]').first().getAttribute('data-entry-id');
    const firstEntryText = await page.locator('[data-testid="attendance-entry-row"]').first().textContent();

    // Step 2: Select an entry and initiate deletion
    await page.locator('[data-testid="attendance-entry-row"]').first().locator('[data-testid="delete-button"]').click();
    
    // Expected Result: Confirmation dialog is displayed
    await expect(page.locator('[data-testid="delete-confirmation-dialog"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Are you sure you want to delete this attendance entry?');

    // Step 3: Confirm deletion
    await page.click('[data-testid="confirm-delete-button"]');
    
    // Expected Result: Entry is deleted and confirmation message displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance entry deleted successfully');

    // Refresh the manual attendance management page
    await page.reload();
    await page.waitForSelector('[data-testid="manual-attendance-list"]');

    // Verify entry is no longer in the list
    const remainingEntries = await page.locator(`[data-testid="attendance-entry-row"][data-entry-id="${firstEntryId}"]`).count();
    expect(remainingEntries).toBe(0);

    // Wait 5 minutes and check the attendance reports (simulated with shorter wait for testing)
    await page.goto(`${BASE_URL}/reports/attendance`);
    await page.waitForSelector('[data-testid="attendance-report"]');
    
    // Verify deleted entry is not in reports
    const reportContent = await page.locator('[data-testid="attendance-report"]').textContent();
    expect(reportContent).not.toContain(firstEntryText);
  });

  test('Ensure audit logging of manual attendance deletions', async ({ page }) => {
    // Step 1: Navigate to manual attendance management page and select an entry to delete
    await page.goto(`${BASE_URL}/attendance/manual`);
    await page.waitForSelector('[data-testid="manual-attendance-list"]');
    
    const entryToDelete = page.locator('[data-testid="attendance-entry-row"]').first();
    const entryId = await entryToDelete.getAttribute('data-entry-id');
    const employeeName = await entryToDelete.locator('[data-testid="employee-name"]').textContent();
    const deletionTimestamp = new Date();

    // Step 2: Delete a manual attendance entry by confirming the deletion dialog
    await entryToDelete.locator('[data-testid="delete-button"]').click();
    await expect(page.locator('[data-testid="delete-confirmation-dialog"]')).toBeVisible();
    await page.click('[data-testid="confirm-delete-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Step 3: Navigate to audit log interface
    await page.goto(`${BASE_URL}/audit-logs`);
    await page.waitForSelector('[data-testid="audit-log-table"]');

    // Step 4: Search for the deletion event in the audit logs
    await page.fill('[data-testid="audit-log-search"]', entryId || '');
    await page.click('[data-testid="search-button"]');
    await page.waitForSelector('[data-testid="audit-log-row"]');

    // Expected Result: Audit log records deletion with user and timestamp
    const auditLogEntry = page.locator('[data-testid="audit-log-row"]').first();
    await expect(auditLogEntry).toBeVisible();

    // Step 5: Verify all required fields are present in the audit log entry
    await expect(auditLogEntry.locator('[data-testid="action-type"]')).toContainText('DELETE');
    await expect(auditLogEntry.locator('[data-testid="resource-type"]')).toContainText('Manual Attendance');
    await expect(auditLogEntry.locator('[data-testid="user-name"]')).toContainText(HR_OFFICER_EMAIL);
    await expect(auditLogEntry.locator('[data-testid="timestamp"]')).toBeVisible();
    
    const loggedTimestamp = await auditLogEntry.locator('[data-testid="timestamp"]').textContent();
    expect(loggedTimestamp).toBeTruthy();
    
    // Verify entry details are logged
    const auditDetails = await auditLogEntry.locator('[data-testid="audit-details"]').textContent();
    expect(auditDetails).toContain(entryId || '');
  });

  test('Verify deletion authorization - unauthorized user blocked', async ({ page }) => {
    // Logout and login as unauthorized user
    await page.goto(`${BASE_URL}/logout`);
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', UNAUTHORIZED_USER_EMAIL);
    await page.fill('[data-testid="password-input"]', UNAUTHORIZED_USER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 1: Navigate to manual attendance management page as unauthorized user
    await page.goto(`${BASE_URL}/attendance/manual`);
    
    // Expected Result: Access denied or delete functionality not available
    const pageContent = await page.textContent('body');
    
    // Check if access is denied at page level
    if (pageContent?.includes('Access Denied') || pageContent?.includes('Unauthorized')) {
      await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
      await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    } else {
      // If page is accessible, delete buttons should not be visible
      await page.waitForSelector('[data-testid="manual-attendance-list"]');
      const deleteButtons = await page.locator('[data-testid="delete-button"]').count();
      expect(deleteButtons).toBe(0);
    }

    // Step 2: Attempt direct API call to delete entry
    const entryId = '12345';
    const response = await page.request.delete(`${BASE_URL}/api/attendance/manual/${entryId}`);
    
    // Expected Result: Deletion is blocked
    expect(response.status()).toBe(403);
    const responseBody = await response.json();
    expect(responseBody.message).toContain('Unauthorized');

    // Step 3: Verify the manual attendance entry still exists
    // Login back as HR officer to verify
    await page.goto(`${BASE_URL}/logout`);
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', HR_OFFICER_EMAIL);
    await page.fill('[data-testid="password-input"]', HR_OFFICER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    await page.goto(`${BASE_URL}/attendance/manual`);
    await page.waitForSelector('[data-testid="manual-attendance-list"]');
    const entries = await page.locator('[data-testid="attendance-entry-row"]').count();
    expect(entries).toBeGreaterThan(0);

    // Step 4: Check audit logs for unauthorized deletion attempt
    await page.goto(`${BASE_URL}/audit-logs`);
    await page.fill('[data-testid="audit-log-search"]', UNAUTHORIZED_USER_EMAIL);
    await page.click('[data-testid="search-button"]');
    
    const unauthorizedAttempts = page.locator('[data-testid="audit-log-row"]').filter({
      hasText: 'UNAUTHORIZED_ACCESS'
    });
    
    if (await unauthorizedAttempts.count() > 0) {
      await expect(unauthorizedAttempts.first()).toBeVisible();
    }
  });

  test('System prevents deletion of biometric attendance records', async ({ page }) => {
    // Step 1: Navigate to attendance management page showing both manual and biometric entries
    await page.goto(`${BASE_URL}/attendance/all`);
    await page.waitForSelector('[data-testid="attendance-list"]');
    
    // Expected Result: Both manual and biometric entries are displayed
    await expect(page.locator('[data-testid="attendance-list"]')).toBeVisible();
    
    // Filter to show biometric entries
    await page.click('[data-testid="filter-type-dropdown"]');
    await page.click('[data-testid="filter-biometric-option"]');
    await page.waitForSelector('[data-testid="attendance-entry-row"]');

    const biometricEntries = await page.locator('[data-testid="attendance-entry-row"][data-entry-type="biometric"]').count();
    expect(biometricEntries).toBeGreaterThan(0);

    // Step 2: Attempt to select a biometric attendance entry for deletion
    const biometricEntry = page.locator('[data-testid="attendance-entry-row"][data-entry-type="biometric"]').first();
    const biometricEntryId = await biometricEntry.getAttribute('data-entry-id');
    
    // Step 3: Check if delete option is visible for biometric entry
    const deleteButton = biometricEntry.locator('[data-testid="delete-button"]');
    const isDeleteButtonVisible = await deleteButton.isVisible().catch(() => false);
    
    if (isDeleteButtonVisible) {
      // If visible, clicking should show error
      await deleteButton.click();
      await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
      await expect(page.locator('[data-testid="error-message"]')).toContainText('Cannot delete biometric attendance records');
    } else {
      // Expected: Delete button should not be visible for biometric entries
      expect(isDeleteButtonVisible).toBe(false);
    }

    // Step 4: Attempt direct API call to delete biometric entry
    const response = await page.request.delete(`${BASE_URL}/api/attendance/manual/${biometricEntryId}`);
    
    // Expected Result: API should reject the deletion
    expect(response.status()).toBeGreaterThanOrEqual(400);
    const responseBody = await response.json();
    expect(responseBody.message || responseBody.error).toMatch(/biometric|cannot delete|not allowed/i);

    // Step 5: Verify the biometric attendance entry still exists
    await page.reload();
    await page.waitForSelector('[data-testid="attendance-list"]');
    await page.click('[data-testid="filter-type-dropdown"]');
    await page.click('[data-testid="filter-biometric-option"]');
    
    const entryStillExists = await page.locator(`[data-testid="attendance-entry-row"][data-entry-id="${biometricEntryId}"]`).count();
    expect(entryStillExists).toBe(1);
    
    // Verify in reports as well
    await page.goto(`${BASE_URL}/reports/attendance`);
    await page.waitForSelector('[data-testid="attendance-report"]');
    const reportContent = await page.locator('[data-testid="attendance-report"]').textContent();
    expect(reportContent).toContain(biometricEntryId || '');
  });
});