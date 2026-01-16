import { test, expect } from '@playwright/test';

test.describe('User Permissions Management - Story 16', () => {
  const ADMIN_EMAIL = 'admin@example.com';
  const ADMIN_PASSWORD = 'AdminPass123!';
  const TEST_USER_EMAIL = 'testuser@example.com';
  const TEST_USER_PASSWORD = 'TestUser123!';
  const BASE_URL = 'https://app.example.com';
  const ADMIN_PORTAL_URL = `${BASE_URL}/admin`;

  test.beforeEach(async ({ page }) => {
    // Login as admin before each test
    await page.goto(`${ADMIN_PORTAL_URL}/login`);
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(new RegExp(`${ADMIN_PORTAL_URL}/dashboard`));
  });

  test('Verify admin can assign and revoke quote editing permissions', async ({ page, context }) => {
    // Navigate to user management section
    await page.click('[data-testid="user-management-nav"]');
    await expect(page.locator('[data-testid="user-management-header"]')).toBeVisible();

    // Search for and select test user
    await page.fill('[data-testid="user-search-input"]', TEST_USER_EMAIL);
    await page.click('[data-testid="search-button"]');
    await page.click(`[data-testid="user-row-${TEST_USER_EMAIL}"]`);
    await expect(page.locator('[data-testid="user-details-panel"]')).toBeVisible();

    // Verify quote editing permission is not assigned
    const editPermissionCheckbox = page.locator('[data-testid="permission-quote-editing"]');
    await expect(editPermissionCheckbox).not.toBeChecked();

    // Assign quote editing permission
    await editPermissionCheckbox.check();
    await expect(editPermissionCheckbox).toBeChecked();
    await page.click('[data-testid="save-permissions-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Permissions updated successfully');

    // Open new context and login as test user
    const testUserPage = await context.newPage();
    await testUserPage.goto(`${BASE_URL}/login`);
    await testUserPage.fill('[data-testid="email-input"]', TEST_USER_EMAIL);
    await testUserPage.fill('[data-testid="password-input"]', TEST_USER_PASSWORD);
    await testUserPage.click('[data-testid="login-button"]');
    await expect(testUserPage).toHaveURL(new RegExp(`${BASE_URL}/dashboard`));

    // Navigate to existing quote and attempt to edit
    await testUserPage.click('[data-testid="quotes-nav"]');
    await testUserPage.click('[data-testid="quote-item"]:first-child');
    await expect(testUserPage.locator('[data-testid="edit-quote-button"]')).toBeVisible();
    await testUserPage.click('[data-testid="edit-quote-button"]');

    // Make a minor change and save
    await testUserPage.fill('[data-testid="quote-description-input"]', 'Updated description by test user');
    await testUserPage.click('[data-testid="save-quote-button"]');
    await expect(testUserPage.locator('[data-testid="success-message"]')).toContainText('Quote saved successfully');

    // Return to admin portal and revoke permission
    await page.bringToFront();
    await page.click('[data-testid="user-management-nav"]');
    await page.fill('[data-testid="user-search-input"]', TEST_USER_EMAIL);
    await page.click('[data-testid="search-button"]');
    await page.click(`[data-testid="user-row-${TEST_USER_EMAIL}"]`);

    // Revoke quote editing permission
    await editPermissionCheckbox.uncheck();
    await expect(editPermissionCheckbox).not.toBeChecked();
    await page.click('[data-testid="save-permissions-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Permissions updated successfully');

    // Return to test user session and verify access revoked
    await testUserPage.bringToFront();
    await testUserPage.reload();
    await expect(testUserPage.locator('[data-testid="edit-quote-button"]')).not.toBeVisible();

    // Attempt to edit should fail or show error
    const editButton = testUserPage.locator('[data-testid="edit-quote-button"]');
    const editButtonCount = await editButton.count();
    expect(editButtonCount).toBe(0);

    await testUserPage.close();
  });

  test('Ensure permission changes are logged', async ({ page }) => {
    // Note current timestamp and admin user ID
    const startTimestamp = new Date();
    await page.click('[data-testid="admin-profile-menu"]');
    const adminUserId = await page.locator('[data-testid="admin-user-id"]').textContent();
    await page.click('[data-testid="admin-profile-menu"]'); // Close menu

    // Navigate to user management section
    await page.click('[data-testid="user-management-nav"]');
    await expect(page.locator('[data-testid="user-management-header"]')).toBeVisible();

    // Search for and select test user
    await page.fill('[data-testid="user-search-input"]', TEST_USER_EMAIL);
    await page.click('[data-testid="search-button"]');
    await page.click(`[data-testid="user-row-${TEST_USER_EMAIL}"]`);

    // Get test user ID
    const testUserId = await page.locator('[data-testid="selected-user-id"]').textContent();

    // Change permissions - assign quote editing permission
    const editPermissionCheckbox = page.locator('[data-testid="permission-quote-editing"]');
    const initialEditState = await editPermissionCheckbox.isChecked();
    await editPermissionCheckbox.check();

    // Grant version history access
    const versionHistoryCheckbox = page.locator('[data-testid="permission-version-history"]');
    const initialVersionState = await versionHistoryCheckbox.isChecked();
    await versionHistoryCheckbox.check();

    // Enable audit trail viewing
    const auditTrailCheckbox = page.locator('[data-testid="permission-audit-trail"]');
    const initialAuditState = await auditTrailCheckbox.isChecked();
    await auditTrailCheckbox.check();

    // Save changes
    await page.click('[data-testid="save-permissions-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Permissions updated successfully');

    // Navigate to audit logs section
    await page.click('[data-testid="audit-logs-nav"]');
    await expect(page.locator('[data-testid="audit-logs-header"]')).toBeVisible();

    // Search for permission change logs
    await page.fill('[data-testid="filter-admin-user-id"]', adminUserId || '');
    await page.fill('[data-testid="filter-target-user-id"]', testUserId || '');
    await page.fill('[data-testid="filter-start-date"]', startTimestamp.toISOString().split('T')[0]);
    await page.click('[data-testid="apply-filters-button"]');

    // Locate log entries for the permission changes
    const logEntries = page.locator('[data-testid="audit-log-entry"]');
    await expect(logEntries).toHaveCountGreaterThan(0);

    // Verify first log entry contains required information
    const firstLogEntry = logEntries.first();
    await expect(firstLogEntry.locator('[data-testid="log-admin-id"]')).toContainText(adminUserId || '');
    await expect(firstLogEntry.locator('[data-testid="log-target-user-id"]')).toContainText(testUserId || '');
    await expect(firstLogEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(firstLogEntry.locator('[data-testid="log-permission-type"]')).toBeVisible();
    await expect(firstLogEntry.locator('[data-testid="log-old-value"]')).toBeVisible();
    await expect(firstLogEntry.locator('[data-testid="log-new-value"]')).toBeVisible();

    // Verify timestamp is after start time
    const logTimestamp = await firstLogEntry.locator('[data-testid="log-timestamp"]').textContent();
    const logDate = new Date(logTimestamp || '');
    expect(logDate.getTime()).toBeGreaterThanOrEqual(startTimestamp.getTime());

    // Make additional permission change
    await page.click('[data-testid="user-management-nav"]');
    await page.fill('[data-testid="user-search-input"]', TEST_USER_EMAIL);
    await page.click('[data-testid="search-button"]');
    await page.click(`[data-testid="user-row-${TEST_USER_EMAIL}"]`);

    // Toggle a different permission
    const secondChangeCheckbox = page.locator('[data-testid="permission-quote-deletion"]');
    await secondChangeCheckbox.check();
    await page.click('[data-testid="save-permissions-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Permissions updated successfully');

    // Refresh audit logs
    await page.click('[data-testid="audit-logs-nav"]');
    await page.click('[data-testid="refresh-logs-button"]');

    // Verify second permission change is logged
    const updatedLogEntries = page.locator('[data-testid="audit-log-entry"]');
    const logCount = await updatedLogEntries.count();
    expect(logCount).toBeGreaterThan(3); // Should have multiple entries for all changes

    // Verify the most recent log entry
    const latestLogEntry = updatedLogEntries.first();
    await expect(latestLogEntry.locator('[data-testid="log-admin-id"]')).toContainText(adminUserId || '');
    await expect(latestLogEntry.locator('[data-testid="log-target-user-id"]')).toContainText(testUserId || '');
    await expect(latestLogEntry.locator('[data-testid="log-permission-type"]')).toContainText('quote-deletion');
  });

  test('Verify admin can assign and revoke quote editing permissions - happy path', async ({ page, context }) => {
    // Log into admin portal as System Administrator (already done in beforeEach)
    await expect(page).toHaveURL(new RegExp(`${ADMIN_PORTAL_URL}/dashboard`));

    // Navigate to user management section
    await page.click('[data-testid="user-management-nav"]');
    await expect(page.locator('[data-testid="user-management-header"]')).toBeVisible();

    // Search for and select test user account
    await page.fill('[data-testid="user-search-input"]', TEST_USER_EMAIL);
    await page.click('[data-testid="search-button"]');
    await expect(page.locator(`[data-testid="user-row-${TEST_USER_EMAIL}"]`)).toBeVisible();
    await page.click(`[data-testid="user-row-${TEST_USER_EMAIL}"]`);
    await expect(page.locator('[data-testid="user-details-panel"]')).toBeVisible();

    // Verify quote editing permission is not assigned
    const editPermissionCheckbox = page.locator('[data-testid="permission-quote-editing"]');
    const isInitiallyChecked = await editPermissionCheckbox.isChecked();
    if (isInitiallyChecked) {
      await editPermissionCheckbox.uncheck();
      await page.click('[data-testid="save-permissions-button"]');
      await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    }
    await expect(editPermissionCheckbox).not.toBeChecked();

    // Assign quote editing permission
    await editPermissionCheckbox.check();
    await expect(editPermissionCheckbox).toBeChecked();

    // Click Save or Apply Changes button
    await page.click('[data-testid="save-permissions-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Permissions updated successfully');

    // Open new browser window/incognito session and login as test user
    const testUserPage = await context.newPage();
    await testUserPage.goto(`${BASE_URL}/login`);
    await testUserPage.fill('[data-testid="email-input"]', TEST_USER_EMAIL);
    await testUserPage.fill('[data-testid="password-input"]', TEST_USER_PASSWORD);
    await testUserPage.click('[data-testid="login-button"]');
    await expect(testUserPage).toHaveURL(new RegExp(`${BASE_URL}/dashboard`));

    // Navigate to existing quote and attempt to edit
    await testUserPage.click('[data-testid="quotes-nav"]');
    await expect(testUserPage.locator('[data-testid="quotes-list"]')).toBeVisible();
    await testUserPage.click('[data-testid="quote-item"]:first-child');
    await expect(testUserPage.locator('[data-testid="quote-details"]')).toBeVisible();
    await expect(testUserPage.locator('[data-testid="edit-quote-button"]')).toBeVisible();
    await testUserPage.click('[data-testid="edit-quote-button"]');

    // Make minor change and save
    const originalDescription = await testUserPage.locator('[data-testid="quote-description-input"]').inputValue();
    await testUserPage.fill('[data-testid="quote-description-input"]', `${originalDescription} - Updated by test`);
    await testUserPage.click('[data-testid="save-quote-button"]');
    await expect(testUserPage.locator('[data-testid="success-message"]')).toContainText('Quote saved successfully');

    // Return to admin portal and navigate to test user permissions
    await page.bringToFront();
    await page.click('[data-testid="user-management-nav"]');
    await page.fill('[data-testid="user-search-input"]', TEST_USER_EMAIL);
    await page.click('[data-testid="search-button"]');
    await page.click(`[data-testid="user-row-${TEST_USER_EMAIL}"]`);

    // Revoke quote editing permission
    await editPermissionCheckbox.uncheck();
    await expect(editPermissionCheckbox).not.toBeChecked();

    // Click Save or Apply Changes button
    await page.click('[data-testid="save-permissions-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Permissions updated successfully');

    // Return to test user session and refresh
    await testUserPage.bringToFront();
    await testUserPage.reload();

    // Attempt to edit quote as test user
    const editButtonAfterRevoke = testUserPage.locator('[data-testid="edit-quote-button"]');
    await expect(editButtonAfterRevoke).not.toBeVisible();

    await testUserPage.close();
  });

  test('Ensure permission changes are logged - happy path', async ({ page }) => {
    // Note current timestamp and admin user ID
    const startTimestamp = new Date();
    await page.click('[data-testid="admin-profile-menu"]');
    const adminUserId = await page.locator('[data-testid="admin-user-id"]').textContent();
    await page.keyboard.press('Escape'); // Close menu

    // Navigate to user management section
    await page.click('[data-testid="user-management-nav"]');
    await expect(page.locator('[data-testid="user-management-header"]')).toBeVisible();

    // Search for and select test user account
    await page.fill('[data-testid="user-search-input"]', TEST_USER_EMAIL);
    await page.click('[data-testid="search-button"]');
    await page.click(`[data-testid="user-row-${TEST_USER_EMAIL}"]`);
    const testUserId = await page.locator('[data-testid="selected-user-id"]').textContent();

    // Change permissions
    const editPermissionCheckbox = page.locator('[data-testid="permission-quote-editing"]');
    const versionHistoryCheckbox = page.locator('[data-testid="permission-version-history"]');
    const auditTrailCheckbox = page.locator('[data-testid="permission-audit-trail"]');

    const oldEditValue = await editPermissionCheckbox.isChecked();
    const oldVersionValue = await versionHistoryCheckbox.isChecked();
    const oldAuditValue = await auditTrailCheckbox.isChecked();

    await editPermissionCheckbox.check();
    await versionHistoryCheckbox.check();
    await auditTrailCheckbox.check();

    // Click Save or Apply Changes
    await page.click('[data-testid="save-permissions-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Permissions updated successfully');

    // Navigate to audit logs section
    await page.click('[data-testid="audit-logs-nav"]');
    await expect(page.locator('[data-testid="audit-logs-header"]')).toBeVisible();

    // Search for permission change logs with filters
    await page.fill('[data-testid="filter-admin-user-id"]', adminUserId || '');
    await page.fill('[data-testid="filter-target-user-id"]', testUserId || '');
    await page.fill('[data-testid="filter-start-date"]', startTimestamp.toISOString().split('T')[0]);
    await page.click('[data-testid="apply-filters-button"]');

    // Locate log entry for permission change
    const logEntries = page.locator('[data-testid="audit-log-entry"]');
    await expect(logEntries).toHaveCountGreaterThan(0);

    // Verify log entry contains all required fields
    const logEntry = logEntries.first();
    await expect(logEntry.locator('[data-testid="log-admin-id"]')).toContainText(adminUserId || '');
    await expect(logEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(logEntry.locator('[data-testid="log-target-user-id"]')).toContainText(testUserId || '');
    await expect(logEntry.locator('[data-testid="log-permission-type"]')).toBeVisible();
    await expect(logEntry.locator('[data-testid="log-old-value"]')).toBeVisible();
    await expect(logEntry.locator('[data-testid="log-new-value"]')).toBeVisible();

    // Make additional permission change
    await page.click('[data-testid="user-management-nav"]');
    await page.fill('[data-testid="user-search-input"]', TEST_USER_EMAIL);
    await page.click('[data-testid="search-button"]');
    await page.click(`[data-testid="user-row-${TEST_USER_EMAIL}"]`);

    const additionalPermissionCheckbox = page.locator('[data-testid="permission-quote-deletion"]');
    await additionalPermissionCheckbox.check();
    await page.click('[data-testid="save-permissions-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Refresh or re-search audit logs
    await page.click('[data-testid="audit-logs-nav"]');
    await page.click('[data-testid="refresh-logs-button"]');

    // Verify second permission change is logged
    const updatedLogEntries = page.locator('[data-testid="audit-log-entry"]');
    const finalLogCount = await updatedLogEntries.count();
    expect(finalLogCount).toBeGreaterThan(0);

    // Verify latest entry has complete information
    const latestEntry = updatedLogEntries.first();
    await expect(latestEntry.locator('[data-testid="log-admin-id"]')).toContainText(adminUserId || '');
    await expect(latestEntry.locator('[data-testid="log-target-user-id"]')).toContainText(testUserId || '');
    await expect(latestEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(latestEntry.locator('[data-testid="log-permission-type"]')).toBeVisible();
    await expect(latestEntry.locator('[data-testid="log-old-value"]')).toBeVisible();
    await expect(latestEntry.locator('[data-testid="log-new-value"]')).toBeVisible();
  });
});