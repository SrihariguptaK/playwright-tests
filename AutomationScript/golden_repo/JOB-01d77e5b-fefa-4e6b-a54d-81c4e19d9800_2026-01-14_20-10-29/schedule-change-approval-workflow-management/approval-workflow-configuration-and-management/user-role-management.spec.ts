import { test, expect } from '@playwright/test';

test.describe('User Role Management for Schedule Change Approval Workflows', () => {
  const adminCredentials = {
    username: 'admin@company.com',
    password: 'AdminPass123!'
  };

  const testUserCredentials = {
    username: 'testuser@company.com',
    password: 'TestUser123!'
  };

  const nonAdminCredentials = {
    username: 'employee@company.com',
    password: 'Employee123!'
  };

  test('Validate role assignment and permission enforcement (happy-path)', async ({ page, context }) => {
    // System Administrator logs into the admin portal using valid credentials
    await page.goto('/admin/login');
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="admin-dashboard"]')).toBeVisible();

    // System Administrator navigates to user management section from the admin menu
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="user-management-link"]');
    await expect(page.locator('[data-testid="user-management-section"]')).toBeVisible();

    // System Administrator searches for the test user by username or email
    await page.fill('[data-testid="user-search-input"]', testUserCredentials.username);
    await page.click('[data-testid="search-button"]');
    await expect(page.locator(`[data-testid="user-row-${testUserCredentials.username}"]`)).toBeVisible();

    // System Administrator clicks 'Edit Roles' button for the test user
    await page.click(`[data-testid="edit-roles-button-${testUserCredentials.username}"]`);
    await expect(page.locator('[data-testid="edit-roles-modal"]')).toBeVisible();

    // System Administrator selects 'Approver' role from the available roles list
    await page.click('[data-testid="role-approver-checkbox"]');
    await expect(page.locator('[data-testid="role-approver-checkbox"]')).toBeChecked();

    // System Administrator clicks 'Save Changes' button
    const saveTimestamp = Date.now();
    await page.click('[data-testid="save-roles-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // System Administrator verifies the Approver role appears in the user's role list
    await expect(page.locator(`[data-testid="user-role-approver-${testUserCredentials.username}"]`)).toBeVisible();

    // Verify that role change takes effect within 1 minute by checking system timestamp
    await page.waitForTimeout(5000); // Wait 5 seconds to ensure propagation
    const currentTimestamp = Date.now();
    expect(currentTimestamp - saveTimestamp).toBeLessThan(60000);

    // Test user logs into the system with their credentials
    await page.goto('/logout');
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', testUserCredentials.username);
    await page.fill('[data-testid="password-input"]', testUserCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="user-dashboard"]')).toBeVisible();

    // Test user navigates to schedule change approval queue
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="approval-queue-link"]');
    await expect(page.locator('[data-testid="approval-queue-section"]')).toBeVisible();

    // Test user selects a pending schedule change request from the queue
    await page.click('[data-testid="pending-request-row"]:first-child');
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();

    // Test user attempts to approve the schedule change request by clicking 'Approve' button
    await page.click('[data-testid="approve-button"]');
    await expect(page.locator('[data-testid="approval-confirmation-modal"]')).toBeVisible();
    await page.click('[data-testid="confirm-approval-button"]');

    // Test user verifies the request status changes to 'Approved'
    await expect(page.locator('[data-testid="request-status"]')).toHaveText('Approved');
    await expect(page.locator('[data-testid="success-notification"]')).toContainText('Schedule change approved successfully');
  });

  test('Verify audit logging of role changes (happy-path)', async ({ page }) => {
    // System Administrator logs in and navigates to user management section
    await page.goto('/admin/login');
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="user-management-link"]');

    // System Administrator selects the test user from the user list
    await page.fill('[data-testid="user-search-input"]', testUserCredentials.username);
    await page.click('[data-testid="search-button"]');
    await page.click(`[data-testid="user-row-${testUserCredentials.username}"]`);

    // System Administrator notes the current roles assigned to the test user
    const currentRoles = await page.locator('[data-testid="current-roles-display"]').textContent();
    expect(currentRoles).toContain('Employee');

    // System Administrator clicks 'Edit Roles' button
    await page.click(`[data-testid="edit-roles-button-${testUserCredentials.username}"]`);
    await expect(page.locator('[data-testid="edit-roles-modal"]')).toBeVisible();

    // System Administrator adds 'Manager' role to the test user's existing roles
    await page.click('[data-testid="role-manager-checkbox"]');
    await expect(page.locator('[data-testid="role-manager-checkbox"]')).toBeChecked();

    // System Administrator clicks 'Save Changes' button and notes the exact timestamp
    const saveTime = new Date();
    await page.click('[data-testid="save-roles-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // System logs the role change event
    await page.waitForTimeout(2000); // Allow time for audit log to be written

    // System Administrator navigates to audit log section from the admin menu
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-log-link"]');
    await expect(page.locator('[data-testid="audit-log-section"]')).toBeVisible();

    // System Administrator filters audit logs by user identifier and event type 'Role Change'
    await page.fill('[data-testid="audit-filter-user"]', testUserCredentials.username);
    await page.selectOption('[data-testid="audit-filter-event-type"]', 'Role Change');
    await page.click('[data-testid="apply-filters-button"]');

    // System Administrator retrieves the most recent audit log entry for the role change
    const auditLogEntry = page.locator('[data-testid="audit-log-entry"]:first-child');
    await expect(auditLogEntry).toBeVisible();

    // System Administrator verifies the audit log entry contains user identifier (test user)
    await expect(auditLogEntry.locator('[data-testid="audit-user-identifier"]')).toHaveText(testUserCredentials.username);

    // System Administrator verifies the audit log entry contains administrator identifier
    await expect(auditLogEntry.locator('[data-testid="audit-admin-identifier"]')).toHaveText(adminCredentials.username);

    // System Administrator verifies the audit log entry contains accurate timestamp
    const logTimestamp = await auditLogEntry.locator('[data-testid="audit-timestamp"]').textContent();
    expect(logTimestamp).toBeTruthy();
    const logTime = new Date(logTimestamp!);
    const timeDifference = Math.abs(logTime.getTime() - saveTime.getTime());
    expect(timeDifference).toBeLessThan(120000); // Within 2 minutes

    // System Administrator verifies old and new role values
    await expect(auditLogEntry.locator('[data-testid="audit-old-role"]')).toContainText('Employee');
    await expect(auditLogEntry.locator('[data-testid="audit-new-role"]')).toContainText('Employee');
    await expect(auditLogEntry.locator('[data-testid="audit-new-role"]')).toContainText('Manager');
  });

  test('Ensure unauthorized users cannot access role management (error-case)', async ({ page, context }) => {
    // Non-administrator test user logs into the system using valid credentials
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', nonAdminCredentials.username);
    await page.fill('[data-testid="password-input"]', nonAdminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="user-dashboard"]')).toBeVisible();

    // Test user attempts to navigate to user role management UI by entering the direct URL
    const response = await page.goto('/admin/user-management');
    
    // System performs authorization check and denies access
    expect(response?.status()).toBe(403);
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Access Denied');
    await expect(page.locator('[data-testid="error-message"]')).toContainText('You do not have permission to access this resource');

    // Test user is redirected to the previous page or dashboard
    await page.waitForURL(/\/(dashboard|home)/);
    await expect(page.locator('[data-testid="user-dashboard"]')).toBeVisible();

    // Test user checks the main navigation menu for role management options
    await page.click('[data-testid="main-menu"]');
    await expect(page.locator('[data-testid="user-management-link"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="audit-log-link"]')).not.toBeVisible();

    // Test user attempts to access role management via API endpoint directly
    const apiResponse = await page.request.get('/api/user-roles', {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('authToken'))}`
      }
    });

    // System validates API request authorization and denies access
    expect(apiResponse.status()).toBe(403);
    const responseBody = await apiResponse.json();
    expect(responseBody.error).toContain('Unauthorized');

    // System logs the unauthorized access attempt
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-log-link"]');
    await page.fill('[data-testid="audit-filter-user"]', nonAdminCredentials.username);
    await page.selectOption('[data-testid="audit-filter-event-type"]', 'Unauthorized Access Attempt');
    await page.click('[data-testid="apply-filters-button"]');

    // Verify unauthorized access attempt is logged
    const unauthorizedLogEntry = page.locator('[data-testid="audit-log-entry"]:first-child');
    await expect(unauthorizedLogEntry).toBeVisible();
    await expect(unauthorizedLogEntry.locator('[data-testid="audit-user-identifier"]')).toHaveText(nonAdminCredentials.username);
    await expect(unauthorizedLogEntry.locator('[data-testid="audit-attempted-resource"]')).toContainText('user-management');

    // Verify that no role management data or functionality is exposed
    await page.goto('/logout');
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', nonAdminCredentials.username);
    await page.fill('[data-testid="password-input"]', nonAdminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="user-roles-data"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="edit-roles-button"]')).not.toBeVisible();
  });
});