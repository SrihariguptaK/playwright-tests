import { test, expect } from '@playwright/test';

test.describe('User Role Management and Permissions', () => {
  const adminCredentials = {
    username: 'admin@example.com',
    password: 'AdminPass123!'
  };

  const testUserCredentials = {
    username: 'testuser@example.com',
    password: 'TestUser123!'
  };

  const nonAdminCredentials = {
    username: 'scheduler@example.com',
    password: 'Scheduler123!'
  };

  test.beforeEach(async ({ page }) => {
    await page.goto('/login');
  });

  test('Assign and enforce user roles (happy-path)', async ({ page }) => {
    // Navigate to user management console as Admin
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to user management console
    await page.click('[data-testid="user-management-link"]');
    await expect(page).toHaveURL(/.*user-management/);

    // Search for and select the test user from the user list
    await page.fill('[data-testid="user-search-input"]', testUserCredentials.username);
    await page.click('[data-testid="search-button"]');
    await expect(page.locator('[data-testid="user-list-item"]').filter({ hasText: testUserCredentials.username })).toBeVisible();

    // Click on 'Edit Roles' or 'Assign Role' button for the selected user
    await page.locator('[data-testid="user-list-item"]').filter({ hasText: testUserCredentials.username }).click();
    await page.click('[data-testid="edit-roles-button"]');

    // Select 'Approver' role from the available roles list
    await page.click('[data-testid="role-dropdown"]');
    await page.click('[data-testid="role-option-approver"]');

    // Click 'Save' button to confirm role assignment
    await page.click('[data-testid="save-role-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Role assignment saved');

    // Verify the audit log for the role change entry
    await page.click('[data-testid="audit-log-link"]');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('Approver');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText(testUserCredentials.username);
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText(adminCredentials.username);

    // Log out from admin account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Log in as the test user with newly assigned 'Approver' role
    await page.fill('[data-testid="username-input"]', testUserCredentials.username);
    await page.fill('[data-testid="password-input"]', testUserCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the approval dashboard
    await page.click('[data-testid="approval-dashboard-link"]');
    await expect(page).toHaveURL(/.*approval-dashboard/);
    await expect(page.locator('[data-testid="approval-dashboard-content"]')).toBeVisible();

    // Attempt to perform an action restricted to 'Approver' role
    await expect(page.locator('[data-testid="pending-approvals-list"]')).toBeVisible();
    await page.locator('[data-testid="approval-item"]').first().click();
    await page.click('[data-testid="approve-button"]');
    await expect(page.locator('[data-testid="approval-success-message"]')).toContainText('approved');

    // Attempt to access an unauthorized action for 'Approver' role
    await page.goto('/admin/configuration');
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');

    // Attempt to access user management console
    await page.goto('/user-management');
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');

    // Verify that unauthorized action attempt is logged in security audit log
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Log back in as admin to verify security log
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await page.click('[data-testid="audit-log-link"]');
    await page.fill('[data-testid="audit-search-input"]', testUserCredentials.username);
    await expect(page.locator('[data-testid="security-audit-entry"]').filter({ hasText: 'unauthorized access attempt' })).toBeVisible();
  });

  test('Restrict role management access (error-case)', async ({ page }) => {
    // Log into the system as a non-admin user
    await page.fill('[data-testid="username-input"]', nonAdminCredentials.username);
    await page.fill('[data-testid="password-input"]', nonAdminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Verify that role management navigation option is not visible in the user interface
    await expect(page.locator('[data-testid="user-management-link"]')).not.toBeVisible();

    // Attempt to navigate to the role management page by entering the URL directly
    await page.goto('/user-management');
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('authorized');

    // Attempt to access role management API endpoint directly using non-admin credentials
    const apiResponse = await page.request.get('/api/user-roles');
    expect(apiResponse.status()).toBe(403);
    const responseBody = await apiResponse.json();
    expect(responseBody.error).toContain('Unauthorized');

    // Verify that the unauthorized access attempt is logged in security audit log
    // This will be verified when admin logs in

    // Log out from non-admin account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Log in as an admin user
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the role management page using the same URL or navigation link
    await page.click('[data-testid="user-management-link"]');
    await expect(page).toHaveURL(/.*user-management/);
    await expect(page.locator('[data-testid="user-management-content"]')).toBeVisible();

    // Verify that all role management functions are accessible
    await expect(page.locator('[data-testid="user-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="user-search-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="add-user-button"]')).toBeVisible();

    // Select a user to verify assign and modify roles functionality
    await page.locator('[data-testid="user-list-item"]').first().click();
    await expect(page.locator('[data-testid="edit-roles-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="modify-permissions-button"]')).toBeVisible();

    // Access role management API endpoint using admin credentials
    const adminApiResponse = await page.request.get('/api/user-roles');
    expect(adminApiResponse.status()).toBe(200);
    const adminResponseBody = await adminApiResponse.json();
    expect(Array.isArray(adminResponseBody)).toBeTruthy();
    expect(adminResponseBody.length).toBeGreaterThan(0);

    // Verify admin access is logged in audit trail
    await page.click('[data-testid="audit-log-link"]');
    await expect(page).toHaveURL(/.*audit-log/);
    await page.fill('[data-testid="audit-search-input"]', adminCredentials.username);
    await expect(page.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'accessed role management' })).toBeVisible();

    // Verify non-admin unauthorized access attempt was logged
    await page.fill('[data-testid="audit-search-input"]', nonAdminCredentials.username);
    await expect(page.locator('[data-testid="security-audit-entry"]').filter({ hasText: 'unauthorized access attempt' })).toBeVisible();
    await expect(page.locator('[data-testid="security-audit-entry"]').filter({ hasText: '/user-management' })).toBeVisible();
  });
});