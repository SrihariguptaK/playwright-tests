import { test, expect } from '@playwright/test';

test.describe('Approval Workflow Roles Configuration', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('Create and assign approval roles successfully', async ({ page }) => {
    // Step 1: Login to the system as an administrator with valid credentials
    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to the role management page from admin menu or configuration panel
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="role-management-link"]');
    await expect(page).toHaveURL(/.*role-management/);

    // Step 3: Verify existing roles are displayed correctly
    await expect(page.locator('[data-testid="roles-list"]')).toBeVisible();
    const existingRolesCount = await page.locator('[data-testid="role-item"]').count();
    expect(existingRolesCount).toBeGreaterThanOrEqual(0);

    // Step 4: Click 'Create New Role' or 'Add Role' button
    await page.click('[data-testid="create-role-button"]');
    await expect(page.locator('[data-testid="role-form"]')).toBeVisible();

    // Step 5: Enter role name
    await page.fill('[data-testid="role-name-input"]', 'Department Manager Approver');

    // Step 6: Enter role description
    await page.fill('[data-testid="role-description-input"]', 'Approves schedule changes for department employees');

    // Step 7: Select multiple users from available users list to assign to this role
    await page.click('[data-testid="user-selector"]');
    await page.click('[data-testid="user-option-1"]');
    await page.click('[data-testid="user-option-2"]');
    await page.click('[data-testid="user-option-3"]');
    
    // Verify selected users count
    const selectedUsersCount = await page.locator('[data-testid="selected-user"]').count();
    expect(selectedUsersCount).toBe(3);

    // Step 8: Click 'Save' or 'Create Role' button
    await page.click('[data-testid="save-role-button"]');

    // Step 9: Verify the new role appears in the roles list
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Role and assignments saved successfully');
    
    const newRoleItem = page.locator('[data-testid="role-item"]', { hasText: 'Department Manager Approver' });
    await expect(newRoleItem).toBeVisible();

    // Step 10: Click on the newly created role to view details
    await newRoleItem.click();
    await expect(page.locator('[data-testid="role-details"]')).toBeVisible();

    // Step 11: Verify role details
    await expect(page.locator('[data-testid="role-name-display"]')).toContainText('Department Manager Approver');
    await expect(page.locator('[data-testid="role-description-display"]')).toContainText('Approves schedule changes for department employees');
    
    // Step 12: Verify user assignments are displayed
    const assignedUsers = await page.locator('[data-testid="assigned-user"]').count();
    expect(assignedUsers).toBe(3);
  });

  test('Validate role configuration errors', async ({ page }) => {
    // Step 1: Login to the system as an administrator
    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to role management page
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="role-management-link"]');
    await expect(page).toHaveURL(/.*role-management/);

    // Step 3: Click 'Create New Role' or 'Add Role' button
    await page.click('[data-testid="create-role-button"]');
    await expect(page.locator('[data-testid="role-form"]')).toBeVisible();

    // Step 4: Leave the role name field empty and enter only description
    await page.fill('[data-testid="role-name-input"]', '');
    await page.fill('[data-testid="role-description-input"]', 'Test description without name');

    // Step 5: Attempt to save the role without entering required role name
    await page.click('[data-testid="save-role-button"]');

    // Step 6: Verify validation errors displayed, save prevented
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Role name is required');
    await expect(page.locator('[data-testid="role-form"]')).toBeVisible();

    // Step 7: Verify the role was not saved by checking the roles list
    const roleWithEmptyName = page.locator('[data-testid="role-item"]', { hasText: 'Test description without name' });
    await expect(roleWithEmptyName).not.toBeVisible();

    // Step 8: Enter a valid role name
    await page.fill('[data-testid="role-name-input"]', 'Senior Approver');

    // Step 9: Leave other required fields empty if applicable
    await page.fill('[data-testid="role-description-input"]', '');

    // Step 10: Attempt to save again with remaining missing required fields
    await page.click('[data-testid="save-role-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();

    // Step 11: Correct all validation errors by filling in all required fields with valid data
    await page.fill('[data-testid="role-name-input"]', 'Senior Approver');
    await page.fill('[data-testid="role-description-input"]', 'Senior level approval authority');
    await page.click('[data-testid="user-selector"]');
    await page.click('[data-testid="user-option-1"]');

    // Step 12: Click 'Save' button after correcting all errors
    await page.click('[data-testid="save-role-button"]');

    // Step 13: Verify the role now appears in the roles list
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Role saved successfully');
    
    const newRole = page.locator('[data-testid="role-item"]', { hasText: 'Senior Approver' });
    await expect(newRole).toBeVisible();
  });

  test('Ensure only authorized admins can access role management', async ({ page }) => {
    // Step 1: Login to the system using non-admin user credentials
    await page.fill('[data-testid="username-input"]', 'user@company.com');
    await page.fill('[data-testid="password-input"]', 'UserPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Verify admin menu or configuration panel is not visible in navigation
    const adminMenu = page.locator('[data-testid="admin-menu"]');
    await expect(adminMenu).not.toBeVisible();

    // Step 3: Attempt to access role management page directly via URL
    await page.goto('/role-management');

    // Step 4: Verify user is redirected to appropriate page or access denied message
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');
    
    // Verify URL is either error page or redirected to dashboard
    const currentUrl = page.url();
    expect(currentUrl).toMatch(/.*dashboard|.*error|.*access-denied/);

    // Step 5: Logout from non-admin user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 6: Login using administrator credentials with role management permissions
    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 7: Navigate to role management page using admin menu
    await expect(page.locator('[data-testid="admin-menu"]')).toBeVisible();
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="role-management-link"]');
    await expect(page).toHaveURL(/.*role-management/);

    // Step 8: Verify all role management functions are accessible
    await expect(page.locator('[data-testid="create-role-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="roles-list"]')).toBeVisible();
    
    // Verify edit and delete buttons are present on role items
    const firstRole = page.locator('[data-testid="role-item"]').first();
    if (await firstRole.isVisible()) {
      await firstRole.hover();
      await expect(page.locator('[data-testid="edit-role-button"]').first()).toBeVisible();
      await expect(page.locator('[data-testid="delete-role-button"]').first()).toBeVisible();
    }
  });
});