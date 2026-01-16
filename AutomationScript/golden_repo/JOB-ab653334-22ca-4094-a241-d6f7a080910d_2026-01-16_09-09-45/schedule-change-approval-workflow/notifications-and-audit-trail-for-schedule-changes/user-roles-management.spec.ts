import { test, expect } from '@playwright/test';

test.describe('User Roles and Permissions Management', () => {
  const adminCredentials = {
    username: 'admin@system.com',
    password: 'AdminPass123!'
  };

  const regularUserCredentials = {
    username: 'user@system.com',
    password: 'UserPass123!'
  };

  const approverUserCredentials = {
    username: 'approver@system.com',
    password: 'ApproverPass123!'
  };

  test.beforeEach(async ({ page }) => {
    await page.goto('/login');
  });

  test('Validate creation and assignment of user roles', async ({ page }) => {
    // Step 1: Log in as System Administrator
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: User roles management page is accessible
    await expect(page).toHaveURL(/.*dashboard/);
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="user-roles-management"]');
    await expect(page).toHaveURL(/.*user-roles/);
    await expect(page.locator('[data-testid="roles-management-header"]')).toBeVisible();

    // Step 2: Create a new role and assign permissions
    await page.click('[data-testid="create-role-button"]');
    await expect(page.locator('[data-testid="create-role-modal"]')).toBeVisible();
    
    const newRoleName = `TestRole_${Date.now()}`;
    await page.fill('[data-testid="role-name-input"]', newRoleName);
    await page.fill('[data-testid="role-description-input"]', 'Test role for automation');
    
    // Assign permissions
    await page.check('[data-testid="permission-view-schedules"]');
    await page.check('[data-testid="permission-submit-changes"]');
    await page.check('[data-testid="permission-approve-changes"]');
    
    await page.click('[data-testid="save-role-button"]');
    
    // Expected Result: Role is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Role created successfully');
    await expect(page.locator(`[data-testid="role-item-${newRoleName}"]`)).toBeVisible();

    // Step 3: Assign users to the new role
    await page.click(`[data-testid="role-item-${newRoleName}"]`);
    await page.click('[data-testid="assign-users-button"]');
    await expect(page.locator('[data-testid="assign-users-modal"]')).toBeVisible();
    
    await page.fill('[data-testid="user-search-input"]', 'user@system.com');
    await page.click('[data-testid="search-user-button"]');
    await page.click('[data-testid="user-checkbox-user@system.com"]');
    await page.click('[data-testid="confirm-assign-button"]');
    
    // Expected Result: Users are assigned and permissions enforced
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Users assigned successfully');
    await expect(page.locator('[data-testid="assigned-users-list"]')).toContainText('user@system.com');
  });

  test('Verify enforcement of role-based access control', async ({ page }) => {
    // Step 1: Log in as user without approval permissions
    await page.fill('[data-testid="username-input"]', regularUserCredentials.username);
    await page.fill('[data-testid="password-input"]', regularUserCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Expected Result: Approval features are not accessible
    await page.click('[data-testid="schedule-changes-menu"]');
    await expect(page.locator('[data-testid="approval-section"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="approve-button"]')).not.toBeVisible();
    
    // Attempt to navigate directly to approval page
    await page.goto('/schedule-changes/approvals');
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('You do not have permission to access this page');
    
    // Log out
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 2: Log in as user with approval permissions
    await page.fill('[data-testid="username-input"]', approverUserCredentials.username);
    await page.fill('[data-testid="password-input"]', approverUserCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Expected Result: Approval features are accessible
    await page.click('[data-testid="schedule-changes-menu"]');
    await expect(page.locator('[data-testid="approval-section"]')).toBeVisible();
    
    await page.goto('/schedule-changes/approvals');
    await expect(page).toHaveURL(/.*approvals/);
    await expect(page.locator('[data-testid="approvals-page-header"]')).toBeVisible();
    await expect(page.locator('[data-testid="approve-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="reject-button"]')).toBeVisible();
  });

  test('Ensure audit logging of role changes', async ({ page }) => {
    // Log in as System Administrator
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="user-roles-management"]');
    await expect(page).toHaveURL(/.*user-roles/);

    // Step 1: Create or modify a user role
    await page.click('[data-testid="create-role-button"]');
    const auditRoleName = `AuditTestRole_${Date.now()}`;
    await page.fill('[data-testid="role-name-input"]', auditRoleName);
    await page.fill('[data-testid="role-description-input"]', 'Role for audit testing');
    await page.check('[data-testid="permission-view-schedules"]');
    await page.click('[data-testid="save-role-button"]');
    
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Role created successfully');
    
    // Expected Result: Change is logged with user and timestamp
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-logs"]');
    await expect(page).toHaveURL(/.*audit-logs/);
    
    await page.fill('[data-testid="audit-search-input"]', auditRoleName);
    await page.click('[data-testid="audit-search-button"]');
    
    const auditEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditEntry).toBeVisible();
    await expect(auditEntry).toContainText('Role Created');
    await expect(auditEntry).toContainText(auditRoleName);
    await expect(auditEntry).toContainText(adminCredentials.username);
    await expect(auditEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
    
    // Navigate back to roles management
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="user-roles-management"]');

    // Step 2: Delete a user role
    await page.click(`[data-testid="role-item-${auditRoleName}"]`);
    await page.click('[data-testid="delete-role-button"]');
    await expect(page.locator('[data-testid="confirm-delete-modal"]')).toBeVisible();
    await page.click('[data-testid="confirm-delete-button"]');
    
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Role deleted successfully');
    await expect(page.locator(`[data-testid="role-item-${auditRoleName}"]`)).not.toBeVisible();
    
    // Expected Result: Deletion is logged in audit trail
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-logs"]');
    await expect(page).toHaveURL(/.*audit-logs/);
    
    await page.fill('[data-testid="audit-search-input"]', auditRoleName);
    await page.click('[data-testid="audit-search-button"]');
    
    const deleteAuditEntry = page.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'Role Deleted' }).first();
    await expect(deleteAuditEntry).toBeVisible();
    await expect(deleteAuditEntry).toContainText('Role Deleted');
    await expect(deleteAuditEntry).toContainText(auditRoleName);
    await expect(deleteAuditEntry).toContainText(adminCredentials.username);
    await expect(deleteAuditEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
  });
});