import { test, expect } from '@playwright/test';

test.describe('User Role Management for Approval Workflows', () => {
  const adminUser = {
    username: 'admin@example.com',
    password: 'AdminPass123!'
  };

  const testUser = {
    username: 'testuser@example.com',
    password: 'TestPass123!',
    name: 'Test User'
  };

  const approverUser = {
    username: 'approver@example.com',
    password: 'ApproverPass123!',
    name: 'Approver User'
  };

  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto('/login');
  });

  test('Validate assignment of user roles', async ({ page }) => {
    // Step 1: System Administrator accesses user role management interface
    await page.fill('[data-testid="username-input"]', adminUser.username);
    await page.fill('[data-testid="password-input"]', adminUser.password);
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to user role management interface
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="user-role-management-link"]');
    
    // Expected Result: Current user roles are displayed
    await expect(page.locator('[data-testid="user-roles-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="user-roles-header"]')).toContainText('User Role Management');
    
    // Step 2: Assign 'Approver' role to a user
    await page.click('[data-testid="select-user-dropdown"]');
    await page.click(`text=${testUser.name}`);
    
    // Select Approver role
    await page.click('[data-testid="role-dropdown"]');
    await page.click('[data-testid="role-option-approver"]');
    
    // Click Save or Submit button
    await page.click('[data-testid="save-role-button"]');
    
    // Expected Result: Role is assigned and saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Role assigned successfully');
    
    // Step 3: Verify audit log records role assignment
    await page.click('[data-testid="audit-log-tab"]');
    
    // Expected Result: Audit log shows user, timestamp, and role change
    const auditLogEntry = page.locator('[data-testid="audit-log-table"] tbody tr').first();
    await expect(auditLogEntry).toBeVisible();
    await expect(auditLogEntry.locator('[data-testid="audit-user"]')).toContainText(testUser.name);
    await expect(auditLogEntry.locator('[data-testid="audit-action"]')).toContainText('Role Assigned');
    await expect(auditLogEntry.locator('[data-testid="audit-role"]')).toContainText('Approver');
    await expect(auditLogEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
  });

  test('Verify enforcement of role-based access control', async ({ page }) => {
    // Step 1: User without 'Approver' role attempts to access approval dashboard
    await page.fill('[data-testid="username-input"]', testUser.username);
    await page.fill('[data-testid="password-input"]', testUser.password);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Attempt to navigate to approval dashboard
    await page.goto('/approval-dashboard');
    
    // Expected Result: Access denied message displayed
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    await expect(page.locator('[data-testid="error-description"]')).toContainText('You do not have permission to access this page');
    
    // Log out from the first user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Step 2: Log in as user with 'Approver' role
    await page.fill('[data-testid="username-input"]', approverUser.username);
    await page.fill('[data-testid="password-input"]', approverUser.password);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to approval dashboard
    await page.goto('/approval-dashboard');
    
    // Expected Result: Access granted
    await expect(page).toHaveURL(/.*approval-dashboard/);
    await expect(page.locator('[data-testid="approval-dashboard-header"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-dashboard-header"]')).toContainText('Approval Dashboard');
    await expect(page.locator('[data-testid="pending-approvals-section"]')).toBeVisible();
  });

  test('Test revocation of user roles', async ({ page }) => {
    // Step 1: System Administrator accesses user role management interface
    await page.fill('[data-testid="username-input"]', adminUser.username);
    await page.fill('[data-testid="password-input"]', adminUser.password);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to user role management interface
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="user-role-management-link"]');
    
    await expect(page.locator('[data-testid="user-roles-table"]')).toBeVisible();
    
    // Select the user with 'Approver' role
    await page.click('[data-testid="select-user-dropdown"]');
    await page.click(`text=${approverUser.name}`);
    
    // Wait for current roles to load
    await expect(page.locator('[data-testid="current-roles-list"]')).toBeVisible();
    
    // Remove or revoke the 'Approver' role
    await page.click('[data-testid="role-approver-remove-button"]');
    
    // Click Save or Submit button
    await page.click('[data-testid="save-role-button"]');
    
    // Expected Result: Role revoked and saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Role revoked successfully');
    
    // Log out from admin account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Step 2: Log in as the user whose 'Approver' role was revoked
    await page.fill('[data-testid="username-input"]', approverUser.username);
    await page.fill('[data-testid="password-input"]', approverUser.password);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Attempt to access approval dashboard
    await page.goto('/approval-dashboard');
    
    // Expected Result: Access denied for approval features
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    await expect(page.locator('[data-testid="error-description"]')).toContainText('You do not have permission to access this page');
    
    // Verify user cannot see approval-related menu items
    await page.click('[data-testid="user-menu"]');
    await expect(page.locator('[data-testid="approval-menu-item"]')).not.toBeVisible();
  });
});