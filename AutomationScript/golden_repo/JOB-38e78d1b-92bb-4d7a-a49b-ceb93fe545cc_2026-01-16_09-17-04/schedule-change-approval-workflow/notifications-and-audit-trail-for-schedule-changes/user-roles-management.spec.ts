import { test, expect } from '@playwright/test';

test.describe('User Roles and Permissions Management', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('Validate creation and assignment of user roles', async ({ page }) => {
    // Step 1: Log in as System Administrator
    await page.fill('[data-testid="username-input"]', 'admin@system.com');
    await page.fill('[data-testid="password-input"]', 'AdminPassword123!');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: User roles management page is accessible
    await expect(page).toHaveURL(/\/dashboard/);
    await page.waitForSelector('[data-testid="user-roles-management-menu"]', { state: 'visible' });
    
    // Step 2: Navigate to User Roles Management
    await page.click('[data-testid="user-roles-management-menu"]');
    await expect(page).toHaveURL(/\/admin\/user-roles/);
    await expect(page.locator('[data-testid="page-title"]')).toContainText('User Roles Management');
    
    // Step 3: Create a new role
    await page.click('[data-testid="create-new-role-button"]');
    await expect(page.locator('[data-testid="role-form-modal"]')).toBeVisible();
    
    // Step 4: Enter role details
    const roleName = 'Schedule Approver';
    const roleDescription = 'Can approve schedule change requests';
    await page.fill('[data-testid="role-name-input"]', roleName);
    await page.fill('[data-testid="role-description-input"]', roleDescription);
    
    // Step 5: Select permissions
    await page.check('[data-testid="permission-view-schedule-changes"]');
    await page.check('[data-testid="permission-approve-schedule-changes"]');
    await page.check('[data-testid="permission-reject-schedule-changes"]');
    
    // Step 6: Save the role
    await page.click('[data-testid="save-role-button"]');
    
    // Expected Result: Role is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Role created successfully');
    await expect(page.locator(`[data-testid="role-list"] >> text=${roleName}`)).toBeVisible();
    
    // Step 7: Assign users to the new role
    await page.click(`[data-testid="role-row-${roleName}"] [data-testid="assign-users-button"]`);
    await expect(page.locator('[data-testid="assign-users-modal"]')).toBeVisible();
    
    // Step 8: Select test users
    await page.fill('[data-testid="user-search-input"]', 'test.user@company.com');
    await page.waitForSelector('[data-testid="user-search-results"]');
    await page.check('[data-testid="user-checkbox-test.user@company.com"]');
    await page.check('[data-testid="user-checkbox-another.user@company.com"]');
    
    // Step 9: Add selected users
    await page.click('[data-testid="add-users-button"]');
    await page.click('[data-testid="save-assignments-button"]');
    
    // Expected Result: Users are assigned and permissions enforced
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Users assigned successfully');
    
    // Step 10: Verify as assigned user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Step 11: Log in as newly assigned user
    await page.fill('[data-testid="username-input"]', 'test.user@company.com');
    await page.fill('[data-testid="password-input"]', 'TestUser123!');
    await page.click('[data-testid="login-button"]');
    
    // Step 12: Verify access to approval features
    await page.click('[data-testid="schedule-changes-menu"]');
    await expect(page.locator('[data-testid="approve-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="reject-button"]')).toBeVisible();
  });

  test('Verify enforcement of role-based access control', async ({ page }) => {
    // Step 1: Log in as user without approval permissions (User A)
    await page.fill('[data-testid="username-input"]', 'userA@company.com');
    await page.fill('[data-testid="password-input"]', 'UserAPassword123!');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: User is logged in
    await expect(page).toHaveURL(/\/dashboard/);
    
    // Step 2: Navigate to Schedule Changes section
    await page.click('[data-testid="schedule-changes-menu"]');
    await expect(page).toHaveURL(/\/schedule-changes/);
    
    // Step 3: Click on a pending schedule change request
    await page.click('[data-testid="schedule-change-request"]:first-child');
    await expect(page.locator('[data-testid="schedule-change-details"]')).toBeVisible();
    
    // Expected Result: Approval features are not accessible
    await expect(page.locator('[data-testid="approve-button"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="reject-button"]')).not.toBeVisible();
    
    // Step 4: Attempt direct URL manipulation
    const requestId = await page.locator('[data-testid="request-id"]').textContent();
    await page.goto(`/schedule-changes/approve/${requestId}`);
    
    // Expected Result: Access denied or redirected
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/Access denied|Unauthorized|Permission required/);
    
    // Step 5: Check navigation menu
    await page.click('[data-testid="main-menu"]');
    await expect(page.locator('[data-testid="approve-schedule-menu-item"]')).not.toBeVisible();
    
    // Step 6: Log out as User A
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Step 7: Log in as user with approval permissions (User B)
    await page.fill('[data-testid="username-input"]', 'userB@company.com');
    await page.fill('[data-testid="password-input"]', 'UserBPassword123!');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: User B is logged in
    await expect(page).toHaveURL(/\/dashboard/);
    
    // Step 8: Navigate to Schedule Changes section
    await page.click('[data-testid="schedule-changes-menu"]');
    await expect(page).toHaveURL(/\/schedule-changes/);
    
    // Step 9: Click on the same pending schedule change request
    await page.click('[data-testid="schedule-change-request"]:first-child');
    await expect(page.locator('[data-testid="schedule-change-details"]')).toBeVisible();
    
    // Expected Result: Approval features are accessible
    await expect(page.locator('[data-testid="approve-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="reject-button"]')).toBeVisible();
    
    // Step 10: Click the Approve button
    await page.click('[data-testid="approve-button"]');
    await expect(page.locator('[data-testid="approve-confirmation-modal"]')).toBeVisible();
    
    // Step 11: Confirm the approval action
    await page.click('[data-testid="confirm-approve-button"]');
    
    // Expected Result: Approval is successful
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule change approved successfully');
    
    // Step 12: Verify consistent access throughout application
    await page.click('[data-testid="main-menu"]');
    await expect(page.locator('[data-testid="approve-schedule-menu-item"]')).toBeVisible();
  });

  test('Ensure audit logging of role changes', async ({ page }) => {
    // Step 1: Log in as System Administrator
    await page.fill('[data-testid="username-input"]', 'admin@system.com');
    await page.fill('[data-testid="password-input"]', 'AdminPassword123!');
    await page.click('[data-testid="login-button"]');
    
    // Step 2: Navigate to User Roles Management
    await page.click('[data-testid="user-roles-management-menu"]');
    await expect(page).toHaveURL(/\/admin\/user-roles/);
    
    // Step 3: Create a new role for audit testing
    await page.click('[data-testid="create-new-role-button"]');
    await expect(page.locator('[data-testid="role-form-modal"]')).toBeVisible();
    
    const roleName = 'Test Audit Role';
    const roleDescription = 'Role for audit testing';
    await page.fill('[data-testid="role-name-input"]', roleName);
    await page.fill('[data-testid="role-description-input"]', roleDescription);
    
    // Select 2-3 permissions
    await page.check('[data-testid="permission-view-schedule-changes"]');
    await page.check('[data-testid="permission-create-schedule-changes"]');
    await page.check('[data-testid="permission-edit-schedule-changes"]');
    
    // Note timestamp before saving
    const createTimestamp = new Date();
    await page.click('[data-testid="save-role-button"]');
    
    // Expected Result: Role is created successfully
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Role created successfully');
    
    // Step 4: Navigate to Audit Logs
    await page.click('[data-testid="administration-menu"]');
    await page.click('[data-testid="audit-logs-menu"]');
    await expect(page).toHaveURL(/\/admin\/audit-logs/);
    
    // Step 5: Filter audit logs for role creation
    await page.selectOption('[data-testid="action-type-filter"]', 'Role Created');
    await page.fill('[data-testid="search-input"]', roleName);
    await page.click('[data-testid="search-button"]');
    
    // Expected Result: Change is logged with user and timestamp
    const createLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(createLogEntry).toBeVisible();
    await expect(createLogEntry.locator('[data-testid="action-type"]')).toContainText('Role Created');
    await expect(createLogEntry.locator('[data-testid="role-name"]')).toContainText(roleName);
    await expect(createLogEntry.locator('[data-testid="user-name"]')).toContainText('admin@system.com');
    await expect(createLogEntry.locator('[data-testid="timestamp"]')).toBeVisible();
    
    // Step 6: Return to User Roles Management and modify the role
    await page.click('[data-testid="user-roles-management-menu"]');
    await page.click(`[data-testid="role-row-${roleName}"] [data-testid="edit-role-button"]`);
    await expect(page.locator('[data-testid="role-form-modal"]')).toBeVisible();
    
    // Step 7: Modify role details
    const updatedDescription = 'Updated role for audit testing';
    await page.fill('[data-testid="role-description-input"]', updatedDescription);
    await page.uncheck('[data-testid="permission-create-schedule-changes"]');
    await page.check('[data-testid="permission-delete-schedule-changes"]');
    
    const modifyTimestamp = new Date();
    await page.click('[data-testid="save-role-button"]');
    
    // Expected Result: Role is modified successfully
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Role updated successfully');
    
    // Step 8: Return to Audit Logs and verify modification entry
    await page.click('[data-testid="audit-logs-menu"]');
    await page.selectOption('[data-testid="action-type-filter"]', 'Role Modified');
    await page.fill('[data-testid="search-input"]', roleName);
    await page.click('[data-testid="search-button"]');
    
    const modifyLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(modifyLogEntry).toBeVisible();
    await expect(modifyLogEntry.locator('[data-testid="action-type"]')).toContainText('Role Modified');
    await expect(modifyLogEntry.locator('[data-testid="role-name"]')).toContainText(roleName);
    await expect(modifyLogEntry.locator('[data-testid="user-name"]')).toContainText('admin@system.com');
    await expect(modifyLogEntry.locator('[data-testid="changes"]')).toContainText('Description');
    
    // Step 9: Return to User Roles Management and delete the role
    await page.click('[data-testid="user-roles-management-menu"]');
    await page.click(`[data-testid="role-row-${roleName}"] [data-testid="delete-role-button"]`);
    await expect(page.locator('[data-testid="delete-confirmation-modal"]')).toBeVisible();
    
    // Step 10: Confirm deletion
    const deleteTimestamp = new Date();
    await page.click('[data-testid="confirm-delete-button"]');
    
    // Expected Result: Deletion is logged in audit trail
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Role deleted successfully');
    await expect(page.locator(`[data-testid="role-row-${roleName}"]`)).not.toBeVisible();
    
    // Step 11: Return to Audit Logs and verify deletion entry
    await page.click('[data-testid="audit-logs-menu"]');
    await page.selectOption('[data-testid="action-type-filter"]', 'Role Deleted');
    await page.fill('[data-testid="search-input"]', roleName);
    await page.click('[data-testid="search-button"]');
    
    const deleteLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(deleteLogEntry).toBeVisible();
    await expect(deleteLogEntry.locator('[data-testid="action-type"]')).toContainText('Role Deleted');
    await expect(deleteLogEntry.locator('[data-testid="role-name"]')).toContainText(roleName);
    await expect(deleteLogEntry.locator('[data-testid="user-name"]')).toContainText('admin@system.com');
    
    // Step 12: Verify completeness of audit trail
    await page.selectOption('[data-testid="action-type-filter"]', 'All');
    await page.fill('[data-testid="search-input"]', roleName);
    await page.click('[data-testid="search-button"]');
    
    const allLogEntries = page.locator('[data-testid="audit-log-entry"]');
    await expect(allLogEntries).toHaveCount(3);
    
    // Verify sequence: Create, Modify, Delete
    await expect(allLogEntries.nth(0).locator('[data-testid="action-type"]')).toContainText('Role Deleted');
    await expect(allLogEntries.nth(1).locator('[data-testid="action-type"]')).toContainText('Role Modified');
    await expect(allLogEntries.nth(2).locator('[data-testid="action-type"]')).toContainText('Role Created');
  });
});