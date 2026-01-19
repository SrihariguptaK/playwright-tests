import { test, expect } from '@playwright/test';

test.describe('User Role and Permission Management', () => {
  test.beforeEach(async ({ page }) => {
    // Administrator logs into admin portal
    await page.goto('/admin/login');
    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*\/admin\/dashboard/);
  });

  test('Create and assign user roles successfully', async ({ page }) => {
    // Administrator navigates to user management section from the admin portal main menu
    await page.click('[data-testid="user-management-menu"]');
    await expect(page.locator('[data-testid="user-management-section"]')).toBeVisible();

    // Administrator clicks on 'Role Management' tab or menu option
    await page.click('[data-testid="role-management-tab"]');
    await expect(page).toHaveURL(/.*\/admin\/role-management/);

    // Administrator clicks 'Create New Role' button
    await page.click('[data-testid="create-new-role-button"]');
    await expect(page.locator('[data-testid="role-creation-form"]')).toBeVisible();

    // Administrator enters role name 'Schedule Approver' and description
    await page.fill('[data-testid="role-name-input"]', 'Schedule Approver');
    await page.fill('[data-testid="role-description-input"]', 'Can approve schedule change requests');

    // Administrator selects specific permissions from the permissions list
    await page.click('[data-testid="permission-view-schedule-requests"]');
    await page.click('[data-testid="permission-approve-schedule-requests"]');
    await page.click('[data-testid="permission-reject-schedule-requests"]');

    // Verify permissions are selected
    await expect(page.locator('[data-testid="permission-view-schedule-requests"]')).toBeChecked();
    await expect(page.locator('[data-testid="permission-approve-schedule-requests"]')).toBeChecked();
    await expect(page.locator('[data-testid="permission-reject-schedule-requests"]')).toBeChecked();

    // Administrator clicks 'Save Role' button
    await page.click('[data-testid="save-role-button"]');

    // Expected Result: Role is saved and visible in role list
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Role created successfully');
    await expect(page.locator('[data-testid="role-list"]')).toContainText('Schedule Approver');

    // Administrator navigates to 'User Management' section and selects a user
    await page.click('[data-testid="user-management-tab"]');
    await expect(page.locator('[data-testid="user-list"]')).toBeVisible();
    
    // Select user 'John Doe' from the user list
    await page.click('[data-testid="user-row-john-doe"]');
    await expect(page.locator('[data-testid="user-details-panel"]')).toBeVisible();

    // Administrator clicks 'Assign Role' button and selects role from dropdown
    await page.click('[data-testid="assign-role-button"]');
    await page.selectOption('[data-testid="role-dropdown"]', 'Schedule Approver');

    // Administrator confirms the role assignment
    await page.click('[data-testid="confirm-assign-button"]');

    // Expected Result: User role assignment is saved and effective immediately
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Role assigned successfully');
    await expect(page.locator('[data-testid="user-roles-list"]')).toContainText('Schedule Approver');

    // Administrator navigates to audit log section and filters by role management activities
    await page.click('[data-testid="audit-log-menu"]');
    await expect(page).toHaveURL(/.*\/admin\/audit-log/);
    await page.selectOption('[data-testid="activity-filter"]', 'role-management');
    await page.click('[data-testid="apply-filter-button"]');

    // Expected Result: Audit log shows correct details
    await expect(page.locator('[data-testid="audit-log-table"]')).toContainText('Role created: Schedule Approver');
    await expect(page.locator('[data-testid="audit-log-table"]')).toContainText('Role assigned to John Doe');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('admin@company.com');
    
    // Verify timestamp is present
    const auditEntries = page.locator('[data-testid="audit-log-entry"]');
    const firstEntry = auditEntries.first();
    await expect(firstEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
  });

  test('Prevent unauthorized access to role management', async ({ page }) => {
    // Logout as administrator
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*\/login/);

    // Non-administrator user logs into the system with valid credentials
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*\/dashboard/);

    // Non-administrator user attempts to access role management UI by entering direct URL
    await page.goto('/admin/role-management');

    // Expected Result: Access denied error is displayed
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    await expect(page.locator('[data-testid="error-description"]')).toContainText('You do not have permission to access this page');

    // Verify user is redirected or stays on error page
    const currentUrl = page.url();
    expect(currentUrl).toMatch(/.*\/(access-denied|unauthorized|dashboard)/);

    // Non-administrator user checks their navigation menu for role management options
    await page.goto('/dashboard');
    const roleManagementMenu = page.locator('[data-testid="role-management-menu"]');
    await expect(roleManagementMenu).not.toBeVisible();

    // Non-administrator user attempts to access role management via API endpoint
    const response = await page.request.get('/api/user-roles', {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('authToken'))}`
      }
    });

    // Expected Result: API returns 403 Forbidden
    expect(response.status()).toBe(403);

    // System logs the unauthorized access attempt - verify in audit log as admin
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    await page.goto('/admin/audit-log');
    await page.selectOption('[data-testid="activity-filter"]', 'unauthorized-access');
    await page.click('[data-testid="apply-filter-button"]');
    
    await expect(page.locator('[data-testid="audit-log-table"]')).toContainText('Unauthorized access attempt');
    await expect(page.locator('[data-testid="audit-log-table"]')).toContainText('employee@company.com');
  });

  test('Validate role and permission consistency', async ({ page }) => {
    // Administrator navigates to role management section and clicks 'Create New Role'
    await page.click('[data-testid="user-management-menu"]');
    await page.click('[data-testid="role-management-tab"]');
    await page.click('[data-testid="create-new-role-button"]');
    await expect(page.locator('[data-testid="role-creation-form"]')).toBeVisible();

    // Administrator enters role name and description
    await page.fill('[data-testid="role-name-input"]', 'Conflicting Role Test');
    await page.fill('[data-testid="role-description-input"]', 'Testing permission conflict validation');

    // Administrator selects permission 'Submit Schedule Change Request'
    await page.click('[data-testid="permission-submit-schedule-change-request"]');
    await expect(page.locator('[data-testid="permission-submit-schedule-change-request"]')).toBeChecked();

    // Administrator attempts to also select conflicting permission 'Final Approval Authority'
    await page.click('[data-testid="permission-final-approval-authority"]');

    // Verify warning message appears
    await expect(page.locator('[data-testid="permission-conflict-warning"]')).toBeVisible();
    await expect(page.locator('[data-testid="permission-conflict-warning"]')).toContainText('conflicts with');
    await expect(page.locator('[data-testid="permission-conflict-warning"]')).toContainText('separation of duties');

    // Administrator attempts to save with conflicting permissions
    await page.click('[data-testid="save-role-button"]');

    // Expected Result: Validation error prevents saving
    await expect(page.locator('[data-testid="validation-error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-message"]')).toContainText('Cannot assign conflicting permissions');
    
    // Verify role was not saved
    await expect(page.locator('[data-testid="role-creation-form"]')).toBeVisible();
    const roleNameValue = await page.inputValue('[data-testid="role-name-input"]');
    expect(roleNameValue).toBe('Conflicting Role Test');

    // Administrator deselects conflicting permission
    await page.click('[data-testid="permission-final-approval-authority"]');
    await expect(page.locator('[data-testid="permission-final-approval-authority"]')).not.toBeChecked();
    await expect(page.locator('[data-testid="permission-submit-schedule-change-request"]')).toBeChecked();

    // Verify warning message disappears
    await expect(page.locator('[data-testid="permission-conflict-warning"]')).not.toBeVisible();

    // Administrator clicks 'Save Role' button with valid permission set
    await page.click('[data-testid="save-role-button"]');

    // Expected Result: Role is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Role created successfully');
    await expect(page.locator('[data-testid="role-list"]')).toContainText('Conflicting Role Test');
    
    // Verify the role appears in the list with correct permissions
    await page.click('[data-testid="role-conflicting-role-test"]');
    await expect(page.locator('[data-testid="role-permissions-list"]')).toContainText('Submit Schedule Change Request');
    await expect(page.locator('[data-testid="role-permissions-list"]')).not.toContainText('Final Approval Authority');
  });
});