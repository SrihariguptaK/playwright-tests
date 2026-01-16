import { test, expect } from '@playwright/test';

test.describe('User Roles and Permissions Management', () => {
  const adminCredentials = {
    username: 'admin@company.com',
    password: 'AdminPass123!'
  };

  const schedulerCredentials = {
    username: 'scheduler@company.com',
    password: 'SchedulerPass123!'
  };

  const approverCredentials = {
    username: 'approver@company.com',
    password: 'ApproverPass123!'
  };

  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto('/login');
  });

  test('Validate creation and assignment of user roles', async ({ page }) => {
    // Step 1: Administrator creates a new role with specific permissions
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to the user management portal and access the roles management section
    await page.click('[data-testid="user-management-menu"]');
    await page.click('[data-testid="roles-management-link"]');
    
    await expect(page.locator('[data-testid="roles-management-header"]')).toBeVisible();
    
    // Click on 'Create New Role' button
    await page.click('[data-testid="create-new-role-button"]');
    
    // Enter role name 'Scheduler' in the role name field
    await page.fill('[data-testid="role-name-input"]', 'Scheduler');
    
    // Select specific permissions: 'Submit Schedule Changes' and 'View Schedule History'
    await page.check('[data-testid="permission-submit-schedule-changes"]');
    await page.check('[data-testid="permission-view-schedule-history"]');
    
    // Click 'Save Role' button
    await page.click('[data-testid="save-role-button"]');
    
    // Expected Result: Role is saved with assigned permissions
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Role created successfully');
    await expect(page.locator('[data-testid="role-list"]')).toContainText('Scheduler');
    
    // Step 2: Administrator assigns users to the new role
    // Navigate to the user assignment section for the newly created 'Scheduler' role
    await page.click('[data-testid="role-item-scheduler"]');
    await page.click('[data-testid="assign-users-tab"]');
    
    // Select a user from the available users list and click 'Assign to Role' button
    await page.selectOption('[data-testid="available-users-dropdown"]', schedulerCredentials.username);
    await page.click('[data-testid="assign-to-role-button"]');
    
    // Expected Result: Users are assigned and can access features per permissions
    await expect(page.locator('[data-testid="assigned-users-list"]')).toContainText(schedulerCredentials.username);
    await expect(page.locator('[data-testid="success-message"]')).toContainText('User assigned successfully');
    
    // Log out as administrator
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Log in as the newly assigned user
    await page.fill('[data-testid="username-input"]', schedulerCredentials.username);
    await page.fill('[data-testid="password-input"]', schedulerCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Verify the user can submit schedule changes
    await page.click('[data-testid="schedule-management-menu"]');
    await expect(page.locator('[data-testid="submit-schedule-changes-button"]')).toBeVisible();
    
    // Verify the user cannot approve schedule changes
    await expect(page.locator('[data-testid="approve-schedule-changes-button"]')).not.toBeVisible();
  });

  test('Verify audit logging of role changes', async ({ page }) => {
    // Step 1: Administrator modifies role permissions
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to the roles management section and select an existing role 'Approver'
    await page.click('[data-testid="user-management-menu"]');
    await page.click('[data-testid="roles-management-link"]');
    
    // Click 'Edit Role' button for the 'Approver' role
    await page.click('[data-testid="role-item-approver"]');
    await page.click('[data-testid="edit-role-button"]');
    
    // Add a new permission 'Configure Approval Workflows' to the existing permissions
    await page.check('[data-testid="permission-configure-approval-workflows"]');
    
    // Click 'Save Changes' button
    await page.click('[data-testid="save-changes-button"]');
    
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Role updated successfully');
    
    // Navigate to the audit logs section of the user management portal
    await page.click('[data-testid="audit-logs-link"]');
    
    // Filter audit logs by 'Role Changes' and search for the 'Approver' role modification
    await page.selectOption('[data-testid="audit-log-filter"]', 'Role Changes');
    await page.fill('[data-testid="audit-log-search"]', 'Approver');
    await page.click('[data-testid="search-button"]');
    
    // Expected Result: Change is logged with user and timestamp
    const auditLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    
    // Verify the audit log entry contains the administrator username who made the change
    await expect(auditLogEntry.locator('[data-testid="audit-log-user"]')).toContainText(adminCredentials.username);
    
    // Verify the audit log entry contains the accurate timestamp of the change
    await expect(auditLogEntry.locator('[data-testid="audit-log-timestamp"]')).toBeVisible();
    const timestamp = await auditLogEntry.locator('[data-testid="audit-log-timestamp"]').textContent();
    expect(timestamp).toBeTruthy();
    
    // Verify the audit log entry contains details of the permission added
    await expect(auditLogEntry.locator('[data-testid="audit-log-details"]')).toContainText('Configure Approval Workflows');
    await expect(auditLogEntry.locator('[data-testid="audit-log-details"]')).toContainText('Approver');
  });

  test('Test enforcement of role-based access control', async ({ page, request }) => {
    // Step 1: Log in to the system as a user with 'Scheduler' role (no approval permissions)
    await page.fill('[data-testid="username-input"]', schedulerCredentials.username);
    await page.fill('[data-testid="password-input"]', schedulerCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to the schedule management section
    await page.click('[data-testid="schedule-management-menu"]');
    
    // Attempt to access the 'Approve Schedule Changes' feature
    // Verify that approval-related buttons and menu items are not visible in the user interface
    await expect(page.locator('[data-testid="approve-schedule-changes-button"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="approval-menu-item"]')).not.toBeVisible();
    
    // Attempt to access the approval feature using direct API endpoint call
    const apiResponse = await request.post('/api/schedule-approvals', {
      data: {
        scheduleId: 'test-schedule-123',
        action: 'approve'
      }
    });
    
    // Expected Result: Access denied with error message
    expect(apiResponse.status()).toBe(403);
    const responseBody = await apiResponse.json();
    expect(responseBody.error).toContain('Access denied');
    
    // Log out and log in as a user with 'Approver' role
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.fill('[data-testid="username-input"]', approverCredentials.username);
    await page.fill('[data-testid="password-input"]', approverCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to the 'Approve Schedule Changes' feature
    await page.click('[data-testid="schedule-management-menu"]');
    await page.click('[data-testid="approve-schedule-changes-button"]');
    
    // Verify access is granted for Approver role
    await expect(page.locator('[data-testid="approval-dashboard"]')).toBeVisible();
    
    // Navigate to audit logs to verify the access attempt by the 'Scheduler' role user is logged
    await page.click('[data-testid="user-management-menu"]');
    await page.click('[data-testid="audit-logs-link"]');
    
    // Filter for security audit trail
    await page.selectOption('[data-testid="audit-log-filter"]', 'Security Events');
    await page.fill('[data-testid="audit-log-search"]', schedulerCredentials.username);
    await page.click('[data-testid="search-button"]');
    
    // Verify the access attempt is logged in the security audit trail
    const securityLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(securityLogEntry.locator('[data-testid="audit-log-user"]')).toContainText(schedulerCredentials.username);
    await expect(securityLogEntry.locator('[data-testid="audit-log-details"]')).toContainText('Access denied');
    await expect(securityLogEntry.locator('[data-testid="audit-log-details"]')).toContainText('schedule-approvals');
  });
});