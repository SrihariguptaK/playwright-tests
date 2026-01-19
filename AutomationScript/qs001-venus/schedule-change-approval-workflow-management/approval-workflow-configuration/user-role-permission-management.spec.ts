import { test, expect } from '@playwright/test';

test.describe('User Role and Permission Management for Approval Workflows', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page and authenticate as Administrator
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="admin-dashboard"]')).toBeVisible();
  });

  test('Create and assign user roles successfully (happy-path)', async ({ page }) => {
    // Navigate to the user management module from the admin dashboard
    await page.click('[data-testid="admin-dashboard"]');
    await page.click('[data-testid="user-management-menu"]');
    await expect(page.locator('[data-testid="user-management-page"]')).toBeVisible();

    // Click on 'Create New Role' button
    await page.click('[data-testid="create-new-role-button"]');
    await expect(page.locator('[data-testid="create-role-modal"]')).toBeVisible();

    // Enter role name as 'Workflow Manager' and description as 'Manages approval workflows'
    await page.fill('[data-testid="role-name-input"]', 'Workflow Manager');
    await page.fill('[data-testid="role-description-input"]', 'Manages approval workflows');

    // Select specific permissions: 'Configure Workflows', 'View Submissions', 'Manage Approvers'
    await page.check('[data-testid="permission-configure-workflows"]');
    await page.check('[data-testid="permission-view-submissions"]');
    await page.check('[data-testid="permission-manage-approvers"]');

    // Click 'Save Role' button
    await page.click('[data-testid="save-role-button"]');
    await expect(page.locator('[data-testid="success-notification"]')).toBeVisible();

    // Expected Result: Role is saved and visible in role list
    await expect(page.locator('[data-testid="role-list"]')).toContainText('Workflow Manager');
    const roleItem = page.locator('[data-testid="role-item-workflow-manager"]');
    await expect(roleItem).toBeVisible();

    // Select the newly created 'Workflow Manager' role from the role list
    await roleItem.click();
    await expect(page.locator('[data-testid="role-details-panel"]')).toBeVisible();

    // Click 'Assign Users' button and select 2 test users from the available user list
    await page.click('[data-testid="assign-users-button"]');
    await expect(page.locator('[data-testid="assign-users-modal"]')).toBeVisible();
    await page.check('[data-testid="user-checkbox-testuser1@company.com"]');
    await page.check('[data-testid="user-checkbox-testuser2@company.com"]');

    // Click 'Confirm Assignment' button
    await page.click('[data-testid="confirm-assignment-button"]');
    await expect(page.locator('[data-testid="assignment-success-notification"]')).toBeVisible();

    // Expected Result: Users are assigned and permissions applied
    await expect(page.locator('[data-testid="assigned-users-list"]')).toContainText('testuser1@company.com');
    await expect(page.locator('[data-testid="assigned-users-list"]')).toContainText('testuser2@company.com');

    // Log out as Administrator and log in as one of the assigned users
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-page"]')).toBeVisible();

    await page.fill('[data-testid="username-input"]', 'testuser1@company.com');
    await page.fill('[data-testid="password-input"]', 'TestUser123!');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Verify user has access to workflow management features
    await page.click('[data-testid="workflows-menu"]');
    await expect(page.locator('[data-testid="configure-workflows-section"]')).toBeVisible();
  });

  test('Enforce permissions across approval modules (error-case)', async ({ page }) => {
    // Log out as Administrator and log in to the system as 'User A' who does not have 'Approve Requests' permission
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-page"]')).toBeVisible();

    await page.fill('[data-testid="username-input"]', 'usera@company.com');
    await page.fill('[data-testid="password-input"]', 'UserA123!');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to the approval workflow module
    await page.click('[data-testid="approval-workflow-menu"]');
    await expect(page.locator('[data-testid="approval-workflow-page"]')).toBeVisible();

    // Attempt to access the pending approval request and click 'Approve' button
    await page.click('[data-testid="pending-request-item-1"]');
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    
    const approveButton = page.locator('[data-testid="approve-button"]');
    if (await approveButton.isVisible()) {
      await approveButton.click();
    }

    // Expected Result: Access is denied with error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Access denied');
    await expect(page.locator('[data-testid="error-message"]')).toContainText('insufficient permissions');

    // Verify that the approval action was not executed by checking the request status
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Pending');
    await expect(page.locator('[data-testid="request-status"]')).not.toContainText('Approved');

    // Log out as 'User A' and log in as 'User B' with 'Approver' role
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-page"]')).toBeVisible();

    await page.fill('[data-testid="username-input"]', 'userb@company.com');
    await page.fill('[data-testid="password-input"]', 'UserB123!');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to the approval workflow module and access the same pending approval request
    await page.click('[data-testid="approval-workflow-menu"]');
    await expect(page.locator('[data-testid="approval-workflow-page"]')).toBeVisible();
    await page.click('[data-testid="pending-request-item-1"]');
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();

    // Click 'Approve' button and add approval comments
    await page.click('[data-testid="approve-button"]');
    await expect(page.locator('[data-testid="approval-modal"]')).toBeVisible();
    await page.fill('[data-testid="approval-comments-input"]', 'Request approved after review');
    await page.click('[data-testid="confirm-approval-button"]');

    // Expected Result: Action succeeds
    await expect(page.locator('[data-testid="approval-success-notification"]')).toBeVisible();

    // Verify the approval is recorded with User B's name and timestamp
    await expect(page.locator('[data-testid="request-status"]')).toContainText('Approved');
    await expect(page.locator('[data-testid="approval-details"]')).toContainText('userb@company.com');
    await expect(page.locator('[data-testid="approval-details"]')).toContainText('Request approved after review');
    
    const approvalTimestamp = page.locator('[data-testid="approval-timestamp"]');
    await expect(approvalTimestamp).toBeVisible();
    const timestampText = await approvalTimestamp.textContent();
    expect(timestampText).toBeTruthy();
  });

  test('Audit logging of role and user assignment changes (happy-path)', async ({ page }) => {
    // Navigate to user management module and select the 'Manager' role
    await page.click('[data-testid="user-management-menu"]');
    await expect(page.locator('[data-testid="user-management-page"]')).toBeVisible();
    await page.click('[data-testid="role-item-manager"]');
    await expect(page.locator('[data-testid="role-details-panel"]')).toBeVisible();

    // Click 'Edit Permissions' and add new permission 'Delete Workflows'
    await page.click('[data-testid="edit-permissions-button"]');
    await expect(page.locator('[data-testid="edit-permissions-modal"]')).toBeVisible();
    await page.check('[data-testid="permission-delete-workflows"]');

    // Click 'Save Changes' button
    await page.click('[data-testid="save-changes-button"]');
    await expect(page.locator('[data-testid="changes-saved-notification"]')).toBeVisible();

    // Expected Result: Changes are logged with user and timestamp
    // Navigate to user assignment section and remove user 'John Doe' from 'Manager' role
    await page.click('[data-testid="user-assignments-tab"]');
    await expect(page.locator('[data-testid="user-assignments-section"]')).toBeVisible();
    
    const johnDoeRow = page.locator('[data-testid="user-row-johndoe@company.com"]');
    await expect(johnDoeRow).toBeVisible();
    await johnDoeRow.locator('[data-testid="remove-user-button"]').click();

    // Confirm the removal action
    await expect(page.locator('[data-testid="confirm-removal-modal"]')).toBeVisible();
    await page.click('[data-testid="confirm-removal-button"]');
    await expect(page.locator('[data-testid="removal-success-notification"]')).toBeVisible();

    // Navigate to the audit log viewer from the admin menu
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-log-viewer-menu"]');
    await expect(page.locator('[data-testid="audit-log-viewer-page"]')).toBeVisible();

    // Filter audit logs by 'Role Management' category and today's date
    await page.selectOption('[data-testid="category-filter"]', 'Role Management');
    
    const today = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="date-filter"]', today);
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForTimeout(1000);

    // Locate the log entry for 'Manager' role permission change
    const permissionChangeLog = page.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'Manager' }).filter({ hasText: 'Delete Workflows' }).first();
    await expect(permissionChangeLog).toBeVisible();
    
    // Expected Result: All changes are visible and accurate
    await expect(permissionChangeLog).toContainText('Permission added');
    await expect(permissionChangeLog).toContainText('admin@company.com');
    
    const permissionLogTimestamp = permissionChangeLog.locator('[data-testid="log-timestamp"]');
    await expect(permissionLogTimestamp).toBeVisible();

    // Locate the log entry for user assignment change
    const userAssignmentLog = page.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'johndoe@company.com' }).filter({ hasText: 'Manager' }).first();
    await expect(userAssignmentLog).toBeVisible();
    await expect(userAssignmentLog).toContainText('User removed from role');
    await expect(userAssignmentLog).toContainText('admin@company.com');
    
    const assignmentLogTimestamp = userAssignmentLog.locator('[data-testid="log-timestamp"]');
    await expect(assignmentLogTimestamp).toBeVisible();

    // Export audit logs to CSV format and verify data integrity
    await page.click('[data-testid="export-logs-button"]');
    await page.selectOption('[data-testid="export-format-select"]', 'CSV');
    
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="confirm-export-button"]');
    const download = await downloadPromise;
    
    expect(download.suggestedFilename()).toContain('.csv');
    
    // Verify download completed successfully
    await expect(page.locator('[data-testid="export-success-notification"]')).toBeVisible();
  });
});