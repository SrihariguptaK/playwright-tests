import { test, expect } from '@playwright/test';

test.describe('User Roles and Permissions Management', () => {
  const adminCredentials = {
    username: 'admin@example.com',
    password: 'AdminPass123!'
  };

  const restrictedUserCredentials = {
    username: 'restricteduser@example.com',
    password: 'UserPass123!'
  };

  const authorizedUserCredentials = {
    username: 'authorizeduser@example.com',
    password: 'UserPass123!'
  };

  const testRoleName = `Performance Reviewer ${Date.now()}`;
  const testRoleDescription = 'Can view and review performance metrics but cannot generate reports';

  test.beforeEach(async ({ page }) => {
    // Login as admin before each test
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate role creation and assignment', async ({ page }) => {
    // Step 1: Navigate to User Management page
    await page.click('[data-testid="user-management-menu"]');
    await expect(page).toHaveURL(/.*user-management/);
    await expect(page.locator('[data-testid="user-management-page"]')).toBeVisible();

    // Step 2: Navigate to Roles tab
    await page.click('[data-testid="roles-tab"]');
    await expect(page.locator('[data-testid="roles-section"]')).toBeVisible();

    // Step 3: Click Create New Role button
    await page.click('[data-testid="create-role-button"]');
    await expect(page.locator('[data-testid="role-creation-modal"]')).toBeVisible();

    // Step 4: Enter role name
    await page.fill('[data-testid="role-name-input"]', testRoleName);

    // Step 5: Enter role description
    await page.fill('[data-testid="role-description-input"]', testRoleDescription);

    // Step 6: Select specific permissions
    await page.check('[data-testid="permission-view-performance-metrics"]');
    await page.check('[data-testid="permission-view-review-cycles"]');
    await page.uncheck('[data-testid="permission-generate-reports"]');
    await page.uncheck('[data-testid="permission-export-data"]');

    // Step 7: Save the role
    await page.click('[data-testid="save-role-button"]');
    await expect(page.locator('[data-testid="role-created-success-message"]')).toBeVisible();
    await expect(page.locator(`text=${testRoleName}`)).toBeVisible();

    // Step 8: Navigate to Users tab
    await page.click('[data-testid="users-tab"]');
    await expect(page.locator('[data-testid="users-section"]')).toBeVisible();

    // Step 9: Select a user from the list
    await page.click(`[data-testid="user-row-${authorizedUserCredentials.username}"]`);
    await expect(page.locator('[data-testid="user-details-panel"]')).toBeVisible();

    // Step 10: Click Assign Role button
    await page.click('[data-testid="assign-role-button"]');
    await expect(page.locator('[data-testid="assign-role-modal"]')).toBeVisible();

    // Step 11: Select the newly created role
    await page.selectOption('[data-testid="role-select-dropdown"]', { label: testRoleName });

    // Step 12: Save role assignment
    await page.click('[data-testid="save-assignment-button"]');
    await expect(page.locator('[data-testid="role-assigned-success-message"]')).toBeVisible();

    // Step 13: Verify immediate effect
    await expect(page.locator(`[data-testid="user-role-badge"]:has-text("${testRoleName}")`)).toBeVisible();

    // Step 14: Navigate to audit log
    await page.click('[data-testid="audit-log-menu"]');
    await expect(page.locator('[data-testid="audit-log-page"]')).toBeVisible();
    await expect(page.locator(`text=Role created: ${testRoleName}`)).toBeVisible();
    await expect(page.locator(`text=Role assigned to ${authorizedUserCredentials.username}`)).toBeVisible();
  });

  test('Verify access restriction based on roles', async ({ page, context }) => {
    // Step 1: Log out from System Administrator account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 2: Log in as user without required role
    await page.fill('[data-testid="username-input"]', restrictedUserCredentials.username);
    await page.fill('[data-testid="password-input"]', restrictedUserCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 3: Attempt to navigate to Performance Metrics page
    await page.click('[data-testid="performance-metrics-menu"]').catch(() => {});
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();

    // Step 4: Attempt to navigate to Review Cycles page
    await page.goto('/review-cycles');
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();

    // Step 5: Attempt to navigate to Reporting page
    await page.goto('/reporting');
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();

    // Step 6: Attempt to access restricted API endpoint
    const apiResponse = await page.request.get('/api/reports/performance');
    expect(apiResponse.status()).toBe(403);

    // Step 7: Verify user can only access appropriate features
    await page.goto('/dashboard');
    await expect(page.locator('[data-testid="performance-metrics-menu"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="review-cycles-menu"]')).not.toBeVisible();

    // Step 8: Log out from restricted user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 9: Log in as user with assigned role
    await page.fill('[data-testid="username-input"]', authorizedUserCredentials.username);
    await page.fill('[data-testid="password-input"]', authorizedUserCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 10: Navigate to Performance Metrics page
    await page.click('[data-testid="performance-metrics-menu"]');
    await expect(page).toHaveURL(/.*performance-metrics/);
    await expect(page.locator('[data-testid="performance-metrics-page"]')).toBeVisible();

    // Step 11: Navigate to Review Cycles page
    await page.click('[data-testid="review-cycles-menu"]');
    await expect(page).toHaveURL(/.*review-cycles/);
    await expect(page.locator('[data-testid="review-cycles-page"]')).toBeVisible();

    // Step 12: Navigate to Reporting page (should be restricted based on role)
    await page.goto('/reporting');
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();

    // Step 13: Verify user can perform allowed actions
    await page.goto('/performance-metrics');
    await expect(page.locator('[data-testid="view-metrics-button"]')).toBeVisible();
    await page.click('[data-testid="view-metrics-button"]');
    await expect(page.locator('[data-testid="metrics-data"]')).toBeVisible();

    // Step 14: Attempt to access features not in role permissions
    await expect(page.locator('[data-testid="generate-report-button"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="export-data-button"]')).not.toBeVisible();

    // Step 15: Check audit logs for access attempts
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Login back as admin to check audit logs
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await page.click('[data-testid="audit-log-menu"]');
    await expect(page.locator(`text=${restrictedUserCredentials.username}`)).toBeVisible();
    await expect(page.locator('text=Access denied')).toBeVisible();
    await expect(page.locator(`text=${authorizedUserCredentials.username}`)).toBeVisible();
    await expect(page.locator('text=Access granted')).toBeVisible();
  });
});