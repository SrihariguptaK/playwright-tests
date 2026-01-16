import { test, expect } from '@playwright/test';

test.describe('Approval Workflow Configuration - Story 15', () => {
  const adminCredentials = {
    username: 'admin@company.com',
    password: 'AdminPass123!'
  };

  const employeeCredentials = {
    username: 'employee@company.com',
    password: 'EmployeePass123!'
  };

  const managerCredentials = {
    username: 'manager@company.com',
    password: 'ManagerPass123!'
  };

  test.beforeEach(async ({ page }) => {
    await page.goto('/login');
  });

  test('Verify administrator can create and save valid workflow configurations', async ({ page }) => {
    // Login as administrator
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to workflow configuration UI
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="workflow-configuration-link"]');
    await expect(page).toHaveURL(/.*admin\/workflow-configuration/);

    // Verify UI displays current configurations and options to create new
    await expect(page.locator('[data-testid="workflow-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="create-workflow-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="workflow-configuration-header"]')).toContainText('Approval Workflow Settings');

    // Click Create New Workflow button
    await page.click('[data-testid="create-workflow-button"]');
    await expect(page.locator('[data-testid="workflow-form"]')).toBeVisible();

    // Enter workflow name
    const workflowName = `Department Manager Approval Workflow ${Date.now()}`;
    await page.fill('[data-testid="workflow-name-input"]', workflowName);

    // Enter workflow description
    await page.fill('[data-testid="workflow-description-input"]', 'Two-level approval for schedule changes requiring department manager and HR approval');

    // Add first approval level
    await page.click('[data-testid="add-approval-level-button"]');
    await page.selectOption('[data-testid="approval-level-1-role-select"]', 'Department Manager');
    await expect(page.locator('[data-testid="approval-level-1"]')).toContainText('Department Manager');

    // Add second approval level
    await page.click('[data-testid="add-approval-level-button"]');
    await page.selectOption('[data-testid="approval-level-2-role-select"]', 'HR Manager');
    await expect(page.locator('[data-testid="approval-level-2"]')).toContainText('HR Manager');

    // Add conditional routing rule
    await page.click('[data-testid="add-conditional-rule-button"]');
    await page.selectOption('[data-testid="rule-condition-select"]', 'duration');
    await page.selectOption('[data-testid="rule-operator-select"]', 'greater_than');
    await page.fill('[data-testid="rule-value-input"]', '5');
    await page.selectOption('[data-testid="rule-action-approver-select"]', 'VP');

    // Validate configuration
    await page.click('[data-testid="validate-configuration-button"]');
    await expect(page.locator('[data-testid="validation-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-success-message"]')).toContainText('Configuration is valid');

    // Save configuration
    await page.click('[data-testid="save-workflow-button"]');
    await expect(page.locator('[data-testid="save-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="save-success-message"]')).toContainText('Workflow saved successfully');

    // Wait for configuration propagation (5 minutes requirement, using shorter wait for test)
    await page.waitForTimeout(5000);

    // Logout and login as employee to submit schedule change request
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    await page.fill('[data-testid="username-input"]', employeeCredentials.username);
    await page.fill('[data-testid="password-input"]', employeeCredentials.password);
    await page.click('[data-testid="login-button"]');

    // Submit new schedule change request
    await page.click('[data-testid="schedule-menu"]');
    await page.click('[data-testid="request-schedule-change-link"]');
    await page.fill('[data-testid="request-start-date"]', '2024-06-01');
    await page.fill('[data-testid="request-end-date"]', '2024-06-07');
    await page.fill('[data-testid="request-reason"]', 'Testing workflow assignment');
    await page.click('[data-testid="submit-request-button"]');
    await expect(page.locator('[data-testid="request-submitted-message"]')).toBeVisible();

    const requestId = await page.locator('[data-testid="request-id"]').textContent();

    // Logout and login back as administrator
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');

    // Navigate to submitted request details
    await page.goto(`/admin/requests/${requestId}`);
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();

    // Verify approval workflow assignment
    await expect(page.locator('[data-testid="assigned-workflow"]')).toContainText(workflowName);

    // Verify approval chain displays both approvers in correct sequence
    const approvalChain = page.locator('[data-testid="approval-chain"]');
    await expect(approvalChain).toBeVisible();
    await expect(approvalChain.locator('[data-testid="approval-level-1-approver"]')).toContainText('Department Manager');
    await expect(approvalChain.locator('[data-testid="approval-level-2-approver"]')).toContainText('HR Manager');
  });

  test('Ensure invalid workflow configurations are rejected', async ({ page }) => {
    // Login as administrator
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');

    // Navigate to workflow configuration UI
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="workflow-configuration-link"]');

    // Test 1: Missing approvers
    await page.click('[data-testid="create-workflow-button"]');
    await page.fill('[data-testid="workflow-name-input"]', 'Test Invalid Workflow - Missing Approvers');
    await page.fill('[data-testid="workflow-description-input"]', 'Testing workflow without approvers');

    // Attempt to save without adding approval levels
    await page.click('[data-testid="save-workflow-button"]');

    // Verify error message is displayed
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('At least one approval level is required');

    // Verify workflow was not saved by checking workflow list
    await page.click('[data-testid="cancel-workflow-button"]');
    await expect(page.locator('[data-testid="workflow-list"]')).not.toContainText('Test Invalid Workflow - Missing Approvers');

    // Test 2: Circular rule scenario
    await page.click('[data-testid="create-workflow-button"]');
    await page.fill('[data-testid="workflow-name-input"]', 'Test Circular Rule Workflow');
    await page.fill('[data-testid="workflow-description-input"]', 'Testing circular rule detection');

    // Add Department Manager as Level 1 approver
    await page.click('[data-testid="add-approval-level-button"]');
    await page.selectOption('[data-testid="approval-level-1-role-select"]', 'Department Manager');

    // Add circular conditional rule
    await page.click('[data-testid="add-conditional-rule-button"]');
    await page.selectOption('[data-testid="rule-condition-select"]', 'rejection');
    await page.selectOption('[data-testid="rule-action-approver-select"]', 'Department Manager');

    // Validate configuration
    await page.click('[data-testid="validate-configuration-button"]');
    await expect(page.locator('[data-testid="validation-error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-message"]')).toContainText('Circular routing rule detected');

    // Attempt to save
    await page.click('[data-testid="save-workflow-button"]');
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Invalid workflow configuration');

    // Verify workflow was not saved
    await page.click('[data-testid="cancel-workflow-button"]');
    await expect(page.locator('[data-testid="workflow-list"]')).not.toContainText('Test Circular Rule Workflow');

    // Test 3: Duplicate workflow name
    const existingWorkflowName = await page.locator('[data-testid="workflow-list"] [data-testid="workflow-item"]:first-child [data-testid="workflow-name"]').textContent();
    
    await page.click('[data-testid="create-workflow-button"]');
    await page.fill('[data-testid="workflow-name-input"]', existingWorkflowName || 'Existing Workflow');
    await page.fill('[data-testid="workflow-description-input"]', 'Testing duplicate name');
    await page.click('[data-testid="add-approval-level-button"]');
    await page.selectOption('[data-testid="approval-level-1-role-select"]', 'Department Manager');
    await page.click('[data-testid="save-workflow-button"]');

    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Workflow name already exists');

    await page.click('[data-testid="cancel-workflow-button"]');

    // Test 4: Special characters and SQL injection patterns
    await page.click('[data-testid="create-workflow-button"]');
    await page.fill('[data-testid="workflow-name-input"]', "Test'; DROP TABLE workflows; --");
    await page.fill('[data-testid="workflow-description-input"]', 'Testing SQL injection prevention');
    await page.click('[data-testid="add-approval-level-button"]');
    await page.selectOption('[data-testid="approval-level-1-role-select"]', 'Department Manager');
    await page.click('[data-testid="save-workflow-button"]');

    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Invalid characters in workflow name');
  });

  test('Verify access control for workflow configuration features', async ({ page }) => {
    // Login as non-administrator user (Employee)
    await page.fill('[data-testid="username-input"]', employeeCredentials.username);
    await page.fill('[data-testid="password-input"]', employeeCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Verify admin menu is not visible in navigation
    await expect(page.locator('[data-testid="admin-menu"]')).not.toBeVisible();

    // Attempt to manually navigate to workflow configuration URL
    await page.goto('/admin/workflow-configuration');

    // Verify access denied or redirect
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');
    await expect(page).not.toHaveURL(/.*admin\/workflow-configuration/);

    // Attempt to access workflow configuration API endpoint
    const getResponse = await page.request.get('/api/workflows', {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('authToken'))}`
      }
    });
    expect(getResponse.status()).toBe(403);
    const getResponseBody = await getResponse.json();
    expect(getResponseBody.error).toContain('Insufficient permissions');

    // Attempt to create workflow via API
    const postResponse = await page.request.post('/api/workflows', {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('authToken'))}`,
        'Content-Type': 'application/json'
      },
      data: {
        name: 'Unauthorized Workflow',
        description: 'Testing unauthorized access',
        approvalLevels: [
          { level: 1, role: 'Department Manager' }
        ]
      }
    });
    expect(postResponse.status()).toBe(403);
    const postResponseBody = await postResponse.json();
    expect(postResponseBody.error).toContain('Insufficient permissions');

    // Logout employee
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Login as Manager (also non-admin)
    await page.fill('[data-testid="username-input"]', managerCredentials.username);
    await page.fill('[data-testid="password-input"]', managerCredentials.password);
    await page.click('[data-testid="login-button"]');

    // Verify manager also cannot access workflow configuration
    await expect(page.locator('[data-testid="admin-menu"]')).not.toBeVisible();
    await page.goto('/admin/workflow-configuration');
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();

    // Logout manager
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Login as administrator
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');

    // Verify administrator can access workflow configuration
    await expect(page.locator('[data-testid="admin-menu"]')).toBeVisible();
    await page.click('[data-testid="admin-menu"]');
    await expect(page.locator('[data-testid="workflow-configuration-link"]')).toBeVisible();

    // Navigate to workflow configuration
    await page.click('[data-testid="workflow-configuration-link"]');
    await expect(page).toHaveURL(/.*admin\/workflow-configuration/);
    await expect(page.locator('[data-testid="workflow-configuration-header"]')).toBeVisible();

    // Verify access is logged in audit trail
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-logs-link"]');
    await expect(page.locator('[data-testid="audit-log-list"]')).toBeVisible();
    
    const latestLogEntry = page.locator('[data-testid="audit-log-list"] [data-testid="audit-log-entry"]:first-child');
    await expect(latestLogEntry).toContainText('Workflow Configuration Access');
    await expect(latestLogEntry).toContainText(adminCredentials.username);
    await expect(latestLogEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
  });
});