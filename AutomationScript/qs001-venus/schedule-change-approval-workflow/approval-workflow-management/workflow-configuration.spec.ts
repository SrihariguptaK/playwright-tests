import { test, expect } from '@playwright/test';

test.describe('Approval Workflow Configuration - Story 25', () => {
  const adminCredentials = {
    username: 'admin@company.com',
    password: 'AdminPass123!'
  };

  const nonAdminCredentials = {
    username: 'employee@company.com',
    password: 'EmployeePass123!'
  };

  test('Validate creation and activation of approval workflow rules', async ({ page }) => {
    // Step 1: Login as system administrator and navigate to workflow configuration
    await page.goto('/admin/login');
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Configuration UI is displayed
    await expect(page.locator('[data-testid="admin-dashboard"]')).toBeVisible();
    
    // Navigate to Approval Workflow Configuration
    await page.click('text=Approval Workflow Configuration');
    await expect(page.locator('[data-testid="workflow-config-page"]')).toBeVisible();
    
    // Step 2: Create a new workflow rule with approvers and conditions
    await page.click('[data-testid="create-workflow-button"]');
    await expect(page.locator('[data-testid="workflow-form"]')).toBeVisible();
    
    // Enter workflow details
    await page.fill('[data-testid="workflow-name-input"]', 'Schedule Change - Manager Approval');
    await page.fill('[data-testid="workflow-description-input"]', 'Requires manager approval for schedule changes up to 5 days');
    
    // Configure conditions
    await page.selectOption('[data-testid="condition-request-type"]', 'Schedule Change');
    await page.selectOption('[data-testid="condition-operator"]', 'AND');
    await page.selectOption('[data-testid="condition-duration-field"]', 'Duration');
    await page.selectOption('[data-testid="condition-duration-operator"]', 'less than or equal to');
    await page.fill('[data-testid="condition-duration-value"]', '5');
    await page.selectOption('[data-testid="condition-duration-unit"]', 'days');
    
    // Configure approver
    await page.selectOption('[data-testid="level-1-approver-dropdown"]', 'Direct Manager');
    
    // Validate workflow
    await page.click('[data-testid="validate-workflow-button"]');
    await expect(page.locator('[data-testid="validation-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-success-message"]')).toContainText('Workflow validated successfully');
    
    // Save workflow
    await page.click('[data-testid="save-workflow-button"]');
    
    // Expected Result: Rule is saved and validated without errors
    await expect(page.locator('[data-testid="save-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="save-success-message"]')).toContainText('Workflow saved successfully');
    
    // Step 3: Activate the workflow rule
    await page.click('[data-testid="workflow-list-link"]');
    await page.click('[data-testid="workflow-item-Schedule Change - Manager Approval"]');
    await page.click('[data-testid="activate-workflow-button"]');
    await page.click('[data-testid="confirm-activation-button"]');
    
    // Expected Result: Rule becomes active and applies to new requests
    await expect(page.locator('[data-testid="workflow-status"]')).toContainText('Active');
    await expect(page.locator('[data-testid="activation-success-message"]')).toBeVisible();
    
    // Verify workflow applies to new requests
    await page.goto('/requests/create');
    await page.selectOption('[data-testid="request-type-select"]', 'Schedule Change');
    await page.fill('[data-testid="request-duration"]', '3');
    await page.selectOption('[data-testid="request-duration-unit"]', 'days');
    await page.fill('[data-testid="request-reason"]', 'Testing workflow activation');
    await page.click('[data-testid="submit-request-button"]');
    
    await expect(page.locator('[data-testid="request-submitted-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-workflow-applied"]')).toContainText('Schedule Change - Manager Approval');
  });

  test('Ensure validation prevents circular routing in workflow rules', async ({ page }) => {
    // Login as administrator
    await page.goto('/admin/login');
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Navigate to Approval Workflow Configuration
    await page.click('text=Approval Workflow Configuration');
    await expect(page.locator('[data-testid="workflow-config-page"]')).toBeVisible();
    
    // Step 1: Attempt to create a workflow rule with circular approver routing
    await page.click('[data-testid="create-workflow-button"]');
    
    // Enter workflow details
    await page.fill('[data-testid="workflow-name-input"]', 'Circular Test Workflow');
    await page.fill('[data-testid="workflow-description-input"]', 'Testing circular routing validation');
    
    // Configure multi-level approval chain
    await page.selectOption('[data-testid="level-1-approver-dropdown"]', 'Manager');
    await page.click('[data-testid="add-approval-level-button"]');
    await page.selectOption('[data-testid="level-2-approver-dropdown"]', 'Director');
    await page.click('[data-testid="add-approval-level-button"]');
    await page.selectOption('[data-testid="level-3-approver-dropdown"]', 'VP');
    
    // Attempt to add Level 4 with circular reference
    await page.click('[data-testid="add-approval-level-button"]');
    await page.selectOption('[data-testid="level-4-approver-dropdown"]', 'Manager');
    
    // Attempt to validate
    await page.click('[data-testid="validate-workflow-button"]');
    
    // Expected Result: System displays validation error preventing save
    await expect(page.locator('[data-testid="validation-error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-message"]')).toContainText('Circular routing detected');
    
    // Verify save button is disabled or save fails
    const saveButton = page.locator('[data-testid="save-workflow-button"]');
    await expect(saveButton).toBeDisabled();
    
    // Test escalation circular routing
    await page.selectOption('[data-testid="level-4-approver-dropdown"]', 'CFO');
    await page.click('[data-testid="configure-escalation-button"]');
    await page.selectOption('[data-testid="escalation-target-dropdown"]', 'Manager');
    await page.fill('[data-testid="escalation-timeout-input"]', '24');
    
    await page.click('[data-testid="validate-workflow-button"]');
    
    // Expected Result: Validation error for escalation circular routing
    await expect(page.locator('[data-testid="validation-error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-message"]')).toContainText('Escalation creates circular routing');
    
    // Attempt to save anyway
    await page.click('[data-testid="save-workflow-button"]', { force: true }).catch(() => {});
    
    // Verify workflow is not saved
    await page.goto('/admin/workflow-config');
    await expect(page.locator('[data-testid="workflow-item-Circular Test Workflow"]')).not.toBeVisible();
  });

  test('Verify access restriction to workflow configuration', async ({ page, request }) => {
    // Step 1: Login as non-admin user and attempt to access workflow configuration
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', nonAdminCredentials.username);
    await page.fill('[data-testid="password-input"]', nonAdminCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="user-dashboard"]')).toBeVisible();
    
    // Attempt to access admin console via menu
    const adminMenuVisible = await page.locator('text=Admin Console').isVisible().catch(() => false);
    expect(adminMenuVisible).toBe(false);
    
    // Attempt to directly navigate to workflow configuration URL
    await page.goto('/admin/workflow-config');
    
    // Expected Result: Access is denied with appropriate error message
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    await expect(page.locator('[data-testid="error-message"]')).toContainText('You do not have permission to access this resource');
    
    // Verify redirect to unauthorized page or dashboard
    await expect(page).toHaveURL(/\/(unauthorized|dashboard|access-denied)/);
    
    // Extract authentication token for API testing
    const cookies = await page.context().cookies();
    const authToken = cookies.find(c => c.name === 'auth_token' || c.name === 'session')?.value || '';
    
    // Test API endpoint access with non-admin token
    const getResponse = await request.get('/api/workflow-config', {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    // Expected Result: API returns 403 Forbidden
    expect(getResponse.status()).toBe(403);
    const getBody = await getResponse.json();
    expect(getBody.error).toContain('Forbidden');
    
    // Attempt POST to create workflow via API
    const postResponse = await request.post('/api/workflow-config', {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      data: {
        name: 'Unauthorized Workflow',
        description: 'This should not be created',
        conditions: [
          {
            field: 'requestType',
            operator: 'equals',
            value: 'Schedule Change'
          }
        ],
        approvers: [
          {
            level: 1,
            role: 'Manager'
          }
        ]
      }
    });
    
    // Expected Result: API returns 403 Forbidden
    expect(postResponse.status()).toBe(403);
    const postBody = await postResponse.json();
    expect(postBody.error).toContain('Forbidden');
    
    // Verify audit logs (if accessible via UI)
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await page.click('text=Audit Logs');
    await page.fill('[data-testid="audit-search-input"]', nonAdminCredentials.username);
    await page.click('[data-testid="audit-search-button"]');
    
    // Verify unauthorized access attempts are logged
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('Unauthorized access attempt');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('/admin/workflow-config');
  });
});