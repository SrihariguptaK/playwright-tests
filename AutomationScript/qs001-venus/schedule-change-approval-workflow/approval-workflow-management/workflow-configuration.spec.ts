import { test, expect } from '@playwright/test';

test.describe('Approval Workflow Configuration - Story 5', () => {
  const ADMIN_USERNAME = 'admin@example.com';
  const ADMIN_PASSWORD = 'AdminPass123!';
  const NON_ADMIN_USERNAME = 'user@example.com';
  const NON_ADMIN_PASSWORD = 'UserPass123!';
  const WORKFLOW_CONFIG_URL = '/admin/workflow-configuration';
  const BASE_URL = 'http://localhost:3000';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('Validate creation and saving of workflow configuration (happy-path)', async ({ page }) => {
    // Step 1: System Administrator navigates to workflow configuration page
    await page.fill('[data-testid="login-username"]', ADMIN_USERNAME);
    await page.fill('[data-testid="login-password"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-submit"]');
    
    await page.goto(`${BASE_URL}${WORKFLOW_CONFIG_URL}`);
    
    // Expected Result: Configuration UI is displayed
    await expect(page.locator('[data-testid="workflow-config-page"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Workflow Configuration');

    // Step 2: Create new workflow with approvers and routing rules
    await page.click('[data-testid="create-new-workflow-btn"]');
    
    // Enter workflow name
    await page.fill('[data-testid="workflow-name-input"]', 'Purchase Order Approval Workflow');
    
    // Select approver roles
    await page.click('[data-testid="approver-roles-dropdown"]');
    await page.click('[data-testid="role-option-manager"]');
    await page.click('[data-testid="role-option-director"]');
    await page.click('[data-testid="approver-roles-dropdown"]'); // Close dropdown
    
    // Select approver users
    await page.click('[data-testid="approver-users-dropdown"]');
    await page.click('[data-testid="user-option-john-manager"]');
    await page.click('[data-testid="user-option-jane-director"]');
    await page.click('[data-testid="approver-users-dropdown"]'); // Close dropdown
    
    // Define multi-level approval sequence
    await page.click('[data-testid="add-approval-level-btn"]');
    await page.selectOption('[data-testid="level-1-approver"]', 'Manager');
    
    await page.click('[data-testid="add-approval-level-btn"]');
    await page.selectOption('[data-testid="level-2-approver"]', 'Director');
    
    // Set routing rules
    await page.click('[data-testid="add-routing-rule-btn"]');
    await page.selectOption('[data-testid="routing-condition-type"]', 'amount');
    await page.fill('[data-testid="routing-condition-value"]', '10000');
    await page.selectOption('[data-testid="routing-action"]', 'require-director-approval');
    
    // Expected Result: Configuration is accepted and saved
    await page.click('[data-testid="save-workflow-btn"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow configuration saved successfully');
    await expect(page.locator('[data-testid="workflow-list"]')).toContainText('Purchase Order Approval Workflow');

    // Step 3: Activate the workflow configuration
    await page.click('[data-testid="workflow-item-Purchase Order Approval Workflow"]');
    await page.click('[data-testid="activate-workflow-btn"]');
    
    // Expected Result: Configuration is applied and active
    await expect(page.locator('[data-testid="activation-success-message"]')).toContainText('Workflow activated successfully');
    await expect(page.locator('[data-testid="workflow-status"]')).toContainText('Active');
    
    // Wait for 5 minutes and verify workflow is operational (using reduced timeout for testing)
    await page.waitForTimeout(5000); // Simulated wait - in real scenario would be 300000ms
    await expect(page.locator('[data-testid="workflow-operational-status"]')).toContainText('Operational');
  });

  test('Verify validation prevents invalid configurations (error-case)', async ({ page }) => {
    // Login as admin
    await page.fill('[data-testid="login-username"]', ADMIN_USERNAME);
    await page.fill('[data-testid="login-password"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-submit"]');
    
    // Navigate to workflow configuration page and click 'Create New Workflow'
    await page.goto(`${BASE_URL}${WORKFLOW_CONFIG_URL}`);
    await page.click('[data-testid="create-new-workflow-btn"]');
    
    // Step 1: Enter workflow name but leave approver roles and users fields empty
    await page.fill('[data-testid="workflow-name-input"]', 'Incomplete Workflow');
    
    // Click 'Save' button with incomplete configuration
    await page.click('[data-testid="save-workflow-btn"]');
    
    // Expected Result: Validation errors displayed, save blocked
    await expect(page.locator('[data-testid="validation-error-approver-roles"]')).toContainText('At least one approver role is required');
    await expect(page.locator('[data-testid="validation-error-approver-users"]')).toContainText('At least one approver user is required');
    await expect(page.locator('[data-testid="workflow-list"]')).not.toContainText('Incomplete Workflow');
    
    // Add approvers but create conflicting routing rules
    await page.click('[data-testid="approver-roles-dropdown"]');
    await page.click('[data-testid="role-option-manager"]');
    await page.click('[data-testid="approver-roles-dropdown"]');
    
    await page.click('[data-testid="approver-users-dropdown"]');
    await page.click('[data-testid="user-option-john-manager"]');
    await page.click('[data-testid="approver-users-dropdown"]');
    
    // Create circular dependency in routing rules
    await page.click('[data-testid="add-routing-rule-btn"]');
    await page.selectOption('[data-testid="routing-condition-type"]', 'status');
    await page.fill('[data-testid="routing-condition-value"]', 'pending');
    await page.selectOption('[data-testid="routing-action"]', 'route-to-level-2');
    
    await page.click('[data-testid="add-routing-rule-btn"]');
    await page.selectOption('[data-testid="routing-condition-type-2"]', 'status');
    await page.fill('[data-testid="routing-condition-value-2"]', 'pending');
    await page.selectOption('[data-testid="routing-action-2"]', 'route-to-level-1');
    
    await page.click('[data-testid="save-workflow-btn"]');
    
    // Expected Result: Validation errors for conflicting rules
    await expect(page.locator('[data-testid="validation-error-routing-rules"]')).toContainText('Circular dependency detected in routing rules');
    
    // Step 2: Correct all validation errors
    await page.click('[data-testid="remove-routing-rule-2-btn"]');
    await page.selectOption('[data-testid="routing-action"]', 'approve');
    
    // Click 'Save' button with corrected configuration
    await page.click('[data-testid="save-workflow-btn"]');
    
    // Expected Result: Configuration saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow configuration saved successfully');
    await expect(page.locator('[data-testid="workflow-list"]')).toContainText('Incomplete Workflow');
  });

  test('Test access restriction to workflow configuration (error-case)', async ({ page }) => {
    // Step 1: Log in to the system using non-admin user credentials
    await page.fill('[data-testid="login-username"]', NON_ADMIN_USERNAME);
    await page.fill('[data-testid="login-password"]', NON_ADMIN_PASSWORD);
    await page.click('[data-testid="login-submit"]');
    
    await expect(page.locator('[data-testid="user-dashboard"]')).toBeVisible();
    
    // Attempt to navigate to workflow configuration page by entering URL directly
    await page.goto(`${BASE_URL}${WORKFLOW_CONFIG_URL}`);
    
    // Expected Result: Access denied message displayed
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    await expect(page.locator('[data-testid="error-description"]')).toContainText('You do not have permission to access this page');
    await expect(page.locator('[data-testid="workflow-config-page"]')).not.toBeVisible();
    
    // Attempt through navigation menu
    const workflowConfigLink = page.locator('[data-testid="nav-workflow-config"]');
    if (await workflowConfigLink.isVisible()) {
      await workflowConfigLink.click();
      await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    }
    
    // Step 2: Log out from non-admin user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-btn"]');
    await expect(page.locator('[data-testid="login-page"]')).toBeVisible();
    
    // Log in to the system using Admin user credentials
    await page.fill('[data-testid="login-username"]', ADMIN_USERNAME);
    await page.fill('[data-testid="login-password"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-submit"]');
    
    // Navigate to workflow configuration page
    await page.goto(`${BASE_URL}${WORKFLOW_CONFIG_URL}`);
    
    // Expected Result: Full access granted
    await expect(page.locator('[data-testid="workflow-config-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).not.toBeVisible();
    
    // Verify all workflow configuration features are accessible
    await expect(page.locator('[data-testid="create-new-workflow-btn"]')).toBeVisible();
    await expect(page.locator('[data-testid="workflow-list"]')).toBeVisible();
    
    // Test edit functionality
    const firstWorkflow = page.locator('[data-testid^="workflow-item-"]').first();
    if (await firstWorkflow.isVisible()) {
      await firstWorkflow.click();
      await expect(page.locator('[data-testid="edit-workflow-btn"]')).toBeVisible();
      await expect(page.locator('[data-testid="activate-workflow-btn"]')).toBeVisible();
      await expect(page.locator('[data-testid="deactivate-workflow-btn"]')).toBeVisible();
    }
  });
});