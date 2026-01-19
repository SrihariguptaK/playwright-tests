import { test, expect } from '@playwright/test';

test.describe('Workflow Configuration Validation', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to admin dashboard and login
    await page.goto('/admin/dashboard');
    // Assuming user is already authenticated or handle login here
  });

  test('Detect circular dependencies in workflow', async ({ page }) => {
    // Navigate to the workflow configuration module from the admin dashboard
    await page.click('[data-testid="workflow-configuration-menu"]');
    
    // Click 'Create New Workflow' button
    await page.click('[data-testid="create-new-workflow-btn"]');
    
    // Enter workflow name as 'Purchase Approval' and description
    await page.fill('[data-testid="workflow-name-input"]', 'Purchase Approval');
    await page.fill('[data-testid="workflow-description-input"]', 'Multi-level purchase approval process');
    
    // Add approval level 'Level 1' with approver 'Manager A' and set routing to 'Level 2'
    await page.click('[data-testid="add-approval-level-btn"]');
    await page.fill('[data-testid="level-name-input-0"]', 'Level 1');
    await page.fill('[data-testid="approver-input-0"]', 'Manager A');
    await page.selectOption('[data-testid="routing-select-0"]', 'Level 2');
    
    // Add approval level 'Level 2' with approver 'Manager B' and set routing to 'Level 3'
    await page.click('[data-testid="add-approval-level-btn"]');
    await page.fill('[data-testid="level-name-input-1"]', 'Level 2');
    await page.fill('[data-testid="approver-input-1"]', 'Manager B');
    await page.selectOption('[data-testid="routing-select-1"]', 'Level 3');
    
    // Add approval level 'Level 3' with approver 'Director C' and set routing back to 'Level 1' creating a circular loop
    await page.click('[data-testid="add-approval-level-btn"]');
    await page.fill('[data-testid="level-name-input-2"]', 'Level 3');
    await page.fill('[data-testid="approver-input-2"]', 'Director C');
    await page.selectOption('[data-testid="routing-select-2"]', 'Level 1');
    
    // Click 'Save Workflow' button
    await page.click('[data-testid="save-workflow-btn"]');
    
    // Expected Result: System displays circular dependency error
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('circular dependency');
    
    // Verify that the workflow is not saved by checking the workflow list
    await page.click('[data-testid="workflow-list-link"]');
    await expect(page.locator('[data-testid="workflow-item"]').filter({ hasText: 'Purchase Approval' })).not.toBeVisible();
    
    // Navigate back to edit the workflow
    await page.goBack();
    
    // Edit Level 3 routing and change it from 'Level 1' to 'End Workflow'
    await page.selectOption('[data-testid="routing-select-2"]', 'End Workflow');
    
    // Click 'Save Workflow' button again
    await page.click('[data-testid="save-workflow-btn"]');
    
    // Expected Result: Workflow saves successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow saved successfully');
  });

  test('Prevent saving workflow with missing approvers', async ({ page }) => {
    // Navigate to workflow configuration module and click 'Create New Workflow'
    await page.click('[data-testid="workflow-configuration-menu"]');
    await page.click('[data-testid="create-new-workflow-btn"]');
    
    // Enter workflow name as 'Expense Approval' and description
    await page.fill('[data-testid="workflow-name-input"]', 'Expense Approval');
    await page.fill('[data-testid="workflow-description-input"]', 'Employee expense approval workflow');
    
    // Add approval level 'Level 1 - Team Lead' and assign approver 'Sarah Johnson'
    await page.click('[data-testid="add-approval-level-btn"]');
    await page.fill('[data-testid="level-name-input-0"]', 'Level 1 - Team Lead');
    await page.fill('[data-testid="approver-input-0"]', 'Sarah Johnson');
    
    // Add approval level 'Level 2 - Department Manager' but leave the approver field empty
    await page.click('[data-testid="add-approval-level-btn"]');
    await page.fill('[data-testid="level-name-input-1"]', 'Level 2 - Department Manager');
    // Intentionally leave approver field empty
    
    // Add approval level 'Level 3 - Finance Director' and assign approver 'Michael Chen'
    await page.click('[data-testid="add-approval-level-btn"]');
    await page.fill('[data-testid="level-name-input-2"]', 'Level 3 - Finance Director');
    await page.fill('[data-testid="approver-input-2"]', 'Michael Chen');
    
    // Click 'Save Workflow' button
    await page.click('[data-testid="save-workflow-btn"]');
    
    // Expected Result: System displays error and blocks save
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('approver');
    
    // Verify the error indicator is displayed on Level 2 approval section
    await expect(page.locator('[data-testid="approval-level-error-1"]')).toBeVisible();
    
    // Attempt to navigate away from the workflow configuration page
    await page.click('[data-testid="workflow-list-link"]');
    
    // Cancel navigation and return to Level 2 configuration
    const confirmDialog = page.locator('[data-testid="unsaved-changes-dialog"]');
    if (await confirmDialog.isVisible()) {
      await page.click('[data-testid="cancel-navigation-btn"]');
    }
    
    // Assign approver 'David Martinez' to Level 2
    await page.fill('[data-testid="approver-input-1"]', 'David Martinez');
    
    // Click 'Save Workflow' button
    await page.click('[data-testid="save-workflow-btn"]');
    
    // Expected Result: Workflow saves successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow saved successfully');
  });

  test('Validate conditional routing logic', async ({ page }) => {
    // Navigate to workflow configuration module and click 'Create New Workflow'
    await page.click('[data-testid="workflow-configuration-menu"]');
    await page.click('[data-testid="create-new-workflow-btn"]');
    
    // Enter workflow name as 'Invoice Approval' and description
    await page.fill('[data-testid="workflow-name-input"]', 'Invoice Approval');
    await page.fill('[data-testid="workflow-description-input"]', 'Conditional invoice approval based on amount');
    
    // Add approval level 'Level 1 - Supervisor' with approver 'Alice Brown'
    await page.click('[data-testid="add-approval-level-btn"]');
    await page.fill('[data-testid="level-name-input-0"]', 'Level 1 - Supervisor');
    await page.fill('[data-testid="approver-input-0"]', 'Alice Brown');
    
    // Enable conditional routing for Level 1 and enter invalid condition
    await page.click('[data-testid="enable-conditional-routing-0"]');
    await page.fill('[data-testid="conditional-logic-input-0"]', 'IF amount > $5000 THEN goto Level 2 ELSE goto');
    
    // Add approval level 'Level 2 - Finance Manager' with approver 'Robert Lee'
    await page.click('[data-testid="add-approval-level-btn"]');
    await page.fill('[data-testid="level-name-input-1"]', 'Level 2 - Finance Manager');
    await page.fill('[data-testid="approver-input-1"]', 'Robert Lee');
    
    // Click 'Save Workflow' button
    await page.click('[data-testid="save-workflow-btn"]');
    
    // Expected Result: System displays validation error
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    
    // Verify that the error message highlights the specific syntax issue in the conditional logic
    await expect(page.locator('[data-testid="conditional-logic-error-0"]')).toBeVisible();
    await expect(page.locator('[data-testid="conditional-logic-error-0"]')).toContainText('syntax');
    
    // Click 'View Syntax Help' link in the error message
    await page.click('[data-testid="view-syntax-help-link"]');
    await expect(page.locator('[data-testid="syntax-help-modal"]')).toBeVisible();
    await page.click('[data-testid="close-syntax-help-btn"]');
    
    // Correct the conditional routing logic
    await page.fill('[data-testid="conditional-logic-input-0"]', 'IF amount > $5000 THEN goto Level 2 ELSE end workflow');
    
    // Click 'Validate Logic' button to test the condition syntax
    await page.click('[data-testid="validate-logic-btn-0"]');
    await expect(page.locator('[data-testid="validation-success-message-0"]')).toBeVisible();
    
    // Click 'Save Workflow' button
    await page.click('[data-testid="save-workflow-btn"]');
    
    // Expected Result: Workflow saves successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow saved successfully');
  });
});