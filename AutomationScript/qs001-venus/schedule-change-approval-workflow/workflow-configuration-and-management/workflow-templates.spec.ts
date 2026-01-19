import { test, expect } from '@playwright/test';

test.describe('Workflow Template Management', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as workflow administrator
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'workflow.admin@company.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful creation of workflow template', async ({ page }) => {
    // Step 1: Navigate to workflow management page
    await page.click('[data-testid="workflow-management-menu"]');
    await expect(page.locator('[data-testid="workflow-management-page"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Workflow Management');

    // Step 2: Create new workflow template with multiple approval steps and assign approvers
    await page.click('[data-testid="create-new-workflow-button"]');
    await expect(page.locator('[data-testid="workflow-form"]')).toBeVisible();
    
    // Enter workflow name
    await page.fill('[data-testid="workflow-name-input"]', 'Schedule Change Approval - Level 1');
    
    // Enter workflow description
    await page.fill('[data-testid="workflow-description-input"]', 'Standard approval process for schedule changes requiring manager approval');
    
    // Add first approval step
    await page.click('[data-testid="add-approval-step-button"]');
    await page.fill('[data-testid="step-name-input-0"]', 'Manager Approval');
    await page.selectOption('[data-testid="approver-type-select-0"]', 'role');
    await page.selectOption('[data-testid="approver-role-select-0"]', 'Manager');
    
    // Configure escalation rule
    await page.fill('[data-testid="escalation-time-input-0"]', '24');
    await page.selectOption('[data-testid="escalation-approver-select-0"]', 'Senior Manager');
    
    // Add second approval step
    await page.click('[data-testid="add-approval-step-button"]');
    await page.fill('[data-testid="step-name-input-1"]', 'Director Approval');
    await page.selectOption('[data-testid="approver-type-select-1"]', 'user');
    await page.selectOption('[data-testid="approver-user-select-1"]', 'John Director');
    
    // Save and activate workflow
    await page.click('[data-testid="save-activate-workflow-button"]');
    
    // Verify confirmation message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow template saved successfully');
    
    // Step 3: Verify the workflow appears in the list of templates
    await expect(page.locator('[data-testid="workflow-templates-list"]')).toBeVisible();
    const workflowRow = page.locator('[data-testid="workflow-row"]', { hasText: 'Schedule Change Approval - Level 1' });
    await expect(workflowRow).toBeVisible();
    await expect(workflowRow).toContainText('Manager Approval');
    await expect(workflowRow).toContainText('Director Approval');
  });

  test('Verify validation prevents saving invalid workflow', async ({ page }) => {
    // Navigate to workflow management page
    await page.click('[data-testid="workflow-management-menu"]');
    await expect(page.locator('[data-testid="workflow-management-page"]')).toBeVisible();
    
    // Step 1: Attempt to save workflow template with missing approver assignments
    await page.click('[data-testid="create-new-workflow-button"]');
    await page.fill('[data-testid="workflow-name-input"]', 'Incomplete Workflow Test');
    
    // Add approval step without assigning approver
    await page.click('[data-testid="add-approval-step-button"]');
    await page.fill('[data-testid="step-name-input-0"]', 'Manager Review');
    
    // Attempt to save without approver assignment
    await page.click('[data-testid="save-activate-workflow-button"]');
    
    // Verify validation error is displayed
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Approver assignment is required');
    await expect(page.locator('[data-testid="approver-field-error-0"]')).toHaveClass(/error|invalid/);
    
    // Step 2: Correct approver assignments and save again
    await page.selectOption('[data-testid="approver-type-select-0"]', 'role');
    await page.selectOption('[data-testid="approver-role-select-0"]', 'Manager');
    
    // Save with valid approver assignment
    await page.click('[data-testid="save-activate-workflow-button"]');
    
    // Verify successful save
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow template saved successfully');
    
    // Verify workflow appears in list
    const workflowRow = page.locator('[data-testid="workflow-row"]', { hasText: 'Incomplete Workflow Test' });
    await expect(workflowRow).toBeVisible();
  });

  test('Ensure editing and deleting workflows works correctly', async ({ page }) => {
    // Navigate to workflow management page
    await page.click('[data-testid="workflow-management-menu"]');
    await expect(page.locator('[data-testid="workflow-management-page"]')).toBeVisible();
    
    // Step 1: Select existing workflow template to edit
    const workflowToEdit = page.locator('[data-testid="workflow-row"]', { hasText: 'Test Workflow for Edit' });
    await workflowToEdit.locator('[data-testid="edit-workflow-button"]').click();
    
    // Verify workflow details are loaded for editing
    await expect(page.locator('[data-testid="workflow-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="workflow-name-input"]')).toHaveValue('Test Workflow for Edit');
    await expect(page.locator('[data-testid="step-name-input-0"]')).toBeVisible();
    
    // Step 2: Modify approval steps and save changes
    // Change first approval step approver from Manager to Senior Manager
    await page.selectOption('[data-testid="approver-role-select-0"]', 'Senior Manager');
    
    // Add new third approval step
    await page.click('[data-testid="add-approval-step-button"]');
    await page.fill('[data-testid="step-name-input-2"]', 'Final Review');
    await page.selectOption('[data-testid="approver-type-select-2"]', 'user');
    await page.selectOption('[data-testid="approver-user-select-2"]', 'VP Operations');
    
    // Save changes
    await page.click('[data-testid="save-changes-button"]');
    
    // Verify changes are saved
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow updated successfully');
    
    // Verify changes are reflected in workflow list
    const updatedWorkflow = page.locator('[data-testid="workflow-row"]', { hasText: 'Test Workflow for Edit' });
    await expect(updatedWorkflow).toBeVisible();
    await expect(updatedWorkflow).toContainText('Senior Manager');
    await expect(updatedWorkflow).toContainText('Final Review');
    
    // Step 3: Delete a workflow template
    const workflowToDelete = page.locator('[data-testid="workflow-row"]', { hasText: 'Obsolete Workflow Template' });
    await workflowToDelete.locator('[data-testid="delete-workflow-button"]').click();
    
    // Verify confirmation prompt appears
    await expect(page.locator('[data-testid="delete-confirmation-dialog"]')).toBeVisible();
    await expect(page.locator('[data-testid="delete-confirmation-dialog"]')).toContainText('Are you sure you want to delete this workflow?');
    
    // Cancel deletion
    await page.click('[data-testid="cancel-delete-button"]');
    await expect(page.locator('[data-testid="delete-confirmation-dialog"]')).not.toBeVisible();
    
    // Verify workflow still exists
    await expect(workflowToDelete).toBeVisible();
    
    // Delete workflow again and confirm
    await workflowToDelete.locator('[data-testid="delete-workflow-button"]').click();
    await expect(page.locator('[data-testid="delete-confirmation-dialog"]')).toBeVisible();
    await page.click('[data-testid="confirm-delete-button"]');
    
    // Verify workflow is removed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow deleted successfully');
    await expect(page.locator('[data-testid="workflow-row"]', { hasText: 'Obsolete Workflow Template' })).not.toBeVisible();
  });
});