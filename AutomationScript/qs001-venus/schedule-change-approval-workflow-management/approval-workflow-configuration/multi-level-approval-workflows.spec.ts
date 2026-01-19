import { test, expect } from '@playwright/test';

test.describe('Multi-Level Approval Workflow Configuration', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as administrator
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'admin@example.com');
    await page.fill('[data-testid="password-input"]', 'AdminPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful creation of multi-level approval workflow', async ({ page }) => {
    // Step 1: Administrator navigates to workflow configuration page
    await page.click('[data-testid="workflow-management-menu"]');
    await expect(page.locator('[data-testid="workflow-configuration-page"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Workflow Configuration');

    // Step 2: Administrator creates a new workflow with two approval levels and assigns approvers
    await page.click('[data-testid="create-new-workflow-button"]');
    await expect(page.locator('[data-testid="workflow-form"]')).toBeVisible();
    
    // Enter workflow name and description
    await page.fill('[data-testid="workflow-name-input"]', 'Schedule Change Approval - Level 2');
    await page.fill('[data-testid="workflow-description-input"]', 'Two-level approval for schedule modifications');
    
    // Add first approval level
    await page.click('[data-testid="add-approval-level-button"]');
    await expect(page.locator('[data-testid="approval-level-1"]')).toBeVisible();
    await page.fill('[data-testid="level-name-input-1"]', 'Manager Approval');
    await page.click('[data-testid="approver-dropdown-1"]');
    await page.click('[data-testid="approver-option-john-smith"]');
    await expect(page.locator('[data-testid="selected-approver-1"]')).toContainText('John Smith');
    
    // Add second approval level
    await page.click('[data-testid="add-approval-level-button"]');
    await expect(page.locator('[data-testid="approval-level-2"]')).toBeVisible();
    await page.fill('[data-testid="level-name-input-2"]', 'Director Approval');
    await page.click('[data-testid="approver-dropdown-2"]');
    await page.click('[data-testid="approver-option-jane-doe"]');
    await expect(page.locator('[data-testid="selected-approver-2"]')).toContainText('Jane Doe');
    
    // Verify workflow levels and approvers are displayed correctly
    await expect(page.locator('[data-testid="approval-level-1"]')).toContainText('Manager Approval');
    await expect(page.locator('[data-testid="approval-level-2"]')).toContainText('Director Approval');

    // Step 3: Administrator saves the workflow
    await page.click('[data-testid="save-workflow-button"]');
    
    // System confirms successful workflow creation
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow created successfully');
    await expect(page.locator('[data-testid="workflow-list"]')).toContainText('Schedule Change Approval - Level 2');
  });

  test('Prevent saving workflow with circular dependencies', async ({ page }) => {
    // Step 1: Administrator attempts to create a workflow with circular approval routing
    await page.click('[data-testid="workflow-management-menu"]');
    await page.click('[data-testid="create-new-workflow-button"]');
    
    // Enter workflow name
    await page.fill('[data-testid="workflow-name-input"]', 'Circular Test Workflow');
    
    // Add three approval levels
    await page.click('[data-testid="add-approval-level-button"]');
    await page.fill('[data-testid="level-name-input-1"]', 'Level 1');
    await page.click('[data-testid="approver-dropdown-1"]');
    await page.click('[data-testid="approver-option-user-a"]');
    await page.click('[data-testid="conditional-routing-dropdown-1"]');
    await page.click('[data-testid="routing-option-level-2"]');
    
    await page.click('[data-testid="add-approval-level-button"]');
    await page.fill('[data-testid="level-name-input-2"]', 'Level 2');
    await page.click('[data-testid="approver-dropdown-2"]');
    await page.click('[data-testid="approver-option-user-b"]');
    await page.click('[data-testid="conditional-routing-dropdown-2"]');
    await page.click('[data-testid="routing-option-level-3"]');
    
    await page.click('[data-testid="add-approval-level-button"]');
    await page.fill('[data-testid="level-name-input-3"]', 'Level 3');
    await page.click('[data-testid="approver-dropdown-3"]');
    await page.click('[data-testid="approver-option-user-c"]');
    await page.click('[data-testid="conditional-routing-dropdown-3"]');
    await page.click('[data-testid="routing-option-level-1"]');
    
    // Attempt to save workflow with circular dependency
    await page.click('[data-testid="save-workflow-button"]');
    
    // System detects circular dependency and displays error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Circular dependency detected');
    await expect(page.locator('[data-testid="error-message"]')).toContainText('workflow cannot route back to a previous level');

    // Step 2: Administrator corrects the workflow configuration
    await page.click('[data-testid="conditional-routing-dropdown-3"]');
    await page.click('[data-testid="routing-option-end-workflow"]');
    
    // Save corrected workflow
    await page.click('[data-testid="save-workflow-button"]');
    
    // System allows saving the corrected workflow
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow created successfully');
  });

  test('Validate mandatory approver per level before saving', async ({ page }) => {
    // Step 1: Administrator creates a workflow level without assigning an approver
    await page.click('[data-testid="workflow-management-menu"]');
    await page.click('[data-testid="create-new-workflow-button"]');
    
    // Enter workflow name and description
    await page.fill('[data-testid="workflow-name-input"]', 'Incomplete Workflow Test');
    await page.fill('[data-testid="workflow-description-input"]', 'Testing mandatory approver validation');
    
    // Add approval level without assigning approver
    await page.click('[data-testid="add-approval-level-button"]');
    await page.fill('[data-testid="level-name-input-1"]', 'Manager Review');
    // Intentionally leave approver field empty
    
    // Attempt to save workflow without approver
    await page.click('[data-testid="save-workflow-button"]');
    
    // System displays validation error preventing save
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('At least one approver is required per approval level');
    await expect(page.locator('[data-testid="approver-field-error-1"]')).toBeVisible();
    await expect(page.locator('[data-testid="approver-field-error-1"]')).toContainText('Approver is required');

    // Step 2: Administrator assigns approver and saves workflow
    await page.click('[data-testid="approver-dropdown-1"]');
    await page.click('[data-testid="approver-option-sarah-johnson"]');
    await expect(page.locator('[data-testid="selected-approver-1"]')).toContainText('Sarah Johnson');
    
    // Save workflow with approver assigned
    await page.click('[data-testid="save-workflow-button"]');
    
    // Workflow is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow created successfully');
    await expect(page.locator('[data-testid="workflow-list"]')).toContainText('Incomplete Workflow Test');
  });
});