import { test, expect } from '@playwright/test';

test.describe('Approval Workflow Configuration', () => {
  test.beforeEach(async ({ page }) => {
    // Administrator logs into admin portal
    await page.goto('/admin/login');
    await page.fill('[data-testid="username-input"]', 'admin@example.com');
    await page.fill('[data-testid="password-input"]', 'AdminPassword123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*\/admin\/dashboard/);
  });

  test('Validate creation of new approval workflow', async ({ page }) => {
    // Step 1: Administrator navigates to workflow configuration page
    await page.click('[data-testid="admin-menu"]');
    await page.click('text=Approval Workflows');
    await expect(page).toHaveURL(/.*\/admin\/workflows/);
    
    // Expected Result: Page displays existing workflows and create option
    await expect(page.locator('[data-testid="workflows-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="create-workflow-button"]')).toBeVisible();

    // Step 2: Creates new workflow with multiple approval steps and assigns approvers
    await page.click('[data-testid="create-workflow-button"]');
    await page.fill('[data-testid="workflow-name-input"]', 'Department Schedule Change Workflow');
    
    // Add Step 1: Direct Manager
    await page.click('[data-testid="add-approval-step-button"]');
    await page.fill('[data-testid="step-name-input-0"]', 'Direct Manager');
    await page.selectOption('[data-testid="step-type-select-0"]', 'sequential');
    await page.selectOption('[data-testid="approver-type-select-0"]', 'role');
    await page.selectOption('[data-testid="approver-role-select-0"]', 'Direct Manager');
    await page.check('[data-testid="step-required-checkbox-0"]');
    
    // Add Step 2: Department Head
    await page.click('[data-testid="add-approval-step-button"]');
    await page.fill('[data-testid="step-name-input-1"]', 'Department Head');
    await page.selectOption('[data-testid="step-type-select-1"]', 'sequential');
    await page.selectOption('[data-testid="approver-type-select-1"]', 'role');
    await page.selectOption('[data-testid="approver-role-select-1"]', 'Department Head');
    await page.check('[data-testid="step-required-checkbox-1"]');
    
    // Add Step 3: HR Manager
    await page.click('[data-testid="add-approval-step-button"]');
    await page.fill('[data-testid="step-name-input-2"]', 'HR Manager');
    await page.selectOption('[data-testid="step-type-select-2"]', 'sequential');
    await page.selectOption('[data-testid="approver-type-select-2"]', 'role');
    await page.selectOption('[data-testid="approver-role-select-2"]', 'HR Manager');
    await page.check('[data-testid="step-required-checkbox-2"]');
    
    await page.click('[data-testid="save-workflow-button"]');
    
    // Expected Result: Workflow is saved and listed with correct details
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow saved successfully');
    await expect(page.locator('[data-testid="workflows-list"]')).toContainText('Department Schedule Change Workflow');
    
    // Step 3: Validates workflow configuration
    await page.click('[data-testid="workflow-item-Department Schedule Change Workflow"]');
    await page.click('[data-testid="validate-configuration-button"]');
    
    // Expected Result: No validation errors and workflow is active
    await expect(page.locator('[data-testid="validation-status"]')).toContainText('Valid');
    await expect(page.locator('[data-testid="validation-errors"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="workflow-status"]')).toContainText('Active');
  });

  test('Verify prevention of circular workflow configurations', async ({ page }) => {
    // Navigate to workflow configuration page
    await page.click('[data-testid="admin-menu"]');
    await page.click('text=Approval Workflows');
    await expect(page).toHaveURL(/.*\/admin\/workflows/);
    
    // Step 1: Administrator attempts to create a workflow with circular approval steps
    await page.click('[data-testid="create-workflow-button"]');
    await page.fill('[data-testid="workflow-name-input"]', 'Circular Test Workflow');
    
    // Create Step 1 that escalates to Step 2
    await page.click('[data-testid="add-approval-step-button"]');
    await page.fill('[data-testid="step-name-input-0"]', 'Step 1');
    await page.selectOption('[data-testid="approver-type-select-0"]', 'role');
    await page.selectOption('[data-testid="approver-role-select-0"]', 'Manager');
    await page.selectOption('[data-testid="escalation-target-select-0"]', 'step-2');
    
    // Create Step 2 that escalates to Step 3
    await page.click('[data-testid="add-approval-step-button"]');
    await page.fill('[data-testid="step-name-input-1"]', 'Step 2');
    await page.selectOption('[data-testid="approver-type-select-1"]', 'role');
    await page.selectOption('[data-testid="approver-role-select-1"]', 'Director');
    await page.selectOption('[data-testid="escalation-target-select-1"]', 'step-3');
    
    // Create Step 3 that escalates back to Step 1 (circular)
    await page.click('[data-testid="add-approval-step-button"]');
    await page.fill('[data-testid="step-name-input-2"]', 'Step 3');
    await page.selectOption('[data-testid="approver-type-select-2"]', 'role');
    await page.selectOption('[data-testid="approver-role-select-2"]', 'VP');
    await page.selectOption('[data-testid="escalation-target-select-2"]', 'step-1');
    
    await page.click('[data-testid="save-workflow-button"]');
    
    // Expected Result: System rejects configuration with descriptive error
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Circular dependency detected');
    await expect(page.locator('[data-testid="validation-errors"]')).toContainText('workflow contains a circular approval chain');
    
    // Step 2: Administrator modifies workflow to remove circular dependency
    await page.selectOption('[data-testid="escalation-target-select-2"]', 'none');
    await page.click('[data-testid="save-workflow-button"]');
    
    // Expected Result: System accepts configuration
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow saved successfully');
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="validation-status"]')).toContainText('Valid');
  });

  test('Ensure escalation rules are configurable and saved', async ({ page }) => {
    // Navigate to workflow configuration page
    await page.click('[data-testid="admin-menu"]');
    await page.click('text=Approval Workflows');
    await expect(page).toHaveURL(/.*\/admin\/workflows/);
    
    // Step 1: Administrator sets escalation time thresholds for a workflow
    await page.click('[data-testid="create-workflow-button"]');
    await page.fill('[data-testid="workflow-name-input"]', 'Escalation Test Workflow');
    
    // Add Step 1 with 24 hour escalation
    await page.click('[data-testid="add-approval-step-button"]');
    await page.fill('[data-testid="step-name-input-0"]', 'Step 1');
    await page.selectOption('[data-testid="approver-type-select-0"]', 'role');
    await page.selectOption('[data-testid="approver-role-select-0"]', 'Manager');
    await page.click('[data-testid="escalation-rules-section-0"]');
    await page.fill('[data-testid="escalation-time-threshold-0"]', '24');
    await page.selectOption('[data-testid="escalation-time-unit-0"]', 'hours');
    await page.selectOption('[data-testid="escalation-target-select-0"]', 'next-level');
    
    // Add Step 2 with 48 hour escalation
    await page.click('[data-testid="add-approval-step-button"]');
    await page.fill('[data-testid="step-name-input-1"]', 'Step 2');
    await page.selectOption('[data-testid="approver-type-select-1"]', 'role');
    await page.selectOption('[data-testid="approver-role-select-1"]', 'Director');
    await page.click('[data-testid="escalation-rules-section-1"]');
    await page.fill('[data-testid="escalation-time-threshold-1"]', '48');
    await page.selectOption('[data-testid="escalation-time-unit-1"]', 'hours');
    await page.selectOption('[data-testid="escalation-target-select-1"]', 'specific-role');
    await page.selectOption('[data-testid="escalation-role-select-1"]', 'VP');
    
    await page.click('[data-testid="save-workflow-button"]');
    
    // Expected Result: Escalation rules are saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow saved successfully');
    
    // Verify escalation rules are persisted
    await page.click('[data-testid="workflow-item-Escalation Test Workflow"]');
    await expect(page.locator('[data-testid="escalation-time-threshold-0"]')).toHaveValue('24');
    await expect(page.locator('[data-testid="escalation-time-unit-0"]')).toHaveValue('hours');
    await expect(page.locator('[data-testid="escalation-time-threshold-1"]')).toHaveValue('48');
    await expect(page.locator('[data-testid="escalation-time-unit-1"]')).toHaveValue('hours');
    
    // Step 2: Verify escalation rules are applied during approval process
    // Navigate to create schedule change request
    await page.goto('/schedule/requests/new');
    await page.fill('[data-testid="request-title-input"]', 'Test Schedule Change for Escalation');
    await page.selectOption('[data-testid="workflow-select"]', 'Escalation Test Workflow');
    await page.fill('[data-testid="request-description-input"]', 'Testing escalation rules');
    await page.click('[data-testid="submit-request-button"]');
    
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request submitted successfully');
    
    // Get request ID for verification
    const requestId = await page.locator('[data-testid="request-id"]').textContent();
    
    // Navigate to request details to verify escalation configuration
    await page.goto(`/schedule/requests/${requestId}`);
    await expect(page.locator('[data-testid="escalation-threshold-step-1"]')).toContainText('24 hours');
    await expect(page.locator('[data-testid="escalation-threshold-step-2"]')).toContainText('48 hours');
    
    // Expected Result: Escalations trigger as per configured thresholds
    // Note: Actual time-based escalation would require time simulation or waiting
    await expect(page.locator('[data-testid="escalation-rules-active"]')).toContainText('Escalation rules configured');
    await expect(page.locator('[data-testid="workflow-status"]')).toContainText('Pending approval');
  });
});