import { test, expect } from '@playwright/test';

test.describe('Workflow Configuration Management', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page and authenticate as administrator
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'AdminPassword123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Create and save new approval workflow configuration', async ({ page }) => {
    // Navigate to workflow configuration page from admin menu
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="workflow-configuration-link"]');
    
    // Verify configuration UI loads successfully
    await expect(page.locator('[data-testid="workflow-config-page"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Workflow Configuration');
    
    // Click 'Add New Approval Level' button
    await page.click('[data-testid="add-approval-level-button"]');
    
    // Enter approval level details
    await page.fill('[data-testid="level-name-input"]', 'Senior Management Approval');
    await page.fill('[data-testid="sequence-input"]', '3');
    await page.selectOption('[data-testid="role-select"]', 'Senior Manager');
    
    // Verify inputs accepted without validation errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    
    // Click 'Add Role' to assign additional roles
    await page.click('[data-testid="add-role-button"]');
    await page.selectOption('[data-testid="additional-role-dropdown"]', 'Director');
    await page.click('[data-testid="confirm-add-role-button"]');
    
    // Verify Director role is added to the approval level
    await expect(page.locator('[data-testid="assigned-roles-list"]')).toContainText('Director');
    
    // Define escalation path
    await page.selectOption('[data-testid="escalation-dropdown"]', 'Executive Level');
    
    // Review the complete workflow configuration in preview panel
    await expect(page.locator('[data-testid="workflow-preview-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="workflow-preview-panel"]')).toContainText('Senior Management Approval');
    await expect(page.locator('[data-testid="workflow-preview-panel"]')).toContainText('Escalates to: Executive Level');
    
    // Click 'Save Configuration' button
    await page.click('[data-testid="save-configuration-button"]');
    
    // Confirm the save action in confirmation dialog
    await expect(page.locator('[data-testid="confirmation-dialog"]')).toBeVisible();
    await page.click('[data-testid="confirm-save-button"]');
    
    // Verify configuration validated, saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Configuration saved successfully');
    
    // Wait for 5 minutes (simulated with shorter wait for testing purposes)
    // In production, this would be 300000ms (5 minutes)
    await page.waitForTimeout(5000);
    
    // Refresh the workflow configuration page
    await page.reload();
    await expect(page.locator('[data-testid="workflow-config-page"]')).toBeVisible();
    
    // Verify configuration is applied
    await expect(page.locator('[data-testid="approval-levels-list"]')).toContainText('Senior Management Approval');
    
    // Navigate to audit logs
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-logs-link"]');
    
    // Search for workflow configuration changes
    await page.fill('[data-testid="audit-search-input"]', 'workflow configuration');
    await page.click('[data-testid="search-button"]');
    
    // Verify audit log entry exists with user and timestamp
    await expect(page.locator('[data-testid="audit-log-results"]')).toContainText('Workflow configuration updated');
    await expect(page.locator('[data-testid="audit-log-results"]')).toContainText('admin@company.com');
    await expect(page.locator('[data-testid="audit-log-timestamp"]')).toBeVisible();
  });

  test('Reject invalid workflow configuration', async ({ page }) => {
    // Navigate to workflow configuration page
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="workflow-configuration-link"]');
    await expect(page.locator('[data-testid="workflow-config-page"]')).toBeVisible();
    
    // Click 'Add New Approval Level' to create a new level
    await page.click('[data-testid="add-approval-level-button"]');
    
    // Enter approval level details
    await page.fill('[data-testid="level-name-input"]', 'Department Head');
    await page.fill('[data-testid="sequence-input"]', '2');
    await page.selectOption('[data-testid="role-select"]', 'Department Manager');
    
    // Configure escalation path to point to non-existent approval level
    await page.selectOption('[data-testid="escalation-dropdown"]', 'Non-Existent Level');
    
    // Create another approval level with same sequence number
    await page.click('[data-testid="add-approval-level-button"]');
    await page.fill('[data-testid="level-name-input"]:nth-of-type(2)', 'Duplicate Sequence Level');
    await page.fill('[data-testid="sequence-input"]:nth-of-type(2)', '2');
    await page.selectOption('[data-testid="role-select"]:nth-of-type(2)', 'Team Lead');
    
    // Click 'Save Configuration' button
    await page.click('[data-testid="save-configuration-button"]');
    
    // Review validation error messages displayed on screen
    await expect(page.locator('[data-testid="validation-errors"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-errors"]')).toContainText('Escalation path points to non-existent approval level');
    await expect(page.locator('[data-testid="validation-errors"]')).toContainText('Duplicate sequence number detected');
    
    // Verify save is blocked
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
    
    // Attempt to save configuration again without corrections
    await page.click('[data-testid="save-configuration-button"]');
    
    // Verify validation errors still displayed
    await expect(page.locator('[data-testid="validation-errors"]')).toBeVisible();
    await expect(page.locator('[data-testid="save-configuration-button"]')).toBeDisabled();
    
    // Verify original workflow configuration remains unchanged
    await page.reload();
    await expect(page.locator('[data-testid="approval-levels-list"]')).not.toContainText('Department Head');
    await expect(page.locator('[data-testid="approval-levels-list"]')).not.toContainText('Duplicate Sequence Level');
    
    // Correct the errors: Change escalation path to valid existing level
    await page.click('[data-testid="add-approval-level-button"]');
    await page.fill('[data-testid="level-name-input"]', 'Department Head');
    await page.fill('[data-testid="sequence-input"]', '4');
    await page.selectOption('[data-testid="role-select"]', 'Department Manager');
    await page.selectOption('[data-testid="escalation-dropdown"]', 'Executive Level');
    
    // Click 'Save Configuration' with corrected data
    await page.click('[data-testid="save-configuration-button"]');
    
    // Verify no validation errors
    await expect(page.locator('[data-testid="validation-errors"]')).not.toBeVisible();
    
    // Confirm save in dialog
    await expect(page.locator('[data-testid="confirmation-dialog"]')).toBeVisible();
    await page.click('[data-testid="confirm-save-button"]');
    
    // Verify configuration saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Configuration saved successfully');
  });
});