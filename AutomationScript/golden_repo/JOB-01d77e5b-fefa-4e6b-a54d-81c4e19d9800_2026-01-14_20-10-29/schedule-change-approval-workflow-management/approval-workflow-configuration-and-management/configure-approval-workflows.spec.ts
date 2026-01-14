import { test, expect } from '@playwright/test';

test.describe('Configure Approval Workflows - Story 2', () => {
  test.beforeEach(async ({ page }) => {
    // Administrator logs into the system using valid credentials
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate creation of multi-level approval workflow (happy-path)', async ({ page }) => {
    // Administrator navigates to workflow configuration page from the main menu
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="workflow-configuration-link"]');
    
    // Expected Result: Configuration UI is displayed
    await expect(page.locator('[data-testid="workflow-configuration-page"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Workflow Configuration');
    
    // Administrator clicks on 'Create New Workflow' button
    await page.click('[data-testid="create-workflow-button"]');
    await expect(page.locator('[data-testid="workflow-form"]')).toBeVisible();
    
    // Administrator enters workflow name and description
    await page.fill('[data-testid="workflow-name-input"]', 'Schedule Change Approval - Level 3');
    await page.fill('[data-testid="workflow-description-input"]', 'Three-level approval workflow for schedule changes');
    
    // Administrator adds first approval level
    await page.click('[data-testid="add-level-button"]');
    await page.fill('[data-testid="level-name-input-0"]', 'Team Lead Approval');
    
    // Administrator adds second approval level
    await page.click('[data-testid="add-level-button"]');
    await page.fill('[data-testid="level-name-input-1"]', 'Department Manager Approval');
    
    // Administrator adds third approval level
    await page.click('[data-testid="add-level-button"]');
    await page.fill('[data-testid="level-name-input-2"]', 'HR Director Approval');
    
    // Administrator assigns approvers to first level by selecting role 'Team Lead'
    await page.selectOption('[data-testid="approver-role-select-0"]', 'Team Lead');
    
    // Expected Result: Approvers are assigned and validated
    await expect(page.locator('[data-testid="approver-role-select-0"]')).toHaveValue('Team Lead');
    
    // Administrator assigns approvers to second level
    await page.selectOption('[data-testid="approver-role-select-1"]', 'Department Manager');
    await expect(page.locator('[data-testid="approver-role-select-1"]')).toHaveValue('Department Manager');
    
    // Administrator assigns approvers to third level
    await page.selectOption('[data-testid="approver-role-select-2"]', 'HR Director');
    await expect(page.locator('[data-testid="approver-role-select-2"]')).toHaveValue('HR Director');
    
    // Administrator clicks 'Save Workflow' button
    await page.click('[data-testid="save-workflow-button"]');
    
    // Expected Result: Workflow is created and saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow created successfully');
    
    // Administrator verifies the workflow appears in the workflow list
    await expect(page.locator('[data-testid="workflow-list"]')).toContainText('Schedule Change Approval - Level 3');
  });

  test('Verify prevention of circular references in workflow configuration (error-case)', async ({ page }) => {
    // Administrator navigates to workflow configuration page
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="workflow-configuration-link"]');
    await expect(page.locator('[data-testid="workflow-configuration-page"]')).toBeVisible();
    
    // Administrator clicks 'Create New Workflow' button
    await page.click('[data-testid="create-workflow-button"]');
    
    // Administrator enters workflow name
    await page.fill('[data-testid="workflow-name-input"]', 'Circular Test Workflow');
    
    // Administrator creates first approval level 'Level A' and assigns it to route to 'Level B'
    await page.click('[data-testid="add-level-button"]');
    await page.fill('[data-testid="level-name-input-0"]', 'Level A');
    await page.selectOption('[data-testid="approver-role-select-0"]', 'Team Lead');
    await page.selectOption('[data-testid="next-level-select-0"]', 'Level B');
    
    // Administrator creates second approval level 'Level B' and assigns it to route to 'Level C'
    await page.click('[data-testid="add-level-button"]');
    await page.fill('[data-testid="level-name-input-1"]', 'Level B');
    await page.selectOption('[data-testid="approver-role-select-1"]', 'Department Manager');
    await page.selectOption('[data-testid="next-level-select-1"]', 'Level C');
    
    // Administrator creates third approval level 'Level C' and attempts to route it back to 'Level A'
    await page.click('[data-testid="add-level-button"]');
    await page.fill('[data-testid="level-name-input-2"]', 'Level C');
    await page.selectOption('[data-testid="approver-role-select-2"]', 'HR Director');
    await page.selectOption('[data-testid="next-level-select-2"]', 'Level A');
    
    // Administrator clicks 'Save Workflow' button
    await page.click('[data-testid="save-workflow-button"]');
    
    // Expected Result: System displays validation error preventing save
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Circular reference detected');
    await expect(page.locator('[data-testid="workflow-list"]')).not.toContainText('Circular Test Workflow');
    
    // Administrator reviews the error message and modifies Level C routing to 'End Workflow'
    await page.selectOption('[data-testid="next-level-select-2"]', 'End Workflow');
    
    // Administrator clicks 'Save Workflow' button again
    await page.click('[data-testid="save-workflow-button"]');
    
    // Expected Result: Workflow is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow created successfully');
    
    // Administrator verifies the workflow is saved and appears in the workflow list
    await expect(page.locator('[data-testid="workflow-list"]')).toContainText('Circular Test Workflow');
  });

  test('Ensure workflow changes apply without downtime (happy-path)', async ({ page }) => {
    // Administrator navigates to workflow configuration page
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="workflow-configuration-link"]');
    await expect(page.locator('[data-testid="workflow-configuration-page"]')).toBeVisible();
    
    // Administrator selects an existing active workflow from the list
    await page.click('[data-testid="workflow-item-standard-schedule-change"]');
    
    // Administrator clicks 'Edit Workflow' button
    await page.click('[data-testid="edit-workflow-button"]');
    await expect(page.locator('[data-testid="workflow-form"]')).toBeVisible();
    
    // Verify current workflow structure before modification
    const levelCountBefore = await page.locator('[data-testid^="level-name-input-"]').count();
    
    // Administrator modifies the workflow by adding a new approval level 'Senior Manager Review'
    await page.click('[data-testid="add-level-button"]');
    const newLevelIndex = levelCountBefore;
    await page.fill(`[data-testid="level-name-input-${newLevelIndex}"]`, 'Senior Manager Review');
    
    // Administrator assigns 'Senior Manager' role to the new approval level
    await page.selectOption(`[data-testid="approver-role-select-${newLevelIndex}"]`, 'Senior Manager');
    await expect(page.locator(`[data-testid="approver-role-select-${newLevelIndex}"]`)).toHaveValue('Senior Manager');
    
    // Administrator clicks 'Save Changes' button
    const savePromise = page.click('[data-testid="save-changes-button"]');
    
    // Expected Result: Changes are accepted and applied
    await savePromise;
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow updated successfully');
    
    // System applies the workflow changes dynamically
    await page.waitForTimeout(1000);
    
    // Verify that users can continue to submit schedule change requests during workflow modification
    // Open a new context to simulate concurrent user activity
    const context = page.context();
    const userPage = await context.newPage();
    await userPage.goto('/login');
    await userPage.fill('[data-testid="username-input"]', 'user@company.com');
    await userPage.fill('[data-testid="password-input"]', 'UserPass123!');
    await userPage.click('[data-testid="login-button"]');
    
    // Expected Result: No downtime or errors occur
    await userPage.click('[data-testid="schedule-changes-link"]');
    await expect(userPage.locator('[data-testid="schedule-change-page"]')).toBeVisible();
    
    // User submits a schedule change request
    await userPage.click('[data-testid="new-schedule-change-button"]');
    await userPage.fill('[data-testid="change-reason-input"]', 'Personal appointment');
    await userPage.click('[data-testid="submit-request-button"]');
    await expect(userPage.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(userPage.locator('[data-testid="success-message"]')).toContainText('Schedule change request submitted');
    
    // Verify no error indicators
    await expect(userPage.locator('[data-testid="error-message"]')).not.toBeVisible();
    
    // Verify that new schedule change requests use the modified workflow
    await page.bringToFront();
    await page.click('[data-testid="audit-logs-link"]');
    await expect(page.locator('[data-testid="audit-log-list"]')).toContainText('Workflow updated');
    await expect(page.locator('[data-testid="audit-log-list"]')).toContainText('Senior Manager Review');
    
    await userPage.close();
  });
});