import { test, expect } from '@playwright/test';

test.describe('Configure Approval Workflows - Story 2', () => {
  test.beforeEach(async ({ page }) => {
    // Administrator logs into admin portal
    await page.goto('/admin/login');
    await page.fill('[data-testid="username-input"]', 'admin@example.com');
    await page.fill('[data-testid="password-input"]', 'AdminPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*admin\/dashboard/);
  });

  test('Validate creation of multi-stage approval workflow (happy-path)', async ({ page }) => {
    // Step 1: Administrator navigates to workflow configuration page
    await page.click('[data-testid="workflows-menu"]');
    await page.click('[data-testid="workflow-configuration-link"]');
    await expect(page.locator('[data-testid="workflow-configuration-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="existing-workflows-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="create-workflow-button"]')).toBeVisible();

    // Step 2: Administrator clicks 'Create New Workflow' button
    await page.click('[data-testid="create-workflow-button"]');
    await expect(page.locator('[data-testid="workflow-form"]')).toBeVisible();

    // Step 3: Administrator enters workflow name and description
    await page.fill('[data-testid="workflow-name-input"]', 'Multi-Stage Schedule Approval Workflow');
    await page.fill('[data-testid="workflow-description-input"]', 'Three-stage approval workflow for schedule changes');

    // Step 4: Administrator adds first approval stage and assigns approvers by role
    await page.click('[data-testid="add-stage-button"]');
    await page.fill('[data-testid="stage-name-input-0"]', 'Stage 1 - Team Lead Review');
    await page.click('[data-testid="stage-approver-type-0"]');
    await page.click('[data-testid="approver-type-role"]');
    await page.click('[data-testid="stage-approver-select-0"]');
    await page.click('text=Team Lead');
    await expect(page.locator('[data-testid="stage-0"]')).toContainText('Team Lead Review');
    await expect(page.locator('[data-testid="stage-approver-display-0"]')).toContainText('Team Lead');

    // Step 5: Administrator adds second approval stage and assigns approvers by department
    await page.click('[data-testid="add-stage-button"]');
    await page.fill('[data-testid="stage-name-input-1"]', 'Stage 2 - Department Manager Review');
    await page.click('[data-testid="stage-approver-type-1"]');
    await page.click('[data-testid="approver-type-department"]');
    await page.click('[data-testid="stage-approver-select-1"]');
    await page.click('text=Operations Department');
    await expect(page.locator('[data-testid="stage-1"]')).toContainText('Department Manager Review');
    await expect(page.locator('[data-testid="stage-approver-display-1"]')).toContainText('Operations Department');

    // Step 6: Administrator adds third approval stage and assigns specific approvers
    await page.click('[data-testid="add-stage-button"]');
    await page.fill('[data-testid="stage-name-input-2"]', 'Stage 3 - Director Final Approval');
    await page.click('[data-testid="stage-approver-type-2"]');
    await page.click('[data-testid="approver-type-specific"]');
    await page.click('[data-testid="stage-approver-select-2"]');
    await page.click('text=John Director');
    await expect(page.locator('[data-testid="stage-2"]')).toContainText('Director Final Approval');
    await expect(page.locator('[data-testid="stage-approver-display-2"]')).toContainText('John Director');

    // Step 7: Administrator reviews the complete multi-stage workflow configuration
    await expect(page.locator('[data-testid="workflow-stages-container"]')).toContainText('Stage 1 - Team Lead Review');
    await expect(page.locator('[data-testid="workflow-stages-container"]')).toContainText('Stage 2 - Department Manager Review');
    await expect(page.locator('[data-testid="workflow-stages-container"]')).toContainText('Stage 3 - Director Final Approval');
    const stageCount = await page.locator('[data-testid^="stage-"]').count();
    expect(stageCount).toBe(3);

    // Step 8: Administrator clicks 'Save' button to save the workflow
    await page.click('[data-testid="save-workflow-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow saved successfully');

    // Step 9: Administrator navigates to workflow version history
    await page.click('[data-testid="version-history-tab"]');
    await expect(page.locator('[data-testid="version-history-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="version-history-list"]')).toContainText('Multi-Stage Schedule Approval Workflow');
    await expect(page.locator('[data-testid="version-entry-0"]')).toContainText('Version 1');
  });

  test('Verify validation prevents circular dependencies (error-case)', async ({ page }) => {
    // Step 1: Administrator navigates to workflow configuration page and clicks 'Create New Workflow'
    await page.click('[data-testid="workflows-menu"]');
    await page.click('[data-testid="workflow-configuration-link"]');
    await page.click('[data-testid="create-workflow-button"]');

    // Step 2: Administrator enters workflow name 'Test Circular Workflow'
    await page.fill('[data-testid="workflow-name-input"]', 'Test Circular Workflow');
    await page.fill('[data-testid="workflow-description-input"]', 'Testing circular dependency validation');

    // Step 3: Administrator creates Stage A with approver from Role 1
    await page.click('[data-testid="add-stage-button"]');
    await page.fill('[data-testid="stage-name-input-0"]', 'Stage A');
    await page.click('[data-testid="stage-approver-type-0"]');
    await page.click('[data-testid="approver-type-role"]');
    await page.click('[data-testid="stage-approver-select-0"]');
    await page.click('text=Role 1');

    // Step 4: Administrator creates Stage B with approver from Role 2 and sets Stage A as next stage
    await page.click('[data-testid="add-stage-button"]');
    await page.fill('[data-testid="stage-name-input-1"]', 'Stage B');
    await page.click('[data-testid="stage-approver-type-1"]');
    await page.click('[data-testid="approver-type-role"]');
    await page.click('[data-testid="stage-approver-select-1"]');
    await page.click('text=Role 2');
    await page.click('[data-testid="stage-next-stage-select-1"]');
    await page.click('text=Stage A');

    // Step 5: Administrator attempts to configure Stage A to route back to Stage B, creating a circular dependency
    await page.click('[data-testid="stage-next-stage-select-0"]');
    await page.click('text=Stage B');

    // Step 6: Administrator clicks 'Save' button to save the workflow
    await page.click('[data-testid="save-workflow-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Circular dependency detected');
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('workflow cannot have circular stages');

    // Step 7: Administrator removes the circular routing from Stage A
    await page.click('[data-testid="stage-next-stage-select-0"]');
    await page.click('[data-testid="clear-next-stage-0"]');

    // Step 8: Administrator configures Stage A to route to Stage C (new final stage)
    await page.click('[data-testid="add-stage-button"]');
    await page.fill('[data-testid="stage-name-input-2"]', 'Stage C');
    await page.click('[data-testid="stage-approver-type-2"]');
    await page.click('[data-testid="approver-type-role"]');
    await page.click('[data-testid="stage-approver-select-2"]');
    await page.click('text=Role 3');
    await page.click('[data-testid="stage-next-stage-select-0"]');
    await page.click('text=Stage C');

    // Step 9: Administrator clicks 'Save' button again
    await page.click('[data-testid="save-workflow-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow saved successfully');
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
  });

  test('Test escalation rule configuration (happy-path)', async ({ page }) => {
    // Step 1: Administrator navigates to workflow configuration page and selects existing workflow to edit
    await page.click('[data-testid="workflows-menu"]');
    await page.click('[data-testid="workflow-configuration-link"]');
    await expect(page.locator('[data-testid="existing-workflows-list"]')).toBeVisible();
    await page.click('[data-testid="workflow-item-0"]');
    await page.click('[data-testid="edit-workflow-button"]');

    // Step 2: Administrator clicks on 'Escalation Rules' tab or section
    await page.click('[data-testid="escalation-rules-tab"]');
    await expect(page.locator('[data-testid="escalation-rules-section"]')).toBeVisible();

    // Step 3: Administrator clicks 'Add Escalation Rule' button for Stage 1
    await page.click('[data-testid="add-escalation-rule-stage-0"]');
    await expect(page.locator('[data-testid="escalation-rule-form-0-0"]')).toBeVisible();

    // Step 4: Administrator sets escalation timeout to 24 hours for Stage 1
    await page.fill('[data-testid="escalation-timeout-0-0"]', '24');
    await page.click('[data-testid="escalation-timeout-unit-0-0"]');
    await page.click('text=Hours');

    // Step 5: Administrator selects escalation approver as 'Department Manager' role
    await page.click('[data-testid="escalation-approver-select-0-0"]');
    await page.click('text=Department Manager');
    await expect(page.locator('[data-testid="escalation-rule-0-0"]')).toContainText('24 Hours');
    await expect(page.locator('[data-testid="escalation-rule-0-0"]')).toContainText('Department Manager');

    // Step 6: Administrator adds second escalation rule for Stage 1 with 48 hours timeout escalating to 'Director' role
    await page.click('[data-testid="add-escalation-rule-stage-0"]');
    await page.fill('[data-testid="escalation-timeout-0-1"]', '48');
    await page.click('[data-testid="escalation-timeout-unit-0-1"]');
    await page.click('text=Hours');
    await page.click('[data-testid="escalation-approver-select-0-1"]');
    await page.click('text=Director');
    await expect(page.locator('[data-testid="escalation-rule-0-1"]')).toContainText('48 Hours');
    await expect(page.locator('[data-testid="escalation-rule-0-1"]')).toContainText('Director');

    // Step 7: Administrator reviews escalation rules configuration
    const escalationRulesCount = await page.locator('[data-testid^="escalation-rule-0-"]').count();
    expect(escalationRulesCount).toBe(2);
    await expect(page.locator('[data-testid="escalation-rules-section"]')).toContainText('24 Hours');
    await expect(page.locator('[data-testid="escalation-rules-section"]')).toContainText('48 Hours');
    await expect(page.locator('[data-testid="escalation-rules-section"]')).toContainText('Department Manager');
    await expect(page.locator('[data-testid="escalation-rules-section"]')).toContainText('Director');

    // Step 8: Administrator clicks 'Save' button to save the workflow with escalation rules
    await page.click('[data-testid="save-workflow-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow saved successfully');

    // Step 9: Administrator refreshes the workflow details page
    await page.reload();
    await expect(page.locator('[data-testid="workflow-details-page"]')).toBeVisible();

    // Step 10: Administrator checks version history
    await page.click('[data-testid="version-history-tab"]');
    await expect(page.locator('[data-testid="version-history-list"]')).toBeVisible();
    const versionEntries = await page.locator('[data-testid^="version-entry-"]').count();
    expect(versionEntries).toBeGreaterThan(0);
    await expect(page.locator('[data-testid="version-entry-0"]')).toContainText('Escalation rules updated');
  });
});