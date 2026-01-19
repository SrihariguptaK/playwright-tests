import { test, expect } from '@playwright/test';

test.describe('Approval Workflow Configuration', () => {
  const ADMIN_EMAIL = 'admin@company.com';
  const ADMIN_PASSWORD = 'AdminPass123!';
  const NON_ADMIN_EMAIL = 'user@company.com';
  const NON_ADMIN_PASSWORD = 'UserPass123!';
  const BASE_URL = 'http://localhost:3000';

  test('Create and activate a new approval workflow (happy-path)', async ({ page }) => {
    // Navigate to the admin portal login page and enter valid administrator credentials
    await page.goto(`${BASE_URL}/admin/login`);
    await page.fill('input[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('input[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('button[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*admin\/dashboard/);

    // Locate and click on the workflow configuration section in the navigation menu
    await page.click('a[data-testid="workflow-config-nav"]');
    await expect(page.locator('h1')).toContainText('Workflow Configuration');

    // Click on 'Create New Workflow' button
    await page.click('button[data-testid="create-workflow-button"]');
    await expect(page.locator('[data-testid="workflow-form"]')).toBeVisible();

    // Enter workflow name as 'Multi-Level Schedule Approval' and description as 'Three-stage approval process for schedule changes'
    await page.fill('input[data-testid="workflow-name-input"]', 'Multi-Level Schedule Approval');
    await page.fill('textarea[data-testid="workflow-description-input"]', 'Three-stage approval process for schedule changes');

    // Add first approval stage named 'Manager Review' and assign approver by role 'Department Manager'
    await page.click('button[data-testid="add-stage-button"]');
    await page.fill('input[data-testid="stage-name-input-0"]', 'Manager Review');
    await page.selectOption('select[data-testid="approver-type-select-0"]', 'role');
    await page.selectOption('select[data-testid="approver-value-select-0"]', 'Department Manager');

    // Add second approval stage named 'HR Review' and assign approver by department 'Human Resources'
    await page.click('button[data-testid="add-stage-button"]');
    await page.fill('input[data-testid="stage-name-input-1"]', 'HR Review');
    await page.selectOption('select[data-testid="approver-type-select-1"]', 'department');
    await page.selectOption('select[data-testid="approver-value-select-1"]', 'Human Resources');

    // Add third approval stage named 'Executive Approval' and assign specific individual approver 'John Smith - VP Operations'
    await page.click('button[data-testid="add-stage-button"]');
    await page.fill('input[data-testid="stage-name-input-2"]', 'Executive Approval');
    await page.selectOption('select[data-testid="approver-type-select-2"]', 'individual');
    await page.selectOption('select[data-testid="approver-value-select-2"]', 'John Smith - VP Operations');

    // Click 'Save Workflow' button
    await page.click('button[data-testid="save-workflow-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow saved successfully');

    // Locate the newly created workflow in the list and click 'Activate' button
    const workflowRow = page.locator('[data-testid="workflow-row"]', { hasText: 'Multi-Level Schedule Approval' });
    await expect(workflowRow).toBeVisible();
    await workflowRow.locator('button[data-testid="activate-button"]').click();

    // Click 'Confirm' on the activation dialog
    await page.click('button[data-testid="confirm-activation-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow activated successfully');
    await expect(workflowRow.locator('[data-testid="workflow-status"]')).toContainText('Active');

    // Submit a new schedule change request that should trigger this workflow
    await page.goto(`${BASE_URL}/schedule-changes/new`);
    await page.fill('input[data-testid="change-reason-input"]', 'Testing new workflow');
    await page.selectOption('select[data-testid="change-type-select"]', 'shift-swap');
    await page.click('button[data-testid="submit-request-button"]');
    await expect(page.locator('[data-testid="workflow-applied-message"]')).toContainText('Multi-Level Schedule Approval');
  });

  test('Prevent invalid workflow configurations (error-case)', async ({ page }) => {
    // Navigate to workflow configuration page and click 'Create New Workflow' button
    await page.goto(`${BASE_URL}/admin/login`);
    await page.fill('input[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('input[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('button[data-testid="login-button"]');
    await page.click('a[data-testid="workflow-config-nav"]');
    await page.click('button[data-testid="create-workflow-button"]');

    // Enter workflow name as 'Incomplete Workflow Test' and description
    await page.fill('input[data-testid="workflow-name-input"]', 'Incomplete Workflow Test');
    await page.fill('textarea[data-testid="workflow-description-input"]', 'Testing validation for incomplete workflows');

    // Add first approval stage named 'Initial Review' but leave the approver assignment field empty
    await page.click('button[data-testid="add-stage-button"]');
    await page.fill('input[data-testid="stage-name-input-0"]', 'Initial Review');

    // Add second approval stage named 'Final Review' but leave the approver assignment field empty
    await page.click('button[data-testid="add-stage-button"]');
    await page.fill('input[data-testid="stage-name-input-1"]', 'Final Review');

    // Click 'Save Workflow' button without assigning any approvers
    await page.click('button[data-testid="save-workflow-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Approver must be assigned for all stages');
    await expect(page.locator('[data-testid="error-stage-0"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-stage-1"]')).toBeVisible();

    // Verify that the workflow does not appear in the workflow list
    await page.goto(`${BASE_URL}/admin/workflows`);
    await expect(page.locator('[data-testid="workflow-row"]', { hasText: 'Incomplete Workflow Test' })).not.toBeVisible();

    // Return to the workflow form and assign approver by role 'Team Lead' to the first approval stage
    await page.click('button[data-testid="create-workflow-button"]');
    await page.fill('input[data-testid="workflow-name-input"]', 'Incomplete Workflow Test');
    await page.fill('textarea[data-testid="workflow-description-input"]', 'Testing validation for incomplete workflows');
    await page.click('button[data-testid="add-stage-button"]');
    await page.fill('input[data-testid="stage-name-input-0"]', 'Initial Review');
    await page.selectOption('select[data-testid="approver-type-select-0"]', 'role');
    await page.selectOption('select[data-testid="approver-value-select-0"]', 'Team Lead');

    // Assign approver by department 'Finance' to the second approval stage
    await page.click('button[data-testid="add-stage-button"]');
    await page.fill('input[data-testid="stage-name-input-1"]', 'Final Review');
    await page.selectOption('select[data-testid="approver-type-select-1"]', 'department');
    await page.selectOption('select[data-testid="approver-value-select-1"]', 'Finance');

    // Click 'Save Workflow' button with all required approvers assigned
    await page.click('button[data-testid="save-workflow-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow saved successfully');
    await expect(page.locator('[data-testid="workflow-row"]', { hasText: 'Incomplete Workflow Test' })).toBeVisible();
  });

  test('Restrict workflow configuration access to administrators (error-case)', async ({ page }) => {
    // Navigate to the application login page using non-admin user credentials
    await page.goto(`${BASE_URL}/login`);

    // Enter valid non-admin user credentials and click 'Login'
    await page.fill('input[data-testid="email-input"]', NON_ADMIN_EMAIL);
    await page.fill('input[data-testid="password-input"]', NON_ADMIN_PASSWORD);
    await page.click('button[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Attempt to navigate directly to the workflow configuration page URL
    await page.goto(`${BASE_URL}/admin/workflows`);
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');
    await expect(page.locator('[data-testid="error-message"]')).toContainText('You do not have permission to access this page');

    // Verify that workflow configuration menu option is not visible in the navigation menu
    await page.goto(`${BASE_URL}/dashboard`);
    await expect(page.locator('a[data-testid="workflow-config-nav"]')).not.toBeVisible();

    // Log out from the non-admin user account
    await page.click('button[data-testid="user-menu-button"]');
    await page.click('button[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Enter valid administrator credentials and click 'Login'
    await page.fill('input[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('input[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('button[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*admin\/dashboard/);

    // Locate workflow configuration option in the navigation menu
    await expect(page.locator('a[data-testid="workflow-config-nav"]')).toBeVisible();

    // Click on workflow configuration menu option
    await page.click('a[data-testid="workflow-config-nav"]');
    await expect(page).toHaveURL(/.*admin\/workflows/);
    await expect(page.locator('h1')).toContainText('Workflow Configuration');

    // Verify all workflow management features are available: create new workflow, edit existing workflow, delete workflow, and activate/deactivate workflow
    await expect(page.locator('button[data-testid="create-workflow-button"]')).toBeVisible();
    const workflowRow = page.locator('[data-testid="workflow-row"]').first();
    if (await workflowRow.isVisible()) {
      await expect(workflowRow.locator('button[data-testid="edit-button"]')).toBeVisible();
      await expect(workflowRow.locator('button[data-testid="delete-button"]')).toBeVisible();
      const activateButton = workflowRow.locator('button[data-testid="activate-button"]');
      const deactivateButton = workflowRow.locator('button[data-testid="deactivate-button"]');
      const hasActivateOrDeactivate = await activateButton.isVisible() || await deactivateButton.isVisible();
      expect(hasActivateOrDeactivate).toBeTruthy();
    }
  });
});