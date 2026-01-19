import { test, expect } from '@playwright/test';

test.describe('Approval Workflow Configuration', () => {
  test.beforeEach(async ({ page }) => {
    // Login as administrator before each test
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'AdminPassword123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate creation of multi-step approval workflow', async ({ page }) => {
    // Step 1: Administrator navigates to workflow configuration page from the main menu
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="workflow-configuration-menu-item"]');
    
    // Expected Result: Workflow configuration UI is displayed
    await expect(page.locator('[data-testid="workflow-configuration-page"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Workflow Configuration');

    // Step 2: Administrator clicks 'Create New Workflow' button
    await page.click('[data-testid="create-new-workflow-button"]');
    await expect(page.locator('[data-testid="workflow-form"]')).toBeVisible();

    // Step 3: Administrator enters workflow name and description
    await page.fill('[data-testid="workflow-name-input"]', 'Schedule Change Approval Process');
    await page.fill('[data-testid="workflow-description-input"]', 'Three-tier approval for schedule modifications');

    // Step 4: Administrator creates first workflow step
    await page.click('[data-testid="add-workflow-step-button"]');
    await page.fill('[data-testid="step-order-input-0"]', '1');
    await page.fill('[data-testid="step-name-input-0"]', 'Manager Approval');
    await page.selectOption('[data-testid="step-approver-role-select-0"]', 'Manager');

    // Step 5: Administrator creates second workflow step
    await page.click('[data-testid="add-workflow-step-button"]');
    await page.fill('[data-testid="step-order-input-1"]', '2');
    await page.fill('[data-testid="step-name-input-1"]', 'Department Head Approval');
    await page.selectOption('[data-testid="step-approver-role-select-1"]', 'Department Head');

    // Step 6: Administrator creates third workflow step
    await page.click('[data-testid="add-workflow-step-button"]');
    await page.fill('[data-testid="step-order-input-2"]', '3');
    await page.fill('[data-testid="step-name-input-2"]', 'HR Approval');
    await page.selectOption('[data-testid="step-approver-role-select-2"]', 'HR Manager');

    // Expected Result: Workflow steps are saved and displayed in correct order
    await expect(page.locator('[data-testid="workflow-step-0"]')).toContainText('Manager Approval');
    await expect(page.locator('[data-testid="workflow-step-1"]')).toContainText('Department Head Approval');
    await expect(page.locator('[data-testid="workflow-step-2"]')).toContainText('HR Approval');

    // Step 7: Administrator clicks 'Save and Activate' button
    await page.click('[data-testid="save-activate-workflow-button"]');

    // Expected Result: Workflow is persisted and activated successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow saved and activated successfully');

    // Step 8: Administrator verifies the workflow appears in the active workflows list
    await expect(page.locator('[data-testid="active-workflows-list"]')).toBeVisible();
    const workflowItem = page.locator('[data-testid="workflow-item"]').filter({ hasText: 'Schedule Change Approval Process' });
    await expect(workflowItem).toBeVisible();
    
    // Verify all three steps are visible in the workflow
    await workflowItem.click();
    await expect(page.locator('[data-testid="workflow-step-list"]')).toContainText('Manager Approval');
    await expect(page.locator('[data-testid="workflow-step-list"]')).toContainText('Department Head Approval');
    await expect(page.locator('[data-testid="workflow-step-list"]')).toContainText('HR Approval');
  });

  test('Verify validation prevents duplicate step orders', async ({ page }) => {
    // Step 1: Administrator navigates to workflow configuration page
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="workflow-configuration-menu-item"]');
    await expect(page.locator('[data-testid="workflow-configuration-page"]')).toBeVisible();

    // Step 2: Administrator clicks 'Create New Workflow' button
    await page.click('[data-testid="create-new-workflow-button"]');
    await expect(page.locator('[data-testid="workflow-form"]')).toBeVisible();

    // Step 3: Administrator enters workflow name
    await page.fill('[data-testid="workflow-name-input"]', 'Test Duplicate Steps Workflow');

    // Step 4: Administrator creates first workflow step with order number 1
    await page.click('[data-testid="add-workflow-step-button"]');
    await page.fill('[data-testid="step-order-input-0"]', '1');
    await page.fill('[data-testid="step-name-input-0"]', 'First Approval');
    await page.selectOption('[data-testid="step-approver-role-select-0"]', 'Manager');

    // Step 5: Administrator attempts to create second workflow step with the same order number 1
    await page.click('[data-testid="add-workflow-step-button"]');
    await page.fill('[data-testid="step-order-input-1"]', '1');
    await page.fill('[data-testid="step-name-input-1"]', 'Second Approval');
    await page.selectOption('[data-testid="step-approver-role-select-1"]', 'Department Head');

    // Step 6: Administrator attempts to click 'Save' button
    await page.click('[data-testid="save-activate-workflow-button"]');

    // Expected Result: Validation error is displayed preventing save
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Duplicate step order numbers are not allowed');
    
    // Verify workflow was not saved
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();

    // Step 7: Administrator corrects the second step order number to 2
    await page.fill('[data-testid="step-order-input-1"]', '2');
    
    // Verify error is cleared after correction
    await page.click('[data-testid="save-activate-workflow-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
  });

  test('Ensure only administrators can access workflow configuration', async ({ page }) => {
    // Logout from admin account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 1: Login as non-admin user
    await page.fill('[data-testid="username-input"]', 'user@company.com');
    await page.fill('[data-testid="password-input"]', 'UserPassword123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Non-admin user attempts to navigate to workflow configuration page by entering the URL directly
    await page.goto('/workflow-configuration');

    // Expected Result: Access is denied with appropriate error message
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    await expect(page.locator('[data-testid="error-description"]')).toContainText('You do not have permission to access this page');

    // Step 3: Verify user is redirected to appropriate page
    await page.waitForTimeout(2000);
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 4: Non-admin user attempts to access workflow configuration API endpoint directly
    const response = await page.request.post('/api/approval-workflows', {
      data: {
        name: 'Unauthorized Workflow',
        description: 'This should fail',
        steps: []
      }
    });

    // Expected Result: API request is rejected with 403 Forbidden
    expect(response.status()).toBe(403);
    const responseBody = await response.json();
    expect(responseBody.error).toContain('Unauthorized');

    // Step 5: Log out non-admin user and log in with Administrator credentials
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'AdminPassword123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 6: Administrator navigates to workflow configuration page
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="workflow-configuration-menu-item"]');

    // Expected Result: Administrator can access the page successfully
    await expect(page.locator('[data-testid="workflow-configuration-page"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Workflow Configuration');
    await expect(page.locator('[data-testid="create-new-workflow-button"]')).toBeVisible();
  });
});