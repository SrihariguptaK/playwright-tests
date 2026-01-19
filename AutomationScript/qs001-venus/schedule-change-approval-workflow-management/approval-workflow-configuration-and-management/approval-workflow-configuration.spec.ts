import { test, expect } from '@playwright/test';

test.describe('Approval Workflow Configuration', () => {
  const MANAGER_EMAIL = 'manager@company.com';
  const MANAGER_PASSWORD = 'Manager@123';
  const EMPLOYEE_EMAIL = 'employee@company.com';
  const EMPLOYEE_PASSWORD = 'Employee@123';
  const BASE_URL = 'http://localhost:3000';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('Validate creation of multi-level approval workflow', async ({ page }) => {
    // Step 1: Manager navigates to workflow configuration page from the admin portal menu
    await page.fill('[data-testid="email-input"]', MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*admin/);
    
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="workflow-configuration-link"]');
    
    // Expected Result: Workflow configuration UI is displayed
    await expect(page.locator('[data-testid="workflow-configuration-page"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Workflow Configuration');

    // Step 2: Manager clicks 'Create New Workflow' button
    await page.click('[data-testid="create-workflow-button"]');
    await expect(page.locator('[data-testid="workflow-form"]')).toBeVisible();

    // Step 3: Manager enters workflow name and description
    await page.fill('[data-testid="workflow-name-input"]', 'Schedule Change Approval - Level 2');
    await page.fill('[data-testid="workflow-description-input"]', 'Two-level approval for schedule changes');

    // Step 4: Manager adds first approval level
    await page.click('[data-testid="add-level-button"]');
    await expect(page.locator('[data-testid="approval-level-1"]')).toBeVisible();
    await page.selectOption('[data-testid="level-1-approver-select"]', { label: 'Team Lead' });

    // Step 5: Manager adds second approval level
    await page.click('[data-testid="add-level-button"]');
    await expect(page.locator('[data-testid="approval-level-2"]')).toBeVisible();
    await page.selectOption('[data-testid="level-2-approver-select"]', { label: 'Department Manager' });

    // Step 6: Manager clicks 'Save' button to save the workflow configuration
    await page.click('[data-testid="save-workflow-button"]');
    
    // Expected Result: Workflow is saved successfully and visible in list
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow saved successfully');
    await expect(page.locator('[data-testid="workflow-list"]')).toContainText('Schedule Change Approval - Level 2');

    // Step 7: Manager navigates to the audit log section and filters by workflow configuration changes
    await page.click('[data-testid="audit-log-link"]');
    await expect(page.locator('[data-testid="audit-log-page"]')).toBeVisible();
    await page.selectOption('[data-testid="audit-filter-select"]', { label: 'Workflow Configuration' });
    
    // Expected Result: Audit log shows creation with correct details
    const auditEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditEntry).toContainText('Schedule Change Approval - Level 2');
    await expect(auditEntry).toContainText('Created');
    await expect(auditEntry).toContainText(MANAGER_EMAIL);
    await expect(auditEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
  });

  test('Verify rejection of invalid workflow configuration', async ({ page }) => {
    // Login as manager
    await page.fill('[data-testid="email-input"]', MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Step 1: Manager navigates to workflow configuration page and clicks 'Create New Workflow'
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="workflow-configuration-link"]');
    await page.click('[data-testid="create-workflow-button"]');

    // Step 2: Manager enters workflow name 'Invalid Circular Workflow'
    await page.fill('[data-testid="workflow-name-input"]', 'Invalid Circular Workflow');

    // Step 3: Manager creates Level 1 approver as 'Manager A'
    await page.click('[data-testid="add-level-button"]');
    await page.selectOption('[data-testid="level-1-approver-select"]', { label: 'Manager A' });

    // Step 4: Manager creates Level 2 approver as 'Manager B' with escalation back to 'Manager A'
    await page.click('[data-testid="add-level-button"]');
    await page.selectOption('[data-testid="level-2-approver-select"]', { label: 'Manager B' });
    await page.selectOption('[data-testid="level-2-escalation-select"]', { label: 'Manager A' });

    // Step 5: Manager creates Level 3 approver as 'Manager A', creating a circular hierarchy
    await page.click('[data-testid="add-level-button"]');
    await page.selectOption('[data-testid="level-3-approver-select"]', { label: 'Manager A' });

    // Step 6: Manager clicks 'Save' button to attempt saving the workflow
    await page.click('[data-testid="save-workflow-button"]');
    
    // Expected Result: Validation error is displayed preventing save
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Circular approval hierarchy detected');
    await expect(page.locator('[data-testid="workflow-list"]')).not.toContainText('Invalid Circular Workflow');

    // Step 7: Manager removes Level 3 from the workflow configuration
    await page.click('[data-testid="remove-level-3-button"]');
    await expect(page.locator('[data-testid="approval-level-3"]')).not.toBeVisible();

    // Step 8: Manager clicks 'Save' button again to save the corrected workflow
    await page.click('[data-testid="save-workflow-button"]');
    
    // Expected Result: Workflow is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow saved successfully');
    await expect(page.locator('[data-testid="workflow-list"]')).toContainText('Invalid Circular Workflow');
  });

  test('Test role-based access control for workflow configuration', async ({ page }) => {
    // Step 1: Unauthorized user (Employee role) logs into the system with valid credentials
    await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Unauthorized user attempts to navigate to workflow configuration page
    await page.goto(`${BASE_URL}/admin/workflow-configuration`);
    
    // Expected Result: Access is denied with appropriate error message
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    await expect(page.locator('[data-testid="error-description"]')).toContainText('You do not have permission to access this page');
    await expect(page.locator('[data-testid="workflow-configuration-page"]')).not.toBeVisible();

    // Step 3: Unauthorized user logs out of the system
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 4: Authorized manager logs into the admin portal with valid manager credentials
    await page.fill('[data-testid="email-input"]', MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*admin/);

    // Step 5: Authorized manager navigates to workflow configuration page from the admin menu
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="workflow-configuration-link"]');
    
    // Expected Result: Access granted and UI is displayed
    await expect(page.locator('[data-testid="workflow-configuration-page"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Workflow Configuration');

    // Step 6: Manager verifies all workflow configuration features are accessible
    await expect(page.locator('[data-testid="create-workflow-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="create-workflow-button"]')).toBeEnabled();
    
    // Verify edit functionality is accessible
    const workflowRow = page.locator('[data-testid="workflow-row"]').first();
    if (await workflowRow.isVisible()) {
      await expect(workflowRow.locator('[data-testid="edit-workflow-button"]')).toBeVisible();
      await expect(workflowRow.locator('[data-testid="delete-workflow-button"]')).toBeVisible();
    }
    
    await expect(page.locator('[data-testid="workflow-list"]')).toBeVisible();
  });
});