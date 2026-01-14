import { test, expect } from '@playwright/test';

test.describe('Workflow Configuration - Approval Workflow Rules', () => {
  const adminCredentials = {
    username: 'admin@company.com',
    password: 'AdminPass123!'
  };

  const nonAdminCredentials = {
    username: 'approver@company.com',
    password: 'ApproverPass123!'
  };

  test.beforeEach(async ({ page }) => {
    // Navigate to base URL before each test
    await page.goto('/');
  });

  test('Validate creation and editing of approval workflow rules', async ({ page }) => {
    // Step 1: Navigate to the system login page and enter valid administrator credentials
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and dashboard load
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="user-profile"]')).toBeVisible();

    // Step 2: Click on 'Workflow Configuration' or 'Approval Workflow Settings' menu item
    await page.click('[data-testid="workflow-configuration-menu"]');
    
    // Expected Result: Page loads with existing rules displayed
    await expect(page).toHaveURL(/.*workflow-configuration/);
    await expect(page.locator('[data-testid="workflow-rules-list"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Workflow Configuration');

    // Step 3: Click on 'Create New Rule' or 'Add Rule' button
    await page.click('[data-testid="create-new-rule-button"]');
    await expect(page.locator('[data-testid="rule-form"]')).toBeVisible();

    // Step 4: Enter rule details
    await page.fill('[data-testid="rule-name-input"]', 'High Priority Schedule Changes');
    await page.selectOption('[data-testid="condition-type-select"]', 'Request Type');
    await page.fill('[data-testid="condition-value-input"]', 'Urgent');
    await page.selectOption('[data-testid="approver-level-select"]', '2-Level Approval');
    await page.fill('[data-testid="approver-roles-input"]', 'Manager, Director');

    // Step 5: Click 'Save' button to save the new workflow rule
    await page.click('[data-testid="save-rule-button"]');
    
    // Expected Result: Rule is saved and confirmation displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Rule saved successfully');

    // Step 6: Verify the newly created rule appears in the workflow rules list
    await expect(page.locator('[data-testid="workflow-rules-list"]')).toContainText('High Priority Schedule Changes');
    const newRule = page.locator('[data-testid="rule-item"]', { hasText: 'High Priority Schedule Changes' });
    await expect(newRule).toBeVisible();

    // Step 7: Select an existing workflow rule from the list by clicking the 'Edit' button
    await newRule.locator('[data-testid="edit-rule-button"]').click();
    await expect(page.locator('[data-testid="rule-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="rule-name-input"]')).toHaveValue('High Priority Schedule Changes');

    // Step 8: Modify the rule by changing the Approver Level and adding 'VP' to Approver Roles
    await page.selectOption('[data-testid="approver-level-select"]', '3-Level Approval');
    await page.fill('[data-testid="approver-roles-input"]', 'Manager, Director, VP');

    // Step 9: Click 'Save Changes' button to update the workflow rule
    await page.click('[data-testid="save-rule-button"]');
    
    // Expected Result: Changes are saved and applied
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Rule updated successfully');

    // Step 10: Verify the edited rule reflects the changes in the workflow rules list
    const updatedRule = page.locator('[data-testid="rule-item"]', { hasText: 'High Priority Schedule Changes' });
    await expect(updatedRule).toContainText('3-Level Approval');
    await expect(updatedRule).toContainText('VP');

    // Step 11: Create a test schedule change request that matches the new rule conditions
    await page.click('[data-testid="schedule-requests-menu"]');
    await page.click('[data-testid="create-request-button"]');
    await page.selectOption('[data-testid="request-type-select"]', 'Urgent');
    await page.fill('[data-testid="request-description"]', 'Test urgent schedule change');
    await page.click('[data-testid="submit-request-button"]');
    
    // Verify request was created and rule applied
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request submitted');
  });

  test('Validate rule conflict detection', async ({ page }) => {
    // Step 1: Navigate to the workflow rule configuration page
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    await page.click('[data-testid="workflow-configuration-menu"]');
    await expect(page).toHaveURL(/.*workflow-configuration/);

    // Step 2: Click 'Create New Rule' button to start creating a new workflow rule
    await page.click('[data-testid="create-new-rule-button"]');
    await expect(page.locator('[data-testid="rule-form"]')).toBeVisible();

    // Step 3: Enter rule details that create a conflict with an existing rule
    await page.fill('[data-testid="rule-name-input"]', 'Conflicting Rule');
    await page.selectOption('[data-testid="condition-type-select"]', 'Request Type');
    await page.fill('[data-testid="condition-value-input"]', 'Urgent');
    await page.selectOption('[data-testid="approver-level-select"]', '1-Level Approval');
    await page.fill('[data-testid="approver-roles-input"]', 'Supervisor');

    // Step 4: Click 'Save' button to attempt saving the conflicting rule
    await page.click('[data-testid="save-rule-button"]');
    
    // Expected Result: System displays validation errors and prevents saving
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('conflict');
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('A rule with the same conditions already exists');

    // Step 5: Verify the conflicting rule is not saved to the database
    await page.click('[data-testid="cancel-button"]');
    await expect(page.locator('[data-testid="workflow-rules-list"]')).not.toContainText('Conflicting Rule');

    // Step 6: Attempt to create a circular dependency rule
    await page.click('[data-testid="create-new-rule-button"]');
    await page.fill('[data-testid="rule-name-input"]', 'Circular Rule A');
    await page.selectOption('[data-testid="condition-type-select"]', 'Approver Group');
    await page.fill('[data-testid="condition-value-input"]', 'Group 1');
    await page.selectOption('[data-testid="route-to-select"]', 'Group 1');
    await page.fill('[data-testid="approver-roles-input"]', 'Manager');

    // Step 7: Click 'Save' button to attempt saving the circular rule
    await page.click('[data-testid="save-rule-button"]');
    
    // Expected Result: System displays validation errors and prevents saving
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('circular dependency');
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Circular routing detected');

    // Step 8: Verify no circular rule is created in the system
    await page.click('[data-testid="cancel-button"]');
    await expect(page.locator('[data-testid="workflow-rules-list"]')).not.toContainText('Circular Rule A');

    // Step 9: Create a valid rule without conflicts or circular dependencies
    await page.click('[data-testid="create-new-rule-button"]');
    await page.fill('[data-testid="rule-name-input"]', 'Valid Non-Urgent Rule');
    await page.selectOption('[data-testid="condition-type-select"]', 'Request Type');
    await page.fill('[data-testid="condition-value-input"]', 'Standard');
    await page.selectOption('[data-testid="approver-level-select"]', '1-Level Approval');
    await page.fill('[data-testid="approver-roles-input"]', 'Manager');
    await page.click('[data-testid="save-rule-button"]');
    
    // Verify valid rule is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Rule saved successfully');
    await expect(page.locator('[data-testid="workflow-rules-list"]')).toContainText('Valid Non-Urgent Rule');
  });

  test('Validate access control for workflow configuration', async ({ page }) => {
    // Step 1: Log into the system using non-administrator credentials
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', nonAdminCredentials.username);
    await page.fill('[data-testid="password-input"]', nonAdminCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="user-profile"]')).toBeVisible();

    // Step 2: Verify that 'Workflow Configuration' menu item is not visible
    await expect(page.locator('[data-testid="workflow-configuration-menu"]')).not.toBeVisible();
    const navigationMenu = page.locator('[data-testid="navigation-menu"]');
    await expect(navigationMenu).not.toContainText('Workflow Configuration');

    // Step 3: Attempt to directly access the workflow configuration page by entering the URL
    await page.goto('/workflow-configuration');
    
    // Expected Result: Access is denied with appropriate error message
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    await expect(page.locator('[data-testid="error-description"]')).toContainText('You do not have permission to access this page');

    // Step 4: Verify the user remains on an error page or is redirected
    await expect(page).toHaveURL(/.*access-denied|.*error|.*dashboard/);
    await expect(page).not.toHaveURL(/.*workflow-configuration/);

    // Step 5: Attempt to access workflow configuration API endpoint directly
    const apiResponse = await page.request.get('/api/workflow-rules');
    expect(apiResponse.status()).toBe(403);
    const responseBody = await apiResponse.json();
    expect(responseBody.error).toContain('Unauthorized');

    // Step 6: Log out the non-administrator user
    await page.click('[data-testid="user-profile"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 7: Log in with valid administrator credentials
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 8: Verify 'Workflow Configuration' menu item is visible and accessible
    await expect(page.locator('[data-testid="workflow-configuration-menu"]')).toBeVisible();
    const adminNavigationMenu = page.locator('[data-testid="navigation-menu"]');
    await expect(adminNavigationMenu).toContainText('Workflow Configuration');

    // Step 9: Click on 'Workflow Configuration' menu item
    await page.click('[data-testid="workflow-configuration-menu"]');
    
    // Step 10: Verify administrator can access and perform all workflow configuration operations
    await expect(page).toHaveURL(/.*workflow-configuration/);
    await expect(page.locator('[data-testid="workflow-rules-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="create-new-rule-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="create-new-rule-button"]')).toBeEnabled();
    
    // Verify administrator can create a rule
    await page.click('[data-testid="create-new-rule-button"]');
    await expect(page.locator('[data-testid="rule-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="save-rule-button"]')).toBeEnabled();
  });
});