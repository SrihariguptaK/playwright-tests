import { test, expect } from '@playwright/test';

test.describe('Approval Routing Rules Management', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page and authenticate as System Administrator
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'admin@system.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and dashboard load
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate creation and saving of routing rules (happy-path)', async ({ page }) => {
    // Action: Navigate to Routing Rules Management page
    await page.click('[data-testid="routing-rules-menu"]');
    
    // Expected Result: Routing rules management page is accessible
    await expect(page).toHaveURL(/.*routing-rules/);
    await expect(page.locator('[data-testid="routing-rules-header"]')).toBeVisible();
    
    // Action: Click 'Create New Rule' button to open the rule creation form
    await page.click('[data-testid="create-new-rule-button"]');
    await expect(page.locator('[data-testid="rule-creation-form"]')).toBeVisible();
    
    // Action: Enter rule name, select condition, and assign approver
    await page.fill('[data-testid="rule-name-input"]', 'Engineering Department Routing');
    await page.selectOption('[data-testid="condition-field-select"]', 'Department');
    await page.selectOption('[data-testid="condition-operator-select"]', 'equals');
    await page.fill('[data-testid="condition-value-input"]', 'Engineering');
    await page.selectOption('[data-testid="approver-select"]', 'John Smith');
    
    // Action: Click 'Save' button to submit the new routing rule
    await page.click('[data-testid="save-rule-button"]');
    
    // Expected Result: Rule is saved successfully with confirmation
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Rule saved successfully');
    
    // Action: Navigate to the active rules list view
    await page.click('[data-testid="active-rules-tab"]');
    
    // Expected Result: New rule is listed and active
    await expect(page.locator('[data-testid="active-rules-list"]')).toBeVisible();
    const ruleRow = page.locator('[data-testid="rule-row"]', { hasText: 'Engineering Department Routing' });
    await expect(ruleRow).toBeVisible();
    
    // Action: Verify the rule details by clicking on the rule name
    await ruleRow.click();
    await expect(page.locator('[data-testid="rule-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="rule-name-display"]')).toContainText('Engineering Department Routing');
    await expect(page.locator('[data-testid="rule-condition-display"]')).toContainText('Department equals Engineering');
    await expect(page.locator('[data-testid="rule-approver-display"]')).toContainText('John Smith');
    await expect(page.locator('[data-testid="rule-status-badge"]')).toContainText('Active');
  });

  test('Verify validation prevents conflicting routing rules (error-case)', async ({ page }) => {
    // Action: Navigate to Routing Rules Management page
    await page.click('[data-testid="routing-rules-menu"]');
    await expect(page).toHaveURL(/.*routing-rules/);
    
    // Action: Click 'Create New Rule' button
    await page.click('[data-testid="create-new-rule-button"]');
    await expect(page.locator('[data-testid="rule-creation-form"]')).toBeVisible();
    
    // Action: Enter rule name and configure condition that conflicts with existing rule
    await page.fill('[data-testid="rule-name-input"]', 'Duplicate Engineering Rule');
    await page.selectOption('[data-testid="condition-field-select"]', 'Department');
    await page.selectOption('[data-testid="condition-operator-select"]', 'equals');
    await page.fill('[data-testid="condition-value-input"]', 'Engineering');
    await page.selectOption('[data-testid="approver-select"]', 'Jane Doe');
    
    // Action: Click 'Save' button to attempt saving the conflicting rule
    await page.click('[data-testid="save-rule-button"]');
    
    // Expected Result: System rejects the rule with descriptive error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('conflicts with an existing active rule');
    
    // Action: Verify the rule was not saved by checking the active rules list
    await page.click('[data-testid="cancel-button"]');
    await page.click('[data-testid="active-rules-tab"]');
    const duplicateRule = page.locator('[data-testid="rule-row"]', { hasText: 'Duplicate Engineering Rule' });
    await expect(duplicateRule).not.toBeVisible();
    
    // Action: Modify the rule condition to resolve the conflict
    await page.click('[data-testid="create-new-rule-button"]');
    await page.fill('[data-testid="rule-name-input"]', 'Duplicate Engineering Rule');
    await page.selectOption('[data-testid="condition-field-select"]', 'Department');
    await page.selectOption('[data-testid="condition-operator-select"]', 'equals');
    await page.fill('[data-testid="condition-value-input"]', 'Engineering');
    
    // Add additional condition to resolve conflict
    await page.click('[data-testid="add-condition-button"]');
    await page.selectOption('[data-testid="condition-field-select-2"]', 'Request Type');
    await page.selectOption('[data-testid="condition-operator-select-2"]', 'equals');
    await page.fill('[data-testid="condition-value-input-2"]', 'Shift Swap');
    await page.selectOption('[data-testid="approver-select"]', 'Jane Doe');
    
    // Action: Click 'Save' button to save the modified rule
    await page.click('[data-testid="save-rule-button"]');
    
    // Expected Result: Rule is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Rule saved successfully');
    
    // Action: Verify the modified rule appears in the active rules list
    await page.click('[data-testid="active-rules-tab"]');
    const modifiedRule = page.locator('[data-testid="rule-row"]', { hasText: 'Duplicate Engineering Rule' });
    await expect(modifiedRule).toBeVisible();
  });

  test('Ensure routing rules apply correctly to sample requests (happy-path)', async ({ page }) => {
    // Action: Navigate to Routing Rules Management page
    await page.click('[data-testid="routing-rules-menu"]');
    await expect(page).toHaveURL(/.*routing-rules/);
    
    // Action: Locate the 'Test Routing Rules' section
    await page.click('[data-testid="test-routing-tab"]');
    await expect(page.locator('[data-testid="test-routing-section"]')).toBeVisible();
    
    // Action: Click 'Create Sample Request' button to open the test request form
    await page.click('[data-testid="create-sample-request-button"]');
    await expect(page.locator('[data-testid="sample-request-form"]')).toBeVisible();
    
    // Action: Enter sample request parameters
    await page.selectOption('[data-testid="sample-department-select"]', 'Engineering');
    await page.selectOption('[data-testid="sample-request-type-select"]', 'Shift Swap');
    await page.selectOption('[data-testid="sample-schedule-type-select"]', 'Full-time');
    await page.selectOption('[data-testid="sample-request-size-select"]', 'Single');
    
    // Action: Click 'Test Routing' button to apply routing rules
    await page.click('[data-testid="test-routing-button"]');
    
    // Expected Result: System displays the approvers assigned by the rules
    await expect(page.locator('[data-testid="routing-results-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="assigned-approvers-list"]')).toBeVisible();
    
    // Verify the displayed approvers match the expected routing rule configuration
    const approversList = page.locator('[data-testid="assigned-approvers-list"]');
    await expect(approversList).toContainText('Jane Doe');
    await expect(page.locator('[data-testid="routing-rule-applied"]')).toContainText('Duplicate Engineering Rule');
    
    // Action: Modify sample request parameters to Department='Sales', Request Type='Time Off'
    await page.selectOption('[data-testid="sample-department-select"]', 'Sales');
    await page.selectOption('[data-testid="sample-request-type-select"]', 'Time Off');
    // Keep other fields the same
    
    // Action: Click 'Test Routing' button again to retest with modified parameters
    await page.click('[data-testid="test-routing-button"]');
    
    // Expected Result: Routing results update accordingly based on the modified parameters
    await expect(page.locator('[data-testid="routing-results-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="assigned-approvers-list"]')).toBeVisible();
    
    // Verify routing results updated correctly
    const updatedApproversList = page.locator('[data-testid="assigned-approvers-list"]');
    // Should not contain Jane Doe anymore as the rule doesn't match
    await expect(updatedApproversList).not.toContainText('Jane Doe');
    
    // Verify performance requirement: routing applied within 1 second
    const startTime = Date.now();
    await page.click('[data-testid="test-routing-button"]');
    await expect(page.locator('[data-testid="routing-results-panel"]')).toBeVisible();
    const endTime = Date.now();
    const routingTime = endTime - startTime;
    expect(routingTime).toBeLessThan(1000);
  });
});