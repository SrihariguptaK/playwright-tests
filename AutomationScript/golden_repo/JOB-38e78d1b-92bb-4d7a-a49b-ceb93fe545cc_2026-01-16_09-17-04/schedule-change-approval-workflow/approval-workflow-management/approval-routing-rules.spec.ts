import { test, expect } from '@playwright/test';

test.describe('Approval Routing Rules Management', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page and authenticate as System Administrator
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'admin@system.com');
    await page.fill('[data-testid="password-input"]', 'AdminPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate creation and saving of routing rules (happy-path)', async ({ page }) => {
    // Action: Log in as System Administrator
    // Expected Result: Routing rules management page is accessible
    await page.click('[data-testid="routing-rules-menu"]');
    await expect(page.locator('[data-testid="routing-rules-page"]')).toBeVisible();
    await expect(page).toHaveURL(/.*routing-rules/);

    // Action: Create a new routing rule with valid conditions and approvers
    await page.click('[data-testid="create-new-rule-button"]');
    await expect(page.locator('[data-testid="rule-creation-form"]')).toBeVisible();

    await page.fill('[data-testid="rule-name-input"]', 'Engineering Department Routing');
    await page.selectOption('[data-testid="condition-field-select"]', 'Department');
    await page.selectOption('[data-testid="condition-operator-select"]', 'equals');
    await page.fill('[data-testid="condition-value-input"]', 'Engineering');
    await page.selectOption('[data-testid="approver-select"]', 'John Smith');

    // Expected Result: Rule is saved successfully with confirmation
    await page.click('[data-testid="save-rule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Rule saved successfully');

    // Action: Verify rule appears in the active rules list
    // Expected Result: New rule is listed and active
    await page.click('[data-testid="active-rules-tab"]');
    const ruleRow = page.locator('[data-testid="rule-row"]', { hasText: 'Engineering Department Routing' });
    await expect(ruleRow).toBeVisible();
    await expect(ruleRow.locator('[data-testid="rule-status"]')).toContainText('Active');
  });

  test('Verify validation prevents conflicting routing rules (error-case)', async ({ page }) => {
    // Navigate to routing rules management page
    await page.click('[data-testid="routing-rules-menu"]');
    await expect(page.locator('[data-testid="routing-rules-page"]')).toBeVisible();

    // Action: Attempt to create a routing rule that conflicts with an existing active rule
    await page.click('[data-testid="create-new-rule-button"]');
    await expect(page.locator('[data-testid="rule-creation-form"]')).toBeVisible();

    await page.fill('[data-testid="rule-name-input"]', 'Conflicting Engineering Rule');
    await page.selectOption('[data-testid="condition-field-select"]', 'Department');
    await page.selectOption('[data-testid="condition-operator-select"]', 'equals');
    await page.fill('[data-testid="condition-value-input"]', 'Engineering');
    await page.selectOption('[data-testid="approver-select"]', 'Jane Doe');

    // Expected Result: System rejects the rule with descriptive error message
    await page.click('[data-testid="save-rule-button"]');
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('conflicts with an existing active rule');

    // Verify the rule is not saved and form remains open with entered data
    await expect(page.locator('[data-testid="rule-creation-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="rule-name-input"]')).toHaveValue('Conflicting Engineering Rule');

    // Action: Modify the rule to resolve conflicts and save
    await page.click('[data-testid="add-condition-button"]');
    await page.selectOption('[data-testid="condition-field-select-2"]', 'Request Type');
    await page.selectOption('[data-testid="condition-operator-select-2"]', 'equals');
    await page.fill('[data-testid="condition-value-input-2"]', 'Shift Swap');

    // Expected Result: Rule is saved successfully
    await page.click('[data-testid="save-rule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Rule saved successfully');

    // Verify the new rule appears in the active rules list without conflicts
    await page.click('[data-testid="active-rules-tab"]');
    const ruleRow = page.locator('[data-testid="rule-row"]', { hasText: 'Conflicting Engineering Rule' });
    await expect(ruleRow).toBeVisible();
    await expect(ruleRow.locator('[data-testid="rule-status"]')).toContainText('Active');
  });

  test('Ensure routing rules apply correctly to sample requests (happy-path)', async ({ page }) => {
    // Navigate to routing rules management page
    await page.click('[data-testid="routing-rules-menu"]');
    await expect(page.locator('[data-testid="routing-rules-page"]')).toBeVisible();

    // Action: Use the test feature to apply routing rules to a sample schedule change request
    await page.click('[data-testid="test-routing-rules-tab"]');
    await expect(page.locator('[data-testid="test-routing-section"]')).toBeVisible();

    await page.click('[data-testid="create-sample-request-button"]');
    await expect(page.locator('[data-testid="sample-request-form"]')).toBeVisible();

    // Enter sample request parameters
    await page.selectOption('[data-testid="sample-department-select"]', 'Engineering');
    await page.selectOption('[data-testid="sample-request-type-select"]', 'Shift Swap');
    await page.selectOption('[data-testid="sample-schedule-type-select"]', 'Full-time');
    await page.selectOption('[data-testid="sample-request-size-select"]', 'Single');

    // Expected Result: System displays the approvers assigned by the rules
    await page.click('[data-testid="test-routing-button"]');
    await expect(page.locator('[data-testid="routing-results"]')).toBeVisible();
    await expect(page.locator('[data-testid="assigned-approvers"]')).toBeVisible();
    const initialApprovers = await page.locator('[data-testid="assigned-approvers"]').textContent();
    expect(initialApprovers).toBeTruthy();

    // Action: Modify sample request parameters and retest
    await page.selectOption('[data-testid="sample-department-select"]', 'Marketing');

    // Expected Result: Routing results update accordingly
    await page.click('[data-testid="test-routing-button"]');
    await expect(page.locator('[data-testid="routing-results"]')).toBeVisible();
    const updatedApprovers = await page.locator('[data-testid="assigned-approvers"]').textContent();
    expect(updatedApprovers).toBeTruthy();
    expect(updatedApprovers).not.toBe(initialApprovers);

    // Verify routing results reflect the parameter change accurately
    await expect(page.locator('[data-testid="routing-results-department"]')).toContainText('Marketing');
  });
});