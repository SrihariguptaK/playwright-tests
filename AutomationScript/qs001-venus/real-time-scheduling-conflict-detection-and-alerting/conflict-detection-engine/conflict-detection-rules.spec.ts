import { test, expect } from '@playwright/test';

test.describe('Story-14: Configurable Conflict Detection Rules', () => {
  
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login if required
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler_user');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate creation and modification of conflict detection rules (happy-path)', async ({ page }) => {
    // Navigate to Settings > Conflict Detection Rules
    await page.click('[data-testid="settings-menu"]');
    await page.click('text=Conflict Detection Rules');
    
    // Expected Result: UI is displayed with existing rules
    await expect(page.locator('[data-testid="conflict-rules-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="rules-list"]')).toBeVisible();
    
    // Review the existing rules displayed in the list
    const existingRulesCount = await page.locator('[data-testid="rule-item"]').count();
    
    // Click 'Create New Rule' or 'Add Rule' button
    await page.click('[data-testid="create-rule-button"]');
    
    // Enter new rule details
    await page.fill('[data-testid="rule-name-input"]', 'Standard Consultation Rule');
    await page.fill('[data-testid="rule-description-input"]', 'Default rule for standard consultations');
    await page.selectOption('[data-testid="appointment-type-select"]', 'Standard Consultation');
    await page.fill('[data-testid="overlap-threshold-input"]', '0');
    await page.selectOption('[data-testid="priority-select"]', 'Medium');
    await page.check('[data-testid="active-checkbox"]');
    
    // Click 'Save' button
    await page.click('[data-testid="save-rule-button"]');
    
    // Expected Result: Rule is saved and visible in list
    await expect(page.locator('text=Standard Consultation Rule')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Rule created successfully');
    
    // Verify the new rule appears in the rules list
    const newRulesCount = await page.locator('[data-testid="rule-item"]').count();
    expect(newRulesCount).toBe(existingRulesCount + 1);
    
    // Locate an existing rule and click 'Edit'
    await page.click('[data-testid="rule-item"]:has-text("Standard Consultation Rule") [data-testid="edit-rule-button"]');
    
    // Modify the rule
    await page.fill('[data-testid="overlap-threshold-input"]', '10');
    const currentDate = new Date().toLocaleDateString();
    await page.fill('[data-testid="rule-description-input"]', `Default rule for standard consultations - Updated on ${currentDate}`);
    
    // Click 'Save Changes' button
    await page.click('[data-testid="save-rule-button"]');
    
    // Expected Result: Changes are persisted and applied
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Rule updated successfully');
    await expect(page.locator('[data-testid="rule-item"]:has-text("Standard Consultation Rule")')).toContainText('10');
    
    // Navigate away and return to verify persistence
    await page.click('[data-testid="dashboard-link"]');
    await page.click('[data-testid="settings-menu"]');
    await page.click('text=Conflict Detection Rules');
    
    // Verify the modified rule displays updated information
    await expect(page.locator('[data-testid="rule-item"]:has-text("Standard Consultation Rule")')).toContainText('10');
    await expect(page.locator('[data-testid="rule-item"]:has-text("Standard Consultation Rule")')).toContainText(`Updated on ${currentDate}`);
  });

  test('Verify rule validation and error handling (error-case)', async ({ page }) => {
    // Navigate to Settings > Conflict Detection Rules configuration page
    await page.click('[data-testid="settings-menu"]');
    await page.click('text=Conflict Detection Rules');
    
    // Click 'Create New Rule' button
    await page.click('[data-testid="create-rule-button"]');
    
    // Enter invalid rule syntax - text instead of numeric value
    await page.fill('[data-testid="overlap-threshold-input"]', 'invalid');
    
    // Click 'Save' button to attempt saving
    await page.click('[data-testid="save-rule-button"]');
    
    // Expected Result: System displays validation error and prevents saving
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Overlap threshold must be a valid number');
    await expect(page.locator('[data-testid="conflict-rules-page"]')).toBeVisible();
    
    // Clear the Overlap Threshold field and leave Rule Name field empty
    await page.fill('[data-testid="overlap-threshold-input"]', '');
    await page.fill('[data-testid="rule-name-input"]', '');
    await page.click('[data-testid="save-rule-button"]');
    
    // Expected Result: Validation error for required fields
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Rule name is required');
    
    // Enter a negative number in Overlap Threshold field
    await page.fill('[data-testid="rule-name-input"]', 'Test Rule');
    await page.fill('[data-testid="overlap-threshold-input"]', '-5');
    await page.click('[data-testid="save-rule-button"]');
    
    // Expected Result: Validation error for negative value
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Overlap threshold cannot be negative');
    
    // Enter an excessively large number
    await page.fill('[data-testid="overlap-threshold-input"]', '999999');
    await page.click('[data-testid="save-rule-button"]');
    
    // Expected Result: Validation error for excessive value
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Overlap threshold exceeds maximum allowed value');
    
    // Correct all validation errors
    await page.fill('[data-testid="rule-name-input"]', 'Test Valid Rule');
    await page.fill('[data-testid="overlap-threshold-input"]', '15');
    await page.selectOption('[data-testid="appointment-type-select"]', { index: 1 });
    await page.selectOption('[data-testid="priority-select"]', 'Medium');
    
    // Click 'Save' button
    await page.click('[data-testid="save-rule-button"]');
    
    // Expected Result: Rule is accepted and saved
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Rule created successfully');
    await expect(page.locator('text=Test Valid Rule')).toBeVisible();
    
    // Attempt to create a duplicate rule with the same name
    await page.click('[data-testid="create-rule-button"]');
    await page.fill('[data-testid="rule-name-input"]', 'Test Valid Rule');
    await page.fill('[data-testid="overlap-threshold-input"]', '20');
    await page.selectOption('[data-testid="appointment-type-select"]', { index: 1 });
    await page.selectOption('[data-testid="priority-select"]', 'Medium');
    await page.click('[data-testid="save-rule-button"]');
    
    // Expected Result: Validation error for duplicate rule name
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('A rule with this name already exists');
    
    // Cancel and verify rules list shows only valid saved rule
    await page.click('[data-testid="cancel-button"]');
    const validRuleCount = await page.locator('[data-testid="rule-item"]:has-text("Test Valid Rule")').count();
    expect(validRuleCount).toBe(1);
  });

  test('Ensure dynamic application of rules during conflict detection (happy-path)', async ({ page }) => {
    // Navigate to Settings > Conflict Detection Rules configuration
    await page.click('[data-testid="settings-menu"]');
    await page.click('text=Conflict Detection Rules');
    
    // Create a new rule allowing specific overlap
    await page.click('[data-testid="create-rule-button"]');
    await page.fill('[data-testid="rule-name-input"]', 'Flexible Meeting Rule');
    await page.selectOption('[data-testid="appointment-type-select"]', 'Team Meeting');
    await page.fill('[data-testid="overlap-threshold-input"]', '20');
    await page.selectOption('[data-testid="priority-select"]', 'Low');
    await page.check('[data-testid="active-checkbox"]');
    
    // Click 'Save' and verify the rule status shows as 'Active'
    await page.click('[data-testid="save-rule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Rule created successfully');
    
    // Expected Result: Rule is active
    await expect(page.locator('[data-testid="rule-item"]:has-text("Flexible Meeting Rule") [data-testid="rule-status"]')).toContainText('Active');
    
    // Navigate to appointment creation page
    await page.click('[data-testid="appointments-menu"]');
    await page.click('[data-testid="create-appointment-button"]');
    
    // Create first appointment
    await page.selectOption('[data-testid="appointment-type-select"]', 'Team Meeting');
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const tomorrowStr = tomorrow.toISOString().split('T')[0];
    await page.fill('[data-testid="appointment-date-input"]', tomorrowStr);
    await page.fill('[data-testid="start-time-input"]', '10:00');
    await page.fill('[data-testid="end-time-input"]', '11:00');
    await page.selectOption('[data-testid="resource-select"]', 'Conference Room C');
    await page.click('[data-testid="save-appointment-button"]');
    
    // Verify first appointment is created
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Appointment created successfully');
    
    // Create second overlapping appointment within allowed threshold (15 minutes overlap)
    await page.click('[data-testid="create-appointment-button"]');
    await page.selectOption('[data-testid="appointment-type-select"]', 'Team Meeting');
    await page.fill('[data-testid="appointment-date-input"]', tomorrowStr);
    await page.fill('[data-testid="start-time-input"]', '10:45');
    await page.fill('[data-testid="end-time-input"]', '11:45');
    await page.selectOption('[data-testid="resource-select"]', 'Conference Room C');
    
    // Click 'Save' on the second appointment
    await page.click('[data-testid="save-appointment-button"]');
    
    // Expected Result: System does not flag conflict (within 20-minute threshold)
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Appointment created successfully');
    await expect(page.locator('[data-testid="conflict-warning"]')).not.toBeVisible();
    
    // Create third overlapping appointment exceeding allowed threshold (30 minutes overlap)
    await page.click('[data-testid="create-appointment-button"]');
    await page.selectOption('[data-testid="appointment-type-select"]', 'Team Meeting');
    await page.fill('[data-testid="appointment-date-input"]', tomorrowStr);
    await page.fill('[data-testid="start-time-input"]', '10:30');
    await page.fill('[data-testid="end-time-input"]', '11:30');
    await page.selectOption('[data-testid="resource-select"]', 'Conference Room C');
    
    // Observe system response when attempting to save
    await page.click('[data-testid="save-appointment-button"]');
    
    // Expected Result: System flags conflict
    await expect(page.locator('[data-testid="conflict-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-details"]')).toContainText('10:00 AM - 11:00 AM');
    await expect(page.locator('[data-testid="conflict-details"]')).toContainText('30 minutes');
    await expect(page.locator('[data-testid="conflict-details"]')).toContainText('20 minutes');
    await expect(page.locator('[data-testid="conflict-details"]')).toContainText('Flexible Meeting Rule');
    
    // Cancel the third appointment creation
    await page.click('[data-testid="cancel-appointment-button"]');
    
    // Verify only the two valid appointments exist in the schedule
    await page.click('[data-testid="appointments-menu"]');
    await page.click('[data-testid="view-schedule-button"]');
    const appointmentCount = await page.locator(`[data-testid="appointment-item"][data-date="${tomorrowStr}"]`).count();
    expect(appointmentCount).toBe(2);
    
    // Verify the appointments are the correct ones
    await expect(page.locator(`[data-testid="appointment-item"]:has-text("10:00")`)).toBeVisible();
    await expect(page.locator(`[data-testid="appointment-item"]:has-text("10:45")`)).toBeVisible();
    await expect(page.locator(`[data-testid="appointment-item"]:has-text("10:30")`)).not.toBeVisible();
  });
});