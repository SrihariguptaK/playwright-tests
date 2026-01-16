import { test, expect } from '@playwright/test';

test.describe('Shift Template Management', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to shift template management page
    await page.goto('/shift-templates');
    // Wait for page to load
    await page.waitForLoadState('networkidle');
  });

  test('Validate successful creation of a shift template with valid times', async ({ page }) => {
    // Action: Navigate to shift template creation page
    await page.click('[data-testid="create-template-button"]');
    
    // Expected Result: Shift template form is displayed
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();
    
    // Action: Enter valid start time, end time, and break periods
    await page.fill('[data-testid="start-time-input"]', '09:00 AM');
    await page.fill('[data-testid="end-time-input"]', '05:00 PM');
    await page.fill('[data-testid="break-start-input"]', '12:00 PM');
    await page.fill('[data-testid="break-end-input"]', '01:00 PM');
    
    // Expected Result: Form accepts inputs without validation errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    
    // Action: Submit the form
    await page.click('[data-testid="save-template-button"]');
    
    // Expected Result: Shift template is created and confirmation is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Shift template created successfully');
    
    // Verify template appears in the list
    await expect(page.locator('[data-testid="template-list"]')).toContainText('09:00 AM');
    await expect(page.locator('[data-testid="template-list"]')).toContainText('05:00 PM');
  });

  test('Prevent creation of overlapping shift templates', async ({ page }) => {
    // First, create an existing template (09:00 AM - 05:00 PM)
    await page.click('[data-testid="create-template-button"]');
    await page.fill('[data-testid="start-time-input"]', '09:00 AM');
    await page.fill('[data-testid="end-time-input"]', '05:00 PM');
    await page.fill('[data-testid="break-start-input"]', '12:00 PM');
    await page.fill('[data-testid="break-end-input"]', '01:00 PM');
    await page.click('[data-testid="save-template-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Action: Attempt to create a shift template with times overlapping an existing template
    await page.click('[data-testid="create-template-button"]');
    await page.fill('[data-testid="start-time-input"]', '08:00 AM');
    await page.fill('[data-testid="end-time-input"]', '10:00 AM');
    await page.fill('[data-testid="break-start-input"]', '08:30 AM');
    await page.fill('[data-testid="break-end-input"]', '09:00 AM');
    await page.click('[data-testid="save-template-button"]');
    
    // Expected Result: System displays error message preventing creation
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('overlapping');
    
    // Action: Adjust times to non-overlapping values
    await page.fill('[data-testid="start-time-input"]', '06:00 AM');
    await page.fill('[data-testid="end-time-input"]', '08:00 AM');
    await page.fill('[data-testid="break-start-input"]', '07:00 AM');
    await page.fill('[data-testid="break-end-input"]', '07:30 AM');
    
    // Expected Result: Form accepts inputs without errors
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
    
    // Action: Submit the form
    await page.click('[data-testid="save-template-button"]');
    
    // Expected Result: Shift template is created successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Shift template created successfully');
  });

  test('Edit and delete existing shift templates', async ({ page }) => {
    // First, create a template to edit and delete
    await page.click('[data-testid="create-template-button"]');
    await page.fill('[data-testid="start-time-input"]', '09:00 AM');
    await page.fill('[data-testid="end-time-input"]', '05:00 PM');
    await page.fill('[data-testid="break-start-input"]', '12:00 PM');
    await page.fill('[data-testid="break-end-input"]', '01:00 PM');
    await page.click('[data-testid="save-template-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Action: Select an existing shift template from the list
    await page.click('[data-testid="template-list-item"]:first-child [data-testid="edit-button"]');
    
    // Expected Result: Template details are displayed for editing
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="start-time-input"]')).toHaveValue('09:00 AM');
    await expect(page.locator('[data-testid="end-time-input"]')).toHaveValue('05:00 PM');
    
    // Action: Modify template details and save changes
    await page.fill('[data-testid="end-time-input"]', '06:00 PM');
    await page.click('[data-testid="save-template-button"]');
    
    // Expected Result: Changes are saved and confirmation is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('updated successfully');
    await expect(page.locator('[data-testid="template-list"]')).toContainText('06:00 PM');
    
    // Action: Delete the shift template
    await page.click('[data-testid="template-list-item"]:first-child [data-testid="delete-button"]');
    
    // Expected Result: System prompts for confirmation
    await expect(page.locator('[data-testid="confirmation-dialog"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-dialog"]')).toContainText('Are you sure');
    
    // Confirm deletion
    await page.click('[data-testid="confirm-delete-button"]');
    
    // Expected Result: Template is deleted upon confirmation
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('deleted successfully');
    
    // Verify template is removed from the list
    const templateCount = await page.locator('[data-testid="template-list-item"]').count();
    expect(templateCount).toBe(0);
  });
});