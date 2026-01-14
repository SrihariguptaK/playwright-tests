import { test, expect } from '@playwright/test';

test.describe('Shift Template Management', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as HR Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'hr.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful creation of shift template with valid data', async ({ page }) => {
    // Step 1: Navigate to shift template creation page
    await page.click('text=Shift Templates');
    await page.click('text=Create New Template');
    
    // Expected Result: Shift template form is displayed
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();
    
    // Step 2: Enter valid start time, end time, and break details
    await page.fill('[data-testid="template-name-input"]', 'Morning Shift');
    await page.fill('[data-testid="start-time-input"]', '08:00 AM');
    await page.fill('[data-testid="end-time-input"]', '04:00 PM');
    await page.fill('[data-testid="break-duration-input"]', '30');
    await page.fill('[data-testid="break-time-input"]', '12:00 PM');
    
    // Expected Result: Inputs accept data without validation errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    
    // Step 3: Submit the form
    await page.click('[data-testid="save-button"]');
    
    // Expected Result: Shift template is created and confirmation is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Shift template created successfully');
    
    // Verify template appears in the list
    await expect(page.locator('text=Morning Shift')).toBeVisible();
  });

  test('Verify rejection of overlapping shift template creation', async ({ page }) => {
    // Create an existing template first
    await page.click('text=Shift Templates');
    await page.click('text=Create New Template');
    await page.fill('[data-testid="template-name-input"]', 'Existing Shift');
    await page.fill('[data-testid="start-time-input"]', '08:00 AM');
    await page.fill('[data-testid="end-time-input"]', '04:00 PM');
    await page.fill('[data-testid="break-duration-input"]', '30');
    await page.fill('[data-testid="break-time-input"]', '12:00 PM');
    await page.click('[data-testid="save-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Step 1: Navigate to shift template creation page
    await page.click('text=Create New Template');
    
    // Expected Result: Shift template form is displayed
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();
    
    // Step 2: Enter start and end times overlapping with existing template
    await page.fill('[data-testid="template-name-input"]', 'Overlapping Shift');
    await page.fill('[data-testid="start-time-input"]', '10:00 AM');
    await page.fill('[data-testid="end-time-input"]', '06:00 PM');
    await page.fill('[data-testid="break-duration-input"]', '30');
    await page.fill('[data-testid="break-time-input"]', '02:00 PM');
    
    // Expected Result: Validation error message is displayed
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('overlapping');
    
    // Step 3: Attempt to submit the form
    await page.click('[data-testid="save-button"]');
    
    // Expected Result: Submission is blocked with error notification
    await expect(page.locator('[data-testid="error-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-notification"]')).toContainText('Cannot create overlapping shift template');
    
    // Verify template was not created
    await page.click('[data-testid="cancel-button"]');
    await expect(page.locator('text=Overlapping Shift')).not.toBeVisible();
  });

  test('Validate editing and deletion of existing shift templates', async ({ page }) => {
    // Create a template to edit and delete
    await page.click('text=Shift Templates');
    await page.click('text=Create New Template');
    await page.fill('[data-testid="template-name-input"]', 'Morning Shift');
    await page.fill('[data-testid="start-time-input"]', '08:00 AM');
    await page.fill('[data-testid="end-time-input"]', '04:00 PM');
    await page.fill('[data-testid="break-duration-input"]', '30');
    await page.fill('[data-testid="break-time-input"]', '12:00 PM');
    await page.click('[data-testid="save-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Create another template for deletion
    await page.click('text=Create New Template');
    await page.fill('[data-testid="template-name-input"]', 'Evening Shift');
    await page.fill('[data-testid="start-time-input"]', '05:00 PM');
    await page.fill('[data-testid="end-time-input"]', '01:00 AM');
    await page.fill('[data-testid="break-duration-input"]', '30');
    await page.fill('[data-testid="break-time-input"]', '09:00 PM');
    await page.click('[data-testid="save-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Step 1: Navigate to shift template list
    await page.click('text=Shift Templates');
    
    // Expected Result: List of templates is displayed
    await expect(page.locator('[data-testid="shift-template-list"]')).toBeVisible();
    await expect(page.locator('text=Morning Shift')).toBeVisible();
    await expect(page.locator('text=Evening Shift')).toBeVisible();
    
    // Step 2: Select a template and edit details
    await page.locator('[data-testid="template-row"]:has-text("Morning Shift") [data-testid="edit-button"]').click();
    
    // Expected Result: Edit form is displayed with current data
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="template-name-input"]')).toHaveValue('Morning Shift');
    await expect(page.locator('[data-testid="start-time-input"]')).toHaveValue('08:00 AM');
    await expect(page.locator('[data-testid="end-time-input"]')).toHaveValue('04:00 PM');
    
    // Modify end time
    await page.fill('[data-testid="end-time-input"]', '05:00 PM');
    
    // Step 3: Save changes
    await page.click('[data-testid="update-button"]');
    
    // Expected Result: Template is updated and confirmation is shown
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Shift template updated successfully');
    
    // Verify the updated end time is displayed
    await expect(page.locator('[data-testid="template-row"]:has-text("Morning Shift")')).toContainText('05:00 PM');
    
    // Step 4: Delete a template
    await page.locator('[data-testid="template-row"]:has-text("Evening Shift") [data-testid="delete-button"]').click();
    
    // Expected Result: Confirmation prompt is shown
    await expect(page.locator('[data-testid="confirmation-dialog"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-dialog"]')).toContainText('Are you sure you want to delete this shift template?');
    
    // Confirm deletion
    await page.click('[data-testid="confirm-button"]');
    
    // Expected Result: Template is removed upon confirmation
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Shift template deleted successfully');
    await expect(page.locator('text=Evening Shift')).not.toBeVisible();
    
    // Verify Morning Shift still exists
    await expect(page.locator('text=Morning Shift')).toBeVisible();
  });
});