import { test, expect } from '@playwright/test';

test.describe('Shift Template Management', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Scheduling Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduling.manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful creation of shift template with valid times', async ({ page }) => {
    // Step 1: Navigate to shift template creation page
    await page.click('[data-testid="shift-templates-menu"]');
    await page.click('[data-testid="create-new-template-button"]');
    
    // Expected Result: Shift template form is displayed
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="start-time-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="end-time-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="break-duration-input"]')).toBeVisible();

    // Step 2: Enter valid start time, end time, and break duration
    await page.fill('[data-testid="template-name-input"]', 'Morning Shift');
    await page.fill('[data-testid="start-time-input"]', '09:00');
    await page.selectOption('[data-testid="start-time-period"]', 'AM');
    await page.fill('[data-testid="end-time-input"]', '05:00');
    await page.selectOption('[data-testid="end-time-period"]', 'PM');
    await page.fill('[data-testid="break-duration-input"]', '60');

    // Expected Result: No validation errors shown
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    await expect(page.locator('.error-message')).toHaveCount(0);

    // Step 3: Submit the form
    await page.click('[data-testid="submit-template-button"]');

    // Expected Result: Shift template is created and confirmation displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Shift template created successfully');
    await expect(page.locator('[data-testid="template-list"]')).toContainText('Morning Shift');
  });

  test('Reject creation of shift template with overlapping times', async ({ page }) => {
    // Create an existing template first
    await page.click('[data-testid="shift-templates-menu"]');
    await page.click('[data-testid="create-new-template-button"]');
    await page.fill('[data-testid="template-name-input"]', 'Existing Shift');
    await page.fill('[data-testid="start-time-input"]', '09:00');
    await page.selectOption('[data-testid="start-time-period"]', 'AM');
    await page.fill('[data-testid="end-time-input"]', '05:00');
    await page.selectOption('[data-testid="end-time-period"]', 'PM');
    await page.fill('[data-testid="break-duration-input"]', '60');
    await page.click('[data-testid="submit-template-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Step 1: Navigate to shift template creation page
    await page.click('[data-testid="create-new-template-button"]');
    
    // Expected Result: Shift template form is displayed
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();

    // Step 2: Enter start and end times overlapping an existing template
    await page.fill('[data-testid="template-name-input"]', 'Overlapping Shift');
    await page.fill('[data-testid="start-time-input"]', '08:00');
    await page.selectOption('[data-testid="start-time-period"]', 'AM');
    await page.fill('[data-testid="end-time-input"]', '10:00');
    await page.selectOption('[data-testid="end-time-period"]', 'AM');
    await page.fill('[data-testid="break-duration-input"]', '30');

    // Expected Result: Validation error message displayed
    await page.click('[data-testid="submit-template-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('overlapping');

    // Step 3: Attempt to submit the form
    const submitButton = page.locator('[data-testid="submit-template-button"]');
    
    // Expected Result: Submission blocked until times are corrected
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page).toHaveURL(/.*create/);
    await expect(page.locator('[data-testid="template-list"]')).not.toContainText('Overlapping Shift');
  });

  test('Edit existing shift template successfully', async ({ page }) => {
    // Create a template to edit
    await page.click('[data-testid="shift-templates-menu"]');
    await page.click('[data-testid="create-new-template-button"]');
    await page.fill('[data-testid="template-name-input"]', 'Afternoon Shift');
    await page.fill('[data-testid="start-time-input"]', '01:00');
    await page.selectOption('[data-testid="start-time-period"]', 'PM');
    await page.fill('[data-testid="end-time-input"]', '09:00');
    await page.selectOption('[data-testid="end-time-period"]', 'PM');
    await page.fill('[data-testid="break-duration-input"]', '45');
    await page.click('[data-testid="submit-template-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Step 1: Navigate to shift template list
    await page.click('[data-testid="shift-templates-menu"]');
    
    // Expected Result: List of shift templates displayed
    await expect(page.locator('[data-testid="template-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="template-list"]')).toContainText('Afternoon Shift');

    // Step 2: Select a template and edit details
    await page.click('[data-testid="edit-template-button"]:has-text("Afternoon Shift"), [data-testid="template-row"]:has-text("Afternoon Shift") [data-testid="edit-button"]');
    
    // Expected Result: Edit form displayed with current values
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="template-name-input"]')).toHaveValue('Afternoon Shift');
    await expect(page.locator('[data-testid="start-time-input"]')).toHaveValue('01:00');
    await expect(page.locator('[data-testid="break-duration-input"]')).toHaveValue('45');

    // Step 3: Change times and submit
    await page.fill('[data-testid="start-time-input"]', '02:00');
    await page.selectOption('[data-testid="start-time-period"]', 'PM');
    await page.fill('[data-testid="end-time-input"]', '10:00');
    await page.selectOption('[data-testid="end-time-period"]', 'PM');
    await page.fill('[data-testid="break-duration-input"]', '60');
    await page.click('[data-testid="submit-template-button"], [data-testid="update-template-button"]');

    // Expected Result: Template updated and confirmation shown
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('updated successfully');
    await expect(page.locator('[data-testid="template-list"]')).toContainText('Afternoon Shift');
  });
});