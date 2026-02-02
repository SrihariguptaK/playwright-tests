import { test, expect } from '@playwright/test';

test.describe('Shift Template Creation', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as administrator
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'admin@example.com');
    await page.fill('[data-testid="password-input"]', 'AdminPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful shift template creation', async ({ page }) => {
    // Step 1: Navigate to the shift template creation page
    await page.click('[data-testid="shift-templates-menu"]');
    await page.click('[data-testid="create-new-template-button"]');
    
    // Expected Result: Creation form is displayed
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="template-name-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="start-time-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="end-time-input"]')).toBeVisible();

    // Step 2: Enter valid start and end times
    await page.fill('[data-testid="template-name-input"]', 'Morning Shift');
    await page.fill('[data-testid="start-time-input"]', '08:00');
    await page.fill('[data-testid="end-time-input"]', '16:00');
    await page.fill('[data-testid="break-start-time-input"]', '12:00');
    await page.fill('[data-testid="break-end-time-input"]', '13:00');
    
    // Expected Result: No validation errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    await expect(page.locator('.error-message')).toHaveCount(0);

    // Step 3: Submit the form
    await page.click('[data-testid="submit-template-button"]');
    
    // Expected Result: Template is created successfully with confirmation message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Template created successfully');
    
    // Verify template appears in the list
    await expect(page.locator('[data-testid="template-list"]')).toContainText('Morning Shift');
    await expect(page.locator('[data-testid="template-item"]').filter({ hasText: 'Morning Shift' })).toBeVisible();
  });

  test('Ensure validation for overlapping break times', async ({ page }) => {
    // Step 1: Navigate to the shift template creation page
    await page.click('[data-testid="shift-templates-menu"]');
    await page.click('[data-testid="create-new-template-button"]');
    
    // Expected Result: Creation form is displayed
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="template-name-input"]')).toBeVisible();

    // Step 2: Enter overlapping break times
    await page.fill('[data-testid="template-name-input"]', 'Invalid Break Shift');
    await page.fill('[data-testid="start-time-input"]', '08:00');
    await page.fill('[data-testid="end-time-input"]', '16:00');
    
    // Enter break time that overlaps with shift start time
    await page.fill('[data-testid="break-start-time-input"]', '07:30');
    await page.fill('[data-testid="break-end-time-input"]', '08:30');
    
    // Trigger validation by clicking outside or tabbing
    await page.click('[data-testid="template-name-input"]');
    
    // Expected Result: Validation error is displayed
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText(/break.*overlap|invalid break time/i);

    // Step 3: Attempt to submit the form
    await page.click('[data-testid="submit-template-button"]');
    
    // Expected Result: Submission is blocked with error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/cannot create template|break times overlap|invalid break/i);
    
    // Verify template was not created
    await page.goto('/shift-templates');
    await expect(page.locator('[data-testid="template-list"]')).not.toContainText('Invalid Break Shift');
  });
});