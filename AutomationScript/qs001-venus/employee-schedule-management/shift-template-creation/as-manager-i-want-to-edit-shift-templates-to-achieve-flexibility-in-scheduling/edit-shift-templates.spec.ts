import { test, expect } from '@playwright/test';

test.describe('Edit Shift Templates - Story 2', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'Manager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful editing of shift template', async ({ page }) => {
    // Step 1: Navigate to the shift template section
    await page.click('[data-testid="shift-templates-menu"]');
    await expect(page.locator('[data-testid="shift-template-list"]')).toBeVisible();
    
    // Verify shift template list is displayed
    await expect(page.locator('[data-testid="shift-template-item"]').first()).toBeVisible();
    
    // Step 2: Select a template to edit and modify details
    await page.click('[data-testid="shift-template-item"]', { position: { x: 10, y: 10 } });
    await expect(page.locator('[data-testid="edit-template-form"]')).toBeVisible();
    
    // Verify editing interface is displayed
    await expect(page.locator('[data-testid="shift-start-time-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="break-duration-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="role-dropdown"]')).toBeVisible();
    
    // Modify shift start time
    await page.fill('[data-testid="shift-start-time-input"]', '09:00');
    
    // Modify shift end time
    await page.fill('[data-testid="shift-end-time-input"]', '17:00');
    
    // Update break duration
    await page.fill('[data-testid="break-duration-input"]', '60');
    
    // Change the role assigned to the shift
    await page.click('[data-testid="role-dropdown"]');
    await page.click('[data-testid="role-option-supervisor"]');
    
    // Step 3: Save changes
    await page.click('[data-testid="save-template-button"]');
    
    // Verify template is updated successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Template updated successfully');
    
    // Navigate back to the shift template list
    await page.click('[data-testid="back-to-list-button"]');
    await expect(page.locator('[data-testid="shift-template-list"]')).toBeVisible();
    
    // Verify updated template appears in the list
    await expect(page.locator('[data-testid="shift-template-item"]').first()).toBeVisible();
  });

  test('Ensure overlapping shift templates cannot be edited', async ({ page }) => {
    // Step 1: Navigate to the shift template section
    await page.click('[data-testid="shift-templates-menu"]');
    await expect(page.locator('[data-testid="shift-template-list"]')).toBeVisible();
    
    // Verify shift template list is displayed
    await expect(page.locator('[data-testid="shift-template-item"]').first()).toBeVisible();
    
    // Step 2: Select a template that would create an overlap and modify details
    // Identify and select a template that can be edited to create overlap
    await page.click('[data-testid="shift-template-item"]', { position: { x: 10, y: 10 } });
    await expect(page.locator('[data-testid="edit-template-form"]')).toBeVisible();
    
    // Verify editing interface is displayed
    await expect(page.locator('[data-testid="shift-start-time-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time-input"]')).toBeVisible();
    
    // Modify shift start time to create overlap
    await page.fill('[data-testid="shift-start-time-input"]', '10:00');
    
    // Modify shift end time to create overlapping time range
    await page.fill('[data-testid="shift-end-time-input"]', '14:00');
    
    // Step 3: Save changes
    await page.click('[data-testid="save-template-button"]');
    
    // Verify error message is displayed
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('overlapping');
    
    // Verify template is not updated
    await expect(page.locator('[data-testid="edit-template-form"]')).toBeVisible();
    
    // Verify that the template remains in edit mode with invalid changes visible
    await expect(page.locator('[data-testid="shift-start-time-input"]')).toHaveValue('10:00');
    await expect(page.locator('[data-testid="shift-end-time-input"]')).toHaveValue('14:00');
    
    // Navigate back to the shift template list without saving
    await page.click('[data-testid="cancel-button"]');
    await expect(page.locator('[data-testid="shift-template-list"]')).toBeVisible();
  });
});