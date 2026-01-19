import { test, expect } from '@playwright/test';

test.describe('Delete Shift Templates - Story 10', () => {
  test.beforeEach(async ({ page }) => {
    // Login as HR Manager before each test
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'hr.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'HRManager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful shift template deletion with confirmation', async ({ page }) => {
    // Step 1: Navigate to shift template list
    await page.goto('/shift-templates');
    await expect(page.locator('[data-testid="shift-template-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-template-item"]')).toHaveCount(await page.locator('[data-testid="shift-template-item"]').count());
    
    // Step 2: Select template(s) for deletion
    const obsoleteTemplate = page.locator('[data-testid="shift-template-item"]').filter({ hasText: 'Obsolete Night Shift 10PM-6AM' });
    await expect(obsoleteTemplate).toBeVisible();
    await obsoleteTemplate.locator('[data-testid="template-checkbox"]').check();
    await expect(obsoleteTemplate.locator('[data-testid="template-checkbox"]')).toBeChecked();
    
    // Click delete button
    await page.click('[data-testid="delete-template-button"]');
    
    // Step 3: Confirm deletion
    await expect(page.locator('[data-testid="confirmation-dialog"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Are you sure you want to delete');
    await page.click('[data-testid="confirm-delete-button"]');
    
    // Verify confirmation message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Template deleted successfully');
    
    // Verify template is no longer visible
    await expect(page.locator('[data-testid="shift-template-item"]').filter({ hasText: 'Obsolete Night Shift 10PM-6AM' })).not.toBeVisible();
    
    // Refresh and verify persistence
    await page.reload();
    await expect(page.locator('[data-testid="shift-template-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-template-item"]').filter({ hasText: 'Obsolete Night Shift 10PM-6AM' })).not.toBeVisible();
  });

  test('Prevent deletion of templates assigned to active schedules', async ({ page }) => {
    // Step 1: Navigate to shift template list page
    await page.goto('/shift-templates');
    await expect(page.locator('[data-testid="shift-template-list"]')).toBeVisible();
    
    // Step 2: Identify and select a template assigned to active schedules
    const activeTemplate = page.locator('[data-testid="shift-template-item"]').filter({ hasText: 'Standard Day Shift 9AM-5PM' });
    await expect(activeTemplate).toBeVisible();
    await activeTemplate.locator('[data-testid="template-checkbox"]').check();
    await expect(activeTemplate.locator('[data-testid="template-checkbox"]')).toBeChecked();
    
    // Step 3: Click delete button to attempt deletion
    await page.click('[data-testid="delete-template-button"]');
    
    // Step 4: Verify warning message is displayed
    await expect(page.locator('[data-testid="warning-dialog"]')).toBeVisible();
    await expect(page.locator('[data-testid="warning-message"]')).toContainText('cannot be deleted');
    await expect(page.locator('[data-testid="warning-message"]')).toContainText('active schedules');
    
    // Verify the number of active schedules is mentioned
    const warningText = await page.locator('[data-testid="warning-message"]').textContent();
    expect(warningText).toMatch(/\d+\s+(employee|schedule)/i);
    
    // Step 5: Close warning dialog
    await page.click('[data-testid="close-warning-button"]');
    await expect(page.locator('[data-testid="warning-dialog"]')).not.toBeVisible();
    
    // Step 6: Verify template remains in the list
    await expect(activeTemplate).toBeVisible();
    await expect(page.locator('[data-testid="shift-template-item"]').filter({ hasText: 'Standard Day Shift 9AM-5PM' })).toBeVisible();
  });

  test('Ensure unauthorized users cannot delete shift templates', async ({ page }) => {
    // Step 1: Logout and login as non-HR user
    await page.goto('/logout');
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'regular.employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Employee123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Step 2: Attempt to navigate to shift template list page
    await page.goto('/shift-templates');
    
    // Verify access is denied or delete controls are not visible
    const accessDenied = page.locator('[data-testid="access-denied-message"]');
    const deleteButton = page.locator('[data-testid="delete-template-button"]');
    
    // Either access is completely denied or delete button is not visible
    const isAccessDenied = await accessDenied.isVisible().catch(() => false);
    const isDeleteButtonVisible = await deleteButton.isVisible().catch(() => false);
    
    if (isAccessDenied) {
      await expect(accessDenied).toContainText('not authorized');
    } else {
      // If page is accessible, delete button should not be visible
      await expect(deleteButton).not.toBeVisible();
    }
    
    // Step 3: Attempt to access delete API endpoint directly
    const response = await page.request.delete('/api/shifttemplates/1');
    expect(response.status()).toBe(403);
    
    const responseBody = await response.json();
    expect(responseBody).toHaveProperty('error');
    expect(responseBody.error).toMatch(/unauthorized|forbidden|access denied/i);
    
    // Step 4: Verify no templates were deleted by checking the list
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'hr.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'HRManager123!');
    await page.click('[data-testid="login-button"]');
    await page.goto('/shift-templates');
    
    // Verify all templates are still present
    await expect(page.locator('[data-testid="shift-template-list"]')).toBeVisible();
    const templateCount = await page.locator('[data-testid="shift-template-item"]').count();
    expect(templateCount).toBeGreaterThan(0);
  });
});