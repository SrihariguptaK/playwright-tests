import { test, expect } from '@playwright/test';

test.describe('Delete Shift Templates - Story 5', () => {
  test.beforeEach(async ({ page }) => {
    // Login as HR Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'hr.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful deletion of unassigned shift template', async ({ page }) => {
    // Step 1: Navigate to shift template list
    await page.click('[data-testid="shift-templates-menu"]');
    await expect(page).toHaveURL(/.*shift-templates/);
    await expect(page.locator('[data-testid="template-list"]')).toBeVisible();
    
    // Verify template list is displayed
    await expect(page.locator('[data-testid="template-list-item"]').first()).toBeVisible();
    
    // Step 2: Select an unassigned template and choose delete
    const unassignedTemplate = page.locator('[data-testid="template-list-item"]').filter({ hasText: 'Obsolete Evening Shift' });
    await expect(unassignedTemplate).toBeVisible();
    
    await unassignedTemplate.locator('[data-testid="delete-template-button"]').click();
    
    // Expected Result: Confirmation dialog appears
    const confirmationDialog = page.locator('[data-testid="confirmation-dialog"]');
    await expect(confirmationDialog).toBeVisible();
    await expect(confirmationDialog.locator('text=Are you sure you want to delete this template?')).toBeVisible();
    
    // Step 3: Confirm deletion
    await page.click('[data-testid="confirm-delete-button"]');
    
    // Expected Result: Template is deleted and list updates
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Template deleted successfully');
    
    // Verify template is removed from list
    await expect(page.locator('[data-testid="template-list-item"]').filter({ hasText: 'Obsolete Evening Shift' })).not.toBeVisible();
  });

  test('Verify prevention of deletion for assigned shift template', async ({ page }) => {
    // Step 1: Navigate to shift template list and identify assigned template
    await page.click('[data-testid="shift-templates-menu"]');
    await expect(page).toHaveURL(/.*shift-templates/);
    await expect(page.locator('[data-testid="template-list"]')).toBeVisible();
    
    // Select a template assigned to schedules
    const assignedTemplate = page.locator('[data-testid="template-list-item"]').filter({ hasText: 'Day Shift' });
    await expect(assignedTemplate).toBeVisible();
    
    // Verify template shows assignment info
    await expect(assignedTemplate.locator('text=/assigned to.*employees/i')).toBeVisible();
    
    // Expected Result: Delete option is available
    const deleteButton = assignedTemplate.locator('[data-testid="delete-template-button"]');
    await expect(deleteButton).toBeVisible();
    
    // Step 2: Attempt to delete template
    await deleteButton.click();
    
    // Expected Result: System displays error preventing deletion
    const errorDialog = page.locator('[data-testid="error-dialog"]');
    await expect(errorDialog).toBeVisible();
    await expect(errorDialog.locator('text=/cannot delete.*assigned to schedules/i')).toBeVisible();
    
    // Verify error message content
    await expect(errorDialog).toContainText('This template is currently assigned to schedules and cannot be deleted');
    
    // Step 3: Cancel deletion
    await page.click('[data-testid="close-error-button"]');
    
    // Expected Result: Template remains in list
    await expect(errorDialog).not.toBeVisible();
    await expect(assignedTemplate).toBeVisible();
    await expect(page.locator('[data-testid="template-list-item"]').filter({ hasText: 'Day Shift' })).toBeVisible();
  });

  test('System prompts user for confirmation before deletion', async ({ page }) => {
    // Navigate to shift template list
    await page.click('[data-testid="shift-templates-menu"]');
    await expect(page.locator('[data-testid="template-list"]')).toBeVisible();
    
    // Select any unassigned template
    const template = page.locator('[data-testid="template-list-item"]').first();
    await template.locator('[data-testid="delete-template-button"]').click();
    
    // Verify confirmation dialog appears
    const confirmationDialog = page.locator('[data-testid="confirmation-dialog"]');
    await expect(confirmationDialog).toBeVisible();
    await expect(confirmationDialog.locator('[data-testid="confirm-delete-button"]')).toBeVisible();
    await expect(confirmationDialog.locator('[data-testid="cancel-delete-button"]')).toBeVisible();
    
    // Cancel deletion
    await page.click('[data-testid="cancel-delete-button"]');
    await expect(confirmationDialog).not.toBeVisible();
  });

  test('System updates template list immediately after deletion', async ({ page }) => {
    // Navigate to shift template list
    await page.click('[data-testid="shift-templates-menu"]');
    await expect(page.locator('[data-testid="template-list"]')).toBeVisible();
    
    // Count initial templates
    const initialCount = await page.locator('[data-testid="template-list-item"]').count();
    
    // Delete an unassigned template
    const templateToDelete = page.locator('[data-testid="template-list-item"]').filter({ hasText: 'Obsolete Evening Shift' });
    const templateName = await templateToDelete.locator('[data-testid="template-name"]').textContent();
    
    await templateToDelete.locator('[data-testid="delete-template-button"]').click();
    await page.click('[data-testid="confirm-delete-button"]');
    
    // Verify list updates immediately
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Verify count decreased by 1
    const updatedCount = await page.locator('[data-testid="template-list-item"]').count();
    expect(updatedCount).toBe(initialCount - 1);
    
    // Verify deleted template is not in list
    await expect(page.locator('[data-testid="template-list-item"]').filter({ hasText: templateName || '' })).not.toBeVisible();
  });
});