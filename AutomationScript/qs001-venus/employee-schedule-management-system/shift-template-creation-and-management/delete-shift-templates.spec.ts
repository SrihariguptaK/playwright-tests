import { test, expect } from '@playwright/test';

test.describe('Delete Shift Templates - Story 3', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to shift template list page
    await page.goto('/shift-templates');
    // Wait for the page to load
    await page.waitForLoadState('networkidle');
  });

  test('Delete unused shift template successfully', async ({ page }) => {
    // Step 1: Navigate to shift template list - List is displayed with delete options for unused templates
    await expect(page.locator('[data-testid="shift-template-list"]')).toBeVisible();
    
    // Verify delete options are available for unused templates
    const unusedTemplate = page.locator('[data-testid="shift-template-row"]').filter({ hasText: 'Unused' }).first();
    await expect(unusedTemplate).toBeVisible();
    
    const deleteButton = unusedTemplate.locator('[data-testid="delete-template-button"]');
    await expect(deleteButton).toBeEnabled();
    
    // Get the template name for verification after deletion
    const templateName = await unusedTemplate.locator('[data-testid="template-name"]').textContent();
    
    // Step 2: Select delete on an unused template - Confirmation dialog appears
    await deleteButton.click();
    
    const confirmationDialog = page.locator('[data-testid="confirmation-dialog"]');
    await expect(confirmationDialog).toBeVisible();
    await expect(confirmationDialog.locator('text=Are you sure')).toBeVisible();
    
    const confirmButton = confirmationDialog.locator('[data-testid="confirm-delete-button"]');
    await expect(confirmButton).toBeVisible();
    
    // Step 3: Confirm deletion - Template is deleted and removed from list
    await confirmButton.click();
    
    // Wait for confirmation dialog to close
    await expect(confirmationDialog).not.toBeVisible();
    
    // Verify template is removed from the list
    await expect(page.locator('[data-testid="shift-template-row"]').filter({ hasText: templateName || '' })).not.toBeVisible();
    
    // Verify success message is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('text=Template deleted successfully')).toBeVisible();
  });

  test('Prevent deletion of templates assigned to active schedules', async ({ page }) => {
    // Step 1: Attempt to delete a template assigned to active schedule - System displays error and blocks deletion
    
    // Identify a template that is assigned to an active schedule
    const assignedTemplate = page.locator('[data-testid="shift-template-row"]').filter({ hasText: 'In Use' }).first();
    await expect(assignedTemplate).toBeVisible();
    
    // Get the template name for verification
    const templateName = await assignedTemplate.locator('[data-testid="template-name"]').textContent();
    
    // Attempt to delete the template that is assigned to an active schedule
    const deleteButton = assignedTemplate.locator('[data-testid="delete-template-button"]');
    await deleteButton.click();
    
    // System displays error and blocks deletion
    const errorDialog = page.locator('[data-testid="error-dialog"]');
    await expect(errorDialog).toBeVisible();
    
    // Verify error message content
    await expect(errorDialog.locator('text=Cannot delete template')).toBeVisible();
    await expect(errorDialog.locator('text=assigned to active')).toBeVisible();
    
    // Close error dialog
    const closeButton = errorDialog.locator('[data-testid="close-error-button"]');
    await closeButton.click();
    await expect(errorDialog).not.toBeVisible();
    
    // Verify template still exists in the list
    await expect(page.locator('[data-testid="shift-template-row"]').filter({ hasText: templateName || '' })).toBeVisible();
  });
});