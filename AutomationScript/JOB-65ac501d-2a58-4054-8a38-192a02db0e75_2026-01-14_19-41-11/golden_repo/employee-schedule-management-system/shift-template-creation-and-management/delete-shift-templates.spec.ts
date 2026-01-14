import { test, expect } from '@playwright/test';

test.describe('Delete Shift Templates', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to shift template list page before each test
    await page.goto('/shift-templates');
    await expect(page).toHaveURL(/.*shift-templates/);
  });

  test('Delete unassigned shift template successfully', async ({ page }) => {
    // Step 1: Navigate to shift template list - List displayed
    await expect(page.getByRole('heading', { name: /shift templates/i })).toBeVisible();
    await expect(page.locator('[data-testid="shift-template-list"]')).toBeVisible();

    // Identify an unassigned template
    const unassignedTemplate = page.locator('[data-testid="shift-template-item"]').filter({ hasText: 'Unassigned' }).first();
    await expect(unassignedTemplate).toBeVisible();
    
    // Get the template name for verification
    const templateName = await unassignedTemplate.locator('[data-testid="template-name"]').textContent();

    // Step 2: Select an unassigned template and delete - Confirmation dialog displayed
    await unassignedTemplate.locator('[data-testid="delete-button"]').click();
    
    // Verify confirmation dialog is displayed
    const confirmDialog = page.locator('[data-testid="confirmation-dialog"]');
    await expect(confirmDialog).toBeVisible();
    await expect(confirmDialog.getByText(/are you sure/i)).toBeVisible();

    // Step 3: Confirm deletion - Template deleted and list updated
    await confirmDialog.locator('[data-testid="confirm-button"]').click();
    
    // Wait for deletion to complete
    await expect(confirmDialog).not.toBeVisible();
    
    // Verify template is removed from the list
    await expect(page.locator('[data-testid="shift-template-item"]').filter({ hasText: templateName || '' })).not.toBeVisible();
    
    // Verify success message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/deleted successfully/i);
  });

  test('Prevent deletion of assigned shift template', async ({ page }) => {
    // Step 1: Select a template assigned to schedules - Delete option disabled or warning shown
    const assignedTemplate = page.locator('[data-testid="shift-template-item"]').filter({ hasText: 'Assigned' }).first();
    await expect(assignedTemplate).toBeVisible();
    
    // Get the template name for verification
    const templateName = await assignedTemplate.locator('[data-testid="template-name"]').textContent();
    
    // Check if delete button is disabled
    const deleteButton = assignedTemplate.locator('[data-testid="delete-button"]');
    const isDisabled = await deleteButton.isDisabled();
    
    if (isDisabled) {
      // Verify delete button is disabled
      await expect(deleteButton).toBeDisabled();
    } else {
      // Step 2: Attempt to delete assigned template - Deletion blocked with informative message
      await deleteButton.click();
      
      // Verify error message or warning dialog is displayed
      const errorDialog = page.locator('[data-testid="error-dialog"], [data-testid="warning-dialog"]');
      await expect(errorDialog).toBeVisible();
      await expect(errorDialog.getByText(/cannot delete.*assigned/i)).toBeVisible();
      
      // Close the error message or dialog
      await errorDialog.locator('[data-testid="close-button"], [data-testid="cancel-button"]').click();
      await expect(errorDialog).not.toBeVisible();
    }
    
    // Verify the template still exists in the list
    await expect(page.locator('[data-testid="shift-template-item"]').filter({ hasText: templateName || '' })).toBeVisible();
  });

  test('System requires confirmation before deletion', async ({ page }) => {
    // Navigate to shift template list
    await expect(page.locator('[data-testid="shift-template-list"]')).toBeVisible();
    
    // Select any unassigned template
    const template = page.locator('[data-testid="shift-template-item"]').filter({ hasText: 'Unassigned' }).first();
    await expect(template).toBeVisible();
    
    // Click delete button
    await template.locator('[data-testid="delete-button"]').click();
    
    // Verify confirmation dialog appears
    const confirmDialog = page.locator('[data-testid="confirmation-dialog"]');
    await expect(confirmDialog).toBeVisible();
    await expect(confirmDialog.getByRole('button', { name: /confirm/i })).toBeVisible();
    await expect(confirmDialog.getByRole('button', { name: /cancel/i })).toBeVisible();
    
    // Cancel the deletion
    await confirmDialog.getByRole('button', { name: /cancel/i }).click();
    
    // Verify dialog is closed and template still exists
    await expect(confirmDialog).not.toBeVisible();
    await expect(template).toBeVisible();
  });

  test('System updates the template list immediately after deletion', async ({ page }) => {
    // Get initial count of templates
    const initialCount = await page.locator('[data-testid="shift-template-item"]').count();
    
    // Select an unassigned template
    const templateToDelete = page.locator('[data-testid="shift-template-item"]').filter({ hasText: 'Unassigned' }).first();
    await expect(templateToDelete).toBeVisible();
    
    // Delete the template
    await templateToDelete.locator('[data-testid="delete-button"]').click();
    await page.locator('[data-testid="confirmation-dialog"] [data-testid="confirm-button"]').click();
    
    // Wait for deletion to complete
    await expect(page.locator('[data-testid="confirmation-dialog"]')).not.toBeVisible();
    
    // Verify the list is updated immediately
    const updatedCount = await page.locator('[data-testid="shift-template-item"]').count();
    expect(updatedCount).toBe(initialCount - 1);
    
    // Verify no loading state persists
    await expect(page.locator('[data-testid="loading-spinner"]')).not.toBeVisible();
  });
});