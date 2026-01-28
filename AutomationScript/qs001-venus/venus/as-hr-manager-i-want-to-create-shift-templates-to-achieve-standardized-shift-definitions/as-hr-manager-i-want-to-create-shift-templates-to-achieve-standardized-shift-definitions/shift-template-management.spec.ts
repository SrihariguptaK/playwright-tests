import { test, expect } from '@playwright/test';

test.describe('Shift Template Management', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to shift template management page before each test
    await page.goto('/shift-templates');
    await expect(page).toHaveURL(/.*shift-templates/);
  });

  test('System allows creation of shift templates with all required fields and saves successfully', async ({ page }) => {
    // Click on 'Create New Template' button
    await page.click('[data-testid="create-template-button"]');
    
    // Wait for the form to appear
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();
    
    // Enter shift start time as '09:00 AM'
    await page.fill('[data-testid="shift-start-time"]', '09:00 AM');
    
    // Enter shift end time as '05:00 PM'
    await page.fill('[data-testid="shift-end-time"]', '05:00 PM');
    
    // Enter break duration as '60' minutes
    await page.fill('[data-testid="break-duration"]', '60');
    
    // Select shift type as 'Day Shift' from dropdown
    await page.selectOption('[data-testid="shift-type-dropdown"]', 'Day Shift');
    
    // Click 'Save' button
    await page.click('[data-testid="save-template-button"]');
    
    // Verify the new template appears in the template list
    await expect(page.locator('[data-testid="template-list"]')).toContainText('Day Shift');
    await expect(page.locator('[data-testid="template-list"]')).toContainText('09:00 AM');
    await expect(page.locator('[data-testid="template-list"]')).toContainText('05:00 PM');
  });

  test('System validates and rejects overlapping shift times with descriptive error messages', async ({ page }) => {
    // Click on 'Create New Template' button
    await page.click('[data-testid="create-template-button"]');
    
    // Wait for the form to appear
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();
    
    // Enter shift start time as '08:00 AM'
    await page.fill('[data-testid="shift-start-time"]', '08:00 AM');
    
    // Enter shift end time as '10:00 AM' (overlapping with existing 09:00 AM - 05:00 PM template)
    await page.fill('[data-testid="shift-end-time"]', '10:00 AM');
    
    // Enter break duration as '30' minutes
    await page.fill('[data-testid="break-duration"]', '30');
    
    // Select shift type as 'Morning Shift'
    await page.selectOption('[data-testid="shift-type-dropdown"]', 'Morning Shift');
    
    // Click 'Save' button
    await page.click('[data-testid="save-template-button"]');
    
    // Verify error message is displayed
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/overlap/i);
    
    // Verify template is not saved - check that form is still visible
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();
  });

  test('System supports editing existing templates and maintains version history', async ({ page }) => {
    // Locate the 'Day Shift' template and click 'Edit' button
    const dayShiftRow = page.locator('[data-testid="template-row"]', { hasText: 'Day Shift' });
    await dayShiftRow.locator('[data-testid="edit-template-button"]').click();
    
    // Wait for edit form to appear
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();
    
    // Modify the end time from '05:00 PM' to '06:00 PM'
    await page.fill('[data-testid="shift-end-time"]', '06:00 PM');
    
    // Modify break duration from '60' to '45' minutes
    await page.fill('[data-testid="break-duration"]', '45');
    
    // Click 'Save' button
    await page.click('[data-testid="save-template-button"]');
    
    // Wait for save confirmation
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Navigate to version history for the edited template
    await dayShiftRow.locator('[data-testid="version-history-button"]').click();
    
    // Verify audit trail entry exists
    await expect(page.locator('[data-testid="version-history-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-trail-entry"]')).toContainText('06:00 PM');
    await expect(page.locator('[data-testid="audit-trail-entry"]')).toContainText('45');
  });

  test('System prevents deletion of templates assigned to active schedules and shows warning', async ({ page }) => {
    // Locate the 'Evening Shift' template that is assigned to active schedules
    const eveningShiftRow = page.locator('[data-testid="template-row"]', { hasText: 'Evening Shift' });
    
    // Click the 'Delete' button for the 'Evening Shift' template
    await eveningShiftRow.locator('[data-testid="delete-template-button"]').click();
    
    // Verify the warning dialog appears
    await expect(page.locator('[data-testid="warning-dialog"]')).toBeVisible();
    
    // Verify the warning dialog includes details about active assignments
    await expect(page.locator('[data-testid="warning-dialog"]')).toContainText(/active/i);
    await expect(page.locator('[data-testid="warning-dialog"]')).toContainText(/assigned/i);
    
    // Click 'OK' or 'Close' on the warning dialog
    await page.click('[data-testid="warning-dialog-close"]');
    
    // Verify the template still exists in the list
    await expect(page.locator('[data-testid="template-list"]')).toContainText('Evening Shift');
    await expect(eveningShiftRow).toBeVisible();
  });

  test('System displays confirmation messages upon successful operations', async ({ page }) => {
    // Test 1: Create new template and verify confirmation
    await page.click('[data-testid="create-template-button"]');
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();
    
    // Fill in all required fields: Start time '06:00 AM', End time '02:00 PM', Break '30 mins', Type 'Morning Shift'
    await page.fill('[data-testid="shift-start-time"]', '06:00 AM');
    await page.fill('[data-testid="shift-end-time"]', '02:00 PM');
    await page.fill('[data-testid="break-duration"]', '30');
    await page.selectOption('[data-testid="shift-type-dropdown"]', 'Morning Shift');
    
    // Click 'Save' button
    await page.click('[data-testid="save-template-button"]');
    
    // Verify the confirmation message is clearly visible and styled appropriately
    const successMessage = page.locator('[data-testid="success-message"]');
    await expect(successMessage).toBeVisible();
    await expect(successMessage).toHaveClass(/success|green/);
    await expect(successMessage).toContainText(/success|created/i);
    
    // Test 2: Edit existing template and verify confirmation
    const morningShiftRow = page.locator('[data-testid="template-row"]', { hasText: 'Morning Shift' });
    await morningShiftRow.locator('[data-testid="edit-template-button"]').click();
    await page.fill('[data-testid="break-duration"]', '45');
    await page.click('[data-testid="save-template-button"]');
    
    // Verify edit confirmation message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/updated|saved/i);
    
    // Test 3: Delete unassigned template and verify confirmation
    const unassignedRow = page.locator('[data-testid="template-row"]').first();
    await unassignedRow.locator('[data-testid="delete-template-button"]').click();
    
    // Confirm deletion in dialog if it appears
    const confirmDialog = page.locator('[data-testid="confirm-dialog"]');
    if (await confirmDialog.isVisible()) {
      await page.click('[data-testid="confirm-delete-button"]');
    }
    
    // Verify delete confirmation message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/deleted|removed/i);
    
    // Test 4: Attempt invalid operation and verify error message
    await page.click('[data-testid="create-template-button"]');
    await page.fill('[data-testid="shift-start-time"]', '05:00 PM');
    await page.fill('[data-testid="shift-end-time"]', '09:00 AM'); // End time before start time
    await page.fill('[data-testid="break-duration"]', '30');
    await page.selectOption('[data-testid="shift-type-dropdown"]', 'Day Shift');
    await page.click('[data-testid="save-template-button"]');
    
    // Verify error message is displayed
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText(/invalid|error|before/i);
  });
});