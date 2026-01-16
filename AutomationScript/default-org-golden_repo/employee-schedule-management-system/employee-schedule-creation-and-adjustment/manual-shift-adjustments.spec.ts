import { test, expect } from '@playwright/test';

test.describe('Manual Shift Adjustments', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the schedule management interface
    await page.goto('/schedule-management');
    await expect(page).toHaveURL(/.*schedule-management/);
  });

  test('Edit assigned shift successfully with validation', async ({ page }) => {
    // Locate an assigned shift in the schedule view
    const shiftCard = page.locator('[data-testid="shift-card"]').first();
    await expect(shiftCard).toBeVisible();

    // Select the assigned shift for editing by clicking on it
    await shiftCard.click();
    
    // Verify shift details are displayed in editable form
    const editForm = page.locator('[data-testid="shift-edit-form"]');
    await expect(editForm).toBeVisible();
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time"]')).toBeVisible();

    // Modify the shift start time to a valid new time
    const startTimeInput = page.locator('[data-testid="shift-start-time"]');
    await startTimeInput.clear();
    await startTimeInput.fill('10:00');

    // Modify the shift end time to a valid new time
    const endTimeInput = page.locator('[data-testid="shift-end-time"]');
    await endTimeInput.clear();
    await endTimeInput.fill('18:00');

    // Modify the role assignment if applicable
    const roleSelect = page.locator('[data-testid="shift-role-select"]');
    await roleSelect.click();
    await page.locator('[data-testid="role-option-floor-staff"]').click();

    // Verify no validation errors are shown
    const validationError = page.locator('[data-testid="validation-error"]');
    await expect(validationError).not.toBeVisible();

    // Review all modified fields to ensure changes are correct
    await expect(startTimeInput).toHaveValue('10:00');
    await expect(endTimeInput).toHaveValue('18:00');

    // Click the Save button to save the changes
    const saveButton = page.locator('[data-testid="save-shift-button"]');
    await saveButton.click();

    // Verify confirmation message is displayed
    const confirmationMessage = page.locator('[data-testid="confirmation-message"]');
    await expect(confirmationMessage).toBeVisible();
    await expect(confirmationMessage).toContainText('Shift updated successfully');

    // Verify the updated shift in the schedule view
    await expect(page.locator('[data-testid="shift-card"]').first()).toContainText('10:00');
    await expect(page.locator('[data-testid="shift-card"]').first()).toContainText('18:00');
  });

  test('Prevent saving adjustments with conflicts', async ({ page }) => {
    // Select an assigned shift for editing
    const shiftCard = page.locator('[data-testid="shift-card"]').first();
    await shiftCard.click();

    const editForm = page.locator('[data-testid="shift-edit-form"]');
    await expect(editForm).toBeVisible();

    // Modify the shift time to create an overlap with another existing shift
    const startTimeInput = page.locator('[data-testid="shift-start-time"]');
    await startTimeInput.clear();
    await startTimeInput.fill('14:00');

    const endTimeInput = page.locator('[data-testid="shift-end-time"]');
    await endTimeInput.clear();
    await endTimeInput.fill('22:00');

    // Trigger validation by clicking outside or tabbing
    await page.locator('[data-testid="shift-edit-form"]').click();
    await page.waitForTimeout(500);

    // Review the validation error message
    const validationError = page.locator('[data-testid="validation-error"]');
    await expect(validationError).toBeVisible();
    await expect(validationError).toContainText(/conflict|overlap/i);

    // Attempt to save the changes by clicking the Save button
    const saveButton = page.locator('[data-testid="save-shift-button"]');
    
    // Verify that the Save button is disabled or shows error
    const isDisabled = await saveButton.isDisabled();
    if (!isDisabled) {
      await saveButton.click();
      // Verify error message is shown
      const errorMessage = page.locator('[data-testid="error-message"]');
      await expect(errorMessage).toBeVisible();
      await expect(errorMessage).toContainText(/cannot save|conflict/i);
    } else {
      await expect(saveButton).toBeDisabled();
    }

    // Modify the shift again to remove the conflict
    await endTimeInput.clear();
    await endTimeInput.fill('17:00');
    await page.locator('[data-testid="shift-edit-form"]').click();
    await page.waitForTimeout(500);

    // Verify validation error is cleared
    await expect(validationError).not.toBeVisible();

    // Attempt to save the changes again
    await expect(saveButton).toBeEnabled();
    await saveButton.click();

    // Verify successful save
    const confirmationMessage = page.locator('[data-testid="confirmation-message"]');
    await expect(confirmationMessage).toBeVisible();
  });

  test('Verify audit trail records manual adjustments', async ({ page }) => {
    // Note the current timestamp before making changes
    const timestampBefore = new Date();

    // Select an assigned shift for editing
    const shiftCard = page.locator('[data-testid="shift-card"]').first();
    const shiftId = await shiftCard.getAttribute('data-shift-id');
    await shiftCard.click();

    const editForm = page.locator('[data-testid="shift-edit-form"]');
    await expect(editForm).toBeVisible();

    // Make a manual adjustment to the shift
    const startTimeInput = page.locator('[data-testid="shift-start-time"]');
    const originalStartTime = await startTimeInput.inputValue();
    await startTimeInput.clear();
    await startTimeInput.fill('10:00');

    // Save the changes by clicking the Save button
    const saveButton = page.locator('[data-testid="save-shift-button"]');
    await saveButton.click();

    // Verify adjustment is saved successfully
    const confirmationMessage = page.locator('[data-testid="confirmation-message"]');
    await expect(confirmationMessage).toBeVisible();

    // Navigate to the audit log interface or section
    await page.goto('/audit-logs');
    await expect(page).toHaveURL(/.*audit-logs/);

    // Query or filter audit logs for the specific shift adjustment
    const searchInput = page.locator('[data-testid="audit-search-input"]');
    await searchInput.fill(shiftId || 'shift');
    
    const filterButton = page.locator('[data-testid="audit-filter-button"]');
    await filterButton.click();

    // Locate the audit entry for the manual adjustment just made
    const auditEntry = page.locator('[data-testid="audit-entry"]').first();
    await expect(auditEntry).toBeVisible();

    // Verify the audit entry contains the user ID or username who made the change
    const userField = auditEntry.locator('[data-testid="audit-user"]');
    await expect(userField).toBeVisible();
    await expect(userField).not.toBeEmpty();

    // Verify the audit entry contains an accurate timestamp
    const timestampField = auditEntry.locator('[data-testid="audit-timestamp"]');
    await expect(timestampField).toBeVisible();
    const timestampText = await timestampField.textContent();
    expect(timestampText).toBeTruthy();

    // Verify the audit entry contains details of what was changed
    const changeDetails = auditEntry.locator('[data-testid="audit-change-details"]');
    await expect(changeDetails).toBeVisible();
    await expect(changeDetails).toContainText(originalStartTime);
    await expect(changeDetails).toContainText('10:00');

    // Verify the audit entry contains the action type
    const actionType = auditEntry.locator('[data-testid="audit-action-type"]');
    await expect(actionType).toBeVisible();
    await expect(actionType).toContainText(/Shift Updated|Manual Adjustment/i);
  });
});