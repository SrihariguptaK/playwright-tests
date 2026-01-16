import { test, expect } from '@playwright/test';

test.describe('Reschedule Conflicting Appointments', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the conflict alert dashboard before each test
    await page.goto('/dashboard/conflicts');
    await page.waitForLoadState('networkidle');
  });

  test('Reschedule conflicting appointment successfully', async ({ page }) => {
    // Step 1: Navigate to the conflict alert dashboard and locate a conflicting appointment
    await expect(page.locator('[data-testid="conflict-alert-dashboard"]')).toBeVisible();
    const conflictingAppointment = page.locator('[data-testid="conflict-alert-item"]').first();
    await expect(conflictingAppointment).toBeVisible();

    // Step 2: Click on the 'Reschedule' option from the conflict alert
    await conflictingAppointment.locator('[data-testid="reschedule-button"]').click();
    
    // Step 3: Calendar with available slots is displayed
    await expect(page.locator('[data-testid="calendar-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="available-time-slots"]')).toBeVisible();

    // Step 4: Review the available time slots in the calendar view
    const availableSlots = page.locator('[data-testid="time-slot"][data-available="true"]');
    await expect(availableSlots.first()).toBeVisible();

    // Step 5: Select a new time slot that does not have any conflicts
    const selectedSlot = availableSlots.first();
    await selectedSlot.click();
    await expect(selectedSlot).toHaveAttribute('data-selected', 'true');

    // Step 6: Wait for system to validate the selected time slot
    await page.waitForResponse(response => 
      response.url().includes('/appointments/validate') && response.status() === 200
    );
    
    // System validates and accepts new time
    await expect(page.locator('[data-testid="validation-success"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();

    // Step 7: Click the 'Confirm Reschedule' button to finalize the change
    const confirmButton = page.locator('[data-testid="confirm-reschedule-button"]');
    await expect(confirmButton).toBeEnabled();
    await confirmButton.click();

    // Step 8: Confirm the rescheduling action in the confirmation dialog
    const confirmDialog = page.locator('[data-testid="confirmation-dialog"]');
    await expect(confirmDialog).toBeVisible();
    await page.locator('[data-testid="confirm-dialog-yes"]').click();

    // Wait for reschedule operation to complete (should be within 3 seconds)
    const startTime = Date.now();
    await page.waitForResponse(response => 
      response.url().includes('/appointments') && response.url().includes('/reschedule') && response.status() === 200,
      { timeout: 3000 }
    );
    const endTime = Date.now();
    const operationTime = endTime - startTime;
    
    // Verify operation completed within 3 seconds
    expect(operationTime).toBeLessThan(3000);

    // Appointment is updated and conflict cleared
    await expect(page.locator('[data-testid="reschedule-success-message"]')).toBeVisible();
    
    // Step 9: Verify the conflict status in the conflict alert dashboard
    await page.goto('/dashboard/conflicts');
    await page.waitForLoadState('networkidle');
    
    // Verify conflict is cleared or marked as resolved
    const resolvedConflict = page.locator('[data-testid="conflict-alert-item"][data-status="resolved"]').first();
    await expect(resolvedConflict).toBeVisible();
  });

  test('Prevent rescheduling to conflicting time', async ({ page }) => {
    // Step 1: Navigate to the conflict alert dashboard and select a conflicting appointment
    await expect(page.locator('[data-testid="conflict-alert-dashboard"]')).toBeVisible();
    const conflictingAppointment = page.locator('[data-testid="conflict-alert-item"]').first();
    await expect(conflictingAppointment).toBeVisible();

    // Step 2: Click on the 'Reschedule' option from the conflict alert
    await conflictingAppointment.locator('[data-testid="reschedule-button"]').click();
    await expect(page.locator('[data-testid="calendar-view"]')).toBeVisible();

    // Step 3: Attempt to select a time slot that already has a conflicting appointment scheduled
    const conflictingSlot = page.locator('[data-testid="time-slot"][data-available="false"]').first();
    await expect(conflictingSlot).toBeVisible();
    await conflictingSlot.click();

    // Step 4: Wait for system validation of the selected conflicting time slot
    await page.waitForResponse(response => 
      response.url().includes('/appointments/validate') && response.status() === 400
    );

    // System displays validation error and prevents reschedule
    const validationError = page.locator('[data-testid="validation-error"]');
    await expect(validationError).toBeVisible();
    await expect(validationError).toContainText(/conflict|overlaps|unavailable/i);

    // Step 5: Review the error message details
    const errorMessage = await validationError.textContent();
    expect(errorMessage).toBeTruthy();
    expect(errorMessage?.length).toBeGreaterThan(0);

    // Step 6: Verify that the 'Confirm Reschedule' button is disabled or unavailable
    const confirmButton = page.locator('[data-testid="confirm-reschedule-button"]');
    await expect(confirmButton).toBeDisabled();

    // Step 7: Attempt to click the disabled 'Confirm Reschedule' button
    // Button should not trigger any action when disabled
    const initialUrl = page.url();
    await confirmButton.click({ force: true });
    
    // Wait a moment to ensure no navigation or action occurred
    await page.waitForTimeout(500);
    
    // Step 8: Verify the original appointment remains unchanged
    expect(page.url()).toBe(initialUrl);
    await expect(page.locator('[data-testid="reschedule-success-message"]')).not.toBeVisible();
    
    // Close the reschedule dialog
    await page.locator('[data-testid="cancel-reschedule-button"]').click();
    
    // Navigate back to conflict dashboard
    await page.goto('/dashboard/conflicts');
    await page.waitForLoadState('networkidle');
    
    // Verify the conflict still exists and is not resolved
    const unresolvedConflict = page.locator('[data-testid="conflict-alert-item"][data-status="active"]').first();
    await expect(unresolvedConflict).toBeVisible();
  });
});