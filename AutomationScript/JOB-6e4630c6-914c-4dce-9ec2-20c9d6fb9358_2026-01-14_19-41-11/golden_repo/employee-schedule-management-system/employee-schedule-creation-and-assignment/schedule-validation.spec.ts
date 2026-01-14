import { test, expect } from '@playwright/test';

test.describe('Schedule Validation - Prevent Overlapping Shifts', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling application
    await page.goto('/schedule');
    // Assume user is already authenticated as Scheduling Manager
  });

  test('Detect overlapping shifts during schedule creation (error-case)', async ({ page }) => {
    // Navigate to the schedule creation page
    await page.click('[data-testid="create-schedule-button"]');
    await expect(page).toHaveURL(/.*schedule\/create/);

    // Select an employee who already has an existing shift
    // EMP001 with shift 9:00 AM - 5:00 PM on 2024-01-15
    await page.click('[data-testid="employee-select"]');
    await page.click('[data-testid="employee-option-EMP001"]');

    // Set the date for the new shift
    await page.fill('[data-testid="shift-date-input"]', '2024-01-15');

    // Assign a new shift that overlaps with the existing shift
    // 3:00 PM - 11:00 PM on 2024-01-15
    await page.fill('[data-testid="shift-start-time"]', '15:00');
    await page.fill('[data-testid="shift-end-time"]', '23:00');

    // Validation error should be displayed immediately
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('overlapping');
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('9:00 AM - 5:00 PM');

    // Attempt to save the schedule
    await page.click('[data-testid="save-schedule-button"]');

    // Save should be blocked until conflict resolved
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="save-schedule-button"]')).toBeDisabled();
    
    // Verify schedule was not saved - still on creation page
    await expect(page).toHaveURL(/.*schedule\/create/);
  });

  test('Resolve overlapping shift and save successfully (happy-path)', async ({ page }) => {
    // Navigate to the schedule creation page
    await page.click('[data-testid="create-schedule-button"]');
    await expect(page).toHaveURL(/.*schedule\/create/);

    // Select an employee who already has an existing shift
    await page.click('[data-testid="employee-select"]');
    await page.click('[data-testid="employee-option-EMP001"]');

    // Set the date for the new shift
    await page.fill('[data-testid="shift-date-input"]', '2024-01-15');

    // Initially assign an overlapping shift
    await page.fill('[data-testid="shift-start-time"]', '15:00');
    await page.fill('[data-testid="shift-end-time"]', '23:00');

    // Review the validation error message displaying the shift overlap details
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    const errorMessage = await page.locator('[data-testid="validation-error"]').textContent();
    expect(errorMessage).toContain('overlap');
    expect(errorMessage).toContain('EMP001');

    // Modify the new shift times to remove the overlap
    // Change shift from 3:00 PM - 11:00 PM to 6:00 PM - 11:00 PM on 2024-01-15
    await page.fill('[data-testid="shift-start-time"]', '18:00');
    await page.fill('[data-testid="shift-end-time"]', '23:00');

    // Validation error should be cleared
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="save-schedule-button"]')).toBeEnabled();

    // Click the Save button to save the schedule
    await page.click('[data-testid="save-schedule-button"]');

    // Verify success message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule saved successfully');

    // Verify the saved schedule by navigating to the employee's schedule view
    await page.click('[data-testid="view-schedules-button"]');
    await page.click('[data-testid="employee-filter"]');
    await page.click('[data-testid="employee-filter-option-EMP001"]');

    // Verify the new shift is displayed in the schedule
    const scheduleRow = page.locator('[data-testid="schedule-row"]').filter({ hasText: '2024-01-15' });
    await expect(scheduleRow).toBeVisible();
    await expect(scheduleRow).toContainText('6:00 PM');
    await expect(scheduleRow).toContainText('11:00 PM');
  });

  test('Detect overlapping shifts during schedule editing', async ({ page }) => {
    // Navigate to existing schedules
    await page.click('[data-testid="view-schedules-button"]');
    
    // Select a schedule to edit
    await page.click('[data-testid="schedule-row"]:has-text("EMP001")').first();
    await page.click('[data-testid="edit-schedule-button"]');

    // Modify shift to create an overlap with another existing shift
    await page.fill('[data-testid="shift-end-time"]', '20:00');

    // Validation error should be displayed
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    
    // Attempt to save
    await page.click('[data-testid="save-schedule-button"]');
    
    // Save should be blocked
    await expect(page.locator('[data-testid="save-schedule-button"]')).toBeDisabled();
  });

  test('System logs validation errors for audit purposes', async ({ page }) => {
    // Navigate to the schedule creation page
    await page.click('[data-testid="create-schedule-button"]');

    // Create an overlapping shift scenario
    await page.click('[data-testid="employee-select"]');
    await page.click('[data-testid="employee-option-EMP001"]');
    await page.fill('[data-testid="shift-date-input"]', '2024-01-15');
    await page.fill('[data-testid="shift-start-time"]', '15:00');
    await page.fill('[data-testid="shift-end-time"]', '23:00');

    // Wait for validation error
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();

    // Attempt to save to trigger audit log
    await page.click('[data-testid="save-schedule-button"]');

    // Navigate to audit logs (if accessible to manager)
    await page.goto('/admin/audit-logs');
    
    // Verify validation error is logged
    const auditLog = page.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'Schedule validation error' }).first();
    await expect(auditLog).toBeVisible();
    await expect(auditLog).toContainText('EMP001');
    await expect(auditLog).toContainText('overlap');
  });
});