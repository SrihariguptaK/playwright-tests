import { test, expect } from '@playwright/test';

test.describe('Schedule Validation - Labor Rules Compliance', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as scheduling manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduling.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate schedule against maximum working hours - error case', async ({ page }) => {
    // Navigate to the schedule creation page
    await page.goto('/schedules/create');
    await expect(page.locator('[data-testid="schedule-creation-page"]')).toBeVisible();

    // Select an employee from the employee dropdown
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-john-doe"]');
    await expect(page.locator('[data-testid="selected-employee"]')).toContainText('John Doe');

    // Assign multiple shift templates that exceed maximum daily working hours (e.g., 16 hours when limit is 12)
    await page.click('[data-testid="add-shift-button"]');
    await page.selectOption('[data-testid="shift-template-select"]', 'morning-shift-8hrs');
    await page.fill('[data-testid="shift-start-time"]', '06:00');
    await page.fill('[data-testid="shift-end-time"]', '14:00');
    await page.click('[data-testid="confirm-shift-button"]');

    await page.click('[data-testid="add-shift-button"]');
    await page.selectOption('[data-testid="shift-template-select"]', 'evening-shift-8hrs');
    await page.fill('[data-testid="shift-start-time"]', '14:00');
    await page.fill('[data-testid="shift-end-time"]', '22:00');
    await page.click('[data-testid="confirm-shift-button"]');

    // Click the 'Submit' or 'Save' button to attempt saving the schedule
    await page.click('[data-testid="save-schedule-button"]');

    // Verify that validation error is displayed preventing save
    await expect(page.locator('[data-testid="validation-error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-message"]')).toContainText('exceeds maximum daily working hours');

    // Verify that the schedule is not saved to the database
    const saveSuccessMessage = page.locator('[data-testid="save-success-message"]');
    await expect(saveSuccessMessage).not.toBeVisible();

    // Adjust the schedule by removing one shift to comply with maximum working hours
    await page.click('[data-testid="shift-item-evening-shift"] [data-testid="remove-shift-button"]');
    await expect(page.locator('[data-testid="shift-item-evening-shift"]')).not.toBeVisible();

    // Click the 'Submit' or 'Save' button again
    await page.click('[data-testid="save-schedule-button"]');

    // Verify schedule saves successfully
    await expect(page.locator('[data-testid="save-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="save-success-message"]')).toContainText('Schedule saved successfully');

    // Verify the compliant schedule appears in the employee's schedule view
    await page.goto('/schedules/employee/john-doe');
    await expect(page.locator('[data-testid="schedule-list"]')).toContainText('morning-shift-8hrs');
  });

  test('Enforce minimum rest period between shifts - error case', async ({ page }) => {
    // Navigate to the schedule creation page
    await page.goto('/schedules/create');
    await expect(page.locator('[data-testid="schedule-creation-page"]')).toBeVisible();

    // Select an employee from the employee dropdown
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-jane-smith"]');
    await expect(page.locator('[data-testid="selected-employee"]')).toContainText('Jane Smith');

    // Assign a first shift template with specific end time (e.g., ending at 10:00 PM)
    await page.click('[data-testid="add-shift-button"]');
    await page.selectOption('[data-testid="shift-template-select"]', 'evening-shift');
    await page.fill('[data-testid="shift-date"]', '2024-01-15');
    await page.fill('[data-testid="shift-start-time"]', '14:00');
    await page.fill('[data-testid="shift-end-time"]', '22:00');
    await page.click('[data-testid="confirm-shift-button"]');

    // Assign a second shift that starts before minimum rest period has elapsed (e.g., 6 hours rest when 8 hours required)
    await page.click('[data-testid="add-shift-button"]');
    await page.selectOption('[data-testid="shift-template-select"]', 'morning-shift');
    await page.fill('[data-testid="shift-date"]', '2024-01-16');
    await page.fill('[data-testid="shift-start-time"]', '04:00');
    await page.fill('[data-testid="shift-end-time"]', '12:00');
    await page.click('[data-testid="confirm-shift-button"]');

    // Click the 'Submit' or 'Save' button to attempt saving the schedule
    await page.click('[data-testid="save-schedule-button"]');

    // Verify that warning or error is shown
    const validationMessage = page.locator('[data-testid="validation-warning-message"], [data-testid="validation-error-message"]');
    await expect(validationMessage).toBeVisible();
    await expect(validationMessage).toContainText(/minimum rest period|insufficient rest/i);

    // Verify that the system prevents saving or displays a clear warning requiring acknowledgment
    const acknowledgeButton = page.locator('[data-testid="acknowledge-warning-button"]');
    if (await acknowledgeButton.isVisible()) {
      await expect(acknowledgeButton).toBeVisible();
    } else {
      // If no acknowledge button, verify save was prevented
      await expect(page.locator('[data-testid="save-success-message"]')).not.toBeVisible();
    }
  });

  test('Override validation with justification - edge case', async ({ page }) => {
    // Navigate to the schedule creation page and create a schedule that violates labor rules
    await page.goto('/schedules/create');
    await expect(page.locator('[data-testid="schedule-creation-page"]')).toBeVisible();

    // Select an employee
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-mike-johnson"]');
    await expect(page.locator('[data-testid="selected-employee"]')).toContainText('Mike Johnson');

    // Create schedule that exceeds maximum hours
    await page.click('[data-testid="add-shift-button"]');
    await page.selectOption('[data-testid="shift-template-select"]', 'long-shift');
    await page.fill('[data-testid="shift-date"]', '2024-01-20');
    await page.fill('[data-testid="shift-start-time"]', '06:00');
    await page.fill('[data-testid="shift-end-time"]', '22:00');
    await page.click('[data-testid="confirm-shift-button"]');

    // Click the 'Submit' or 'Save' button to attempt saving the violating schedule
    await page.click('[data-testid="save-schedule-button"]');

    // Verify validation error appears
    await expect(page.locator('[data-testid="validation-error-message"]')).toBeVisible();

    // Click on the 'Override' button or checkbox to indicate intention to override
    await page.click('[data-testid="override-validation-button"]');
    await expect(page.locator('[data-testid="override-justification-modal"]')).toBeVisible();

    // Enter a valid business justification in the justification field
    await page.fill('[data-testid="justification-textarea"]', 'Emergency coverage required due to staff shortage');
    await expect(page.locator('[data-testid="justification-textarea"]')).toHaveValue('Emergency coverage required due to staff shortage');

    // Click the 'Confirm' or 'Save with Override' button to finalize the override
    await page.click('[data-testid="confirm-override-button"]');

    // Verify that schedule saves with override
    await expect(page.locator('[data-testid="save-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="save-success-message"]')).toContainText('Schedule saved with override');

    // Verify that the override and justification are logged in the system audit trail
    await page.goto('/audit-trail');
    await page.fill('[data-testid="audit-search-input"]', 'Mike Johnson');
    await page.click('[data-testid="audit-search-button"]');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('Override');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('Emergency coverage required due to staff shortage');

    // Navigate to the employee's schedule view to verify the schedule is saved
    await page.goto('/schedules/employee/mike-johnson');
    await expect(page.locator('[data-testid="schedule-list"]')).toContainText('long-shift');
    await expect(page.locator('[data-testid="schedule-override-indicator"]')).toBeVisible();
  });
});