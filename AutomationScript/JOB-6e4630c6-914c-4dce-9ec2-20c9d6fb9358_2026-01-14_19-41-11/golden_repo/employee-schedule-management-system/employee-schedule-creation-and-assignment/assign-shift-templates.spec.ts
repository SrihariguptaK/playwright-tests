import { test, expect } from '@playwright/test';

test.describe('Assign Shift Templates to Employees', () => {
  test.beforeEach(async ({ page }) => {
    // Login as Scheduling Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduling.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Assign shift template to employee successfully', async ({ page }) => {
    // Step 1: Navigate to schedule creation page
    await page.goto('/schedule/create');
    await expect(page.locator('[data-testid="schedule-creation-page"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Create Schedule');

    // Step 2: Select employee and shift template with date range
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-john-doe"]');
    await expect(page.locator('[data-testid="employee-dropdown"]')).toContainText('John Doe');

    await page.click('[data-testid="shift-template-dropdown"]');
    await page.click('[data-testid="shift-template-morning-shift"]');
    await expect(page.locator('[data-testid="shift-template-dropdown"]')).toContainText('Morning Shift');

    await page.fill('[data-testid="start-date-picker"]', '2024-02-01');
    await page.fill('[data-testid="end-date-picker"]', '2024-02-07');

    // Verify inputs accepted without errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();

    // Step 3: Submit assignment
    await page.click('[data-testid="submit-assignment-button"]');

    // Verify schedule saved and confirmation shown
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule assigned successfully');

    // Verify assigned schedule appears in calendar view
    await page.click('[data-testid="view-calendar-button"]');
    await expect(page.locator('[data-testid="calendar-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-entry-john-doe-morning-shift"]')).toBeVisible();
  });

  test('Prevent overlapping shift assignment', async ({ page }) => {
    // Step 1: Navigate to schedule creation page
    await page.goto('/schedule/create');
    await expect(page.locator('[data-testid="schedule-creation-page"]')).toBeVisible();

    // Select employee who already has an assigned shift
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-jane-smith"]');
    await expect(page.locator('[data-testid="employee-dropdown"]')).toContainText('Jane Smith');

    // Select shift template that overlaps with existing shift time
    await page.click('[data-testid="shift-template-dropdown"]');
    await page.click('[data-testid="shift-template-afternoon-shift"]');

    // Select date range that includes the date of existing shift
    await page.fill('[data-testid="start-date-picker"]', '2024-02-05');
    await page.fill('[data-testid="end-date-picker"]', '2024-02-05');

    // Trigger validation by clicking outside or tabbing
    await page.click('[data-testid="schedule-creation-page"]');
    await page.waitForTimeout(500);

    // Verify validation error displayed
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('overlapping shift');

    // Step 2: Attempt to save overlapping assignment
    const submitButton = page.locator('[data-testid="submit-assignment-button"]');
    
    // Verify save blocked until conflict resolved
    await expect(submitButton).toBeDisabled();

    // Attempt to click disabled button
    await submitButton.click({ force: true });
    
    // Verify no success message appears
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
    
    // Verify error message persists
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
  });

  test('Enforce maximum working hours per employee', async ({ page }) => {
    // Step 1: Navigate to schedule creation page
    await page.goto('/schedule/create');
    await expect(page.locator('[data-testid="schedule-creation-page"]')).toBeVisible();

    // Select employee from the employee list
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-mike-johnson"]');
    await expect(page.locator('[data-testid="employee-dropdown"]')).toContainText('Mike Johnson');

    // Assign shift template that exceeds max hours per day (14 hours when max is 12)
    await page.click('[data-testid="shift-template-dropdown"]');
    await page.click('[data-testid="shift-template-extended-shift"]');

    await page.fill('[data-testid="start-date-picker"]', '2024-02-10');
    await page.fill('[data-testid="end-date-picker"]', '2024-02-10');

    // Trigger validation
    await page.click('[data-testid="schedule-creation-page"]');
    await page.waitForTimeout(500);

    // Verify warning or error displayed for daily hours
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText(/maximum.*hours.*day|exceeds.*daily.*limit/i);

    // Verify save blocked
    const submitButton = page.locator('[data-testid="submit-assignment-button"]');
    await expect(submitButton).toBeDisabled();

    // Clear previous assignment
    await page.click('[data-testid="clear-form-button"]');

    // Test weekly hours limit
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-mike-johnson"]');

    // Assign shifts that exceed weekly maximum (45 hours when max is 40)
    await page.click('[data-testid="shift-template-dropdown"]');
    await page.click('[data-testid="shift-template-full-day-shift"]');

    await page.fill('[data-testid="start-date-picker"]', '2024-02-12');
    await page.fill('[data-testid="end-date-picker"]', '2024-02-18');

    // Trigger validation
    await page.click('[data-testid="schedule-creation-page"]');
    await page.waitForTimeout(500);

    // Verify warning or error displayed for weekly hours
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText(/maximum.*hours.*week|exceeds.*weekly.*limit/i);

    // Attempt to save schedule with hours exceeding weekly limit
    await expect(submitButton).toBeDisabled();
    await submitButton.click({ force: true });

    // Verify assignment blocked from being saved
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();

    // Modify shift assignments to bring hours within acceptable limits
    await page.fill('[data-testid="end-date-picker"]', '2024-02-16');
    await page.click('[data-testid="schedule-creation-page"]');
    await page.waitForTimeout(500);

    // Verify validation error cleared
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    
    // Verify submit button enabled
    await expect(submitButton).toBeEnabled();
  });
});