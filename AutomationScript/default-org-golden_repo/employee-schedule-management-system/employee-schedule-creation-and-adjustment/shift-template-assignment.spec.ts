import { test, expect } from '@playwright/test';

test.describe('Shift Template Assignment to Employees', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the schedule assignment page before each test
    await page.goto('/schedule/assignment');
    // Wait for page to be fully loaded
    await page.waitForLoadState('networkidle');
  });

  test('Assign shift templates to employees successfully', async ({ page }) => {
    // Step 1: Verify page displays employee selector and calendar
    await expect(page.getByTestId('employee-selector')).toBeVisible();
    await expect(page.getByTestId('schedule-calendar')).toBeVisible();
    await expect(page.getByRole('heading', { name: /schedule assignment/i })).toBeVisible();

    // Step 2: Select employees from the employee directory
    await page.getByTestId('employee-selector').click();
    await page.getByRole('option', { name: 'John Smith' }).click();
    await page.getByRole('option', { name: 'Jane Doe' }).click();
    
    // Verify employees are selected
    await expect(page.getByTestId('selected-employees')).toContainText('John Smith');
    await expect(page.getByTestId('selected-employees')).toContainText('Jane Doe');

    // Select specific dates on the calendar
    await page.getByTestId('calendar-date-2024-06-15').click();
    await page.getByTestId('calendar-date-2024-06-16').click();

    // Choose shift templates and assign to selected employees
    await page.getByTestId('shift-template-selector').click();
    await page.getByRole('option', { name: 'Morning Shift (8:00 AM - 4:00 PM)' }).click();
    await page.getByTestId('assign-shift-button').click();

    // Verify assignments are accepted without validation errors
    await expect(page.getByTestId('validation-error')).not.toBeVisible();
    await expect(page.getByTestId('assignment-preview')).toBeVisible();
    await expect(page.getByTestId('assignment-preview')).toContainText('John Smith');
    await expect(page.getByTestId('assignment-preview')).toContainText('Morning Shift');

    // Step 3: Submit assignments
    await page.getByTestId('submit-assignments-button').click();

    // Verify schedules saved and confirmation displayed
    await expect(page.getByTestId('success-message')).toBeVisible();
    await expect(page.getByTestId('success-message')).toContainText('Schedules saved successfully');
    await expect(page.getByTestId('confirmation-dialog')).toBeVisible();
  });

  test('Detect and prevent overlapping shift assignments', async ({ page }) => {
    // Step 1: Select an employee who already has a shift assigned
    await page.getByTestId('employee-selector').click();
    await page.getByRole('option', { name: 'John Smith' }).click();

    // Select a date where employee already has a shift
    await page.getByTestId('calendar-date-2024-06-15').click();

    // Assign a new shift template that overlaps with existing shift
    await page.getByTestId('shift-template-selector').click();
    await page.getByRole('option', { name: 'Afternoon Shift (12:00 PM - 8:00 PM)' }).click();
    await page.getByTestId('assign-shift-button').click();

    // Verify conflict alert is displayed
    await expect(page.getByTestId('conflict-alert')).toBeVisible();
    await expect(page.getByTestId('conflict-alert')).toContainText('overlapping');
    await expect(page.getByTestId('conflict-alert')).toContainText('John Smith');
    await expect(page.getByRole('alert')).toContainText('conflict');

    // Step 2: Attempt to save conflicting schedule
    await page.getByTestId('submit-assignments-button').click();

    // Verify save is blocked until conflict is resolved
    await expect(page.getByTestId('error-message')).toBeVisible();
    await expect(page.getByTestId('error-message')).toContainText('resolve conflicts');
    await expect(page.getByTestId('submit-assignments-button')).toBeDisabled();
    
    // Verify no success confirmation appears
    await expect(page.getByTestId('success-message')).not.toBeVisible();
  });

  test('Display assigned shifts in calendar view', async ({ page }) => {
    // Step 1: Select an employee
    await page.getByTestId('employee-selector').click();
    await page.getByRole('option', { name: 'Jane Doe' }).click();

    // Assign shift templates to the selected employee on specific dates
    await page.getByTestId('calendar-date-2024-06-20').click();
    await page.getByTestId('shift-template-selector').click();
    await page.getByRole('option', { name: 'Morning Shift (8:00 AM - 4:00 PM)' }).click();
    await page.getByTestId('assign-shift-button').click();

    await page.getByTestId('calendar-date-2024-06-21').click();
    await page.getByTestId('shift-template-selector').click();
    await page.getByRole('option', { name: 'Evening Shift (4:00 PM - 12:00 AM)' }).click();
    await page.getByTestId('assign-shift-button').click();

    // Verify assignments saved successfully
    await expect(page.getByTestId('assignment-preview')).toBeVisible();

    // Step 2: Submit and save the assignments
    await page.getByTestId('submit-assignments-button').click();
    await expect(page.getByTestId('success-message')).toBeVisible();

    // Step 3: View the employee schedule calendar
    await page.getByTestId('view-calendar-button').click();
    await page.waitForLoadState('networkidle');

    // Verify assigned shifts are displayed correctly in calendar view
    await expect(page.getByTestId('calendar-view')).toBeVisible();
    
    const shift1 = page.getByTestId('shift-2024-06-20');
    await expect(shift1).toBeVisible();
    await expect(shift1).toContainText('Jane Doe');
    await expect(shift1).toContainText('Morning Shift');
    await expect(shift1).toContainText('8:00 AM - 4:00 PM');

    const shift2 = page.getByTestId('shift-2024-06-21');
    await expect(shift2).toBeVisible();
    await expect(shift2).toContainText('Jane Doe');
    await expect(shift2).toContainText('Evening Shift');
    await expect(shift2).toContainText('4:00 PM - 12:00 AM');

    // Verify shift details by clicking on individual shifts
    await shift1.click();
    await expect(page.getByTestId('shift-details-modal')).toBeVisible();
    await expect(page.getByTestId('shift-details-modal')).toContainText('Jane Doe');
    await expect(page.getByTestId('shift-details-modal')).toContainText('Morning Shift');
    await expect(page.getByTestId('shift-details-modal')).toContainText('June 20, 2024');
    
    await page.getByTestId('close-modal-button').click();
    
    await shift2.click();
    await expect(page.getByTestId('shift-details-modal')).toBeVisible();
    await expect(page.getByTestId('shift-details-modal')).toContainText('Evening Shift');
    await expect(page.getByTestId('shift-details-modal')).toContainText('June 21, 2024');
  });
});