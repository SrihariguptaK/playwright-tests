import { test, expect } from '@playwright/test';

test.describe('Shift Template Assignment to Employees', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Assign shift template to single employee without conflicts', async ({ page }) => {
    // Step 1: Navigate to employee schedule assignment page
    await page.goto('/schedules/assignment');
    await expect(page.locator('[data-testid="schedule-assignment-form"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Schedule Assignment');

    // Step 2: Select one employee from the employee dropdown list
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-1"]');
    await expect(page.locator('[data-testid="employee-dropdown"]')).toContainText('John Doe');

    // Select a shift template from the shift template dropdown
    await page.click('[data-testid="shift-template-dropdown"]');
    await page.click('[data-testid="shift-template-option-morning"]');
    await expect(page.locator('[data-testid="shift-template-dropdown"]')).toContainText('Morning Shift');

    // Select a specific date using the date picker
    await page.click('[data-testid="date-picker"]');
    await page.fill('[data-testid="date-picker-input"]', '2024-03-15');

    // Verify inputs accepted without validation errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();

    // Step 3: Click the Submit or Assign button to submit the assignment
    await page.click('[data-testid="assign-button"]');

    // Verify shift assigned successfully and confirmation displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Shift assigned successfully');

    // Verify the assigned shift appears in the employee's schedule view
    await page.goto('/schedules/view?employeeId=1');
    await expect(page.locator('[data-testid="schedule-entry"]').filter({ hasText: 'Morning Shift' })).toBeVisible();
    await expect(page.locator('[data-testid="schedule-entry"]').filter({ hasText: '2024-03-15' })).toBeVisible();
  });

  test('Prevent overlapping shift assignments for the same employee', async ({ page }) => {
    // Step 1: Navigate to employee schedule assignment page
    await page.goto('/schedules/assignment');
    await expect(page.locator('[data-testid="schedule-assignment-form"]')).toBeVisible();

    // Select the employee who already has an existing shift assigned
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-2"]');
    await expect(page.locator('[data-testid="employee-dropdown"]')).toContainText('Jane Smith');

    // Select a shift template that overlaps with the employee's existing shift time
    await page.click('[data-testid="shift-template-dropdown"]');
    await page.click('[data-testid="shift-template-option-afternoon"]');
    await expect(page.locator('[data-testid="shift-template-dropdown"]')).toContainText('Afternoon Shift');

    // Select the same date as the existing shift
    await page.click('[data-testid="date-picker"]');
    await page.fill('[data-testid="date-picker-input"]', '2024-03-10');

    // Attempt to submit the assignment by clicking Submit or Assign button
    await page.click('[data-testid="assign-button"]');

    // System displays conflict error and prevents assignment
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('conflict');
    await expect(page.locator('[data-testid="error-message"]')).toContainText('overlapping');

    // Step 2: Adjust the assignment to a non-overlapping time by selecting a different date
    await page.click('[data-testid="date-picker"]');
    await page.fill('[data-testid="date-picker-input"]', '2024-03-11');

    // System accepts inputs without errors
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();

    // Step 3: Submit the adjusted assignment
    await page.click('[data-testid="assign-button"]');

    // Shift assigned successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Shift assigned successfully');

    // Verify both shifts appear in the employee's schedule without conflicts
    await page.goto('/schedules/view?employeeId=2');
    await expect(page.locator('[data-testid="schedule-entry"]').filter({ hasText: '2024-03-10' })).toBeVisible();
    await expect(page.locator('[data-testid="schedule-entry"]').filter({ hasText: '2024-03-11' })).toBeVisible();
    const scheduleEntries = await page.locator('[data-testid="schedule-entry"]').count();
    expect(scheduleEntries).toBeGreaterThanOrEqual(2);
  });

  test('Bulk assign shift templates to multiple employees', async ({ page }) => {
    // Step 1: Navigate to employee schedule assignment page with bulk assignment capability
    await page.goto('/schedules/assignment');
    await expect(page.locator('[data-testid="schedule-assignment-form"]')).toBeVisible();

    // Select multiple employees using the multi-select employee dropdown (select at least 3 employees)
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-3"]');
    await page.click('[data-testid="employee-option-4"]');
    await page.click('[data-testid="employee-option-5"]');
    
    // Verify multiple employees are selected
    await expect(page.locator('[data-testid="selected-employees-count"]')).toContainText('3');

    // Select a shift template from the shift template dropdown
    await page.click('[data-testid="shift-template-dropdown"]');
    await page.click('[data-testid="shift-template-option-evening"]');
    await expect(page.locator('[data-testid="shift-template-dropdown"]')).toContainText('Evening Shift');

    // Specify a date range using the date range picker (e.g., 5 consecutive days)
    await page.click('[data-testid="date-range-picker"]');
    await page.fill('[data-testid="start-date-input"]', '2024-03-20');
    await page.fill('[data-testid="end-date-input"]', '2024-03-24');

    // Bulk assignment form accepts inputs
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();

    // Step 2: Click Submit or Assign button to submit the bulk assignment
    await page.click('[data-testid="assign-button"]');

    // Wait for processing to complete
    await expect(page.locator('[data-testid="processing-indicator"]')).toBeVisible();
    await expect(page.locator('[data-testid="processing-indicator"]')).not.toBeVisible({ timeout: 30000 });

    // Shifts assigned to all selected employees with confirmation
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Shifts assigned to all selected employees');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('3 employees');

    // Step 3: Navigate to the first selected employee's schedule view
    await page.goto('/schedules/view?employeeId=3');
    await expect(page.locator('[data-testid="schedule-entry"]').filter({ hasText: 'Evening Shift' })).toBeVisible();
    const employee3Entries = await page.locator('[data-testid="schedule-entry"]').filter({ hasText: 'Evening Shift' }).count();
    expect(employee3Entries).toBe(5);

    // Navigate to the second selected employee's schedule view
    await page.goto('/schedules/view?employeeId=4');
    await expect(page.locator('[data-testid="schedule-entry"]').filter({ hasText: 'Evening Shift' })).toBeVisible();
    const employee4Entries = await page.locator('[data-testid="schedule-entry"]').filter({ hasText: 'Evening Shift' }).count();
    expect(employee4Entries).toBe(5);

    // Navigate to the third selected employee's schedule view and verify schedules
    await page.goto('/schedules/view?employeeId=5');
    await expect(page.locator('[data-testid="schedule-entry"]').filter({ hasText: 'Evening Shift' })).toBeVisible();
    const employee5Entries = await page.locator('[data-testid="schedule-entry"]').filter({ hasText: 'Evening Shift' }).count();
    expect(employee5Entries).toBe(5);

    // Verify schedules reflect assigned shifts without conflicts
    await expect(page.locator('[data-testid="conflict-indicator"]')).not.toBeVisible();
  });
});