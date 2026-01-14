import { test, expect } from '@playwright/test';

test.describe('Bulk Assign Shift Templates to Employees', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful bulk assignment of shift templates (happy-path)', async ({ page }) => {
    // Navigate to the bulk assignment page from the scheduling dashboard
    await page.click('[data-testid="scheduling-menu"]');
    await page.click('[data-testid="bulk-assignment-link"]');
    await expect(page).toHaveURL(/.*bulk-assignment/);
    await expect(page.locator('[data-testid="bulk-assignment-page"]')).toBeVisible();

    // Select multiple employees (minimum 3) from the employee list by checking their checkboxes
    await page.waitForSelector('[data-testid="employee-list"]');
    const employeeCheckboxes = page.locator('[data-testid^="employee-checkbox-"]');
    await expect(employeeCheckboxes).toHaveCountGreaterThanOrEqual(3);
    
    await page.check('[data-testid="employee-checkbox-1"]');
    await page.check('[data-testid="employee-checkbox-2"]');
    await page.check('[data-testid="employee-checkbox-3"]');
    
    // Verify selection accepted
    await expect(page.locator('[data-testid="selected-employees-count"]')).toContainText('3');

    // Select a shift template from the available shift templates dropdown
    await page.click('[data-testid="shift-template-dropdown"]');
    await page.click('[data-testid="shift-template-option-morning"]');
    await expect(page.locator('[data-testid="shift-template-dropdown"]')).toContainText('Morning Shift');

    // Specify a valid date range by entering start date and end date for the bulk assignment
    await page.fill('[data-testid="start-date-input"]', '2024-02-01');
    await page.fill('[data-testid="end-date-input"]', '2024-02-07');

    // Click the 'Submit' or 'Assign' button to initiate the bulk assignment
    await page.click('[data-testid="submit-bulk-assignment-button"]');

    // Wait for the bulk assignment operation to complete
    await expect(page.locator('[data-testid="assignment-progress"]')).toBeVisible();
    await expect(page.locator('[data-testid="assignment-success-message"]')).toBeVisible({ timeout: 10000 });
    
    // Verify schedules are saved and confirmation displayed
    await expect(page.locator('[data-testid="assignment-success-message"]')).toContainText('Bulk assignment completed successfully');
    await expect(page.locator('[data-testid="successful-assignments-count"]')).toContainText('3');
    await expect(page.locator('[data-testid="failed-assignments-count"]')).toContainText('0');

    // Navigate to the schedule view for the first selected employee
    await page.click('[data-testid="view-schedules-link"]');
    await page.click('[data-testid="employee-schedule-1"]');
    await expect(page.locator('[data-testid="employee-schedule-details"]')).toBeVisible();
    
    // Verify shift templates assigned correctly without conflicts
    const firstEmployeeShifts = page.locator('[data-testid="shift-entry"]').filter({ hasText: 'Morning Shift' });
    await expect(firstEmployeeShifts).toHaveCountGreaterThanOrEqual(1);
    await expect(page.locator('[data-testid="shift-date-2024-02-01"]')).toContainText('Morning Shift');

    // Navigate to the schedule view for the second selected employee
    await page.click('[data-testid="back-to-schedules"]');
    await page.click('[data-testid="employee-schedule-2"]');
    await expect(page.locator('[data-testid="employee-schedule-details"]')).toBeVisible();
    
    const secondEmployeeShifts = page.locator('[data-testid="shift-entry"]').filter({ hasText: 'Morning Shift' });
    await expect(secondEmployeeShifts).toHaveCountGreaterThanOrEqual(1);
    await expect(page.locator('[data-testid="shift-date-2024-02-01"]')).toContainText('Morning Shift');

    // Navigate to the schedule view for the third selected employee
    await page.click('[data-testid="back-to-schedules"]');
    await page.click('[data-testid="employee-schedule-3"]');
    await expect(page.locator('[data-testid="employee-schedule-details"]')).toBeVisible();
    
    const thirdEmployeeShifts = page.locator('[data-testid="shift-entry"]').filter({ hasText: 'Morning Shift' });
    await expect(thirdEmployeeShifts).toHaveCountGreaterThanOrEqual(1);
    await expect(page.locator('[data-testid="shift-date-2024-02-01"]')).toContainText('Morning Shift');
  });

  test('Verify conflict detection during bulk assignment (error-case)', async ({ page }) => {
    // Navigate to the bulk assignment page from the scheduling dashboard
    await page.click('[data-testid="scheduling-menu"]');
    await page.click('[data-testid="bulk-assignment-link"]');
    await expect(page).toHaveURL(/.*bulk-assignment/);
    await expect(page.locator('[data-testid="bulk-assignment-page"]')).toBeVisible();

    // Select multiple employees including at least one employee who has a conflicting schedule for the target date range
    await page.waitForSelector('[data-testid="employee-list"]');
    
    // Select employee with existing schedule conflict
    await page.check('[data-testid="employee-checkbox-5"]');
    // Select employees without conflicts
    await page.check('[data-testid="employee-checkbox-6"]');
    await page.check('[data-testid="employee-checkbox-7"]');
    
    // Verify selection accepted
    await expect(page.locator('[data-testid="selected-employees-count"]')).toContainText('3');

    // Select a shift template from the available shift templates dropdown
    await page.click('[data-testid="shift-template-dropdown"]');
    await page.click('[data-testid="shift-template-option-evening"]');
    await expect(page.locator('[data-testid="shift-template-dropdown"]')).toContainText('Evening Shift');

    // Specify a date range that overlaps with the existing schedule of at least one selected employee
    await page.fill('[data-testid="start-date-input"]', '2024-02-10');
    await page.fill('[data-testid="end-date-input"]', '2024-02-15');

    // Click the 'Submit' or 'Assign' button to attempt the bulk assignment
    await page.click('[data-testid="submit-bulk-assignment-button"]');

    // Observe the system response after validation completes
    await expect(page.locator('[data-testid="assignment-progress"]')).toBeVisible();
    await page.waitForSelector('[data-testid="assignment-summary"]', { timeout: 10000 });
    
    // System alerts conflict and prevents conflicting assignment
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('conflict');

    // Review the detailed assignment summary displayed by the system
    await expect(page.locator('[data-testid="assignment-summary"]')).toBeVisible();
    
    // Summary shows successful and failed assignments
    const successfulCount = await page.locator('[data-testid="successful-assignments-count"]').textContent();
    const failedCount = await page.locator('[data-testid="failed-assignments-count"]').textContent();
    
    expect(parseInt(successfulCount || '0')).toBeGreaterThanOrEqual(1);
    expect(parseInt(failedCount || '0')).toBeGreaterThanOrEqual(1);
    
    await expect(page.locator('[data-testid="assignment-summary"]')).toContainText('2 successful');
    await expect(page.locator('[data-testid="assignment-summary"]')).toContainText('1 failed');

    // Verify the failed assignment details in the summary
    await expect(page.locator('[data-testid="failed-assignments-list"]')).toBeVisible();
    const failedAssignment = page.locator('[data-testid="failed-assignment-employee-5"]');
    await expect(failedAssignment).toBeVisible();
    await expect(failedAssignment).toContainText('Schedule conflict detected');
    await expect(failedAssignment).toContainText('Employee 5');

    // Navigate to the schedule view for the employee with the conflict
    await page.click('[data-testid="view-schedules-link"]');
    await page.click('[data-testid="employee-schedule-5"]');
    await expect(page.locator('[data-testid="employee-schedule-details"]')).toBeVisible();
    
    // Verify the conflicting schedule still exists and no new assignment was made
    const conflictingShifts = page.locator('[data-testid="shift-entry"]').filter({ hasText: '2024-02-10' });
    await expect(conflictingShifts).toHaveCountGreaterThanOrEqual(1);
    const eveningShifts = page.locator('[data-testid="shift-entry"]').filter({ hasText: 'Evening Shift' });
    await expect(eveningShifts).toHaveCount(0);

    // Navigate to the schedule view for an employee without conflicts
    await page.click('[data-testid="back-to-schedules"]');
    await page.click('[data-testid="employee-schedule-6"]');
    await expect(page.locator('[data-testid="employee-schedule-details"]')).toBeVisible();
    
    // Verify successful assignment for non-conflicting employee
    const successfulShifts = page.locator('[data-testid="shift-entry"]').filter({ hasText: 'Evening Shift' });
    await expect(successfulShifts).toHaveCountGreaterThanOrEqual(1);
    await expect(page.locator('[data-testid="shift-date-2024-02-10"]')).toContainText('Evening Shift');
  });
});