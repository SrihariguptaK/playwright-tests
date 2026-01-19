import { test, expect } from '@playwright/test';

test.describe('Assign Shift Templates to Employees', () => {
  test.beforeEach(async ({ page }) => {
    // Login as scheduling manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduling.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager@123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Assign shift template to employee successfully', async ({ page }) => {
    // Step 1: Navigate to schedule creation page
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="create-schedule-button"]');
    await expect(page.locator('[data-testid="schedule-creation-form"]')).toBeVisible();
    
    // Step 2: Select employee and shift template with valid dates
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-john-doe"]');
    await expect(page.locator('[data-testid="employee-dropdown"]')).toContainText('John Doe');
    
    await page.click('[data-testid="shift-template-dropdown"]');
    await page.click('[data-testid="shift-template-morning-shift"]');
    await expect(page.locator('[data-testid="shift-template-dropdown"]')).toContainText('Morning Shift');
    
    // Select valid start and end dates
    const today = new Date();
    const startDate = new Date(today);
    startDate.setDate(today.getDate() + 7);
    const endDate = new Date(startDate);
    endDate.setDate(startDate.getDate() + 1);
    
    await page.fill('[data-testid="start-date-input"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-input"]', endDate.toISOString().split('T')[0]);
    
    // Verify no validation errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    
    // Step 3: Submit schedule assignment
    await page.click('[data-testid="submit-schedule-button"]');
    
    // Verify schedule is saved and confirmation shown
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule assigned successfully');
    
    // Verify the assigned schedule appears in employee's schedule view
    await page.click('[data-testid="view-employee-schedule-link"]');
    await expect(page.locator('[data-testid="schedule-list"]')).toContainText('Morning Shift');
    await expect(page.locator('[data-testid="schedule-list"]')).toContainText('John Doe');
  });

  test('Prevent overlapping shift assignments', async ({ page }) => {
    // Pre-condition: Create an existing shift assignment
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="create-schedule-button"]');
    
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-jane-smith"]');
    
    await page.click('[data-testid="shift-template-dropdown"]');
    await page.click('[data-testid="shift-template-afternoon-shift"]');
    
    const today = new Date();
    const existingShiftDate = new Date(today);
    existingShiftDate.setDate(today.getDate() + 10);
    
    await page.fill('[data-testid="start-date-input"]', existingShiftDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-input"]', existingShiftDate.toISOString().split('T')[0]);
    
    await page.click('[data-testid="submit-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Step 1: Navigate to schedule creation page again
    await page.click('[data-testid="create-schedule-button"]');
    await expect(page.locator('[data-testid="schedule-creation-form"]')).toBeVisible();
    
    // Step 2: Select the same employee who already has an existing shift
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-jane-smith"]');
    
    // Step 3: Select a shift template that overlaps with existing shift
    await page.click('[data-testid="shift-template-dropdown"]');
    await page.click('[data-testid="shift-template-evening-shift"]');
    
    // Step 4: Enter dates that create an overlap with existing shift
    await page.fill('[data-testid="start-date-input"]', existingShiftDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-input"]', existingShiftDate.toISOString().split('T')[0]);
    
    // Step 5: Attempt to save the overlapping schedule
    await page.click('[data-testid="submit-schedule-button"]');
    
    // Step 6: Verify validation error prevents saving
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('overlapping');
    
    // Verify the overlapping schedule is not saved
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
    
    // Step 7: Attempt to close or dismiss the error message
    await page.click('[data-testid="error-dismiss-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    
    // Verify form is still accessible for correction
    await expect(page.locator('[data-testid="schedule-creation-form"]')).toBeVisible();
  });

  test('System restricts schedule creation to authorized managers', async ({ page }) => {
    // Logout as manager
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Login as non-manager user
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'regular.employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Employee@123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Attempt to navigate to schedule creation page
    await page.goto('/schedule/create');
    
    // Verify access is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('not authorized');
  });

  test('System validates and saves employee schedules with assigned shifts', async ({ page }) => {
    // Navigate to schedule creation page
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="create-schedule-button"]');
    
    // Select employee
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-mike-johnson"]');
    
    // Select shift template
    await page.click('[data-testid="shift-template-dropdown"]');
    await page.click('[data-testid="shift-template-night-shift"]');
    
    // Enter valid dates
    const today = new Date();
    const shiftDate = new Date(today);
    shiftDate.setDate(today.getDate() + 14);
    
    await page.fill('[data-testid="start-date-input"]', shiftDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-input"]', shiftDate.toISOString().split('T')[0]);
    
    // Submit and verify successful save
    await page.click('[data-testid="submit-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Navigate to employee schedules list to verify persistence
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="view-all-schedules-link"]');
    
    // Filter by employee
    await page.fill('[data-testid="employee-filter-input"]', 'Mike Johnson');
    await page.click('[data-testid="apply-filter-button"]');
    
    // Verify the schedule appears in the list
    await expect(page.locator('[data-testid="schedule-list-item"]').first()).toContainText('Mike Johnson');
    await expect(page.locator('[data-testid="schedule-list-item"]').first()).toContainText('Night Shift');
    await expect(page.locator('[data-testid="schedule-list-item"]').first()).toContainText(shiftDate.toISOString().split('T')[0]);
  });
});