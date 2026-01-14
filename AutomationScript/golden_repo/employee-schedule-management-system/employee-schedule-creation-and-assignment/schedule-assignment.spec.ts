import { test, expect } from '@playwright/test';

test.describe('Schedule Assignment - Shift Template Assignment', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful assignment of shift template to single employee', async ({ page }) => {
    // Step 1: Navigate to schedule assignment page
    await page.click('[data-testid="schedule-menu"]');
    await page.click('text=Schedule Assignment');
    await expect(page.locator('[data-testid="assignment-form"]')).toBeVisible();
    await expect(page.locator('h1, h2')).toContainText(/Schedule Assignment|Assign Shifts/);

    // Step 2: Select one employee and date range
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-1"]');
    await expect(page.locator('[data-testid="employee-dropdown"]')).toContainText(/John Doe|Employee/);
    
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="start-date"]');
    await page.fill('[data-testid="start-date-input"]', '2024-02-01');
    await page.click('[data-testid="end-date"]');
    await page.fill('[data-testid="end-date-input"]', '2024-02-07');
    await page.click('[data-testid="date-confirm-button"]');

    // Step 3: Choose a shift template and submit assignment
    await page.click('[data-testid="shift-template-dropdown"]');
    await page.click('[data-testid="shift-template-option-morning"]');
    await expect(page.locator('[data-testid="shift-template-dropdown"]')).toContainText(/Morning Shift|Morning/);
    
    await page.click('[data-testid="assign-button"]');
    
    // Verify schedule is saved and confirmation is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/successfully assigned|Schedule created/);
    await expect(page.locator('[data-testid="confirmation-details"]')).toContainText(/John Doe|Employee/);
    await expect(page.locator('[data-testid="confirmation-details"]')).toContainText(/2024-02-01/);
    await expect(page.locator('[data-testid="confirmation-details"]')).toContainText(/Morning/);
  });

  test('Verify bulk assignment of shift templates to multiple employees', async ({ page }) => {
    // Step 1: Navigate to schedule assignment page
    await page.click('[data-testid="schedule-menu"]');
    await page.click('text=Schedule Assignment');
    await expect(page.locator('[data-testid="assignment-form"]')).toBeVisible();

    // Step 2: Select multiple employees and dates
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-checkbox-1"]');
    await page.click('[data-testid="employee-checkbox-2"]');
    await page.click('[data-testid="employee-checkbox-3"]');
    await expect(page.locator('[data-testid="selected-employees-count"]')).toContainText('3');
    
    await page.click('[data-testid="date-range-picker"]');
    await page.fill('[data-testid="start-date-input"]', '2024-02-01');
    await page.fill('[data-testid="end-date-input"]', '2024-02-07');
    await page.click('[data-testid="date-confirm-button"]');

    // Step 3: Assign shift template to all selected employees
    await page.click('[data-testid="shift-template-dropdown"]');
    await page.click('[data-testid="shift-template-option-evening"]');
    await page.click('[data-testid="bulk-assign-button"]');
    
    // Verify schedules saved and confirmation displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/3 employees|successfully assigned/);
    await expect(page.locator('[data-testid="confirmation-details"]')).toContainText(/Evening/);
    await expect(page.locator('[data-testid="confirmation-details"]')).toContainText(/2024-02-01/);
  });

  test('Validate conflict detection during schedule assignment', async ({ page }) => {
    // Step 1: Select employee with existing shift on date
    await page.click('[data-testid="schedule-menu"]');
    await page.click('text=Schedule Assignment');
    await expect(page.locator('[data-testid="assignment-form"]')).toBeVisible();
    
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-existing-shift"]');
    await expect(page.locator('[data-testid="employee-schedule-display"]')).toBeVisible();
    await expect(page.locator('[data-testid="existing-shifts"]')).toContainText(/Existing shift|Current schedule/);

    // Step 2: Attempt to assign overlapping shift template
    await page.click('[data-testid="date-range-picker"]');
    await page.fill('[data-testid="start-date-input"]', '2024-02-05');
    await page.fill('[data-testid="end-date-input"]', '2024-02-05');
    await page.click('[data-testid="date-confirm-button"]');
    
    await page.click('[data-testid="shift-template-dropdown"]');
    await page.click('[data-testid="shift-template-option-overlapping"]');
    
    await page.click('[data-testid="assign-button"]');
    
    // Verify conflict warning is displayed
    await expect(page.locator('[data-testid="conflict-warning"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-warning"]')).toContainText(/conflict|overlapping|already assigned/);
    await expect(page.locator('[data-testid="conflict-details"]')).toContainText(/2024-02-05/);

    // Step 3: Submit assignment despite conflict
    await page.click('[data-testid="confirm-override-button"]');
    
    // Verify system blocks save and shows error
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/cannot assign|conflict detected|unable to save/);
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/overlapping|conflict/);
    await expect(page.locator('[data-testid="suggested-actions"]')).toBeVisible();
    
    // Verify the assignment was not saved
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
  });
});