import { test, expect } from '@playwright/test';

test.describe('Schedule Assignment - Story 3', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const SCHEDULER_EMAIL = 'scheduler@example.com';
  const SCHEDULER_PASSWORD = 'scheduler123';
  const EMPLOYEE_EMAIL = 'employee@example.com';
  const EMPLOYEE_PASSWORD = 'employee123';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('Validate successful schedule assignment with valid inputs', async ({ page }) => {
    // Login as Scheduler
    await page.fill('[data-testid="email-input"]', SCHEDULER_EMAIL);
    await page.fill('[data-testid="password-input"]', SCHEDULER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Action: Navigate to schedule assignment page
    await page.click('text=Schedule Management');
    await page.click('text=Create Schedule');
    
    // Expected Result: Schedule assignment form is displayed
    await expect(page.locator('[data-testid="schedule-assignment-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-dropdown"]')).toBeVisible();
    await expect(page.locator('[data-testid="from-date-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="to-date-field"]')).toBeVisible();

    // Action: Select employee and valid date range
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-1"]');
    
    const today = new Date();
    const startDate = new Date(today);
    startDate.setDate(today.getDate() + 7);
    const endDate = new Date(startDate);
    endDate.setDate(startDate.getDate() + 5);
    
    const formatDate = (date: Date) => date.toISOString().split('T')[0];
    
    await page.fill('[data-testid="from-date-field"]', formatDate(startDate));
    await page.fill('[data-testid="to-date-field"]', formatDate(endDate));
    
    // Expected Result: Inputs accept data without errors
    await expect(page.locator('[data-testid="employee-dropdown"]')).not.toHaveClass(/error/);
    await expect(page.locator('[data-testid="from-date-field"]')).not.toHaveClass(/error/);
    await expect(page.locator('[data-testid="to-date-field"]')).not.toHaveClass(/error/);

    // Action: Assign valid shift templates and submit
    await page.click('[data-testid="shift-template-1"]');
    await page.click('[data-testid="shift-template-2"]');
    await page.click('[data-testid="submit-schedule-button"]');
    
    // Expected Result: Schedule is saved and confirmation is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule saved successfully');
    
    // Verify the schedule appears in the employee's schedule view
    await page.click('text=View Schedules');
    await expect(page.locator('[data-testid="employee-schedule-list"]')).toContainText(formatDate(startDate));
  });

  test('Reject schedule assignment with overlapping shifts', async ({ page }) => {
    // Login as Scheduler
    await page.fill('[data-testid="email-input"]', SCHEDULER_EMAIL);
    await page.fill('[data-testid="password-input"]', SCHEDULER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to schedule assignment page
    await page.click('text=Schedule Management');
    await page.click('text=Create Schedule');
    await expect(page.locator('[data-testid="schedule-assignment-form"]')).toBeVisible();

    // Select the employee who already has an existing shift assignment
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-with-existing-shift"]');
    
    // Select a date range that includes the date with the existing shift
    const today = new Date();
    const startDate = new Date(today);
    startDate.setDate(today.getDate() + 1);
    const endDate = new Date(startDate);
    endDate.setDate(startDate.getDate() + 3);
    
    const formatDate = (date: Date) => date.toISOString().split('T')[0];
    
    await page.fill('[data-testid="from-date-field"]', formatDate(startDate));
    await page.fill('[data-testid="to-date-field"]', formatDate(endDate));

    // Action: Assign shift templates with overlapping times to employee
    await page.click('[data-testid="shift-template-morning"]');
    await page.click('[data-testid="submit-schedule-button"]');
    
    // Expected Result: Validation error is displayed
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('overlapping');
    await expect(page.locator('[data-testid="error-message"]')).toContainText('shift conflict');

    // Action: Attempt to save schedule
    await page.click('[data-testid="submit-schedule-button"]');
    
    // Expected Result: Save is blocked until conflicts are resolved
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="submit-schedule-button"]')).toBeDisabled();
    
    // Remove or modify the overlapping shift template to resolve the conflict
    await page.click('[data-testid="shift-template-morning"]');
    await page.click('[data-testid="shift-template-evening"]');
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="submit-schedule-button"]')).toBeEnabled();
  });

  test('Ensure unauthorized users cannot assign schedules', async ({ page, request }) => {
    // Action: Login as non-Scheduler user
    await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Expected Result: Access to schedule assignment page is denied
    // Attempt to navigate to the schedule assignment page by entering the URL directly
    await page.goto(`${BASE_URL}/schedule-management/create`);
    
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('unauthorized');
    await expect(page.locator('[data-testid="schedule-assignment-form"]')).not.toBeVisible();

    // Verify menu option is not visible for non-Scheduler users
    const scheduleManagementMenu = page.locator('text=Schedule Management');
    if (await scheduleManagementMenu.isVisible()) {
      await scheduleManagementMenu.click();
      await expect(page.locator('text=Create Schedule')).not.toBeVisible();
    }

    // Action: Attempt to call POST /api/schedules
    const authToken = await page.evaluate(() => localStorage.getItem('authToken'));
    
    const scheduleData = {
      employeeId: 1,
      startDate: '2024-01-15',
      endDate: '2024-01-20',
      shiftTemplateIds: [1, 2]
    };

    const response = await request.post(`${BASE_URL}/api/schedules`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      data: scheduleData
    });

    // Expected Result: API returns authorization error
    expect(response.status()).toBe(403);
    const responseBody = await response.json();
    expect(responseBody.error).toContain('unauthorized');
    expect(responseBody.message).toMatch(/not authorized|forbidden|access denied/i);

    // Verify that no schedule data is created or modified in the database
    await page.goto(`${BASE_URL}/schedules`);
    const scheduleList = page.locator('[data-testid="schedule-list"]');
    if (await scheduleList.isVisible()) {
      await expect(scheduleList).not.toContainText('2024-01-15');
    }

    // Logout and login with a user having Scheduler role
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    await page.fill('[data-testid="email-input"]', SCHEDULER_EMAIL);
    await page.fill('[data-testid="password-input"]', SCHEDULER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Verify Scheduler can access the schedule assignment page
    await page.click('text=Schedule Management');
    await page.click('text=Create Schedule');
    await expect(page.locator('[data-testid="schedule-assignment-form"]')).toBeVisible();
  });
});