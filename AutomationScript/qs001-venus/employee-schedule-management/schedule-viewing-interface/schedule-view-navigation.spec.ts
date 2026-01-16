import { test, expect } from '@playwright/test';

test.describe('Schedule View Navigation - Story 13', () => {
  test.beforeEach(async ({ page }) => {
    // Login as employee
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate switching between schedule views (happy-path)', async ({ page }) => {
    // Navigate to schedule section
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);

    // Select Daily View option
    await page.click('[data-testid="daily-view-button"]');
    
    // Verify that the current date is highlighted and displayed in the view header
    await expect(page.locator('[data-testid="schedule-view-header"]')).toContainText('Daily');
    const currentDate = new Date().getDate();
    await expect(page.locator('[data-testid="current-date-highlight"]')).toBeVisible();
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();

    // Navigate to a specific date (15th of the month) using date picker
    await page.click('[data-testid="date-picker-button"]');
    await page.click('[data-testid="date-picker-day-15"]');
    
    // Verify date 15 is selected in daily view
    await expect(page.locator('[data-testid="selected-date"]')).toContainText('15');

    // Store page header content to verify no full page reload
    const headerContent = await page.locator('[data-testid="page-header"]').textContent();
    const navigationContent = await page.locator('[data-testid="main-navigation"]').textContent();

    // Click on Weekly View button
    await page.click('[data-testid="weekly-view-button"]');
    
    // Verify that the date context (15th) is preserved and highlighted in weekly view
    await expect(page.locator('[data-testid="schedule-view-header"]')).toContainText('Weekly');
    await expect(page.locator('[data-testid="selected-date"]')).toContainText('15');
    await expect(page.locator('[data-testid="date-highlight-15"]')).toHaveClass(/highlighted/);
    
    // Verify transition occurred without full page reload
    const headerContentAfter = await page.locator('[data-testid="page-header"]').textContent();
    const navigationContentAfter = await page.locator('[data-testid="main-navigation"]').textContent();
    expect(headerContent).toBe(headerContentAfter);
    expect(navigationContent).toBe(navigationContentAfter);
    
    // Review weekly schedule to ensure all shifts are displayed
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    const weeklyShifts = page.locator('[data-testid="shift-item"]');
    await expect(weeklyShifts).not.toHaveCount(0);

    // Click on Monthly View button
    await page.click('[data-testid="monthly-view-button"]');
    
    // Verify that the date context (15th) is preserved and highlighted in monthly view
    await expect(page.locator('[data-testid="schedule-view-header"]')).toContainText('Monthly');
    await expect(page.locator('[data-testid="selected-date"]')).toContainText('15');
    await expect(page.locator('[data-testid="date-highlight-15"]')).toHaveClass(/highlighted/);
    
    // Verify transition occurred without full page reload
    const headerContentMonthly = await page.locator('[data-testid="page-header"]').textContent();
    expect(headerContent).toBe(headerContentMonthly);
    await expect(page.locator('[data-testid="monthly-schedule-container"]')).toBeVisible();

    // Switch back to daily view
    await page.click('[data-testid="daily-view-button"]');
    await expect(page.locator('[data-testid="schedule-view-header"]')).toContainText('Daily');
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
  });

  test('Verify access control consistency across views (error-case)', async ({ page }) => {
    // Get Employee A's ID from the session/profile
    await page.goto('/profile');
    const employeeAId = await page.getAttribute('[data-testid="employee-id"]', 'data-value');
    
    // Navigate to daily schedule view
    await page.click('[data-testid="schedule-nav-link"]');
    await page.click('[data-testid="daily-view-button"]');
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();

    // Attempt to access Employee B's daily schedule by modifying URL
    const employeeBId = 'employee-b-test-id-12345';
    await page.goto(`/api/schedules/daily?employeeId=${employeeBId}`);
    
    // Verify access denied error is displayed for daily view
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/access denied|unauthorized|forbidden/i);
    
    // Verify redirect back to own schedule or error page
    await page.waitForURL(/.*error|.*schedule.*employeeId=${employeeAId}|.*dashboard/, { timeout: 5000 });

    // Navigate to weekly schedule view
    await page.goto('/schedule');
    await page.click('[data-testid="weekly-view-button"]');
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();

    // Attempt to access Employee B's weekly schedule by modifying URL
    await page.goto(`/api/schedules/weekly?employeeId=${employeeBId}`);
    
    // Verify access denied error is displayed for weekly view
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/access denied|unauthorized|forbidden/i);
    
    // Verify redirect back to own schedule or error page
    await page.waitForURL(/.*error|.*schedule.*employeeId=${employeeAId}|.*dashboard/, { timeout: 5000 });

    // Navigate to monthly schedule view
    await page.goto('/schedule');
    await page.click('[data-testid="monthly-view-button"]');
    await expect(page.locator('[data-testid="monthly-schedule-container"]')).toBeVisible();

    // Attempt to access Employee B's monthly schedule by modifying URL
    await page.goto(`/api/schedules/monthly?employeeId=${employeeBId}`);
    
    // Verify access denied error is displayed for monthly view
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/access denied|unauthorized|forbidden/i);
    
    // Verify redirect back to own schedule or error page
    await page.waitForURL(/.*error|.*schedule.*employeeId=${employeeAId}|.*dashboard/, { timeout: 5000 });
    
    // Verify error handling is consistent across all three views
    // All three attempts should have shown error messages and redirected appropriately
  });

  test('Validate switching between schedule views - Test Case #1', async ({ page }) => {
    // Navigate to schedule
    await page.goto('/schedule');
    
    // Action: Employee views daily schedule
    await page.click('[data-testid="daily-view-button"]');
    
    // Expected Result: Daily schedule is displayed
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-view-header"]')).toContainText('Daily');
    
    // Store the selected date
    const selectedDate = await page.locator('[data-testid="selected-date"]').textContent();
    
    // Action: Employee switches to weekly view
    await page.click('[data-testid="weekly-view-button"]');
    
    // Expected Result: Weekly schedule is displayed preserving selected date
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-view-header"]')).toContainText('Weekly');
    const selectedDateWeekly = await page.locator('[data-testid="selected-date"]').textContent();
    expect(selectedDateWeekly).toBe(selectedDate);
    
    // Action: Employee switches to monthly view
    await page.click('[data-testid="monthly-view-button"]');
    
    // Expected Result: Monthly schedule is displayed preserving selected date
    await expect(page.locator('[data-testid="monthly-schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-view-header"]')).toContainText('Monthly');
    const selectedDateMonthly = await page.locator('[data-testid="selected-date"]').textContent();
    expect(selectedDateMonthly).toBe(selectedDate);
  });

  test('Verify access control consistency across views - Test Case #2', async ({ page }) => {
    // Navigate to schedule
    await page.goto('/schedule');
    
    // Action: Employee attempts to access another employee's schedule in daily view
    await page.click('[data-testid="daily-view-button"]');
    const anotherEmployeeId = 'other-employee-id-67890';
    
    // Attempt to access via URL manipulation
    const response = await page.goto(`/schedule/daily?employeeId=${anotherEmployeeId}`);
    
    // Expected Result: Access denied error is displayed
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/access denied|unauthorized|not authorized/i);
    
    // Verify same behavior in weekly view
    await page.goto('/schedule');
    await page.click('[data-testid="weekly-view-button"]');
    await page.goto(`/schedule/weekly?employeeId=${anotherEmployeeId}`);
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/access denied|unauthorized|not authorized/i);
    
    // Verify same behavior in monthly view
    await page.goto('/schedule');
    await page.click('[data-testid="monthly-view-button"]');
    await page.goto(`/schedule/monthly?employeeId=${anotherEmployeeId}`);
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/access denied|unauthorized|not authorized/i);
  });
});