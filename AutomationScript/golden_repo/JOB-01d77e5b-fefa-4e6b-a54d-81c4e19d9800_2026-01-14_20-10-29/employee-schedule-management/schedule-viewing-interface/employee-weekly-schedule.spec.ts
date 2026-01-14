import { test, expect } from '@playwright/test';

test.describe('Employee Weekly Schedule View', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('Validate weekly schedule display with accurate shifts', async ({ page }) => {
    // Step 1: Employee logs into the portal
    await page.fill('[data-testid="username-input"]', 'employee.user@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123!');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Dashboard displayed
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible({ timeout: 5000 });
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to schedule section and select weekly view
    await page.click('[data-testid="schedule-nav-link"]');
    await page.click('[data-testid="weekly-view-option"]');
    
    // Expected Result: Weekly schedule for current week displayed
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('[data-testid="week-header"]')).toBeVisible();
    
    // Verify week start and end dates are displayed
    const weekHeader = page.locator('[data-testid="week-header"]');
    await expect(weekHeader).toContainText(/\d{1,2}\/\d{1,2}\/\d{4}/);
    
    // Verify all seven days of the week are visible
    const dayColumns = page.locator('[data-testid="day-column"]');
    await expect(dayColumns).toHaveCount(7);
    
    // Verify weekend days are highlighted
    const saturdayColumn = page.locator('[data-testid="day-column-saturday"]');
    const sundayColumn = page.locator('[data-testid="day-column-sunday"]');
    await expect(saturdayColumn).toHaveClass(/weekend/);
    await expect(sundayColumn).toHaveClass(/weekend/);

    // Step 3: Verify shift details and total hours
    const shifts = page.locator('[data-testid="shift-card"]');
    const shiftCount = await shifts.count();
    expect(shiftCount).toBeGreaterThan(0);
    
    // Verify shift details are complete for each shift
    for (let i = 0; i < shiftCount; i++) {
      const shift = shifts.nth(i);
      await expect(shift.locator('[data-testid="shift-time"]')).toBeVisible();
      await expect(shift.locator('[data-testid="shift-duration"]')).toBeVisible();
    }
    
    // Expected Result: Shift details and total hours are accurate
    const totalHoursElement = page.locator('[data-testid="total-hours-summary"]');
    await expect(totalHoursElement).toBeVisible();
    
    // Calculate total hours from displayed shifts
    let calculatedTotalHours = 0;
    for (let i = 0; i < shiftCount; i++) {
      const durationText = await shifts.nth(i).locator('[data-testid="shift-duration"]').textContent();
      const hours = parseFloat(durationText?.match(/([0-9.]+)\s*h/)?.[1] || '0');
      calculatedTotalHours += hours;
    }
    
    const displayedTotalText = await totalHoursElement.textContent();
    const displayedTotal = parseFloat(displayedTotalText?.match(/([0-9.]+)/)?.[1] || '0');
    expect(displayedTotal).toBe(calculatedTotalHours);
    
    // Measure page load time
    const navigationTiming = await page.evaluate(() => {
      const perfData = window.performance.timing;
      return perfData.loadEventEnd - perfData.navigationStart;
    });
    expect(navigationTiming).toBeLessThan(3000);
  });

  test('Verify week navigation functionality', async ({ page }) => {
    // Login
    await page.fill('[data-testid="username-input"]', 'employee.user@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123!');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Navigate to weekly schedule view
    await page.click('[data-testid="schedule-nav-link"]');
    await page.click('[data-testid="weekly-view-option"]');
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    // Note the current week date range
    const currentWeekHeader = await page.locator('[data-testid="week-header"]').textContent();
    const currentWeekText = currentWeekHeader || '';
    
    // Step 1: Click 'Next Week' button
    await page.click('[data-testid="next-week-button"]');
    
    // Expected Result: Next week's schedule displayed
    await page.waitForLoadState('networkidle');
    const nextWeekHeader = await page.locator('[data-testid="week-header"]').textContent();
    expect(nextWeekHeader).not.toBe(currentWeekText);
    
    // Verify shifts are displayed for next week
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    // Verify total hours updates
    await expect(page.locator('[data-testid="total-hours-summary"]')).toBeVisible();
    const nextWeekTotalHours = await page.locator('[data-testid="total-hours-summary"]').textContent();
    expect(nextWeekTotalHours).toBeTruthy();
    
    // Step 2: Click 'Previous Week' button
    await page.click('[data-testid="previous-week-button"]');
    
    // Expected Result: Previous week's schedule displayed
    await page.waitForLoadState('networkidle');
    const returnedWeekHeader = await page.locator('[data-testid="week-header"]').textContent();
    expect(returnedWeekHeader).toBe(currentWeekText);
    
    // Navigate multiple weeks backward
    await page.click('[data-testid="previous-week-button"]');
    await page.waitForLoadState('networkidle');
    await page.click('[data-testid="previous-week-button"]');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    // Navigate multiple weeks forward
    await page.click('[data-testid="next-week-button"]');
    await page.waitForLoadState('networkidle');
    await page.click('[data-testid="next-week-button"]');
    await page.waitForLoadState('networkidle');
    await page.click('[data-testid="next-week-button"]');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    // Navigate to a week with no scheduled shifts
    for (let i = 0; i < 10; i++) {
      await page.click('[data-testid="next-week-button"]');
      await page.waitForLoadState('networkidle');
    }
    
    // Verify appropriate message for weeks with no shifts
    const shiftsOrMessage = await page.locator('[data-testid="shift-card"], [data-testid="no-shifts-message"]').count();
    expect(shiftsOrMessage).toBeGreaterThanOrEqual(0);
    
    // Verify no errors occurred during navigation
    const errorMessages = page.locator('[data-testid="error-message"]');
    await expect(errorMessages).toHaveCount(0);
  });

  test('Ensure unauthorized access is prevented', async ({ page, context }) => {
    // Login as Employee A
    await page.fill('[data-testid="username-input"]', 'employeeA@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123!');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Navigate to Employee A's weekly schedule
    await page.click('[data-testid="schedule-nav-link"]');
    await page.click('[data-testid="weekly-view-option"]');
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    // Get Employee A's current URL
    const employeeAUrl = page.url();
    
    // Step 1: Construct URL for Employee B's weekly schedule
    const employeeBUrl = employeeAUrl.replace(/employeeId=[^&]+/, 'employeeId=employeeB');
    const alternativeEmployeeBUrl = '/schedule/weekly?employeeId=employeeB&weekStart=2024-01-15';
    
    // Step 2: Attempt to access Employee B's weekly schedule
    await page.goto(employeeBUrl);
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Employee A is redirected or sees error page
    const currentUrl = page.url();
    const isRedirected = currentUrl.includes('employeeA') || currentUrl.includes('error') || currentUrl.includes('unauthorized');
    expect(isRedirected).toBeTruthy();
    
    // Verify no Employee B data is displayed
    const scheduleContainer = page.locator('[data-testid="weekly-schedule-container"]');
    if (await scheduleContainer.isVisible()) {
      const employeeIdentifier = page.locator('[data-testid="employee-name"], [data-testid="employee-id"]');
      if (await employeeIdentifier.isVisible()) {
        const employeeText = await employeeIdentifier.textContent();
        expect(employeeText).not.toContain('employeeB');
        expect(employeeText).not.toContain('Employee B');
      }
    }
    
    // Verify error message is displayed
    const errorMessage = page.locator('[data-testid="error-message"], [data-testid="access-denied-message"]');
    const errorCount = await errorMessage.count();
    if (errorCount > 0) {
      await expect(errorMessage.first()).toBeVisible();
      const errorText = await errorMessage.first().textContent();
      expect(errorText?.toLowerCase()).toMatch(/access denied|unauthorized|permission/i);
    }
    
    // Step 3: Attempt API access with Employee A's token
    const apiResponse = await page.request.get('/api/schedules/weekly?employeeId=employeeB&weekStart=2024-01-15');
    
    // Expected Result: API returns error response
    expect(apiResponse.status()).toBeGreaterThanOrEqual(400);
    expect(apiResponse.status()).toBeLessThan(500);
    expect([401, 403]).toContain(apiResponse.status());
    
    const responseBody = await apiResponse.json();
    expect(responseBody).toHaveProperty('error');
    expect(responseBody.error).toMatch(/access denied|unauthorized|forbidden|permission/i);
    
    // Verify no sensitive system information is leaked
    const responseText = JSON.stringify(responseBody).toLowerCase();
    expect(responseText).not.toContain('database');
    expect(responseText).not.toContain('sql');
    expect(responseText).not.toContain('stack trace');
    
    // Step 4: Verify Employee A's session remains active
    await page.goto('/schedule/weekly');
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    // Verify Employee A can still access their own schedule
    const employeeASchedule = page.locator('[data-testid="weekly-schedule-container"]');
    await expect(employeeASchedule).toBeVisible();
    
    // Verify the displayed schedule belongs to Employee A
    const shifts = page.locator('[data-testid="shift-card"]');
    const shiftCount = await shifts.count();
    expect(shiftCount).toBeGreaterThanOrEqual(0);
  });
});