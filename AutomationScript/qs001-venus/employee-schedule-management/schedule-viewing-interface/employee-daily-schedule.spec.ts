import { test, expect } from '@playwright/test';

test.describe('Employee Daily Schedule - Story 12', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_USERNAME = 'employee.user@company.com';
  const VALID_PASSWORD = 'ValidPass123!';
  const OTHER_EMPLOYEE_ID = '99999';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate daily schedule display with valid employee login (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the web portal login page
    await expect(page).toHaveURL(/.*login/);
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Step 2: Enter valid employee credentials
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);

    // Step 3: Click the Login button
    await page.click('[data-testid="login-button"]');

    // Expected Result: Login successful and dashboard displayed
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 5000 });
    await expect(page.locator('[data-testid="dashboard-container"]')).toBeVisible();

    // Step 4: Navigate to the daily schedule page from the dashboard menu
    await page.click('[data-testid="schedule-menu-link"]');
    await expect(page).toHaveURL(/.*schedule/);

    // Step 5: Verify the daily schedule content for current day
    const scheduleContainer = page.locator('[data-testid="daily-schedule-container"]');
    await expect(scheduleContainer).toBeVisible({ timeout: 3000 });

    // Verify shift details are displayed
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-location"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-role"]')).toBeVisible();

    // Step 6: Verify the current day is highlighted in the calendar
    const currentDayHighlight = page.locator('[data-testid="current-day-highlight"]');
    await expect(currentDayHighlight).toBeVisible();
    await expect(currentDayHighlight).toHaveClass(/highlighted|active|current/);

    // Step 7: Click the 'Next Day' navigation button
    const startTime = Date.now();
    await page.click('[data-testid="next-day-button"]');

    // Expected Result: Schedule for next day is displayed without errors
    await expect(scheduleContainer).toBeVisible();
    const loadTime = Date.now() - startTime;

    // Step 8: Verify the schedule data for next day
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();

    // Step 9: Verify page load time is under 3 seconds
    expect(loadTime).toBeLessThan(3000);
  });

  test('Verify access restriction to schedules of other employees (error-case)', async ({ page }) => {
    // Step 1: Log into the web portal with valid employee credentials
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Wait for dashboard to load
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 5000 });

    // Step 2: Navigate to own daily schedule page and note the URL structure
    await page.click('[data-testid="schedule-menu-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();

    const originalUrl = page.url();

    // Step 3: Manually modify the URL to include another employee's ID
    const manipulatedUrl = originalUrl.includes('employeeId')
      ? originalUrl.replace(/employeeId=[^&]+/, `employeeId=${OTHER_EMPLOYEE_ID}`)
      : `${originalUrl}${originalUrl.includes('?') ? '&' : '?'}employeeId=${OTHER_EMPLOYEE_ID}`;

    // Step 4: Press Enter to attempt accessing the modified URL
    await page.goto(manipulatedUrl);

    // Expected Result: Access denied with appropriate error message
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible({ timeout: 3000 });
    await expect(errorMessage).toContainText(/access denied|unauthorized|forbidden|not authorized/i);

    // Step 5: Verify that no schedule data from the other employee is visible
    const otherEmployeeSchedule = page.locator(`[data-testid="schedule-employee-${OTHER_EMPLOYEE_ID}"]`);
    await expect(otherEmployeeSchedule).not.toBeVisible();

    // Step 6: Navigate back to own schedule using the navigation menu
    await page.click('[data-testid="schedule-menu-link"]');

    // Expected Result: Own schedule displays correctly
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
  });

  test('Test responsive design on mobile devices (happy-path)', async ({ page }) => {
    // Step 1: Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 }); // iPhone SE dimensions

    // Step 2: Navigate to the web portal URL
    await expect(page).toHaveURL(/.*login/);

    // Step 3: Enter valid employee credentials and log in
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Wait for dashboard
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 5000 });

    // Step 4: Navigate to the daily schedule page from the menu
    // On mobile, menu might be a hamburger menu
    const mobileMenuButton = page.locator('[data-testid="mobile-menu-button"]');
    if (await mobileMenuButton.isVisible()) {
      await mobileMenuButton.click();
    }
    await page.click('[data-testid="schedule-menu-link"]');

    // Step 5: Verify the schedule layout adapts to mobile screen size
    const scheduleContainer = page.locator('[data-testid="daily-schedule-container"]');
    await expect(scheduleContainer).toBeVisible();

    const containerBox = await scheduleContainer.boundingBox();
    expect(containerBox?.width).toBeLessThanOrEqual(375);

    // Step 6: Verify shift details are clearly visible
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-location"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-role"]')).toBeVisible();

    // Step 7: Tap the 'Next Day' navigation control
    await page.click('[data-testid="next-day-button"]');

    // Expected Result: Next day's schedule displays correctly on mobile
    await expect(scheduleContainer).toBeVisible();
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();

    // Step 8: Tap the 'Previous Day' navigation control
    await page.click('[data-testid="previous-day-button"]');

    // Expected Result: Navigation controls function properly with touch gestures
    await expect(scheduleContainer).toBeVisible();
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();

    // Step 9: Rotate device to landscape orientation
    await page.setViewportSize({ width: 667, height: 375 });

    // Verify layout still adapts correctly
    await expect(scheduleContainer).toBeVisible();
    const landscapeBox = await scheduleContainer.boundingBox();
    expect(landscapeBox?.width).toBeLessThanOrEqual(667);

    // Verify shift details remain visible in landscape
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time"]')).toBeVisible();
  });
});