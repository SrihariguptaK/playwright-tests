import { test, expect } from '@playwright/test';

test.describe('Employee Daily Schedule - Story 11', () => {
  const BASE_URL = 'https://portal.company.com';
  const VALID_USERNAME = 'employee@company.com';
  const VALID_PASSWORD = 'ValidPass123!';
  const SCHEDULE_URL = `${BASE_URL}/schedules/daily`;

  test('Validate successful display of daily schedule (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the web portal login page using a supported browser
    await page.goto(`${BASE_URL}/login`);
    await expect(page).toHaveURL(/.*login/);

    // Step 2: Enter valid employee credentials and click the Login button
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Expected Result: Dashboard is fully loaded and displays navigation menu
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="navigation-menu"]')).toBeVisible();
    await expect(page.locator('[data-testid="dashboard-content"]')).toBeVisible();

    // Step 3: Click on the 'Schedule' section from the navigation menu
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page.locator('[data-testid="schedule-section"]')).toBeVisible();

    // Step 4: Select 'Daily View' option
    await page.click('[data-testid="daily-view-option"]');

    // Expected Result: Daily schedule for current day is displayed
    await expect(page).toHaveURL(/.*schedules\/daily/);
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();

    // Step 5: Review the displayed shift details including shift start time, shift end time, location, and role
    const shiftStartTime = page.locator('[data-testid="shift-start-time"]');
    const shiftEndTime = page.locator('[data-testid="shift-end-time"]');
    const shiftLocation = page.locator('[data-testid="shift-location"]');
    const shiftRole = page.locator('[data-testid="shift-role"]');

    // Expected Result: Shift times, location, and role are correctly shown
    await expect(shiftStartTime).toBeVisible();
    await expect(shiftEndTime).toBeVisible();
    await expect(shiftLocation).toBeVisible();
    await expect(shiftRole).toBeVisible();

    // Verify the shift details contain valid data
    await expect(shiftStartTime).not.toBeEmpty();
    await expect(shiftEndTime).not.toBeEmpty();
    await expect(shiftLocation).not.toBeEmpty();
    await expect(shiftRole).not.toBeEmpty();

    // Step 6: Verify the page layout and readability of schedule information
    const scheduleHeader = page.locator('[data-testid="schedule-header"]');
    await expect(scheduleHeader).toBeVisible();
    await expect(scheduleHeader).toContainText(/Schedule/);
  });

  test('Verify navigation to previous and next days (happy-path)', async ({ page }) => {
    // Login and navigate to daily schedule
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.click('[data-testid="schedule-nav-link"]');
    await page.click('[data-testid="daily-view-option"]');

    // Step 1: Verify the current date is displayed in the schedule header
    const dateHeader = page.locator('[data-testid="schedule-date-header"]');
    await expect(dateHeader).toBeVisible();
    const currentDateText = await dateHeader.textContent();
    expect(currentDateText).toBeTruthy();

    // Step 2: Locate and click the 'Next Day' button or right arrow navigation control
    const startTime = Date.now();
    await page.click('[data-testid="next-day-button"]');

    // Step 3: Verify the date header has updated to show the next day's date
    await expect(dateHeader).toBeVisible();
    const nextDayText = await dateHeader.textContent();
    expect(nextDayText).not.toBe(currentDateText);

    // Expected Result: Schedule for next day is displayed
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();

    // Step 4: Review the shift details for the next day
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time"]')).toBeVisible();

    // Verify page load time is under 3 seconds
    let loadTime = Date.now() - startTime;
    expect(loadTime).toBeLessThan(3000);

    // Step 5: Click the 'Previous Day' button or left arrow navigation control
    const prevStartTime = Date.now();
    await page.click('[data-testid="previous-day-button"]');

    // Step 6: Verify the date header has updated to show the previous day's date
    await expect(dateHeader).toBeVisible();
    const backToCurrentText = await dateHeader.textContent();
    expect(backToCurrentText).toBe(currentDateText);

    // Expected Result: Schedule for previous day is displayed
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();

    // Verify page load time is under 3 seconds
    loadTime = Date.now() - prevStartTime;
    expect(loadTime).toBeLessThan(3000);

    // Step 7: Click 'Previous Day' button again to navigate to the day before current day
    const prevDayStartTime = Date.now();
    await page.click('[data-testid="previous-day-button"]');

    // Verify the date has changed
    await expect(dateHeader).toBeVisible();
    const dayBeforeText = await dateHeader.textContent();
    expect(dayBeforeText).not.toBe(currentDateText);

    // Step 8: Verify no errors occur during navigation and page load time remains under 3 seconds
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    loadTime = Date.now() - prevDayStartTime;
    expect(loadTime).toBeLessThan(3000);

    // Verify no error messages are displayed
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).not.toBeVisible();
  });

  test('Ensure access is restricted to authenticated employees (error-case)', async ({ page, context }) => {
    // Step 1: Open a new browser window or incognito/private browsing session
    // Step 2: Directly navigate to the daily schedule URL without logging in
    await page.goto(SCHEDULE_URL);

    // Step 3: Verify that an appropriate error message is displayed
    // Expected Result: Access denied message is displayed
    const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
    const loginPrompt = page.locator('[data-testid="login-required-message"]');
    const errorContainer = page.locator('[data-testid="error-container"]');

    // Check for various possible authentication error indicators
    const isRedirectedToLogin = page.url().includes('/login');
    const hasAccessDeniedMessage = await accessDeniedMessage.isVisible().catch(() => false);
    const hasLoginPrompt = await loginPrompt.isVisible().catch(() => false);
    const hasErrorContainer = await errorContainer.isVisible().catch(() => false);

    expect(isRedirectedToLogin || hasAccessDeniedMessage || hasLoginPrompt || hasErrorContainer).toBeTruthy();

    // Step 4: Verify that no schedule data is visible or accessible in the page source or network responses
    const scheduleContainer = page.locator('[data-testid="daily-schedule-container"]');
    await expect(scheduleContainer).not.toBeVisible();

    const shiftDetails = page.locator('[data-testid="shift-start-time"]');
    await expect(shiftDetails).not.toBeVisible();

    // Step 5: Navigate to the login page and enter valid employee credentials
    if (!isRedirectedToLogin) {
      await page.goto(`${BASE_URL}/login`);
    }

    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);

    // Step 6: Click the Login button to authenticate
    await page.click('[data-testid="login-button"]');

    // Wait for authentication to complete
    await page.waitForURL(/.*dashboard|.*schedules/, { timeout: 5000 });

    // Step 7: Navigate to daily schedule if not already there
    if (!page.url().includes('/schedules/daily')) {
      await page.click('[data-testid="schedule-nav-link"]');
      await page.click('[data-testid="daily-view-option"]');
    }

    // Expected Result: Daily schedule is now accessible and displays correctly
    await expect(page).toHaveURL(/.*schedules\/daily/);
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-location"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-role"]')).toBeVisible();

    // Step 8: Verify the authentication token is present in the session
    const cookies = await context.cookies();
    const hasAuthToken = cookies.some(cookie => 
      cookie.name.toLowerCase().includes('auth') || 
      cookie.name.toLowerCase().includes('token') ||
      cookie.name.toLowerCase().includes('session')
    );
    expect(hasAuthToken).toBeTruthy();
  });
});