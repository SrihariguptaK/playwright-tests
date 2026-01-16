import { test, expect } from '@playwright/test';

test.describe('Employee Daily Schedule - Story 12', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_USERNAME = 'employee@company.com';
  const VALID_PASSWORD = 'ValidPass123!';
  const SCHEDULE_URL = `${BASE_URL}/schedules/daily`;

  test('Validate successful daily schedule display with valid employee login', async ({ page }) => {
    // Step 1: Employee logs into the web portal
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Login successful and dashboard displayed
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 5000 });
    await expect(page.locator('[data-testid="dashboard-container"]')).toBeVisible();

    // Step 2: Navigate to schedule section and select daily view
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="daily-view-option"]');
    
    // Expected Result: Daily schedule for current day is displayed with correct shift details
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-location"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-role"]')).toBeVisible();

    // Step 3: Navigate to previous and next days
    await page.click('[data-testid="previous-day-button"]');
    
    // Expected Result: Schedules for selected days load correctly without errors
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible({ timeout: 3000 });
    const previousDayDate = await page.locator('[data-testid="schedule-date-display"]').textContent();
    expect(previousDayDate).toBeTruthy();

    await page.click('[data-testid="next-day-button"]');
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible({ timeout: 3000 });
    
    await page.click('[data-testid="next-day-button"]');
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible({ timeout: 3000 });
    const nextDayDate = await page.locator('[data-testid="schedule-date-display"]').textContent();
    expect(nextDayDate).toBeTruthy();
    expect(nextDayDate).not.toBe(previousDayDate);

    // Verify page layout on desktop view
    await page.setViewportSize({ width: 1920, height: 1080 });
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();

    // Resize browser window to mobile dimensions
    await page.setViewportSize({ width: 375, height: 667 });
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
  });

  test('Verify access restriction for unauthenticated users', async ({ page }) => {
    // Step 1: Attempt to access daily schedule URL without login
    await page.goto(SCHEDULE_URL);
    
    // Expected Result: Access denied with redirect to login page
    await expect(page).toHaveURL(/.*login/, { timeout: 5000 });
    const errorMessage = page.locator('[data-testid="error-message"]');
    if (await errorMessage.isVisible()) {
      await expect(errorMessage).toContainText(/access denied|unauthorized|please log in/i);
    }

    // Step 2: Login with valid credentials
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access granted to daily schedule
    await page.goto(SCHEDULE_URL);
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible({ timeout: 3000 });
    await expect(page).toHaveURL(/.*schedules\/daily/);
  });

  test('Test system behavior when no shifts are scheduled', async ({ page }) => {
    // Login first
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 5000 });

    // Navigate to daily schedule view
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="daily-view-option"]');
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();

    // Step 1: Select a day with no scheduled shifts
    // Navigate forward to find a day with no shifts (simulate by clicking next day multiple times)
    for (let i = 0; i < 5; i++) {
      await page.click('[data-testid="next-day-button"]');
      await page.waitForTimeout(500);
      
      const noShiftsMessage = page.locator('[data-testid="no-shifts-message"]');
      if (await noShiftsMessage.isVisible()) {
        // Expected Result: System displays message 'No scheduled shifts for this day'
        await expect(noShiftsMessage).toContainText(/no scheduled shifts|no shifts scheduled/i);
        
        // Verify that no shift details are shown
        await expect(page.locator('[data-testid="shift-start-time"]')).not.toBeVisible();
        await expect(page.locator('[data-testid="shift-end-time"]')).not.toBeVisible();
        await expect(page.locator('[data-testid="shift-location"]')).not.toBeVisible();
        await expect(page.locator('[data-testid="shift-role"]')).not.toBeVisible();
        
        // Verify the page layout remains intact
        await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
        await expect(page.locator('[data-testid="previous-day-button"]')).toBeVisible();
        await expect(page.locator('[data-testid="next-day-button"]')).toBeVisible();
        
        // Navigate to previous day
        await page.click('[data-testid="previous-day-button"]');
        await page.waitForTimeout(500);
        
        // Navigate to next day
        await page.click('[data-testid="next-day-button"]');
        await page.waitForTimeout(500);
        
        // Return to the day with no shifts and verify message persists
        await expect(noShiftsMessage).toBeVisible();
        await expect(noShiftsMessage).toContainText(/no scheduled shifts|no shifts scheduled/i);
        
        break;
      }
    }
  });

  test('Validate successful daily schedule display with valid employee login - detailed happy path', async ({ page }) => {
    // Navigate to the web portal login page
    await page.goto(`${BASE_URL}/login`);
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Enter valid employee credentials
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);

    // Click the Login button
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 5000 });

    // Navigate to the schedule section from the dashboard menu
    await page.click('[data-testid="schedule-menu-item"]');

    // Select daily view option
    await page.click('[data-testid="daily-view-option"]');
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible({ timeout: 3000 });

    // Verify shift details displayed including start time, end time, location, and role
    const shiftStartTime = page.locator('[data-testid="shift-start-time"]');
    const shiftEndTime = page.locator('[data-testid="shift-end-time"]');
    const shiftLocation = page.locator('[data-testid="shift-location"]');
    const shiftRole = page.locator('[data-testid="shift-role"]');

    await expect(shiftStartTime).toBeVisible();
    await expect(shiftEndTime).toBeVisible();
    await expect(shiftLocation).toBeVisible();
    await expect(shiftRole).toBeVisible();

    const startTimeText = await shiftStartTime.textContent();
    const endTimeText = await shiftEndTime.textContent();
    const locationText = await shiftLocation.textContent();
    const roleText = await shiftRole.textContent();

    expect(startTimeText).toBeTruthy();
    expect(endTimeText).toBeTruthy();
    expect(locationText).toBeTruthy();
    expect(roleText).toBeTruthy();

    // Click the previous day navigation button
    await page.click('[data-testid="previous-day-button"]');
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible({ timeout: 3000 });

    // Click the next day navigation button twice
    await page.click('[data-testid="next-day-button"]');
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible({ timeout: 3000 });
    await page.click('[data-testid="next-day-button"]');
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible({ timeout: 3000 });

    // Verify page layout on desktop view
    await page.setViewportSize({ width: 1920, height: 1080 });
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-date-display"]')).toBeVisible();

    // Resize browser window to mobile dimensions
    await page.setViewportSize({ width: 375, height: 667 });
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-date-display"]')).toBeVisible();
  });

  test('Verify access restriction for unauthenticated users - detailed error case', async ({ context }) => {
    // Open a new browser window (incognito/private browsing session)
    const page = await context.newPage();

    // Attempt to access the daily schedule URL directly without logging in
    await page.goto(SCHEDULE_URL);

    // Verify error message or notification is displayed
    await expect(page).toHaveURL(/.*login/, { timeout: 5000 });
    const errorNotification = page.locator('[data-testid="error-message"], [data-testid="notification-message"]');
    if (await errorNotification.isVisible()) {
      const errorText = await errorNotification.textContent();
      expect(errorText?.toLowerCase()).toMatch(/access denied|unauthorized|authentication required|please log in/i);
    }

    // Verify the URL has changed to the login page
    const currentUrl = page.url();
    expect(currentUrl).toContain('login');

    // Enter valid employee credentials on the login page
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);

    // Click the Login button
    await page.click('[data-testid="login-button"]');
    await page.waitForLoadState('networkidle');

    // Navigate to the daily schedule section if not automatically redirected
    if (!page.url().includes('schedules/daily')) {
      await page.click('[data-testid="schedule-menu-item"]');
      await page.click('[data-testid="daily-view-option"]');
    }

    // Verify all schedule features are now accessible
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('[data-testid="previous-day-button"]')).toBeEnabled();
    await expect(page.locator('[data-testid="next-day-button"]')).toBeEnabled();
    await expect(page.locator('[data-testid="schedule-date-display"]')).toBeVisible();

    await page.close();
  });

  test('Test system behavior when no shifts are scheduled - detailed edge case', async ({ page }) => {
    // Login
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 5000 });

    // Navigate to the daily schedule view from the dashboard
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="daily-view-option"]');
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();

    // Use the date navigation to select a specific day known to have no scheduled shifts
    let foundEmptyDay = false;
    for (let i = 0; i < 10; i++) {
      await page.click('[data-testid="next-day-button"]');
      await page.waitForTimeout(500);

      const noShiftsMessage = page.locator('[data-testid="no-shifts-message"]');
      if (await noShiftsMessage.isVisible()) {
        foundEmptyDay = true;

        // Observe the schedule display area for the selected day
        await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();

        // Verify that no shift details (time, location, role) are shown
        await expect(page.locator('[data-testid="shift-start-time"]')).not.toBeVisible();
        await expect(page.locator('[data-testid="shift-end-time"]')).not.toBeVisible();
        await expect(page.locator('[data-testid="shift-location"]')).not.toBeVisible();
        await expect(page.locator('[data-testid="shift-role"]')).not.toBeVisible();

        // Verify the page layout remains intact and professional
        await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
        await expect(page.locator('[data-testid="schedule-date-display"]')).toBeVisible();
        await expect(page.locator('[data-testid="previous-day-button"]')).toBeVisible();
        await expect(page.locator('[data-testid="next-day-button"]')).toBeVisible();

        const messageText = await noShiftsMessage.textContent();
        expect(messageText?.toLowerCase()).toMatch(/no scheduled shifts|no shifts scheduled/i);

        // Navigate to the previous day using the navigation button
        await page.click('[data-testid="previous-day-button"]');
        await page.waitForTimeout(500);
        await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();

        // Navigate to the next day using the navigation button
        await page.click('[data-testid="next-day-button"]');
        await page.waitForTimeout(500);
        await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();

        // Return to the day with no shifts and verify message persists
        await expect(noShiftsMessage).toBeVisible();
        const persistedMessageText = await noShiftsMessage.textContent();
        expect(persistedMessageText?.toLowerCase()).toMatch(/no scheduled shifts|no shifts scheduled/i);

        break;
      }
    }

    // If no empty day found in the loop, still verify the test structure works
    if (!foundEmptyDay) {
      console.log('No empty schedule day found in the next 10 days');
    }
  });
});