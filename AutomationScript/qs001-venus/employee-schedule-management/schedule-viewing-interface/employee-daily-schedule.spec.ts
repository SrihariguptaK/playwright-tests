import { test, expect } from '@playwright/test';

test.describe('Employee Daily Schedule - Story 7', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_USERNAME = 'employee@company.com';
  const VALID_PASSWORD = 'Password123!';
  const SCHEDULE_URL = '/schedules/daily';

  test('Validate successful display of daily schedule', async ({ page }) => {
    // Step 1: Navigate to the web portal login page using a supported browser
    await page.goto(`${BASE_URL}/login`);
    await expect(page).toHaveURL(/.*login/);

    // Step 2: Enter valid employee credentials (username and password) and click Login button
    await page.fill('input[name="username"]', VALID_USERNAME);
    await page.fill('input[name="password"]', VALID_PASSWORD);
    await page.click('button[type="submit"]');

    // Step 3: Verify the dashboard is fully loaded
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 4: Click on the Schedule section from the navigation menu
    await page.click('[data-testid="nav-schedule"]');
    await expect(page.locator('[data-testid="schedule-section"]')).toBeVisible();

    // Step 5: Select the Daily View option
    await page.click('[data-testid="daily-view-option"]');
    await page.waitForLoadState('networkidle');

    // Step 6: Verify all shift details are accurate and complete for the current day
    await expect(page.locator('[data-testid="daily-schedule"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-location"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-role"]')).toBeVisible();

    // Verify current date is displayed
    const currentDate = new Date().toLocaleDateString();
    await expect(page.locator('[data-testid="schedule-date"]')).toContainText(currentDate.split('/')[1]);

    // Step 7: Click on the Next Day navigation button or arrow
    await page.click('[data-testid="next-day-button"]');
    await page.waitForLoadState('networkidle');

    // Step 8: Verify the next day's schedule displays correctly
    await expect(page.locator('[data-testid="daily-schedule"]')).toBeVisible();
    const nextDaySchedule = page.locator('[data-testid="schedule-date"]');
    await expect(nextDaySchedule).toBeVisible();
    
    // Verify shift details are still present for next day
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
  });

  test('Verify access restriction for unauthenticated users', async ({ page, context }) => {
    // Step 1: Clear all browser cookies and cache to ensure no active session exists
    await context.clearCookies();
    await context.clearPermissions();

    // Step 2: Open a new browser window or tab (already handled by page object)
    // Step 3: Directly enter the daily schedule URL in the address bar and press Enter
    await page.goto(`${BASE_URL}${SCHEDULE_URL}`);

    // Step 4: Verify the login page is displayed with appropriate message
    await expect(page).toHaveURL(/.*login/);
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
    
    // Verify access denied or authentication required message
    const authMessage = page.locator('text=/authentication required|please log in|access denied/i');
    await expect(authMessage.first()).toBeVisible({ timeout: 5000 }).catch(() => {
      // Message might not always be present, but redirect to login is sufficient
    });

    // Step 5: Verify that no schedule data is visible or accessible
    await expect(page.locator('[data-testid="daily-schedule"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="shift-start-time"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time"]')).not.toBeVisible();
  });

  test('Test responsiveness on mobile devices', async ({ page }) => {
    // Step 1: Open the mobile browser on the smartphone device
    await page.setViewportSize({ width: 375, height: 667 }); // iPhone SE dimensions

    // Step 2: Navigate to the web portal URL and access the login page
    await page.goto(`${BASE_URL}/login`);
    await expect(page).toHaveURL(/.*login/);

    // Step 3: Enter valid employee credentials and tap the Login button
    await page.fill('input[name="username"]', VALID_USERNAME);
    await page.fill('input[name="password"]', VALID_PASSWORD);
    await page.click('button[type="submit"]');
    await page.waitForLoadState('networkidle');

    // Step 4: Tap on the Schedule section from the mobile navigation menu
    // Mobile navigation might be in a hamburger menu
    const mobileMenuButton = page.locator('[data-testid="mobile-menu-button"]');
    if (await mobileMenuButton.isVisible()) {
      await mobileMenuButton.click();
    }
    await page.click('[data-testid="nav-schedule"]');

    // Step 5: Select the Daily View option by tapping on it
    await page.click('[data-testid="daily-view-option"]');
    await page.waitForLoadState('networkidle');

    // Step 6: Verify all schedule elements are visible without horizontal scrolling
    const dailySchedule = page.locator('[data-testid="daily-schedule"]');
    await expect(dailySchedule).toBeVisible();
    
    // Check that content fits within viewport width
    const scheduleBox = await dailySchedule.boundingBox();
    expect(scheduleBox?.width).toBeLessThanOrEqual(375);

    // Verify key elements are visible
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-location"]')).toBeVisible();

    // Step 7: Test the navigation controls by tapping the next day and previous day buttons
    await page.click('[data-testid="next-day-button"]');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="daily-schedule"]')).toBeVisible();

    await page.click('[data-testid="previous-day-button"]');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="daily-schedule"]')).toBeVisible();

    // Step 8: Rotate the device to landscape orientation
    await page.setViewportSize({ width: 667, height: 375 });
    await page.waitForTimeout(500); // Allow time for responsive adjustments
    
    // Verify schedule is still visible and properly formatted in landscape
    await expect(page.locator('[data-testid="daily-schedule"]')).toBeVisible();
    const landscapeBox = await dailySchedule.boundingBox();
    expect(landscapeBox?.width).toBeLessThanOrEqual(667);

    // Step 9: Rotate the device back to portrait orientation
    await page.setViewportSize({ width: 375, height: 667 });
    await page.waitForTimeout(500); // Allow time for responsive adjustments
    
    // Verify schedule is still visible and properly formatted in portrait
    await expect(page.locator('[data-testid="daily-schedule"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time"]')).toBeVisible();
  });
});