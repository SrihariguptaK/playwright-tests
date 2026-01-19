import { test, expect } from '@playwright/test';

test.describe('Weekly Schedule - Employee View', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_USERNAME = process.env.TEST_USERNAME || 'employee@company.com';
  const VALID_PASSWORD = process.env.TEST_PASSWORD || 'Test123!';

  test('Validate weekly schedule display and navigation', async ({ page }) => {
    // Step 1: Navigate to the web portal login page
    await page.goto(`${BASE_URL}/login`);
    await expect(page).toHaveURL(/.*login/);

    // Step 2: Enter valid employee credentials and click Login button
    await page.fill('input[name="username"]', VALID_USERNAME);
    await page.fill('input[name="password"]', VALID_PASSWORD);
    await page.click('button[type="submit"]');

    // Step 3: Verify the dashboard is fully loaded with all navigation elements visible
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('nav')).toBeVisible();
    await expect(page.locator('[data-testid="navigation-menu"]')).toBeVisible();

    // Step 4: Click on the Schedule section from the navigation menu
    await page.click('text=Schedule');
    await page.waitForLoadState('networkidle');

    // Step 5: Select the Weekly View option
    await page.click('[data-testid="weekly-view-button"]');
    await page.waitForLoadState('networkidle');

    // Step 6: Verify the weekly schedule displays all scheduled shifts with complete details
    await expect(page.locator('[data-testid="weekly-schedule"]')).toBeVisible();
    const shifts = page.locator('[data-testid="shift-item"]');
    await expect(shifts.first()).toBeVisible();
    
    // Verify shift details are present
    const firstShift = shifts.first();
    await expect(firstShift.locator('[data-testid="shift-time"]')).toBeVisible();
    await expect(firstShift.locator('[data-testid="shift-location"]')).toBeVisible();

    // Step 7: Verify weekends are highlighted or visually distinguished
    const weekendDays = page.locator('[data-testid="weekend-day"]');
    const weekendCount = await weekendDays.count();
    expect(weekendCount).toBeGreaterThanOrEqual(2);

    // Step 8: Verify any holidays in the current week are appropriately marked
    const holidays = page.locator('[data-testid="holiday-marker"]');
    if (await holidays.count() > 0) {
      await expect(holidays.first()).toBeVisible();
    }

    // Step 9: Click on the Next Week navigation button
    await page.click('[data-testid="next-week-button"]');
    await page.waitForLoadState('networkidle');

    // Step 10: Verify the next week's schedule displays correctly
    await expect(page.locator('[data-testid="weekly-schedule"]')).toBeVisible();
    const nextWeekShifts = page.locator('[data-testid="shift-item"]');
    await expect(nextWeekShifts.first()).toBeVisible();

    // Step 11: Click on the Previous Week navigation button to return
    await page.click('[data-testid="previous-week-button"]');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="weekly-schedule"]')).toBeVisible();
  });

  test('Verify access control for weekly schedule', async ({ page, context }) => {
    // Step 1: Clear all browser cookies, cache, and session data
    await context.clearCookies();
    await context.clearPermissions();

    // Step 2: Open a new browser window (already in incognito mode via context)
    // Step 3: Directly enter the weekly schedule URL
    await page.goto(`${BASE_URL}/schedules/weekly`);

    // Step 4: Verify the login page is displayed
    await expect(page).toHaveURL(/.*login/, { timeout: 10000 });
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Step 5: Verify no schedule data or sensitive information is visible
    await expect(page.locator('[data-testid="weekly-schedule"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="shift-item"]')).not.toBeVisible();

    // Step 6: Check the browser address bar for the current URL
    const currentUrl = page.url();
    expect(currentUrl).toContain('login');
    expect(currentUrl).not.toContain('schedules/weekly');
  });

  test('Test UI responsiveness on tablet devices', async ({ page }) => {
    // Set tablet viewport (iPad dimensions)
    await page.setViewportSize({ width: 768, height: 1024 });

    // Step 1: Navigate to the web portal URL
    await page.goto(`${BASE_URL}/login`);

    // Step 2: Enter valid employee credentials using on-screen keyboard and tap Login
    await page.fill('input[name="username"]', VALID_USERNAME);
    await page.fill('input[name="password"]', VALID_PASSWORD);
    await page.click('button[type="submit"]');

    // Step 3: Verify dashboard loads
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible({ timeout: 10000 });

    // Step 4: Tap on the Schedule section from the navigation menu
    await page.click('text=Schedule');
    await page.waitForLoadState('networkidle');

    // Step 5: Select the Weekly View option by tapping
    await page.click('[data-testid="weekly-view-button"]');
    await page.waitForLoadState('networkidle');

    // Step 6: Verify the entire week is visible without horizontal scrolling
    const weeklySchedule = page.locator('[data-testid="weekly-schedule"]');
    await expect(weeklySchedule).toBeVisible();
    
    const scheduleBox = await weeklySchedule.boundingBox();
    expect(scheduleBox?.width).toBeLessThanOrEqual(768);

    // Step 7: Verify all shift information is readable
    const shifts = page.locator('[data-testid="shift-item"]');
    const firstShift = shifts.first();
    await expect(firstShift.locator('[data-testid="shift-time"]')).toBeVisible();
    await expect(firstShift.locator('[data-testid="shift-location"]')).toBeVisible();
    
    const shiftTime = firstShift.locator('[data-testid="shift-time"]');
    const fontSize = await shiftTime.evaluate(el => window.getComputedStyle(el).fontSize);
    const fontSizeNum = parseInt(fontSize);
    expect(fontSizeNum).toBeGreaterThanOrEqual(12);

    // Step 8: Test next week navigation
    await page.click('[data-testid="next-week-button"]');
    await page.waitForLoadState('networkidle');
    await expect(weeklySchedule).toBeVisible();

    // Step 9: Test previous week navigation
    await page.click('[data-testid="previous-week-button"]');
    await page.waitForLoadState('networkidle');
    await expect(weeklySchedule).toBeVisible();

    // Step 10: Rotate tablet to landscape orientation
    await page.setViewportSize({ width: 1024, height: 768 });
    await page.waitForTimeout(500);

    // Step 11: Verify all schedule elements remain accessible in landscape
    await expect(weeklySchedule).toBeVisible();
    await expect(shifts.first()).toBeVisible();
    await expect(page.locator('[data-testid="next-week-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="previous-week-button"]')).toBeVisible();

    const landscapeBox = await weeklySchedule.boundingBox();
    expect(landscapeBox?.width).toBeLessThanOrEqual(1024);

    // Step 12: Rotate back to portrait orientation
    await page.setViewportSize({ width: 768, height: 1024 });
    await page.waitForTimeout(500);
    await expect(weeklySchedule).toBeVisible();
  });
});