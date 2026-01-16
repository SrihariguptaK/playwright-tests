import { test, expect } from '@playwright/test';

test.describe('Weekly Schedule View - Employee Portal', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_EMPLOYEE_EMAIL = 'employee@company.com';
  const VALID_EMPLOYEE_PASSWORD = 'Password123!';
  const VALID_EMPLOYEE_ID = '12345';
  const OTHER_EMPLOYEE_ID = '67890';

  test.beforeEach(async ({ page }) => {
    // Set default timeout for all tests
    test.setTimeout(30000);
  });

  test('Validate weekly schedule display for logged-in employee (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the schedule portal login page
    await page.goto(`${BASE_URL}/login`);
    await expect(page).toHaveURL(/.*login/);

    // Step 2: Enter valid employee credentials and click 'Login' button
    await page.fill('[data-testid="email-input"]', VALID_EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Dashboard is displayed
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 5000 });
    await expect(page.locator('[data-testid="dashboard-container"]')).toBeVisible();

    // Step 3: Click on 'Weekly View' option from the navigation menu
    await page.click('[data-testid="weekly-view-link"]');
    
    // Expected Result: System displays all shifts for the week accurately
    await expect(page).toHaveURL(/.*weekly-view/);
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();

    // Step 4: Review all shifts displayed for the current week
    const shiftsContainer = page.locator('[data-testid="weekly-shifts-list"]');
    await expect(shiftsContainer).toBeVisible();
    
    // Step 5: Verify the current week is highlighted or indicated
    const currentWeekIndicator = page.locator('[data-testid="current-week-indicator"]');
    await expect(currentWeekIndicator).toBeVisible();
    await expect(currentWeekIndicator).toContainText(/current week/i);

    // Step 6: Count the total number of shifts displayed and verify against expected schedule
    const shiftElements = page.locator('[data-testid="shift-card"]');
    const shiftCount = await shiftElements.count();
    expect(shiftCount).toBeGreaterThan(0);
    
    // Verify shift details include start/end times, location, and role
    const firstShift = shiftElements.first();
    await expect(firstShift.locator('[data-testid="shift-time"]')).toBeVisible();
    await expect(firstShift.locator('[data-testid="shift-location"]')).toBeVisible();
    await expect(firstShift.locator('[data-testid="shift-role"]')).toBeVisible();

    // Step 7: Click on the 'Next Week' navigation button
    await page.click('[data-testid="next-week-button"]');
    
    // Expected Result: System displays shifts for the next week without errors
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    // Step 8: Verify the next week's schedule details
    const nextWeekShifts = page.locator('[data-testid="shift-card"]');
    await expect(nextWeekShifts.first()).toBeVisible();
    
    // Verify week indicator has changed
    const weekIndicator = page.locator('[data-testid="week-date-range"]');
    await expect(weekIndicator).toBeVisible();
  });

  test('Verify access control for weekly schedules (error-case)', async ({ page }) => {
    // Step 1: Navigate to weekly schedule view for own employee account
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', VALID_EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    await page.click('[data-testid="weekly-view-link"]');
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();

    // Step 2: Note the current URL structure displayed in the browser address bar
    const originalUrl = page.url();
    expect(originalUrl).toContain('weekly-view');

    // Step 3: Manually modify the URL by changing the employeeId parameter to another employee's ID
    const unauthorizedUrl = originalUrl.includes('employeeId') 
      ? originalUrl.replace(VALID_EMPLOYEE_ID, OTHER_EMPLOYEE_ID)
      : `${BASE_URL}/weekly-view?employeeId=${OTHER_EMPLOYEE_ID}`;
    
    await page.goto(unauthorizedUrl);

    // Expected Result: Access denied with authorization error
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible({ timeout: 5000 });
    await expect(errorMessage).toContainText(/access denied|unauthorized|not authorized/i);
    
    // Step 4: Verify that no schedule data for the other employee is visible
    const scheduleData = page.locator('[data-testid="weekly-shifts-list"]');
    await expect(scheduleData).not.toBeVisible();

    // Step 5: Attempt to use browser back button to return to own schedule
    await page.goBack();
    await page.waitForLoadState('networkidle');

    // Step 6: Click on 'Weekly View' from the navigation menu
    await page.click('[data-testid="weekly-view-link"]');
    
    // Expected Result: Schedule displayed correctly
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    // Step 7: Verify all weekly schedule details are correctly displayed
    const ownScheduleShifts = page.locator('[data-testid="shift-card"]');
    await expect(ownScheduleShifts.first()).toBeVisible();
    await expect(page.locator('[data-testid="week-date-range"]')).toBeVisible();
  });

  test('Test weekly view responsiveness on mobile (happy-path)', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });

    // Step 1: Open the mobile browser and navigate to the schedule portal login page
    await page.goto(`${BASE_URL}/login`);
    await expect(page).toHaveURL(/.*login/);

    // Step 2: Enter valid employee credentials and tap 'Login' button
    await page.fill('[data-testid="email-input"]', VALID_EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 3: Tap on 'Weekly View' option from the navigation menu
    await page.click('[data-testid="weekly-view-link"]');
    
    // Expected Result: Layout adjusts for readability and usability
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();

    // Step 4: Review the weekly schedule layout on the mobile screen
    const scheduleContainer = page.locator('[data-testid="weekly-schedule-container"]');
    const containerBox = await scheduleContainer.boundingBox();
    expect(containerBox).not.toBeNull();
    expect(containerBox!.width).toBeLessThanOrEqual(375);

    // Step 5: Scroll vertically through the weekly schedule
    await page.evaluate(() => window.scrollBy(0, 300));
    await page.waitForTimeout(500);
    await page.evaluate(() => window.scrollBy(0, 300));
    await page.waitForTimeout(500);

    // Step 6: Verify all shift details are clearly visible for each day
    const shiftCards = page.locator('[data-testid="shift-card"]');
    const firstShift = shiftCards.first();
    await firstShift.scrollIntoViewIfNeeded();
    await expect(firstShift.locator('[data-testid="shift-time"]')).toBeVisible();
    await expect(firstShift.locator('[data-testid="shift-location"]')).toBeVisible();
    await expect(firstShift.locator('[data-testid="shift-role"]')).toBeVisible();

    // Step 7: Tap on the 'Next Week' navigation button
    const nextWeekButton = page.locator('[data-testid="next-week-button"]');
    await nextWeekButton.scrollIntoViewIfNeeded();
    await nextWeekButton.click();
    
    // Expected Result: Navigation works smoothly on mobile
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();

    // Step 8: Tap on the 'Previous Week' navigation button
    const prevWeekButton = page.locator('[data-testid="previous-week-button"]');
    await prevWeekButton.scrollIntoViewIfNeeded();
    await prevWeekButton.click();
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();

    // Step 9: Rotate the device to landscape orientation
    await page.setViewportSize({ width: 667, height: 375 });
    await page.waitForTimeout(500);
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    // Verify layout adapts to landscape
    const landscapeContainer = page.locator('[data-testid="weekly-schedule-container"]');
    const landscapeBox = await landscapeContainer.boundingBox();
    expect(landscapeBox).not.toBeNull();
    expect(landscapeBox!.width).toBeLessThanOrEqual(667);

    // Step 10: Rotate the device back to portrait orientation
    await page.setViewportSize({ width: 375, height: 667 });
    await page.waitForTimeout(500);
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    // Verify layout adapts back to portrait
    const portraitContainer = page.locator('[data-testid="weekly-schedule-container"]');
    const portraitBox = await portraitContainer.boundingBox();
    expect(portraitBox).not.toBeNull();
    expect(portraitBox!.width).toBeLessThanOrEqual(375);
  });
});