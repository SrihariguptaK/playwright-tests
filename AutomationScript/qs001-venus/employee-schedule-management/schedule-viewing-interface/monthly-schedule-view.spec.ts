import { test, expect } from '@playwright/test';

test.describe('Monthly Schedule View - Story 12', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_EMPLOYEE_EMAIL = 'employee.a@company.com';
  const VALID_EMPLOYEE_PASSWORD = 'Password123!';
  const EMPLOYEE_A_ID = '12345';
  const EMPLOYEE_B_ID = '67890';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate monthly schedule display (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the application login page
    await expect(page).toHaveURL(/.*login/);

    // Step 2: Enter valid employee credentials and click 'Login' button
    await page.fill('[data-testid="email-input"]', VALID_EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Wait for successful login and redirect
    await page.waitForURL(/.*dashboard|.*schedule/, { timeout: 5000 });

    // Step 3: Locate and click on 'Monthly View' option in the navigation menu
    await page.click('[data-testid="monthly-view-link"]');
    await page.waitForLoadState('networkidle');

    // Step 4: Verify that all scheduled shifts for the current month are visible on the calendar
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    const currentMonth = new Date().toLocaleString('default', { month: 'long', year: 'numeric' });
    await expect(page.locator('[data-testid="calendar-month-title"]')).toContainText(currentMonth.split(' ')[0]);
    
    // Verify calendar grid is displayed
    const calendarGrid = page.locator('[data-testid="calendar-grid"]');
    await expect(calendarGrid).toBeVisible();
    
    // Verify at least one shift is visible
    const shifts = page.locator('[data-testid="shift-item"]');
    await expect(shifts.first()).toBeVisible();

    // Step 5: Click on a date that has a scheduled shift
    const firstShift = shifts.first();
    await firstShift.click();

    // Step 6: Verify shift details are displayed in a popup or side panel
    const shiftDetailsPanel = page.locator('[data-testid="shift-details-panel"]');
    await expect(shiftDetailsPanel).toBeVisible();
    await expect(shiftDetailsPanel.locator('[data-testid="shift-time"]')).toBeVisible();
    await expect(shiftDetailsPanel.locator('[data-testid="shift-location"]')).toBeVisible();

    // Step 7: Close the shift details popup/panel by clicking the close button or clicking outside the panel
    await page.click('[data-testid="close-shift-details"]');
    await expect(shiftDetailsPanel).not.toBeVisible();

    // Step 8: Locate and click the 'Next Month' navigation button or arrow
    await page.click('[data-testid="next-month-button"]');
    await page.waitForLoadState('networkidle');

    // Step 9: Verify that shifts scheduled for the next month are displayed correctly
    const nextMonthTitle = page.locator('[data-testid="calendar-month-title"]');
    await expect(nextMonthTitle).toBeVisible();
    
    // Verify the month has changed
    const nextMonthText = await nextMonthTitle.textContent();
    expect(nextMonthText).not.toBe(currentMonth.split(' ')[0]);
    
    // Verify calendar is still displayed
    await expect(calendarGrid).toBeVisible();
  });

  test('Verify access control for monthly schedules (error-case)', async ({ page }) => {
    // Step 1: Login as Employee A
    await page.fill('[data-testid="email-input"]', VALID_EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL(/.*dashboard|.*schedule/, { timeout: 5000 });

    // Step 2: Navigate to the monthly schedule view
    await page.click('[data-testid="monthly-view-link"]');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();

    // Step 3: Attempt to modify the URL to access Employee B's monthly schedule
    const currentDate = new Date();
    const currentMonth = `${currentDate.getFullYear()}-${String(currentDate.getMonth() + 1).padStart(2, '0')}`;
    
    await page.goto(`${BASE_URL}/api/schedules/monthly?employeeId=${EMPLOYEE_B_ID}&month=${currentMonth}`);

    // Step 4: Verify that access is denied
    const responseBody = await page.textContent('body');
    expect(responseBody).toMatch(/access denied|unauthorized|forbidden|error/i);

    // Alternative: Try accessing via UI manipulation
    await page.goto(`${BASE_URL}/schedules/monthly?employeeId=${EMPLOYEE_B_ID}`);
    
    // Step 5: Verify that no schedule data for Employee B is visible or accessible
    const errorMessage = page.locator('[data-testid="error-message"]');
    const accessDeniedText = page.locator('text=/access denied|unauthorized|not authorized/i');
    
    const isErrorVisible = await errorMessage.isVisible().catch(() => false);
    const isAccessDeniedVisible = await accessDeniedText.isVisible().catch(() => false);
    
    expect(isErrorVisible || isAccessDeniedVisible).toBeTruthy();

    // Step 6: Check that Employee A is redirected back to their own schedule or an error page
    await page.waitForTimeout(1000);
    const currentUrl = page.url();
    expect(currentUrl).toMatch(/error|access-denied|schedules\/monthly(?!.*employeeId=${EMPLOYEE_B_ID})/);
  });

  test('Test responsiveness of monthly view on mobile (happy-path)', async ({ page, context }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 }); // iPhone SE dimensions

    // Step 1: Open the application URL in a mobile device browser
    await page.goto(`${BASE_URL}/login`);

    // Step 2: Enter valid employee credentials using the mobile keyboard and tap 'Login' button
    await page.fill('[data-testid="email-input"]', VALID_EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL(/.*dashboard|.*schedule/, { timeout: 5000 });

    // Step 3: Tap on 'Monthly View' option in the navigation menu (may be in a hamburger menu)
    const hamburgerMenu = page.locator('[data-testid="hamburger-menu"]');
    if (await hamburgerMenu.isVisible()) {
      await hamburgerMenu.click();
    }
    await page.click('[data-testid="monthly-view-link"]');
    await page.waitForLoadState('networkidle');

    // Step 4: Verify that the calendar grid is readable with dates and shift information visible without zooming
    const calendar = page.locator('[data-testid="monthly-calendar"]');
    await expect(calendar).toBeVisible();
    
    const calendarBoundingBox = await calendar.boundingBox();
    expect(calendarBoundingBox).not.toBeNull();
    expect(calendarBoundingBox!.width).toBeLessThanOrEqual(375);
    
    // Verify dates are visible
    const dateElements = page.locator('[data-testid="calendar-date"]');
    await expect(dateElements.first()).toBeVisible();
    
    // Verify shift information is visible
    const shiftElements = page.locator('[data-testid="shift-item"]');
    const firstShift = shiftElements.first();
    await expect(firstShift).toBeVisible();

    // Step 5: Tap on a date with a scheduled shift
    await firstShift.tap();

    // Step 6: Verify shift details panel opens
    const shiftDetailsPanel = page.locator('[data-testid="shift-details-panel"]');
    await expect(shiftDetailsPanel).toBeVisible();

    // Step 7: Scroll through the shift details if necessary
    await shiftDetailsPanel.evaluate(el => el.scrollTop = el.scrollHeight / 2);

    // Step 8: Close the shift details by tapping the close button or tapping outside the panel
    await page.click('[data-testid="close-shift-details"]');
    await expect(shiftDetailsPanel).not.toBeVisible();

    // Step 9: Use swipe gesture or tap navigation arrows to move to the next month
    await page.click('[data-testid="next-month-button"]');
    await page.waitForLoadState('networkidle');
    
    // Verify next month is displayed
    await expect(calendar).toBeVisible();

    // Step 10: Rotate the mobile device to landscape orientation
    await page.setViewportSize({ width: 667, height: 375 });
    await page.waitForTimeout(500);
    
    // Verify calendar is still visible and responsive in landscape
    await expect(calendar).toBeVisible();
    const landscapeBoundingBox = await calendar.boundingBox();
    expect(landscapeBoundingBox).not.toBeNull();
    expect(landscapeBoundingBox!.width).toBeLessThanOrEqual(667);

    // Step 11: Rotate back to portrait orientation
    await page.setViewportSize({ width: 375, height: 667 });
    await page.waitForTimeout(500);
    
    // Verify calendar is still visible and responsive in portrait
    await expect(calendar).toBeVisible();
    const portraitBoundingBox = await calendar.boundingBox();
    expect(portraitBoundingBox).not.toBeNull();
    expect(portraitBoundingBox!.width).toBeLessThanOrEqual(375);
  });
});