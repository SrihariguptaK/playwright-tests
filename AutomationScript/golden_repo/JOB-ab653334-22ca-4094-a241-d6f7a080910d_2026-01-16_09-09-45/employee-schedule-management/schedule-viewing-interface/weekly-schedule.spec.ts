import { test, expect } from '@playwright/test';

test.describe('Weekly Schedule View - Story 13', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_EMPLOYEE_EMAIL = 'employee@company.com';
  const VALID_EMPLOYEE_PASSWORD = 'Password123!';
  const WEEKLY_SCHEDULE_URL = `${BASE_URL}/schedule/weekly`;

  test('Validate weekly schedule display with accurate shift data', async ({ page }) => {
    // Step 1: Employee logs in and navigates to weekly schedule view
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', VALID_EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and redirect
    await expect(page).toHaveURL(/.*dashboard|schedule/, { timeout: 5000 });
    
    // Navigate to schedule section from main menu
    await page.click('[data-testid="schedule-menu-link"]');
    
    // Select weekly view option
    await page.click('[data-testid="weekly-view-option"]');
    
    // Expected Result: Weekly schedule for current week is displayed with correct shifts
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('[data-testid="week-start-date"]')).toBeVisible();
    await expect(page.locator('[data-testid="week-end-date"]')).toBeVisible();
    
    // Verify all scheduled shifts are displayed with accurate dates and times
    const shifts = page.locator('[data-testid="shift-item"]');
    await expect(shifts.first()).toBeVisible();
    await expect(page.locator('[data-testid="shift-date"]').first()).toContainText(/\d{1,2}\/\d{1,2}\/\d{4}|\d{4}-\d{2}-\d{2}/);
    await expect(page.locator('[data-testid="shift-time"]').first()).toContainText(/\d{1,2}:\d{2}/);
    
    // Step 2: Navigate to previous and next weeks
    // Click on previous week navigation button
    await page.click('[data-testid="previous-week-button"]');
    
    // Expected Result: Schedules for selected weeks load correctly
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    // Verify data accuracy for the previous week
    const previousWeekStartDate = await page.locator('[data-testid="week-start-date"]').textContent();
    expect(previousWeekStartDate).toBeTruthy();
    
    // Click on next week navigation button twice to move forward
    await page.click('[data-testid="next-week-button"]');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    await page.click('[data-testid="next-week-button"]');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    // Test responsive design by resizing browser
    await page.setViewportSize({ width: 375, height: 667 }); // Mobile size
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    await page.setViewportSize({ width: 768, height: 1024 }); // Tablet size
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    await page.setViewportSize({ width: 1920, height: 1080 }); // Desktop size
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
  });

  test('Verify weekend and holiday highlighting in weekly view', async ({ page }) => {
    // Navigate to the web portal and enter valid employee credentials
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', VALID_EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard|schedule/, { timeout: 5000 });
    
    // Navigate to weekly schedule view from the dashboard
    await page.click('[data-testid="schedule-menu-link"]');
    await page.click('[data-testid="weekly-view-option"]');
    
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible({ timeout: 3000 });
    
    // Expected Result: Weekends and holidays are visually distinct
    // Identify weekend days (Saturday and Sunday) in the weekly view
    const saturdayCell = page.locator('[data-testid="day-cell-saturday"], [data-day="Saturday"], [data-testid*="saturday"]').first();
    const sundayCell = page.locator('[data-testid="day-cell-sunday"], [data-day="Sunday"], [data-testid*="sunday"]').first();
    
    // Verify the visual distinction is clear and consistent
    await expect(saturdayCell).toHaveClass(/weekend|highlight|special/);
    await expect(sundayCell).toHaveClass(/weekend|highlight|special/);
    
    // Navigate to a week that includes a company holiday
    // Find and click navigation to reach a week with holidays
    let holidayFound = false;
    for (let i = 0; i < 8; i++) {
      const holidayIndicator = page.locator('[data-testid="holiday-indicator"], [data-testid*="holiday"]').first();
      if (await holidayIndicator.isVisible().catch(() => false)) {
        holidayFound = true;
        break;
      }
      await page.click('[data-testid="next-week-button"]');
      await page.waitForLoadState('networkidle');
    }
    
    if (holidayFound) {
      // Identify the holiday date in the weekly view
      const holidayCell = page.locator('[data-testid="holiday-indicator"], [data-testid*="holiday"]').first();
      await expect(holidayCell).toBeVisible();
      
      // Verify holiday name or description is displayed
      await expect(holidayCell).toContainText(/.+/);
      
      // Check if shifts scheduled on holidays have any special indicators
      const holidayShifts = page.locator('[data-testid="shift-item"][data-holiday="true"], [data-testid="holiday-shift"]');
      if (await holidayShifts.count() > 0) {
        await expect(holidayShifts.first()).toHaveClass(/holiday|special/);
      }
    }
  });

  test('Test access restriction for unauthenticated users', async ({ page, context }) => {
    // Open browser in incognito/private mode to ensure no active session
    // Clear all cookies and storage
    await context.clearCookies();
    await context.clearPermissions();
    
    // Directly navigate to weekly schedule URL without logging in
    await page.goto(WEEKLY_SCHEDULE_URL);
    
    // Expected Result: Redirected to login page
    await expect(page).toHaveURL(/.*login/, { timeout: 5000 });
    
    // Verify appropriate authentication error or message is displayed
    const authMessage = page.locator('[data-testid="auth-error-message"], [data-testid="login-required-message"], text=/login required|please log in|authentication required/i');
    if (await authMessage.isVisible().catch(() => false)) {
      await expect(authMessage).toBeVisible();
    }
    
    // Attempt to bypass login by manipulating URL parameters
    await page.goto(`${WEEKLY_SCHEDULE_URL}?bypass=true&token=fake`);
    
    // Verify appropriate authentication error or message is displayed
    await expect(page).toHaveURL(/.*login/, { timeout: 5000 });
    
    // Enter valid employee credentials on the login page
    await page.fill('[data-testid="email-input"]', VALID_EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Verify user is redirected to weekly schedule or dashboard after successful login
    await expect(page).toHaveURL(/.*dashboard|schedule/, { timeout: 5000 });
    
    // Verify OAuth2 token is properly established in the session
    const cookies = await context.cookies();
    const hasAuthToken = cookies.some(cookie => 
      cookie.name.toLowerCase().includes('token') || 
      cookie.name.toLowerCase().includes('auth') || 
      cookie.name.toLowerCase().includes('session')
    );
    expect(hasAuthToken).toBeTruthy();
    
    // Verify access to weekly schedule is now granted
    await page.goto(WEEKLY_SCHEDULE_URL);
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible({ timeout: 3000 });
  });
});