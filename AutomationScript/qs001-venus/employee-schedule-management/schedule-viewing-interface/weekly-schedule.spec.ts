import { test, expect } from '@playwright/test';

test.describe('Weekly Schedule View - Story 8', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const EMPLOYEE_A_EMAIL = 'employee.a@company.com';
  const EMPLOYEE_A_PASSWORD = 'Password123!';
  const EMPLOYEE_B_ID = '789';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto(`${BASE_URL}/login`);
    
    // Login with valid employee credentials
    await page.fill('[data-testid="email-input"]', EMPLOYEE_A_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_A_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and dashboard load
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 5000 });
  });

  test('Validate weekly schedule display and navigation', async ({ page }) => {
    // Action: Employee navigates to weekly schedule
    await page.click('[data-testid="schedule-nav-link"]');
    await page.click('[data-testid="weekly-view-option"]');
    
    // Expected Result: Weekly schedule for current week displayed with all shifts
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    // Verify all 7 days are displayed
    const dayElements = page.locator('[data-testid="schedule-day"]');
    await expect(dayElements).toHaveCount(7);
    
    // Verify shifts are displayed
    const shiftElements = page.locator('[data-testid="shift-item"]');
    await expect(shiftElements.first()).toBeVisible();
    
    // Verify weekends and off days are highlighted distinctly
    const weekendDays = page.locator('[data-testid="schedule-day"][data-weekend="true"]');
    await expect(weekendDays.first()).toHaveClass(/weekend|highlighted/);
    
    const offDays = page.locator('[data-testid="schedule-day"][data-off-day="true"]');
    if (await offDays.count() > 0) {
      await expect(offDays.first()).toHaveClass(/off-day/);
    }
    
    // Action: Employee navigates to next week
    const currentWeekText = await page.locator('[data-testid="week-display"]').textContent();
    await page.click('[data-testid="next-week-button"]');
    
    // Expected Result: Schedule for next week displayed correctly
    await page.waitForTimeout(500);
    const nextWeekText = await page.locator('[data-testid="week-display"]').textContent();
    expect(nextWeekText).not.toBe(currentWeekText);
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    await expect(dayElements).toHaveCount(7);
    
    // Action: Employee navigates to previous week (twice to go before original week)
    await page.click('[data-testid="previous-week-button"]');
    await page.waitForTimeout(500);
    await page.click('[data-testid="previous-week-button"]');
    
    // Expected Result: Schedule for previous week displayed correctly
    await page.waitForTimeout(500);
    const previousWeekText = await page.locator('[data-testid="week-display"]').textContent();
    expect(previousWeekText).not.toBe(currentWeekText);
    expect(previousWeekText).not.toBe(nextWeekText);
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    await expect(dayElements).toHaveCount(7);
    
    // Navigate back to current week
    await page.click('[data-testid="next-week-button"]');
    await page.waitForTimeout(500);
    const returnedWeekText = await page.locator('[data-testid="week-display"]').textContent();
    expect(returnedWeekText).toBe(currentWeekText);
  });

  test('Verify access control for weekly schedule', async ({ page }) => {
    // Navigate to weekly schedule view
    await page.click('[data-testid="schedule-nav-link"]');
    await page.click('[data-testid="weekly-view-option"]');
    
    // Wait for schedule to load
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    // Note the current URL pattern
    const currentUrl = page.url();
    
    // Action: Attempt to modify URL to access Employee B's weekly schedule
    let unauthorizedUrl: string;
    if (currentUrl.includes('employeeId=')) {
      unauthorizedUrl = currentUrl.replace(/employeeId=\d+/, `employeeId=${EMPLOYEE_B_ID}`);
    } else if (currentUrl.includes('/employee/')) {
      unauthorizedUrl = currentUrl.replace(/\/employee\/\d+/, `/employee/${EMPLOYEE_B_ID}`);
    } else {
      // Construct URL with employee ID parameter
      unauthorizedUrl = `${currentUrl}${currentUrl.includes('?') ? '&' : '?'}employeeId=${EMPLOYEE_B_ID}`;
    }
    
    await page.goto(unauthorizedUrl);
    
    // Expected Result: Access denied with error message
    const errorMessage = page.locator('[data-testid="error-message"]');
    const accessDeniedMessage = page.locator('text=/access denied|unauthorized|forbidden/i');
    
    // Verify error message is displayed
    await expect(errorMessage.or(accessDeniedMessage)).toBeVisible({ timeout: 5000 });
    
    // Verify no schedule data from Employee B is visible
    const scheduleContainer = page.locator('[data-testid="weekly-schedule-container"]');
    if (await scheduleContainer.isVisible()) {
      // If container is visible, verify it shows error state, not actual schedule data
      const shiftItems = page.locator('[data-testid="shift-item"]');
      await expect(shiftItems).toHaveCount(0);
    }
    
    // Navigate back to schedule section through menu
    await page.click('[data-testid="schedule-nav-link"]');
    await page.click('[data-testid="weekly-view-option"]');
    
    // Expected Result: Employee A can still access their own weekly schedule normally
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    const dayElements = page.locator('[data-testid="schedule-day"]');
    await expect(dayElements).toHaveCount(7);
    const shiftElements = page.locator('[data-testid="shift-item"]');
    if (await shiftElements.count() > 0) {
      await expect(shiftElements.first()).toBeVisible();
    }
  });

  test('Test weekly schedule loading performance', async ({ page }) => {
    // Clear cache by using a new context (handled by Playwright by default per test)
    
    // Navigate to Schedule section and measure load time
    await page.click('[data-testid="schedule-nav-link"]');
    
    // Start performance measurement
    const startTime = Date.now();
    
    // Action: Click on Weekly View option
    await page.click('[data-testid="weekly-view-option"]');
    
    // Wait for weekly schedule to fully render with all 7 days visible
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    const dayElements = page.locator('[data-testid="schedule-day"]');
    await expect(dayElements).toHaveCount(7);
    
    // Wait for all shifts to load
    await page.waitForLoadState('networkidle', { timeout: 5000 });
    
    const loadTime = Date.now() - startTime;
    
    // Expected Result: Schedule loads within 3 seconds (3000ms)
    expect(loadTime).toBeLessThan(3000);
    console.log(`Initial weekly schedule load time: ${loadTime}ms`);
    
    // Refresh the weekly schedule view and measure load time again
    const refreshStartTime = Date.now();
    await page.reload();
    
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    await expect(dayElements).toHaveCount(7);
    await page.waitForLoadState('networkidle', { timeout: 5000 });
    
    const refreshLoadTime = Date.now() - refreshStartTime;
    expect(refreshLoadTime).toBeLessThan(3000);
    console.log(`Refresh weekly schedule load time: ${refreshLoadTime}ms`);
    
    // Navigate to next week and measure load time
    const nextWeekStartTime = Date.now();
    await page.click('[data-testid="next-week-button"]');
    
    await page.waitForLoadState('networkidle', { timeout: 5000 });
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    await expect(dayElements).toHaveCount(7);
    
    const nextWeekLoadTime = Date.now() - nextWeekStartTime;
    expect(nextWeekLoadTime).toBeLessThan(3000);
    console.log(`Next week schedule load time: ${nextWeekLoadTime}ms`);
  });

  test.afterEach(async ({ page }) => {
    // Logout after each test
    const logoutButton = page.locator('[data-testid="logout-button"]');
    if (await logoutButton.isVisible()) {
      await logoutButton.click();
    }
  });
});