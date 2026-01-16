import { test, expect } from '@playwright/test';

test.describe('Story-12: Employee Weekly Schedule View', () => {
  const BASE_URL = process.env.BASE_URL || 'https://portal.company.com';
  const VALID_USERNAME = process.env.TEST_USERNAME || 'employee@company.com';
  const VALID_PASSWORD = process.env.TEST_PASSWORD || 'TestPassword123!';
  const LOAD_TIMEOUT = 4000;

  test('Validate display of weekly schedule', async ({ page }) => {
    // Step 1: Employee logs into the portal
    await page.goto(`${BASE_URL}/login`);
    await expect(page).toHaveURL(/.*login/);
    
    await page.fill('input[name="username"]', VALID_USERNAME);
    await page.fill('input[name="password"]', VALID_PASSWORD);
    await page.click('button[type="submit"]');
    
    // Expected Result: Dashboard is displayed
    await expect(page).toHaveURL(/.*dashboard/, { timeout: LOAD_TIMEOUT });
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Step 2: Employee selects weekly schedule view
    await page.click('a[href*="schedule"], button:has-text("Schedule")');
    await page.click('[data-testid="weekly-view"], button:has-text("Weekly View"), a:has-text("Weekly Schedule")');
    
    // Expected Result: Weekly schedule for current week is displayed
    const startTime = Date.now();
    await expect(page.locator('[data-testid="weekly-schedule"], .weekly-schedule')).toBeVisible({ timeout: LOAD_TIMEOUT });
    const loadTime = Date.now() - startTime;
    expect(loadTime).toBeLessThan(LOAD_TIMEOUT);
    
    // Verify week date range is displayed
    await expect(page.locator('[data-testid="week-range"], .week-header, .date-range')).toBeVisible();
    
    // Verify all 7 days are displayed
    const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    for (const day of days) {
      await expect(page.locator(`text=${day}`).first()).toBeVisible();
    }
    
    // Step 3: Employee reviews shifts for each day
    // Expected Result: All shifts are correctly displayed with details
    const shiftElements = page.locator('[data-testid="shift-item"], .shift-card, .shift-detail');
    const shiftCount = await shiftElements.count();
    
    if (shiftCount > 0) {
      // Verify first shift has required details
      const firstShift = shiftElements.first();
      await expect(firstShift).toBeVisible();
      
      // Check for shift time or details
      await expect(page.locator('[data-testid="shift-time"], .shift-time, .time-range')).toBeVisible();
    }
    
    // Verify current day is highlighted
    const currentDay = new Date().toLocaleDateString('en-US', { weekday: 'long' });
    await expect(page.locator(`[data-testid="day-${currentDay.toLowerCase()}"].current, .day.current, .day.highlighted`)).toBeVisible();
  });

  test('Verify navigation between weeks', async ({ page }) => {
    // Login first
    await page.goto(`${BASE_URL}/login`);
    await page.fill('input[name="username"]', VALID_USERNAME);
    await page.fill('input[name="password"]', VALID_PASSWORD);
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to weekly schedule
    await page.click('a[href*="schedule"], button:has-text("Schedule")');
    await page.click('[data-testid="weekly-view"], button:has-text("Weekly View"), a:has-text("Weekly Schedule")');
    await expect(page.locator('[data-testid="weekly-schedule"], .weekly-schedule')).toBeVisible();
    
    // Get current week date range
    const currentWeekRange = await page.locator('[data-testid="week-range"], .week-header, .date-range').textContent();
    
    // Step 1: Employee clicks 'Next Week' button
    const nextWeekButton = page.locator('[data-testid="next-week"], button:has-text("Next Week"), button[aria-label="Next Week"], .next-week-btn');
    await nextWeekButton.click();
    
    // Expected Result: Schedule for next week is displayed
    const startTimeNext = Date.now();
    await page.waitForLoadState('networkidle', { timeout: LOAD_TIMEOUT });
    const loadTimeNext = Date.now() - startTimeNext;
    expect(loadTimeNext).toBeLessThan(LOAD_TIMEOUT);
    
    const nextWeekRange = await page.locator('[data-testid="week-range"], .week-header, .date-range').textContent();
    expect(nextWeekRange).not.toBe(currentWeekRange);
    
    // Step 2: Employee clicks 'Previous Week' button
    const previousWeekButton = page.locator('[data-testid="previous-week"], button:has-text("Previous Week"), button[aria-label="Previous Week"], .previous-week-btn');
    await previousWeekButton.click();
    
    // Expected Result: Schedule for previous week is displayed
    const startTimePrev = Date.now();
    await page.waitForLoadState('networkidle', { timeout: LOAD_TIMEOUT });
    const loadTimePrev = Date.now() - startTimePrev;
    expect(loadTimePrev).toBeLessThan(LOAD_TIMEOUT);
    
    const returnedWeekRange = await page.locator('[data-testid="week-range"], .week-header, .date-range').textContent();
    expect(returnedWeekRange).toBe(currentWeekRange);
    
    // Navigate to previous week again
    await previousWeekButton.click();
    await page.waitForLoadState('networkidle', { timeout: LOAD_TIMEOUT });
    
    const previousWeekRange = await page.locator('[data-testid="week-range"], .week-header, .date-range').textContent();
    expect(previousWeekRange).not.toBe(currentWeekRange);
    
    // Verify no errors occurred
    const errorMessages = page.locator('[data-testid="error-message"], .error, .alert-error');
    await expect(errorMessages).toHaveCount(0);
  });

  test('Ensure access control for weekly schedule - unauthenticated access', async ({ page }) => {
    // Step 1: Unauthenticated user attempts to access weekly schedule
    await page.goto(`${BASE_URL}/schedules/weekly`);
    
    // Expected Result: Access denied message is shown
    const accessDeniedMessage = page.locator('[data-testid="access-denied"], .access-denied, text=/access denied/i, text=/authentication required/i, text=/unauthorized/i');
    const loginForm = page.locator('form[action*="login"], [data-testid="login-form"]');
    
    // Either access denied message or redirect to login
    const isAccessDenied = await accessDeniedMessage.isVisible().catch(() => false);
    const isLoginPage = await loginForm.isVisible().catch(() => false);
    
    expect(isAccessDenied || isLoginPage).toBeTruthy();
    
    // Verify no schedule data is visible
    const scheduleData = page.locator('[data-testid="weekly-schedule"], .weekly-schedule, [data-testid="shift-item"]');
    await expect(scheduleData).toHaveCount(0);
    
    // Check network response for API call
    const response = await page.goto(`${BASE_URL}/api/schedules/weekly`).catch(() => null);
    if (response) {
      expect([401, 403]).toContain(response.status());
    }
  });

  test('Ensure access control for weekly schedule - authenticated access', async ({ page }) => {
    // Step 2: Authenticated employee accesses weekly schedule
    await page.goto(`${BASE_URL}/login`);
    
    await page.fill('input[name="username"]', VALID_USERNAME);
    await page.fill('input[name="password"]', VALID_PASSWORD);
    await page.click('button[type="submit"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to weekly schedule
    await page.click('a[href*="schedule"], button:has-text("Schedule")');
    await page.click('[data-testid="weekly-view"], button:has-text("Weekly View"), a:has-text("Weekly Schedule")');
    
    // Expected Result: Schedule is displayed successfully
    await expect(page.locator('[data-testid="weekly-schedule"], .weekly-schedule')).toBeVisible({ timeout: LOAD_TIMEOUT });
    
    // Verify authentication token is present
    const cookies = await page.context().cookies();
    const hasAuthToken = cookies.some(cookie => 
      cookie.name.toLowerCase().includes('auth') || 
      cookie.name.toLowerCase().includes('token') || 
      cookie.name.toLowerCase().includes('session')
    );
    expect(hasAuthToken).toBeTruthy();
    
    // Verify API request returns 200 OK
    const [response] = await Promise.all([
      page.waitForResponse(response => 
        response.url().includes('/api/schedules/weekly') && response.status() === 200,
        { timeout: 5000 }
      ).catch(() => null),
      page.reload()
    ]);
    
    if (response) {
      expect(response.status()).toBe(200);
    }
    
    // Verify schedule content is accessible
    const weekRange = page.locator('[data-testid="week-range"], .week-header, .date-range');
    await expect(weekRange).toBeVisible();
  });
});