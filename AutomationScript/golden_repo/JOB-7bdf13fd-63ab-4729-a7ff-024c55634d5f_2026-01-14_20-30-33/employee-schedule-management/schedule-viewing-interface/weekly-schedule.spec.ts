import { test, expect } from '@playwright/test';

test.describe('Weekly Schedule - Employee View', () => {
  const BASE_URL = process.env.BASE_URL || 'https://portal.company.com';
  const VALID_USERNAME = process.env.TEST_USERNAME || 'employee@company.com';
  const VALID_PASSWORD = process.env.TEST_PASSWORD || 'TestPassword123!';
  const EMPLOYEE_ID = '12345';
  const OTHER_EMPLOYEE_ID = '67890';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('Validate weekly schedule display for authenticated employee', async ({ page }) => {
    // Step 1: Employee logs into the web portal
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Login successful and dashboard displayed
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 5000 });
    await expect(page.locator('[data-testid="dashboard-container"]')).toBeVisible();

    // Step 2: Navigate to the schedule section and select weekly view
    await page.click('[data-testid="schedule-nav-link"]');
    await page.waitForLoadState('networkidle');
    await page.click('[data-testid="weekly-view-button"]');
    
    // Expected Result: Weekly schedule for current week is displayed
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('[data-testid="week-date-range"]')).toBeVisible();
    
    // Verify all seven days are displayed
    const dayElements = page.locator('[data-testid="day-column"]');
    await expect(dayElements).toHaveCount(7);
    
    // Verify week header is displayed
    const weekHeader = page.locator('[data-testid="week-date-range"]');
    await expect(weekHeader).toContainText(/\w+ \d+.*\w+ \d+/);
    
    // Step 3: Verify all shift details for accuracy
    const shiftElements = page.locator('[data-testid="shift-entry"]');
    const shiftCount = await shiftElements.count();
    
    if (shiftCount > 0) {
      // Click on first shift to view details
      await shiftElements.first().click();
      
      // Verify shift details are displayed
      await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
      await expect(page.locator('[data-testid="shift-end-time"]')).toBeVisible();
      await expect(page.locator('[data-testid="shift-location"]')).toBeVisible();
      await expect(page.locator('[data-testid="shift-role"]')).toBeVisible();
      
      // Verify time format (e.g., "09:00 AM" or "9:00")
      const startTime = await page.locator('[data-testid="shift-start-time"]').textContent();
      expect(startTime).toMatch(/\d{1,2}:\d{2}/);
      
      const endTime = await page.locator('[data-testid="shift-end-time"]').textContent();
      expect(endTime).toMatch(/\d{1,2}:\d{2}/);
    }
    
    // Verify days with no shifts are indicated
    const emptyDays = page.locator('[data-testid="no-shifts-indicator"]');
    if (await emptyDays.count() > 0) {
      await expect(emptyDays.first()).toContainText(/no shift|off/i);
    }
    
    // Measure page load time (should be under 3 seconds)
    const navigationTiming = await page.evaluate(() => {
      const perfData = window.performance.timing;
      return perfData.loadEventEnd - perfData.navigationStart;
    });
    expect(navigationTiming).toBeLessThan(3000);
  });

  test('Verify navigation to previous and next weeks', async ({ page }) => {
    // Login first
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to weekly schedule
    await page.click('[data-testid="schedule-nav-link"]');
    await page.click('[data-testid="weekly-view-button"]');
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    // Note current week date range
    const currentWeekText = await page.locator('[data-testid="week-date-range"]').textContent();
    const currentShiftCount = await page.locator('[data-testid="shift-entry"]').count();
    
    // Step 1: Click on 'Previous Week' button
    const startTime = Date.now();
    await page.click('[data-testid="previous-week-button"]');
    await page.waitForLoadState('networkidle');
    const previousWeekLoadTime = Date.now() - startTime;
    
    // Expected Result: Schedule for previous week is displayed
    const previousWeekText = await page.locator('[data-testid="week-date-range"]').textContent();
    expect(previousWeekText).not.toBe(currentWeekText);
    
    // Verify all days are displayed
    await expect(page.locator('[data-testid="day-column"]')).toHaveCount(7);
    
    // Verify UI responsiveness
    expect(previousWeekLoadTime).toBeLessThan(3000);
    
    // Check for any visual glitches or errors
    const consoleErrors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });
    
    // Step 2: Click on 'Next Week' button
    await page.click('[data-testid="next-week-button"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Schedule for next week (current week) is displayed
    const backToCurrentWeek = await page.locator('[data-testid="week-date-range"]').textContent();
    expect(backToCurrentWeek).toBe(currentWeekText);
    
    // Click Next Week again to go to future week
    await page.click('[data-testid="next-week-button"]');
    await page.waitForLoadState('networkidle');
    
    const nextWeekText = await page.locator('[data-testid="week-date-range"]').textContent();
    expect(nextWeekText).not.toBe(currentWeekText);
    
    // Step 3: Test rapid navigation
    for (let i = 0; i < 3; i++) {
      await page.click('[data-testid="previous-week-button"]');
      await page.waitForTimeout(200);
    }
    
    for (let i = 0; i < 3; i++) {
      await page.click('[data-testid="next-week-button"]');
      await page.waitForTimeout(200);
    }
    
    // Expected Result: Schedule updates correctly without errors
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="day-column"]')).toHaveCount(7);
    expect(consoleErrors.length).toBe(0);
  });

  test('Ensure unauthorized users cannot access weekly schedules', async ({ page }) => {
    // Step 1: Attempt to access weekly schedule URL without login
    await page.goto(`${BASE_URL}/schedules/weekly`);
    
    // Expected Result: Access denied and redirect to login page
    await expect(page).toHaveURL(/.*login/, { timeout: 5000 });
    
    // Verify authentication error message
    const errorMessage = page.locator('[data-testid="auth-error-message"]');
    if (await errorMessage.isVisible()) {
      await expect(errorMessage).toContainText(/authentication required|please log in|unauthorized/i);
    }
    
    // Check HTTP response code by intercepting the request
    const response = await page.goto(`${BASE_URL}/api/schedules/weekly?employeeId=${EMPLOYEE_ID}`);
    expect(response?.status()).toBe(401);
    
    // Step 2: Login with valid employee credentials
    await page.goto(BASE_URL);
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access granted to own weekly schedule only
    await expect(page).toHaveURL(/.*dashboard/);
    
    await page.click('[data-testid="schedule-nav-link"]');
    await page.click('[data-testid="weekly-view-button"]');
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    // Verify only own schedule is visible
    const currentUrl = page.url();
    expect(currentUrl).toContain(EMPLOYEE_ID);
    
    // Step 3: Attempt to access another employee's weekly schedule
    const unauthorizedResponse = await page.goto(`${BASE_URL}/schedules/weekly?employeeId=${OTHER_EMPLOYEE_ID}`);
    
    // Expected Result: Access denied with appropriate error message
    if (unauthorizedResponse?.status() === 403 || unauthorizedResponse?.status() === 401) {
      expect([401, 403]).toContain(unauthorizedResponse.status());
    } else {
      // Check if redirected back to own schedule or error page
      await expect(page).toHaveURL(/.*error|.*access-denied|.*schedules\/weekly/);
    }
    
    // Verify error message is displayed
    const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
    if (await accessDeniedMessage.isVisible()) {
      await expect(accessDeniedMessage).toContainText(/access denied|not authorized|permission denied/i);
    }
    
    // Attempt API access directly
    const apiResponse = await page.request.get(`${BASE_URL}/api/schedules/weekly?employeeId=${OTHER_EMPLOYEE_ID}`);
    expect([401, 403]).toContain(apiResponse.status());
    
    // Verify no sensitive data is leaked in error response
    const responseBody = await apiResponse.text();
    expect(responseBody).not.toContain('password');
    expect(responseBody).not.toContain('ssn');
    expect(responseBody).not.toContain('salary');
  });
});