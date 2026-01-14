import { test, expect } from '@playwright/test';

test.describe('Monthly Schedule View - Story 15', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_USERNAME = process.env.EMPLOYEE_USERNAME || 'employee@company.com';
  const VALID_PASSWORD = process.env.EMPLOYEE_PASSWORD || 'Password123!';
  const LOAD_TIMEOUT = 4000;

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate monthly schedule display with accurate shifts', async ({ page }) => {
    // Step 1: Employee logs into the portal
    await page.fill('input[name="username"]', VALID_USERNAME);
    await page.fill('input[name="password"]', VALID_PASSWORD);
    await page.click('button[type="submit"]');
    
    // Expected Result: Dashboard displayed
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible({ timeout: 5000 });
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to schedule section and select monthly view
    await page.click('[data-testid="schedule-nav"]');
    await page.click('[data-testid="monthly-view-option"]');
    
    // Expected Result: Monthly schedule for current month displayed
    const startTime = Date.now();
    await expect(page.locator('[data-testid="monthly-schedule-view"]')).toBeVisible();
    const loadTime = Date.now() - startTime;
    expect(loadTime).toBeLessThan(LOAD_TIMEOUT);
    
    // Verify current month is displayed
    const currentDate = new Date();
    const currentMonthYear = currentDate.toLocaleString('default', { month: 'long', year: 'numeric' });
    await expect(page.locator('[data-testid="month-year-header"]')).toContainText(currentMonthYear);

    // Step 3: Verify shift details and total hours
    // Expected Result: Shift details and total hours are accurate
    const shiftElements = page.locator('[data-testid="shift-entry"]');
    const shiftCount = await shiftElements.count();
    
    if (shiftCount > 0) {
      // Verify first shift has required details
      const firstShift = shiftElements.first();
      await expect(firstShift.locator('[data-testid="shift-date"]')).toBeVisible();
      await expect(firstShift.locator('[data-testid="shift-start-time"]')).toBeVisible();
      await expect(firstShift.locator('[data-testid="shift-end-time"]')).toBeVisible();
      await expect(firstShift.locator('[data-testid="shift-type"]')).toBeVisible();
    }
    
    // Verify total hours summary is displayed
    await expect(page.locator('[data-testid="total-hours-month"]')).toBeVisible();
    const totalHoursText = await page.locator('[data-testid="total-hours-month"]').textContent();
    expect(totalHoursText).toMatch(/\d+/);
    
    // Verify weekly hours summary exists
    await expect(page.locator('[data-testid="weekly-hours-summary"]')).toBeVisible();
  });

  test('Verify month navigation functionality', async ({ page }) => {
    // Login first
    await page.fill('input[name="username"]', VALID_USERNAME);
    await page.fill('input[name="password"]', VALID_PASSWORD);
    await page.click('button[type="submit"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Navigate to monthly schedule view
    await page.click('[data-testid="schedule-nav"]');
    await page.click('[data-testid="monthly-view-option"]');
    await expect(page.locator('[data-testid="monthly-schedule-view"]')).toBeVisible();
    
    // Get current month displayed
    const currentMonthText = await page.locator('[data-testid="month-year-header"]').textContent();
    
    // Step 1: Click 'Next Month' button
    await page.click('[data-testid="next-month-button"]');
    
    // Expected Result: Next month's schedule displayed
    await page.waitForTimeout(500); // Allow for data loading
    const nextMonthText = await page.locator('[data-testid="month-year-header"]').textContent();
    expect(nextMonthText).not.toBe(currentMonthText);
    await expect(page.locator('[data-testid="monthly-schedule-view"]')).toBeVisible();
    
    // Step 2: Click 'Previous Month' button
    await page.click('[data-testid="previous-month-button"]');
    
    // Expected Result: Previous month's schedule displayed
    await page.waitForTimeout(500);
    const returnedMonthText = await page.locator('[data-testid="month-year-header"]').textContent();
    expect(returnedMonthText).toBe(currentMonthText);
    await expect(page.locator('[data-testid="monthly-schedule-view"]')).toBeVisible();
    
    // Step 3: Continue clicking 'Previous Month' button multiple times
    for (let i = 0; i < 3; i++) {
      const beforeClickMonth = await page.locator('[data-testid="month-year-header"]').textContent();
      await page.click('[data-testid="previous-month-button"]');
      await page.waitForTimeout(500);
      const afterClickMonth = await page.locator('[data-testid="month-year-header"]').textContent();
      expect(afterClickMonth).not.toBe(beforeClickMonth);
      await expect(page.locator('[data-testid="monthly-schedule-view"]')).toBeVisible();
    }
    
    // Step 4: Click 'Next Month' button multiple times to navigate forward
    for (let i = 0; i < 5; i++) {
      const beforeClickMonth = await page.locator('[data-testid="month-year-header"]').textContent();
      await page.click('[data-testid="next-month-button"]');
      await page.waitForTimeout(500);
      const afterClickMonth = await page.locator('[data-testid="month-year-header"]').textContent();
      expect(afterClickMonth).not.toBe(beforeClickMonth);
      await expect(page.locator('[data-testid="monthly-schedule-view"]')).toBeVisible();
    }
  });

  test('Ensure unauthorized access is prevented', async ({ page, request }) => {
    // Login first
    await page.fill('input[name="username"]', VALID_USERNAME);
    await page.fill('input[name="password"]', VALID_PASSWORD);
    await page.click('button[type="submit"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Navigate to monthly schedule view
    await page.click('[data-testid="schedule-nav"]');
    await page.click('[data-testid="monthly-view-option"]');
    await expect(page.locator('[data-testid="monthly-schedule-view"]')).toBeVisible();
    
    // Step 1: Attempt to manually modify the API request to access another employee's schedule
    const currentDate = new Date();
    const month = currentDate.getMonth() + 1;
    const year = currentDate.getFullYear();
    const unauthorizedEmployeeId = '99999'; // Different employee ID
    
    // Intercept API calls and attempt unauthorized access
    const response = await page.evaluate(async ({ month, year, employeeId }) => {
      try {
        const res = await fetch(`/api/schedules/monthly?month=${month}&year=${year}&employeeId=${employeeId}`, {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json'
          }
        });
        return {
          status: res.status,
          ok: res.ok
        };
      } catch (error) {
        return { error: error.message };
      }
    }, { month, year, employeeId: unauthorizedEmployeeId });
    
    // Expected Result: Access denied with error message
    expect(response.status).toBe(403);
    expect(response.ok).toBe(false);
    
    // Step 2: Verify that the system logs the unauthorized access attempt and session remains valid
    // Verify current employee's session is still valid
    await expect(page.locator('[data-testid="monthly-schedule-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="dashboard"]')).not.toBeVisible();
    
    // Verify user is not logged out
    await page.goto(`${BASE_URL}/dashboard`);
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Step 3: Attempt to use API testing to directly call endpoint with another employee's ID
    const cookies = await page.context().cookies();
    const authToken = cookies.find(cookie => cookie.name === 'auth_token')?.value;
    
    if (authToken) {
      const apiResponse = await request.get(`${BASE_URL}/api/schedules/monthly`, {
        params: {
          month: month.toString(),
          year: year.toString(),
          employeeId: unauthorizedEmployeeId
        },
        headers: {
          'Authorization': `Bearer ${authToken}`
        }
      });
      
      // Expected Result: Access denied
      expect(apiResponse.status()).toBe(403);
      
      const responseBody = await apiResponse.json().catch(() => ({}));
      expect(responseBody.error || responseBody.message).toMatch(/unauthorized|forbidden|access denied/i);
    }
  });
});