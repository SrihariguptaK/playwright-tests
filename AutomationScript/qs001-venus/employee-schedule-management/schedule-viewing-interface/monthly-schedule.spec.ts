import { test, expect } from '@playwright/test';

test.describe('Monthly Schedule View - Story 9', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const EMPLOYEE_A_EMAIL = 'employee.a@company.com';
  const EMPLOYEE_A_PASSWORD = 'Password123!';
  const EMPLOYEE_B_ID = 'emp-456';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate monthly schedule calendar display and navigation', async ({ page }) => {
    // Step 1: Employee logs into the portal
    await page.fill('[data-testid="email-input"]', EMPLOYEE_A_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_A_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to schedule section from main menu
    await page.click('[data-testid="schedule-menu-item"]');
    
    // Select monthly schedule view option
    await page.click('[data-testid="monthly-view-button"]');
    
    // Expected Result: Monthly calendar displayed with shift indicators
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-indicator"]').first()).toBeVisible();
    
    // Verify current month is displayed
    const currentMonthYear = page.locator('[data-testid="current-month-year"]');
    await expect(currentMonthYear).toBeVisible();
    const currentMonthText = await currentMonthYear.textContent();
    
    // Step 2: Employee navigates to next month
    await page.click('[data-testid="next-month-button"]');
    
    // Expected Result: Next month's schedule displayed correctly
    await page.waitForLoadState('networkidle');
    const nextMonthText = await page.locator('[data-testid="current-month-year"]').textContent();
    expect(nextMonthText).not.toBe(currentMonthText);
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    
    // Step 3: Employee navigates to previous month twice
    await page.click('[data-testid="previous-month-button"]');
    await page.waitForLoadState('networkidle');
    
    // Verify back to original month
    const backToCurrentMonth = await page.locator('[data-testid="current-month-year"]').textContent();
    expect(backToCurrentMonth).toBe(currentMonthText);
    
    await page.click('[data-testid="previous-month-button"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Previous month's schedule displayed correctly
    const previousMonthText = await page.locator('[data-testid="current-month-year"]').textContent();
    expect(previousMonthText).not.toBe(currentMonthText);
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    
    // Verify weekends are visually distinct from weekdays
    const weekendDays = page.locator('[data-testid="calendar-day"][data-weekend="true"]');
    await expect(weekendDays.first()).toBeVisible();
    const weekendClass = await weekendDays.first().getAttribute('class');
    expect(weekendClass).toContain('weekend');
    
    // Verify company holidays are visually distinct
    const holidayDays = page.locator('[data-testid="calendar-day"][data-holiday="true"]');
    if (await holidayDays.count() > 0) {
      const holidayClass = await holidayDays.first().getAttribute('class');
      expect(holidayClass).toContain('holiday');
    }
    
    // Logout
    await page.click('[data-testid="user-menu-button"]');
    await page.click('[data-testid="logout-button"]');
  });

  test('Verify access control for monthly schedule', async ({ page }) => {
    // Step 1: Log in as Employee A with valid credentials
    await page.fill('[data-testid="email-input"]', EMPLOYEE_A_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_A_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Step 2: Navigate to the monthly schedule view
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="monthly-view-button"]');
    
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    
    // Get Employee A's schedule data for comparison
    const employeeASchedule = await page.locator('[data-testid="employee-name"]').textContent();
    
    // Step 3: Attempt to access Employee B's monthly schedule by manipulating URL
    const currentUrl = page.url();
    await page.goto(`${BASE_URL}/schedule/monthly?employeeId=${EMPLOYEE_B_ID}`);
    
    // Expected Result: Access denied with error message
    const errorMessage = page.locator('[data-testid="error-message"]');
    const accessDeniedMessage = page.locator('text=/Access Denied|Unauthorized|You do not have permission/i');
    
    // Check if error message is displayed or redirected back
    const isErrorVisible = await errorMessage.isVisible().catch(() => false);
    const isAccessDeniedVisible = await accessDeniedMessage.isVisible().catch(() => false);
    
    if (isErrorVisible || isAccessDeniedVisible) {
      expect(isErrorVisible || isAccessDeniedVisible).toBe(true);
    } else {
      // Verify Employee A's schedule view remains unchanged
      const currentEmployeeName = await page.locator('[data-testid="employee-name"]').textContent();
      expect(currentEmployeeName).toBe(employeeASchedule);
    }
    
    // Attempt via API endpoint
    const response = await page.request.get(`${BASE_URL}/api/schedules/monthly?employeeId=${EMPLOYEE_B_ID}`);
    expect(response.status()).toBe(403);
    
    // Logout
    await page.click('[data-testid="user-menu-button"]');
    await page.click('[data-testid="logout-button"]');
  });

  test('Test monthly schedule loading performance', async ({ page }) => {
    // Step 1: Clear browser cache and cookies
    await page.context().clearCookies();
    await page.context().clearPermissions();
    
    // Step 2: Log in to the employee portal with valid credentials
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', EMPLOYEE_A_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_A_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to schedule section
    await page.click('[data-testid="schedule-menu-item"]');
    
    // Step 3: Start performance timer and navigate to monthly schedule view
    const startTime = Date.now();
    
    await page.click('[data-testid="monthly-view-button"]');
    
    // Wait for calendar to be fully rendered and interactive
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    await page.waitForLoadState('networkidle');
    
    // Ensure all shift indicators are loaded
    await page.waitForSelector('[data-testid="shift-indicator"]', { state: 'visible', timeout: 5000 }).catch(() => {});
    
    const endTime = Date.now();
    const loadTime = (endTime - startTime) / 1000;
    
    console.log(`Monthly schedule load time: ${loadTime} seconds`);
    
    // Expected Result: Schedule loads within 4 seconds
    expect(loadTime).toBeLessThan(4);
    
    // Step 4: Repeat test by navigating to different month and back
    const secondStartTime = Date.now();
    
    await page.click('[data-testid="next-month-button"]');
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    await page.waitForLoadState('networkidle');
    
    const secondEndTime = Date.now();
    const secondLoadTime = (secondEndTime - secondStartTime) / 1000;
    
    console.log(`Next month navigation load time: ${secondLoadTime} seconds`);
    expect(secondLoadTime).toBeLessThan(4);
    
    // Navigate back to original month
    const thirdStartTime = Date.now();
    
    await page.click('[data-testid="previous-month-button"]');
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    await page.waitForLoadState('networkidle');
    
    const thirdEndTime = Date.now();
    const thirdLoadTime = (thirdEndTime - thirdStartTime) / 1000;
    
    console.log(`Previous month navigation load time: ${thirdLoadTime} seconds`);
    expect(thirdLoadTime).toBeLessThan(4);
    
    // Verify consistent performance
    const averageLoadTime = (loadTime + secondLoadTime + thirdLoadTime) / 3;
    console.log(`Average load time: ${averageLoadTime} seconds`);
    expect(averageLoadTime).toBeLessThan(4);
    
    // Logout
    await page.click('[data-testid="user-menu-button"]');
    await page.click('[data-testid="logout-button"]');
  });
});