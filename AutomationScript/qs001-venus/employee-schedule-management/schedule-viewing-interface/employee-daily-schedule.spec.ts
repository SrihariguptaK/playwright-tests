import { test, expect } from '@playwright/test';

test.describe('Employee Daily Schedule View', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_USERNAME = 'employee.test@company.com';
  const VALID_PASSWORD = 'Test@1234';
  const EMPLOYEE_ID = '123';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate successful daily schedule display for authenticated employee', async ({ page }) => {
    // Step 1: Employee logs into the web portal
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Login successful and dashboard displayed
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();

    // Step 2: Navigate to schedule section and select daily view
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page.locator('[data-testid="schedule-section"]')).toBeVisible();
    
    await page.click('[data-testid="daily-view-option"]');
    
    // Expected Result: Daily schedule for current day is displayed with correct shift details
    await expect(page.locator('[data-testid="daily-schedule-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-day-highlight"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-location"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-role"]')).toBeVisible();
    
    // Verify shift details are present and not empty
    const shiftStartTime = await page.locator('[data-testid="shift-start-time"]').textContent();
    expect(shiftStartTime).toBeTruthy();
    expect(shiftStartTime?.trim().length).toBeGreaterThan(0);

    // Step 3: Refresh the schedule view
    await page.click('[data-testid="refresh-schedule-button"]');
    
    // Expected Result: Schedule updates are reflected without errors
    await expect(page.locator('[data-testid="daily-schedule-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
    
    // Verify schedule data is still displayed after refresh
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
  });

  test('Verify access restriction to own schedule only', async ({ page }) => {
    // Login as Employee A
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to schedule section
    await page.click('[data-testid="schedule-nav-link"]');
    await page.click('[data-testid="daily-view-option"]');
    await expect(page.locator('[data-testid="daily-schedule-view"]')).toBeVisible();
    
    // Note the current schedule URL
    const currentURL = page.url();
    expect(currentURL).toContain(EMPLOYEE_ID);

    // Step 1: Employee attempts to access another employee's schedule via URL manipulation
    const manipulatedURL = currentURL.replace(`employeeId=${EMPLOYEE_ID}`, 'employeeId=456');
    await page.goto(manipulatedURL);
    
    // Expected Result: Access denied with appropriate error message
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    const errorMessage = await page.locator('[data-testid="access-denied-message"]').textContent();
    expect(errorMessage).toContain('Access denied');
    
    // Verify no schedule data from other employee is visible
    await expect(page.locator('[data-testid="daily-schedule-view"]')).not.toBeVisible();

    // Step 2: Employee views own schedule
    await page.click('[data-testid="schedule-nav-link"]');
    await page.click('[data-testid="daily-view-option"]');
    
    // Expected Result: Schedule displayed correctly
    await expect(page.locator('[data-testid="daily-schedule-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-name"]')).toContainText('Test Employee');
    
    // Verify all displayed information belongs to logged-in employee
    const displayedEmployeeId = await page.locator('[data-testid="employee-id"]').getAttribute('data-employee-id');
    expect(displayedEmployeeId).toBe(EMPLOYEE_ID);
  });

  test('Test performance of daily schedule loading', async ({ page }) => {
    // Login first
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to schedule section
    await page.click('[data-testid="schedule-nav-link"]');
    
    // Step 1: Employee loads daily schedule view and measure performance
    const startTime = Date.now();
    
    // Set up API response listener to track API call timing
    const apiResponsePromise = page.waitForResponse(
      response => response.url().includes('/api/schedules/daily') && response.status() === 200
    );
    
    await page.click('[data-testid="daily-view-option"]');
    
    // Wait for API response
    const apiResponse = await apiResponsePromise;
    expect(apiResponse.status()).toBe(200);
    
    // Wait for schedule to be fully displayed
    await expect(page.locator('[data-testid="daily-schedule-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
    
    const endTime = Date.now();
    const loadTime = endTime - startTime;
    
    // Expected Result: Schedule loads within 2 seconds (2000ms)
    expect(loadTime).toBeLessThan(2000);
    
    // Test refresh performance - iteration 1
    const refreshStartTime1 = Date.now();
    const refreshApiPromise1 = page.waitForResponse(
      response => response.url().includes('/api/schedules/daily') && response.status() === 200
    );
    
    await page.click('[data-testid="refresh-schedule-button"]');
    await refreshApiPromise1;
    await expect(page.locator('[data-testid="daily-schedule-view"]')).toBeVisible();
    
    const refreshEndTime1 = Date.now();
    const refreshLoadTime1 = refreshEndTime1 - refreshStartTime1;
    expect(refreshLoadTime1).toBeLessThan(2000);
    
    // Test refresh performance - iteration 2
    const refreshStartTime2 = Date.now();
    const refreshApiPromise2 = page.waitForResponse(
      response => response.url().includes('/api/schedules/daily') && response.status() === 200
    );
    
    await page.click('[data-testid="refresh-schedule-button"]');
    await refreshApiPromise2;
    await expect(page.locator('[data-testid="daily-schedule-view"]')).toBeVisible();
    
    const refreshEndTime2 = Date.now();
    const refreshLoadTime2 = refreshEndTime2 - refreshStartTime2;
    expect(refreshLoadTime2).toBeLessThan(2000);
    
    // Verify consistent performance across all three loads
    const avgLoadTime = (loadTime + refreshLoadTime1 + refreshLoadTime2) / 3;
    expect(avgLoadTime).toBeLessThan(2000);
  });
});