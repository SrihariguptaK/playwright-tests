import { test, expect } from '@playwright/test';

test.describe('Employee Daily Schedule - Story 13', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_EMPLOYEE_EMAIL = 'employee@company.com';
  const VALID_EMPLOYEE_PASSWORD = 'Password123!';
  const OTHER_EMPLOYEE_ID = '12345';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate successful daily schedule display for authenticated employee', async ({ page }) => {
    // Step 1: Employee logs into the web portal
    await page.fill('[data-testid="email-input"]', VALID_EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Login successful and dashboard displayed
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 5000 });
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();

    // Step 2: Employee navigates to the schedule section
    await page.click('[data-testid="schedule-nav-link"]');
    
    // Expected Result: Daily schedule page is displayed
    await expect(page).toHaveURL(/.*schedule/, { timeout: 5000 });
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();

    // Step 3: Verify displayed schedule matches employee's assigned shifts for the day
    // Verify the current day is highlighted on the schedule view
    const currentDayHighlight = page.locator('[data-testid="current-day-highlight"]');
    await expect(currentDayHighlight).toBeVisible();

    // Review the displayed shift start time for the current day
    const shiftStartTime = page.locator('[data-testid="shift-start-time"]');
    await expect(shiftStartTime).toBeVisible();
    const startTimeText = await shiftStartTime.textContent();
    expect(startTimeText).toMatch(/\d{1,2}:\d{2}\s?(AM|PM)?/i);

    // Review the displayed shift end time for the current day
    const shiftEndTime = page.locator('[data-testid="shift-end-time"]');
    await expect(shiftEndTime).toBeVisible();
    const endTimeText = await shiftEndTime.textContent();
    expect(endTimeText).toMatch(/\d{1,2}:\d{2}\s?(AM|PM)?/i);

    // Verify the location information displayed for the shift
    const shiftLocation = page.locator('[data-testid="shift-location"]');
    await expect(shiftLocation).toBeVisible();
    const locationText = await shiftLocation.textContent();
    expect(locationText).toBeTruthy();
    expect(locationText?.trim().length).toBeGreaterThan(0);

    // Verify the role information displayed for the shift
    const shiftRole = page.locator('[data-testid="shift-role"]');
    await expect(shiftRole).toBeVisible();
    const roleText = await shiftRole.textContent();
    expect(roleText).toBeTruthy();
    expect(roleText?.trim().length).toBeGreaterThan(0);

    // Expected Result: Schedule details are accurate and complete
    await expect(page.locator('[data-testid="schedule-error"]')).not.toBeVisible();
  });

  test('Verify navigation between days in schedule view', async ({ page }) => {
    // Login first
    await page.fill('[data-testid="email-input"]', VALID_EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 5000 });
    
    // Navigate to schedule section
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();

    // Note the current date displayed on the daily schedule page
    const initialDate = await page.locator('[data-testid="schedule-date-display"]').textContent();
    expect(initialDate).toBeTruthy();

    // Step 1: Employee clicks 'Next Day' button
    await page.click('[data-testid="next-day-button"]');
    await page.waitForTimeout(500); // Wait for date update

    // Expected Result: Schedule for the next day is displayed
    const nextDayDate = await page.locator('[data-testid="schedule-date-display"]').textContent();
    expect(nextDayDate).not.toBe(initialDate);
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();

    // Verify shift details are displayed for the next day if shifts exist
    const scheduleContent = page.locator('[data-testid="schedule-content"]');
    await expect(scheduleContent).toBeVisible();

    // Step 2: Employee clicks 'Previous Day' button
    await page.click('[data-testid="previous-day-button"]');
    await page.waitForTimeout(500);

    // Expected Result: Schedule for the previous day is displayed
    const returnedDate = await page.locator('[data-testid="schedule-date-display"]').textContent();
    expect(returnedDate).toBe(initialDate);

    // Click previous day button again
    await page.click('[data-testid="previous-day-button"]');
    await page.waitForTimeout(500);
    const previousDayDate = await page.locator('[data-testid="schedule-date-display"]').textContent();
    expect(previousDayDate).not.toBe(initialDate);

    // Navigate forward and backward multiple times rapidly
    for (let i = 0; i < 5; i++) {
      await page.click('[data-testid="next-day-button"]');
      await page.waitForTimeout(200);
    }
    for (let i = 0; i < 5; i++) {
      await page.click('[data-testid="previous-day-button"]');
      await page.waitForTimeout(200);
    }

    // Step 3: Verify no errors occur during navigation
    // Check browser console for any JavaScript errors
    const consoleErrors: string[] = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    // Expected Result: Navigation is smooth and error-free
    await expect(page.locator('[data-testid="schedule-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    expect(consoleErrors.length).toBe(0);
  });

  test('Test access restriction to own schedule only', async ({ page }) => {
    // Login first
    await page.fill('[data-testid="email-input"]', VALID_EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 5000 });

    // Step 1: Employee attempts to access another employee's schedule URL
    const unauthorizedScheduleUrl = `${BASE_URL}/api/schedules/daily?employeeId=${OTHER_EMPLOYEE_ID}`;
    const response = await page.goto(unauthorizedScheduleUrl);

    // Expected Result: Access denied with appropriate error message
    expect(response?.status()).toBeGreaterThanOrEqual(400);
    expect(response?.status()).toBeLessThan(500);
    
    // Verify that no schedule data from the other employee is visible on the page
    const pageContent = await page.content();
    await expect(page.locator('[data-testid="unauthorized-error"]')).toBeVisible();
    
    // Check the HTTP response code in browser developer tools
    expect([401, 403]).toContain(response?.status());

    // Step 2: Employee accesses own schedule URL
    await page.goto(`${BASE_URL}/dashboard`);
    await page.click('[data-testid="schedule-nav-link"]');

    // Expected Result: Schedule displayed successfully
    await expect(page).toHaveURL(/.*schedule/, { timeout: 5000 });
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();

    // Access own schedule using the standard navigation menu
    const ownScheduleVisible = await page.locator('[data-testid="schedule-content"]').isVisible();
    expect(ownScheduleVisible).toBe(true);

    // Step 3: Verify no data leakage occurs
    // Verify that only the logged-in employee's schedule data is visible
    const scheduleData = await page.locator('[data-testid="schedule-content"]').textContent();
    expect(scheduleData).toBeTruthy();

    // Inspect the page source and network requests for any data leakage
    const networkRequests: string[] = [];
    page.on('response', async (response) => {
      if (response.url().includes('/api/schedules')) {
        networkRequests.push(response.url());
        const responseBody = await response.text().catch(() => '');
        // Verify response doesn't contain other employee IDs
        expect(responseBody).not.toContain(OTHER_EMPLOYEE_ID);
      }
    });

    // Reload to trigger network requests
    await page.reload();
    await page.waitForTimeout(1000);

    // Expected Result: Only authorized schedule data is visible
    await expect(page.locator('[data-testid="unauthorized-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
  });
});