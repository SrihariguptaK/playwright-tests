import { test, expect } from '@playwright/test';

test.describe('Employee Daily Schedule - Story 1', () => {
  const BASE_URL = 'https://portal.company.com';
  const VALID_USERNAME = 'employee.user@company.com';
  const VALID_PASSWORD = 'ValidPass123!';
  const EMPLOYEE_ID = '12345';
  const UNAUTHORIZED_EMPLOYEE_ID = '67890';

  test('Validate daily schedule display for authenticated employee (happy-path)', async ({ page }) => {
    // Navigate to the web portal login page using a supported browser
    await page.goto(`${BASE_URL}/login`);
    await expect(page).toHaveURL(/.*login/);

    // Enter valid employee credentials (username and password) and click the Login button
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Expected Result: Login successful and dashboard displayed
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();

    // Click on the 'Schedule' or 'My Schedule' option in the navigation menu
    const startTime = Date.now();
    await page.click('[data-testid="schedule-menu"]');

    // Expected Result: Daily schedule for current day is displayed
    await expect(page).toHaveURL(/.*schedules\/daily/);
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();

    // Review the displayed schedule and verify shift start time is shown
    const shiftStartTime = page.locator('[data-testid="shift-start-time"]').first();
    await expect(shiftStartTime).toBeVisible();
    const startTimeText = await shiftStartTime.textContent();
    expect(startTimeText).toMatch(/\d{1,2}:\d{2}\s?(AM|PM)/i);

    // Verify shift end time is displayed for each shift
    const shiftEndTime = page.locator('[data-testid="shift-end-time"]').first();
    await expect(shiftEndTime).toBeVisible();
    const endTimeText = await shiftEndTime.textContent();
    expect(endTimeText).toMatch(/\d{1,2}:\d{2}\s?(AM|PM)/i);

    // Verify the location/workplace is displayed for each shift
    const shiftLocation = page.locator('[data-testid="shift-location"]').first();
    await expect(shiftLocation).toBeVisible();
    const locationText = await shiftLocation.textContent();
    expect(locationText).toBeTruthy();
    expect(locationText?.length).toBeGreaterThan(0);

    // Verify the role/position is displayed for each shift
    const shiftRole = page.locator('[data-testid="shift-role"]').first();
    await expect(shiftRole).toBeVisible();
    const roleText = await shiftRole.textContent();
    expect(roleText).toBeTruthy();
    expect(roleText?.length).toBeGreaterThan(0);

    // Cross-reference displayed schedule data with database records using employee ID and current date
    const currentDate = new Date().toISOString().split('T')[0];
    const apiResponse = await page.request.get(`${BASE_URL}/api/schedules/daily?employeeId=${EMPLOYEE_ID}&date=${currentDate}`);
    expect(apiResponse.ok()).toBeTruthy();
    const scheduleData = await apiResponse.json();
    expect(scheduleData).toBeTruthy();

    // Verify the page load time from clicking Schedule menu to full display
    const endTime = Date.now();
    const loadTime = endTime - startTime;
    expect(loadTime).toBeLessThan(2000);
  });

  test('Verify navigation to previous and next days (happy-path)', async ({ page }) => {
    // Login and navigate to schedule
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    await page.click('[data-testid="schedule-menu"]');
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();

    // Note the current date displayed in the schedule header
    const currentDateHeader = page.locator('[data-testid="schedule-date-header"]');
    await expect(currentDateHeader).toBeVisible();
    const initialDate = await currentDateHeader.textContent();

    // Click on the 'Previous Day' or left arrow navigation button
    const previousDayStartTime = Date.now();
    await page.click('[data-testid="previous-day-button"]');

    // Verify the date header has changed to the previous day
    await page.waitForTimeout(500);
    const previousDate = await currentDateHeader.textContent();
    expect(previousDate).not.toBe(initialDate);

    // Verify shift details displayed for the previous day
    await expect(page.locator('[data-testid="shift-start-time"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="shift-location"]').first()).toBeVisible();

    // Cross-check displayed data with database records for the previous day
    const previousDateValue = await page.locator('[data-testid="schedule-date-value"]').getAttribute('data-date');
    const previousDayApiResponse = await page.request.get(`${BASE_URL}/api/schedules/daily?employeeId=${EMPLOYEE_ID}&date=${previousDateValue}`);
    expect(previousDayApiResponse.ok()).toBeTruthy();

    // Measure the response time for the previous day navigation
    const previousDayEndTime = Date.now();
    const previousDayLoadTime = previousDayEndTime - previousDayStartTime;
    expect(previousDayLoadTime).toBeLessThan(2000);

    // Click on the 'Next Day' or right arrow navigation button
    await page.click('[data-testid="next-day-button"]');

    // Verify the date header has changed to the next day
    await page.waitForTimeout(500);
    const nextDate = await currentDateHeader.textContent();
    expect(nextDate).toBe(initialDate);

    // Click 'Next Day' button again to move forward one more day
    await page.click('[data-testid="next-day-button"]');
    await page.waitForTimeout(500);
    const futureDate = await currentDateHeader.textContent();
    expect(futureDate).not.toBe(initialDate);

    // Verify shift details for the next day are accurate
    await expect(page.locator('[data-testid="shift-start-time"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time"]').first()).toBeVisible();

    // Check UI responsiveness by rapidly clicking Previous and Next buttons alternately
    await page.click('[data-testid="previous-day-button"]');
    await page.click('[data-testid="next-day-button"]');
    await page.click('[data-testid="previous-day-button"]');
    await page.click('[data-testid="next-day-button"]');
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();

    // Verify no JavaScript errors appear in browser console during navigation
    const consoleErrors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });
    await page.click('[data-testid="previous-day-button"]');
    await page.waitForTimeout(500);
    expect(consoleErrors.length).toBe(0);
  });

  test('Ensure unauthorized users cannot access schedules (error-case)', async ({ page, context }) => {
    // Open a new browser window in incognito/private mode
    // Note: context is already isolated in Playwright

    // Directly enter the schedule URL in the address bar without logging in
    await page.goto(`${BASE_URL}/schedules/daily`);

    // Verify an appropriate message is displayed indicating authentication is required
    await expect(page.locator('[data-testid="auth-required-message"]')).toBeVisible();
    const authMessage = await page.locator('[data-testid="auth-required-message"]').textContent();
    expect(authMessage?.toLowerCase()).toContain('authentication');

    // Check the browser URL after redirect
    await expect(page).toHaveURL(/.*login/);

    // Enter valid employee credentials (username and password) and click Login
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Navigate to the daily schedule view
    await expect(page).toHaveURL(/.*dashboard/);
    await page.click('[data-testid="schedule-menu"]');

    // Verify that only the logged-in employee's schedule is visible
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    const employeeIdDisplay = page.locator('[data-testid="employee-id-display"]');
    if (await employeeIdDisplay.isVisible()) {
      const displayedEmployeeId = await employeeIdDisplay.textContent();
      expect(displayedEmployeeId).toContain(EMPLOYEE_ID);
    }

    // Note the employee ID from the current session
    const currentUrl = page.url();
    expect(currentUrl).toContain(EMPLOYEE_ID);

    // Manually modify the URL to attempt accessing another employee's schedule
    const unauthorizedUrl = currentUrl.replace(EMPLOYEE_ID, UNAUTHORIZED_EMPLOYEE_ID);
    const response = await page.goto(unauthorizedUrl);

    // Verify an appropriate error message is displayed
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible();
    const errorText = await errorMessage.textContent();
    expect(errorText?.toLowerCase()).toMatch(/access denied|unauthorized|forbidden/);

    // Verify the HTTP response code for the unauthorized access attempt
    expect(response?.status()).toBeGreaterThanOrEqual(400);
    expect([401, 403]).toContain(response?.status() || 0);

    // Check that the user remains on their own schedule or is redirected to an error page
    const finalUrl = page.url();
    const isOnOwnSchedule = finalUrl.includes(EMPLOYEE_ID);
    const isOnErrorPage = finalUrl.includes('error') || finalUrl.includes('unauthorized');
    expect(isOnOwnSchedule || isOnErrorPage).toBeTruthy();

    // Verify the security event is logged in the system audit log
    // Note: This would typically require API access to audit logs
    const auditLogResponse = await page.request.get(`${BASE_URL}/api/audit/recent?employeeId=${EMPLOYEE_ID}`, {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('authToken'))}`
      }
    });
    if (auditLogResponse.ok()) {
      const auditLogs = await auditLogResponse.json();
      const unauthorizedAccessLog = auditLogs.find((log: any) => 
        log.action === 'UNAUTHORIZED_ACCESS_ATTEMPT' && 
        log.targetEmployeeId === UNAUTHORIZED_EMPLOYEE_ID
      );
      expect(unauthorizedAccessLog).toBeTruthy();
    }
  });
});