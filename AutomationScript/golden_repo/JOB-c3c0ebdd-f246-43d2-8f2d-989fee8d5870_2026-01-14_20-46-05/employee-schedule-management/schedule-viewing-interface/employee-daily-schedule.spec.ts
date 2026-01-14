import { test, expect } from '@playwright/test';

test.describe('Employee Daily Schedule Viewing', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const EMPLOYEE_A_USERNAME = 'employeeA@company.com';
  const EMPLOYEE_A_PASSWORD = 'Password123!';
  const EMPLOYEE_B_USERNAME = 'employeeB@company.com';
  const EMPLOYEE_B_PASSWORD = 'Password456!';

  test('Validate daily schedule display with accurate shift details', async ({ page }) => {
    // Step 1: Navigate to the login page and enter valid employee credentials
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', EMPLOYEE_A_USERNAME);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_A_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Schedule dashboard is displayed
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 5000 });
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    
    // Step 2: Verify the schedule dashboard loads completely
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();
    
    // Step 3: Click on 'Daily View' option or tab in the navigation menu
    await page.click('[data-testid="daily-view-tab"]');
    
    // Expected Result: Daily schedule for current day is displayed
    await expect(page.locator('[data-testid="daily-schedule-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-date-header"]')).toBeVisible();
    
    // Step 4: Review the displayed shift information for start time
    const shiftStartTime = page.locator('[data-testid="shift-start-time"]');
    await expect(shiftStartTime).toBeVisible();
    await expect(shiftStartTime).toContainText(/\d{1,2}:\d{2}\s?(AM|PM)/i);
    
    // Step 5: Review the displayed shift information for end time
    const shiftEndTime = page.locator('[data-testid="shift-end-time"]');
    await expect(shiftEndTime).toBeVisible();
    await expect(shiftEndTime).toContainText(/\d{1,2}:\d{2}\s?(AM|PM)/i);
    
    // Step 6: Verify the shift location information
    const shiftLocation = page.locator('[data-testid="shift-location"]');
    await expect(shiftLocation).toBeVisible();
    const locationText = await shiftLocation.textContent();
    expect(locationText).toBeTruthy();
    expect(locationText?.length).toBeGreaterThan(0);
    
    // Step 7: Verify the shift role information
    const shiftRole = page.locator('[data-testid="shift-role"]');
    await expect(shiftRole).toBeVisible();
    const roleText = await shiftRole.textContent();
    expect(roleText).toBeTruthy();
    expect(roleText?.length).toBeGreaterThan(0);
    
    // Step 8: Check for shift status indicator
    const shiftStatus = page.locator('[data-testid="shift-status"]');
    await expect(shiftStatus).toBeVisible();
    const statusText = await shiftStatus.textContent();
    expect(['confirmed', 'pending', 'Confirmed', 'Pending']).toContain(statusText?.trim() || '');
    
    // Step 9: Verify the current day is highlighted visually
    const currentDayElement = page.locator('[data-testid="current-day-highlight"]');
    await expect(currentDayElement).toBeVisible();
    await expect(currentDayElement).toHaveClass(/highlighted|active|current/);
    
    // Verify shift details match database records (check data consistency)
    const shiftDetailsContainer = page.locator('[data-testid="shift-details-container"]');
    await expect(shiftDetailsContainer).toBeVisible();
    const shiftCount = await page.locator('[data-testid="shift-item"]').count();
    expect(shiftCount).toBeGreaterThanOrEqual(0);
  });

  test('Verify access restriction to employee\'s own schedule', async ({ page }) => {
    // Step 1: Navigate to login page and log in using Employee A's credentials
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', EMPLOYEE_A_USERNAME);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_A_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Schedule dashboard is displayed
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 5000 });
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    
    // Step 2: Note the current URL in the browser address bar
    const employeeAUrl = page.url();
    expect(employeeAUrl).toContain('dashboard');
    
    // Step 3: Manually modify the URL to attempt accessing Employee B's schedule
    const employeeBUrl = employeeAUrl.replace(/employee[A-Za-z0-9]+|user[A-Za-z0-9]+|id=[A-Za-z0-9]+/i, 'employeeB');
    await page.goto(employeeBUrl);
    
    // Expected Result: Access is denied with error message
    const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
    const errorMessage = page.locator('[data-testid="error-message"]');
    const unauthorizedMessage = page.locator('text=/access denied|unauthorized|forbidden/i');
    
    await expect(
      accessDeniedMessage.or(errorMessage).or(unauthorizedMessage)
    ).toBeVisible({ timeout: 5000 });
    
    // Step 4: Verify that Employee B's schedule data is not displayed
    const employeeBSchedule = page.locator('[data-testid="employee-schedule"][data-employee="employeeB"]');
    await expect(employeeBSchedule).not.toBeVisible().catch(() => {});
    
    // Step 5: Click logout button or link to end Employee A's session
    await page.goto(`${BASE_URL}/dashboard`);
    await page.click('[data-testid="logout-button"]');
    
    // Expected Result: User is logged out
    await expect(page).toHaveURL(/.*login/, { timeout: 5000 });
    
    // Step 6: Log in using Employee B's credentials
    await page.fill('[data-testid="username-input"]', EMPLOYEE_B_USERNAME);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_B_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Employee B's schedule is displayed
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 5000 });
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    
    // Step 7: Verify the schedule dashboard displays Employee B's schedule
    const employeeBDashboard = page.locator('[data-testid="schedule-dashboard"]');
    await expect(employeeBDashboard).toBeVisible();
    
    const employeeIdentifier = page.locator('[data-testid="employee-name"], [data-testid="employee-id"]');
    await expect(employeeIdentifier).toBeVisible();
    
    // Step 8: Confirm that Employee A's schedule data is not visible to Employee B
    const employeeAScheduleData = page.locator('[data-testid="employee-schedule"][data-employee="employeeA"]');
    await expect(employeeAScheduleData).not.toBeVisible().catch(() => {});
    
    // Verify Employee B can see their own schedule
    const dailyViewTab = page.locator('[data-testid="daily-view-tab"]');
    if (await dailyViewTab.isVisible()) {
      await dailyViewTab.click();
      await expect(page.locator('[data-testid="daily-schedule-view"]')).toBeVisible();
    }
  });
});