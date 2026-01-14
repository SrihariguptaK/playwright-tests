import { test, expect } from '@playwright/test';

test.describe('Story-13: Employee Weekly Schedule View', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to application login page before each test
    await page.goto('/login');
  });

  test('Validate weekly schedule display and navigation', async ({ page }) => {
    // Step 1: Log in as employee
    await page.fill('[data-testid="username-input"]', 'employee.user@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Schedule dashboard is displayed
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Step 2: Select weekly view
    await page.click('[data-testid="weekly-view-button"]');
    
    // Expected Result: Current week's schedule is displayed
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-week-highlight"]')).toBeVisible();
    
    // Verify schedule contains shift information
    const scheduleData = page.locator('[data-testid="shift-entry"]');
    await expect(scheduleData.first()).toBeVisible();
    
    // Verify shift details are present (start time, end time, location)
    await expect(page.locator('[data-testid="shift-start-time"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="shift-location"]').first()).toBeVisible();
    
    // Step 3: Navigate to next week
    const currentWeekText = await page.locator('[data-testid="week-display"]').textContent();
    await page.click('[data-testid="next-week-button"]');
    
    // Expected Result: Next week's schedule is displayed accurately
    await page.waitForLoadState('networkidle');
    const nextWeekText = await page.locator('[data-testid="week-display"]').textContent();
    expect(nextWeekText).not.toBe(currentWeekText);
    
    // Verify next week schedule loads with shift data
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-entry"]').first()).toBeVisible();
    
    // Verify current week is no longer highlighted
    await expect(page.locator('[data-testid="current-week-highlight"]')).not.toBeVisible();
  });

  test('Verify schedule data access restriction', async ({ page }) => {
    // Step 1: Log in as employee A
    await page.fill('[data-testid="username-input"]', 'employeeA@company.com');
    await page.fill('[data-testid="password-input"]', 'PasswordA123');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Schedule dashboard is displayed
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Get Employee A's ID from the page or session
    const employeeAId = await page.getAttribute('[data-testid="employee-id"]', 'data-employee-id');
    
    // Step 2: Attempt to access employee B's weekly schedule
    const employeeBId = 'employee-b-12345';
    
    // Attempt 1: Manipulate URL parameters
    await page.goto(`/schedule/weekly?employeeId=${employeeBId}`);
    
    // Expected Result: Access denied with error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/access denied|unauthorized|permission/i);
    
    // Verify Employee A's own schedule is still accessible
    await page.goto('/schedule/weekly');
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    // Attempt 2: Direct API call to access another employee's data
    const response = await page.request.get(`/api/schedules/weekly?employeeId=${employeeBId}`);
    expect(response.status()).toBe(403);
    
    const responseBody = await response.json();
    expect(responseBody).toHaveProperty('error');
    expect(responseBody.error).toMatch(/access denied|unauthorized|forbidden/i);
  });

  test('Verify weekly schedule loads within performance requirements', async ({ page }) => {
    // Log in as employee
    await page.fill('[data-testid="username-input"]', 'employee.user@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    
    // Measure load time for weekly schedule
    const startTime = Date.now();
    await page.click('[data-testid="weekly-view-button"]');
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    const loadTime = Date.now() - startTime;
    
    // Verify load time is under 4 seconds (4000ms)
    expect(loadTime).toBeLessThan(4000);
  });

  test('Verify navigation to previous week', async ({ page }) => {
    // Log in as employee
    await page.fill('[data-testid="username-input"]', 'employee.user@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    
    // Select weekly view
    await page.click('[data-testid="weekly-view-button"]');
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    // Get current week display
    const currentWeekText = await page.locator('[data-testid="week-display"]').textContent();
    
    // Navigate to previous week
    await page.click('[data-testid="previous-week-button"]');
    await page.waitForLoadState('networkidle');
    
    // Verify previous week is displayed
    const previousWeekText = await page.locator('[data-testid="week-display"]').textContent();
    expect(previousWeekText).not.toBe(currentWeekText);
    
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
  });

  test('Verify current week is highlighted in schedule view', async ({ page }) => {
    // Log in as employee
    await page.fill('[data-testid="username-input"]', 'employee.user@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    
    // Select weekly view
    await page.click('[data-testid="weekly-view-button"]');
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    // Verify current week highlight is visible
    await expect(page.locator('[data-testid="current-week-highlight"]')).toBeVisible();
    
    // Verify highlight has appropriate styling
    const highlightElement = page.locator('[data-testid="current-week-highlight"]');
    const backgroundColor = await highlightElement.evaluate((el) => window.getComputedStyle(el).backgroundColor);
    expect(backgroundColor).not.toBe('rgba(0, 0, 0, 0)');
  });
});