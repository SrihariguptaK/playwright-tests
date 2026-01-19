import { test, expect } from '@playwright/test';

test.describe('Employee Weekly Schedule', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const validEmployeeCredentials = {
    username: 'employee.user@company.com',
    password: 'ValidPass123!'
  };
  const otherEmployeeId = '12345';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto(`${baseURL}/login`);
  });

  test('Validate weekly schedule display with valid employee login', async ({ page }) => {
    // Step 1: Employee logs into the portal
    await page.fill('[data-testid="username-input"]', validEmployeeCredentials.username);
    await page.fill('[data-testid="password-input"]', validEmployeeCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Login successful and dashboard displayed
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 10000 });
    await expect(page.locator('[data-testid="dashboard-container"]')).toBeVisible();

    // Step 2: Navigate to weekly schedule page
    await page.click('[data-testid="weekly-schedule-menu"]');
    
    // Expected Result: Weekly schedule for current week displayed with correct shift details
    await expect(page).toHaveURL(/.*schedule\/weekly/, { timeout: 10000 });
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    // Verify current week is displayed
    await expect(page.locator('[data-testid="current-week-indicator"]')).toBeVisible();
    
    // Verify calendar grid is present
    await expect(page.locator('[data-testid="calendar-grid"]')).toBeVisible();
    
    // Verify all days of the week are displayed
    const daysOfWeek = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
    for (const day of daysOfWeek) {
      await expect(page.locator(`text=${day}`).first()).toBeVisible();
    }
    
    // Verify shift details are displayed
    const shifts = page.locator('[data-testid="shift-item"]');
    await expect(shifts.first()).toBeVisible({ timeout: 5000 });
    
    // Verify page load time is under 4 seconds (already loaded at this point)
    const loadStartTime = Date.now();
    await page.reload();
    await page.waitForSelector('[data-testid="weekly-schedule-container"]', { timeout: 4000 });
    const loadTime = Date.now() - loadStartTime;
    expect(loadTime).toBeLessThan(4000);

    // Step 3: Navigate to next week
    await page.click('[data-testid="next-week-button"]');
    
    // Expected Result: Schedule for next week displayed without errors
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="calendar-grid"]')).toBeVisible();
    
    // Verify no error messages are displayed
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
    
    // Verify navigation occurred without page reload
    const navigationTime = Date.now();
    await page.click('[data-testid="previous-week-button"]');
    await page.waitForSelector('[data-testid="calendar-grid"]');
    const navDuration = Date.now() - navigationTime;
    expect(navDuration).toBeLessThan(2000);
  });

  test('Verify access restriction to other employees\' weekly schedules', async ({ page }) => {
    // Login with valid employee credentials
    await page.fill('[data-testid="username-input"]', validEmployeeCredentials.username);
    await page.fill('[data-testid="password-input"]', validEmployeeCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 10000 });

    // Navigate to own weekly schedule page
    await page.click('[data-testid="weekly-schedule-menu"]');
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    // Observe and note the URL structure
    const currentURL = page.url();
    const urlPattern = currentURL.match(/employeeId=([^&]+)/);
    
    // Step 1: Attempt to access another employee's weekly schedule via URL manipulation
    const manipulatedURL = currentURL.includes('employeeId=') 
      ? currentURL.replace(/employeeId=[^&]+/, `employeeId=${otherEmployeeId}`)
      : `${currentURL}${currentURL.includes('?') ? '&' : '?'}employeeId=${otherEmployeeId}`;
    
    await page.goto(manipulatedURL);
    
    // Expected Result: Access denied with error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible({ timeout: 5000 });
    const errorMessage = await page.locator('[data-testid="error-message"]').textContent();
    expect(errorMessage).toMatch(/access denied|unauthorized|permission/i);
    
    // Verify no weekly schedule data from other employee is visible
    const scheduleContainer = page.locator('[data-testid="weekly-schedule-container"]');
    if (await scheduleContainer.isVisible()) {
      // If container is visible, verify it shows error state, not actual schedule data
      await expect(page.locator('[data-testid="shift-item"]')).not.toBeVisible();
    }
    
    // Verify error message is user-friendly
    expect(errorMessage?.length).toBeGreaterThan(10);

    // Step 2: View own weekly schedule
    await page.click('[data-testid="weekly-schedule-menu"]');
    
    // Expected Result: Schedule displayed correctly
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="calendar-grid"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-item"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
  });

  test('Test weekly schedule UI responsiveness on mobile', async ({ page, context }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Step 1: Access weekly schedule page on mobile browser
    await page.fill('[data-testid="username-input"]', validEmployeeCredentials.username);
    await page.fill('[data-testid="password-input"]', validEmployeeCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 10000 });
    
    // Navigate to weekly schedule
    await page.click('[data-testid="weekly-schedule-menu"]');
    
    // Expected Result: Calendar layout adjusts correctly to screen size
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="calendar-grid"]')).toBeVisible();
    
    // Verify calendar grid adapts to mobile screen
    const calendarGrid = page.locator('[data-testid="calendar-grid"]');
    const boundingBox = await calendarGrid.boundingBox();
    expect(boundingBox?.width).toBeLessThanOrEqual(375);
    
    // Verify all days of the week are visible and labeled
    const daysOfWeek = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    for (const day of daysOfWeek) {
      const dayElement = page.locator(`text=${day}`).first();
      await expect(dayElement).toBeVisible();
    }
    
    // Verify shift details are clearly visible
    await expect(page.locator('[data-testid="shift-item"]').first()).toBeVisible();
    
    // Verify current week is highlighted
    await expect(page.locator('[data-testid="current-week-indicator"]')).toBeVisible();

    // Step 2: Navigate between weeks
    // Tap next week navigation control
    await page.click('[data-testid="next-week-button"]');
    
    // Expected Result: Navigation controls function properly on mobile
    await expect(page.locator('[data-testid="calendar-grid"]')).toBeVisible();
    await expect(page.locator('[data-testid="weekly-schedule-container"]')).toBeVisible();
    
    // Tap previous week navigation control
    await page.click('[data-testid="previous-week-button"]');
    await expect(page.locator('[data-testid="calendar-grid"]')).toBeVisible();
    
    // Test touch gestures by scrolling
    await page.locator('[data-testid="calendar-grid"]').hover();
    await page.mouse.wheel(0, 100);
    await page.waitForTimeout(500);
    
    // Rotate to landscape orientation
    await page.setViewportSize({ width: 667, height: 375 });
    await page.waitForTimeout(500);
    
    // Verify layout adapts to landscape
    await expect(page.locator('[data-testid="calendar-grid"]')).toBeVisible();
    const landscapeBox = await calendarGrid.boundingBox();
    expect(landscapeBox?.width).toBeLessThanOrEqual(667);
    
    // Rotate back to portrait
    await page.setViewportSize({ width: 375, height: 667 });
    await page.waitForTimeout(500);
    
    // Verify layout adapts back to portrait
    await expect(page.locator('[data-testid="calendar-grid"]')).toBeVisible();
    const portraitBox = await calendarGrid.boundingBox();
    expect(portraitBox?.width).toBeLessThanOrEqual(375);
  });
});