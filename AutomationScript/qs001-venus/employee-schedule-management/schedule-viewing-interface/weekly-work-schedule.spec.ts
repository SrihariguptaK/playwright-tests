import { test, expect } from '@playwright/test';

test.describe('Weekly Work Schedule - Story 13', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const validEmployeeUsername = 'employee.a@company.com';
  const validEmployeePassword = 'Password123!';
  const employeeBUsername = 'employee.b@company.com';

  test.beforeEach(async ({ page }) => {
    // Navigate to scheduling portal login page
    await page.goto(`${baseURL}/login`);
  });

  test('Validate weekly schedule display with valid employee and week', async ({ page }) => {
    // Step 1: Employee logs into the scheduling portal
    await page.fill('input[name="username"]', validEmployeeUsername);
    await page.fill('input[name="password"]', validEmployeePassword);
    await page.click('button[type="submit"]');
    
    // Expected Result: Dashboard is displayed
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    await expect(page).toHaveURL(/.*\/dashboard/);

    // Step 2: Employee selects 'Weekly View' for current week
    await page.click('[data-testid="weekly-view-link"]');
    
    // Expected Result: Schedule for the week is displayed with correct shift details
    await expect(page.locator('[data-testid="weekly-schedule"]')).toBeVisible();
    await expect(page.locator('[data-testid="week-indicator"]')).toBeVisible();
    
    // Verify calendar format is displayed
    await expect(page.locator('[data-testid="calendar-view"]')).toBeVisible();
    
    // Verify shifts are displayed with details
    const shifts = page.locator('[data-testid="shift-item"]');
    await expect(shifts.first()).toBeVisible();
    
    // Verify shift details include start/end times and locations
    await expect(page.locator('[data-testid="shift-time"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="shift-location"]').first()).toBeVisible();

    // Step 3: Employee navigates to next week
    await page.click('[data-testid="next-week-button"]');
    
    // Expected Result: Schedule for next week is displayed correctly
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="weekly-schedule"]')).toBeVisible();
    
    // Verify week indicator updates
    const weekIndicator = page.locator('[data-testid="week-indicator"]');
    await expect(weekIndicator).toContainText(/Week/);
    
    // Verify shifts are displayed for next week
    await expect(page.locator('[data-testid="calendar-view"]')).toBeVisible();
    
    // Navigate back to current week
    await page.click('[data-testid="previous-week-button"]');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="weekly-schedule"]')).toBeVisible();
  });

  test('Verify access restriction to other employees weekly schedules', async ({ page }) => {
    // Step 1: Employee attempts to access another employee's weekly schedule
    // Log in as Employee A
    await page.fill('input[name="username"]', validEmployeeUsername);
    await page.fill('input[name="password"]', validEmployeePassword);
    await page.click('button[type="submit"]');
    
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Navigate to weekly schedule view
    await page.click('[data-testid="weekly-view-link"]');
    await expect(page.locator('[data-testid="weekly-schedule"]')).toBeVisible();
    
    // Get current URL and extract employeeId
    const currentURL = page.url();
    
    // Attempt to access another employee's schedule by modifying URL
    const manipulatedURL = currentURL.replace(/employeeId=[^&]+/, 'employeeId=employee-b-id');
    await page.goto(manipulatedURL);
    
    // Expected Result: Access denied with error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/access denied|unauthorized|permission/i);
    
    // Verify no schedule data for Employee B is visible
    const employeeBSchedule = page.locator('[data-testid="weekly-schedule"]');
    await expect(employeeBSchedule).not.toBeVisible();

    // Step 2: Employee views own weekly schedule
    await page.click('[data-testid="weekly-view-link"]');
    
    // Expected Result: Schedule displayed without errors
    await expect(page.locator('[data-testid="weekly-schedule"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="calendar-view"]')).toBeVisible();
  });

  test('Test weekly schedule responsiveness on mobile devices', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Step 1: Employee accesses weekly schedule on mobile device
    await page.fill('input[name="username"]', validEmployeeUsername);
    await page.fill('input[name="password"]', validEmployeePassword);
    await page.click('button[type="submit"]');
    
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Access weekly view on mobile
    await page.click('[data-testid="weekly-view-link"]');
    
    // Expected Result: Schedule displays correctly with no layout issues
    await expect(page.locator('[data-testid="weekly-schedule"]')).toBeVisible();
    await expect(page.locator('[data-testid="calendar-view"]')).toBeVisible();
    
    // Verify mobile layout elements
    const scheduleContainer = page.locator('[data-testid="weekly-schedule"]');
    const boundingBox = await scheduleContainer.boundingBox();
    
    // Verify schedule fits within mobile viewport
    if (boundingBox) {
      expect(boundingBox.width).toBeLessThanOrEqual(375);
    }
    
    // Verify all schedule elements are visible
    await expect(page.locator('[data-testid="shift-time"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="shift-location"]').first()).toBeVisible();
    
    // Scroll through weekly calendar
    await page.locator('[data-testid="calendar-view"]').scrollIntoViewIfNeeded();
    
    // Step 2: Employee navigates between weeks
    await page.click('[data-testid="next-week-button"]');
    
    // Expected Result: Navigation works smoothly and schedule updates accordingly
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="weekly-schedule"]')).toBeVisible();
    
    // Verify week indicator updates
    await expect(page.locator('[data-testid="week-indicator"]')).toBeVisible();
    
    // Navigate to previous week
    await page.click('[data-testid="previous-week-button"]');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="weekly-schedule"]')).toBeVisible();
    
    // Test landscape orientation
    await page.setViewportSize({ width: 667, height: 375 });
    await expect(page.locator('[data-testid="weekly-schedule"]')).toBeVisible();
    await expect(page.locator('[data-testid="calendar-view"]')).toBeVisible();
    
    // Test back to portrait orientation
    await page.setViewportSize({ width: 375, height: 667 });
    await expect(page.locator('[data-testid="weekly-schedule"]')).toBeVisible();
    await expect(page.locator('[data-testid="calendar-view"]')).toBeVisible();
  });

  test.afterEach(async ({ page }) => {
    // Logout if logged in
    const logoutButton = page.locator('[data-testid="logout-button"]');
    if (await logoutButton.isVisible()) {
      await logoutButton.click();
    }
    await page.close();
  });
});