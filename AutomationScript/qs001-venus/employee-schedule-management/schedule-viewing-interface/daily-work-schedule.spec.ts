import { test, expect } from '@playwright/test';

test.describe('Daily Work Schedule - Story 12', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_USERNAME = 'employee.a@company.com';
  const VALID_PASSWORD = 'Password123!';
  const EMPLOYEE_A_ID = 'emp-001';
  const EMPLOYEE_B_ID = 'emp-002';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate daily schedule display with valid employee and date', async ({ page }) => {
    // Step 1: Employee logs into the scheduling portal
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Dashboard is displayed
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="navigation-menu"]')).toBeVisible();

    // Step 2: Employee selects 'Daily View' for today's date
    await page.click('[data-testid="daily-view-option"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Schedule for today is displayed with correct shift details
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-date"]')).toContainText(new Date().toLocaleDateString());
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-location"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-role"]')).toBeVisible();

    // Step 3: Employee navigates to previous day
    await page.click('[data-testid="previous-day-button"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Schedule for previous day is displayed correctly
    const previousDate = new Date();
    previousDate.setDate(previousDate.getDate() - 1);
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-date"]')).toContainText(previousDate.toLocaleDateString());
    
    // Navigate back to today
    await page.click('[data-testid="next-day-button"]');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="schedule-date"]')).toContainText(new Date().toLocaleDateString());
  });

  test('Verify access restriction to other employees schedules', async ({ page }) => {
    // Step 1: Log into the scheduling portal as Employee A
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to daily schedule view for Employee A
    await page.click('[data-testid="daily-view-option"]');
    await page.waitForLoadState('networkidle');
    
    // Note the current URL structure
    const currentUrl = page.url();
    expect(currentUrl).toContain(EMPLOYEE_A_ID);

    // Step 2: Manually modify the URL to attempt accessing Employee B's schedule
    const today = new Date().toISOString().split('T')[0];
    const unauthorizedUrl = `${BASE_URL}/api/schedules/daily?employeeId=${EMPLOYEE_B_ID}&date=${today}`;
    await page.goto(unauthorizedUrl);
    
    // Expected Result: Access is denied with appropriate error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/access.*denied|unauthorized|forbidden/i);
    
    // Verify that no schedule data for Employee B is visible
    await expect(page.locator('[data-testid="daily-schedule-container"]')).not.toBeVisible();

    // Step 3: Navigate back to Employee A's own schedule
    await page.click('[data-testid="daily-view-option"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Schedule is displayed without errors
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
  });

  test('Test responsive design on mobile devices', async ({ page, context }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Step 1: Navigate to scheduling portal and login
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Dashboard is displayed on mobile
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 2: Tap on 'Daily View' option from mobile navigation
    await page.click('[data-testid="mobile-menu-toggle"]');
    await page.click('[data-testid="daily-view-option"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Schedule displays correctly with no layout issues
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    const scheduleContainer = page.locator('[data-testid="daily-schedule-container"]');
    const boundingBox = await scheduleContainer.boundingBox();
    expect(boundingBox?.width).toBeLessThanOrEqual(375);
    
    // Verify all schedule elements are properly formatted for mobile
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-location"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-role"]')).toBeVisible();

    // Step 3: Tap on 'Next Day' navigation button
    await page.click('[data-testid="next-day-button"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Schedule updates to show next day's information
    const nextDate = new Date();
    nextDate.setDate(nextDate.getDate() + 1);
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-date"]')).toContainText(nextDate.toLocaleDateString());

    // Step 4: Tap on 'Previous Day' navigation button
    await page.click('[data-testid="previous-day-button"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Schedule returns to today's view
    await expect(page.locator('[data-testid="schedule-date"]')).toContainText(new Date().toLocaleDateString());

    // Step 5: Rotate to landscape orientation
    await page.setViewportSize({ width: 667, height: 375 });
    await page.waitForTimeout(500);
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    const landscapeBox = await scheduleContainer.boundingBox();
    expect(landscapeBox?.width).toBeLessThanOrEqual(667);

    // Step 6: Rotate back to portrait orientation
    await page.setViewportSize({ width: 375, height: 667 });
    await page.waitForTimeout(500);
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    const portraitBox = await scheduleContainer.boundingBox();
    expect(portraitBox?.width).toBeLessThanOrEqual(375);
  });

  test.afterEach(async ({ page }) => {
    // Logout after each test if logged in
    const logoutButton = page.locator('[data-testid="logout-button"]');
    if (await logoutButton.isVisible()) {
      await logoutButton.click();
    }
  });
});