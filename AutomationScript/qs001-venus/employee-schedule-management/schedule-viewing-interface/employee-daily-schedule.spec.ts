import { test, expect } from '@playwright/test';

test.describe('Employee Daily Schedule View', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_EMPLOYEE_EMAIL = 'employee@company.com';
  const VALID_EMPLOYEE_PASSWORD = 'Password123!';
  const VALID_EMPLOYEE_ID = '12345';
  const OTHER_EMPLOYEE_ID = '67890';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate daily schedule display for logged-in employee', async ({ page }) => {
    // Step 1: Employee logs into the schedule portal
    await page.fill('[data-testid="email-input"]', VALID_EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Dashboard is displayed
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="dashboard-container"]')).toBeVisible();

    // Step 2: Employee selects 'Daily View' for today's date
    await page.click('[data-testid="daily-view-link"]');
    
    // Expected Result: System displays today's schedule with correct shift details
    await expect(page).toHaveURL(/.*schedules\/daily/);
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    
    // Verify schedule details are present
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-location"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-role"]')).toBeVisible();
    
    // Verify current date is displayed
    const currentDate = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    await expect(page.locator('[data-testid="schedule-date"]')).toContainText(currentDate.split(',')[0]);

    // Step 3: Employee navigates to previous day
    await page.click('[data-testid="previous-day-button"]');
    
    // Expected Result: System displays schedule for previous day without errors
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    
    // Verify date has changed to previous day
    const previousDate = new Date();
    previousDate.setDate(previousDate.getDate() - 1);
    const previousDateString = previousDate.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    await expect(page.locator('[data-testid="schedule-date"]')).toContainText(previousDateString.split(',')[0]);
    
    // Verify no error messages are displayed
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
  });

  test('Verify access restriction to other employees schedules', async ({ page }) => {
    // Step 1: Employee attempts to access schedule of another employee via URL manipulation
    await page.fill('[data-testid="email-input"]', VALID_EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to daily view
    await page.click('[data-testid="daily-view-link"]');
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    
    // Note the current URL structure
    const currentURL = page.url();
    
    // Manually modify the URL by changing the employeeId parameter
    const today = new Date().toISOString().split('T')[0];
    await page.goto(`${BASE_URL}/schedules/daily?employeeId=${OTHER_EMPLOYEE_ID}&date=${today}`);
    
    // Expected Result: System denies access and displays an authorization error
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/authorization|access denied|unauthorized/i);
    
    // Verify no schedule data for the other employee is visible
    const scheduleItems = await page.locator('[data-testid="shift-details"]').count();
    expect(scheduleItems).toBe(0);

    // Step 2: Employee views own schedule
    await page.click('[data-testid="daily-view-link"]');
    
    // Expected Result: System displays schedule without errors
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
    
    // Verify schedule details are correctly displayed
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-location"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-role"]')).toBeVisible();
  });

  test('Test responsive layout on mobile devices', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Step 1: Access daily schedule view on a mobile device
    await page.fill('[data-testid="email-input"]', VALID_EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Tap on 'Daily View' option
    await page.click('[data-testid="daily-view-link"]');
    
    // Expected Result: Schedule layout adjusts correctly with readable text and controls
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    
    // Verify all schedule details are clearly visible
    const shiftStartTime = page.locator('[data-testid="shift-start-time"]');
    await expect(shiftStartTime).toBeVisible();
    const shiftStartBox = await shiftStartTime.boundingBox();
    expect(shiftStartBox).not.toBeNull();
    expect(shiftStartBox!.width).toBeGreaterThan(0);
    
    const shiftEndTime = page.locator('[data-testid="shift-end-time"]');
    await expect(shiftEndTime).toBeVisible();
    
    const shiftLocation = page.locator('[data-testid="shift-location"]');
    await expect(shiftLocation).toBeVisible();
    
    const shiftRole = page.locator('[data-testid="shift-role"]');
    await expect(shiftRole).toBeVisible();

    // Step 2: Navigate between dates
    // Tap on 'Next Day' navigation button
    const nextDayButton = page.locator('[data-testid="next-day-button"]');
    await expect(nextDayButton).toBeVisible();
    await nextDayButton.click();
    
    // Expected Result: Navigation controls function correctly on mobile
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    
    // Verify date has changed
    const nextDate = new Date();
    nextDate.setDate(nextDate.getDate() + 1);
    const nextDateString = nextDate.toLocaleDateString('en-US', { month: 'long', day: 'numeric' });
    await expect(page.locator('[data-testid="schedule-date"]')).toContainText(nextDateString.split(',')[0]);
    
    // Tap on 'Previous Day' navigation button
    const previousDayButton = page.locator('[data-testid="previous-day-button"]');
    await expect(previousDayButton).toBeVisible();
    await previousDayButton.click();
    
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    
    // Rotate device to landscape orientation
    await page.setViewportSize({ width: 667, height: 375 });
    
    // Verify layout still works in landscape
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time"]')).toBeVisible();
    await expect(nextDayButton).toBeVisible();
    await expect(previousDayButton).toBeVisible();
  });
});