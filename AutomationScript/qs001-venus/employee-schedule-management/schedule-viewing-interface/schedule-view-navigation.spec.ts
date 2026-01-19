import { test, expect } from '@playwright/test';

test.describe('Schedule View Navigation - Story 18', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const EMPLOYEE_EMAIL = 'employee@company.com';
  const EMPLOYEE_PASSWORD = 'Password123!';
  const VIEW_LOAD_TIMEOUT = 3000;

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate schedule view switching - Employee selects weekly view and preference persists after logout', async ({ page }) => {
    // Step 1: Navigate to the application login page
    await expect(page).toHaveURL(/.*login/);
    
    // Step 2: Enter valid employee credentials and click Login button
    await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and navigation
    await expect(page).toHaveURL(/.*dashboard|schedule/, { timeout: 5000 });
    
    // Step 3: Navigate to the schedule page if not already there
    const currentUrl = page.url();
    if (!currentUrl.includes('schedule')) {
      await page.click('[data-testid="schedule-nav-link"]');
      await expect(page).toHaveURL(/.*schedule/);
    }
    
    // Step 4: Note the current schedule view format displayed
    const initialView = await page.getAttribute('[data-testid="schedule-view-container"]', 'data-view-type');
    
    // Step 5: Click on the weekly view navigation control button
    const startTime = Date.now();
    await page.click('[data-testid="weekly-view-button"]');
    
    // Action: Employee selects weekly view | Expected Result: Schedule updates to weekly format within 3 seconds
    await page.waitForSelector('[data-testid="schedule-view-container"][data-view-type="weekly"]', { timeout: VIEW_LOAD_TIMEOUT });
    const loadTime = Date.now() - startTime;
    expect(loadTime).toBeLessThan(VIEW_LOAD_TIMEOUT);
    
    // Step 6: Verify that all shifts for the week are displayed with proper formatting
    await expect(page.locator('[data-testid="weekly-schedule-grid"]')).toBeVisible();
    const weekDays = await page.locator('[data-testid="week-day-column"]').count();
    expect(weekDays).toBeGreaterThanOrEqual(7);
    
    // Verify weekly view button is active/selected
    await expect(page.locator('[data-testid="weekly-view-button"]')).toHaveClass(/active|selected/);
    
    // Step 7: Click on the Logout button or menu option
    await page.click('[data-testid="user-menu-button"]');
    await page.click('[data-testid="logout-button"]');
    
    // Action: Employee logs out and logs back in | Expected Result: Weekly view is restored as default
    await expect(page).toHaveURL(/.*login/);
    
    // Step 8: Enter the same employee credentials and click Login button
    await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for login and navigate to schedule if needed
    await page.waitForLoadState('networkidle');
    const urlAfterLogin = page.url();
    if (!urlAfterLogin.includes('schedule')) {
      await page.click('[data-testid="schedule-nav-link"]');
    }
    
    // Step 9: Observe the default schedule view displayed upon login
    await page.waitForSelector('[data-testid="schedule-view-container"]', { timeout: 5000 });
    const restoredView = await page.getAttribute('[data-testid="schedule-view-container"]', 'data-view-type');
    expect(restoredView).toBe('weekly');
    
    // Step 10: Verify that the weekly view navigation control appears selected or highlighted
    await expect(page.locator('[data-testid="weekly-view-button"]')).toHaveClass(/active|selected/);
    await expect(page.locator('[data-testid="weekly-schedule-grid"]')).toBeVisible();
  });

  test('Verify UI responsiveness of view navigation controls on mobile device', async ({ page }) => {
    // Step 1: Open the application on a mobile device or use browser developer tools to emulate mobile device
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Step 2: Navigate to the login page on the mobile device
    await expect(page).toHaveURL(/.*login/);
    
    // Step 3: Enter valid employee credentials using mobile keyboard and tap Login button
    await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login
    await page.waitForLoadState('networkidle');
    
    // Navigate to schedule page if not already there
    const currentUrl = page.url();
    if (!currentUrl.includes('schedule')) {
      await page.click('[data-testid="schedule-nav-link"]');
      await expect(page).toHaveURL(/.*schedule/);
    }
    
    // Action: Access schedule page on mobile device | Expected Result: Navigation controls are usable and layout adjusts correctly
    
    // Step 4: Locate the schedule view navigation controls on the mobile interface
    const navigationControls = page.locator('[data-testid="schedule-view-navigation"]');
    await expect(navigationControls).toBeVisible();
    
    // Step 5: Verify the layout of navigation controls
    const controlsBox = await navigationControls.boundingBox();
    expect(controlsBox).not.toBeNull();
    expect(controlsBox!.width).toBeLessThanOrEqual(375);
    
    // Verify all view buttons are present and visible
    await expect(page.locator('[data-testid="daily-view-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="weekly-view-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="monthly-view-button"]')).toBeVisible();
    
    // Step 6: Tap on the weekly view navigation control
    await page.click('[data-testid="weekly-view-button"]');
    await page.waitForSelector('[data-testid="schedule-view-container"][data-view-type="weekly"]', { timeout: VIEW_LOAD_TIMEOUT });
    
    // Step 7: Verify that the weekly schedule is readable and properly formatted on mobile screen
    const weeklySchedule = page.locator('[data-testid="weekly-schedule-grid"]');
    await expect(weeklySchedule).toBeVisible();
    const scheduleBox = await weeklySchedule.boundingBox();
    expect(scheduleBox).not.toBeNull();
    expect(scheduleBox!.width).toBeLessThanOrEqual(375);
    
    // Verify no horizontal overflow
    const hasHorizontalScroll = await page.evaluate(() => {
      return document.documentElement.scrollWidth > document.documentElement.clientWidth;
    });
    expect(hasHorizontalScroll).toBe(false);
    
    // Step 8: Tap on the monthly view navigation control
    await page.click('[data-testid="monthly-view-button"]');
    await page.waitForSelector('[data-testid="schedule-view-container"][data-view-type="monthly"]', { timeout: VIEW_LOAD_TIMEOUT });
    await expect(page.locator('[data-testid="monthly-schedule-grid"]')).toBeVisible();
    await expect(page.locator('[data-testid="monthly-view-button"]')).toHaveClass(/active|selected/);
    
    // Step 9: Tap on the daily view navigation control
    await page.click('[data-testid="daily-view-button"]');
    await page.waitForSelector('[data-testid="schedule-view-container"][data-view-type="daily"]', { timeout: VIEW_LOAD_TIMEOUT });
    await expect(page.locator('[data-testid="daily-schedule-grid"]')).toBeVisible();
    await expect(page.locator('[data-testid="daily-view-button"]')).toHaveClass(/active|selected/);
    
    // Step 10: Rotate the mobile device to landscape orientation
    await page.setViewportSize({ width: 667, height: 375 });
    await page.waitForTimeout(500); // Allow time for layout adjustment
    
    // Verify navigation controls are still visible and usable in landscape
    await expect(navigationControls).toBeVisible();
    await expect(page.locator('[data-testid="daily-schedule-grid"]')).toBeVisible();
    
    // Step 11: Rotate back to portrait orientation
    await page.setViewportSize({ width: 375, height: 667 });
    await page.waitForTimeout(500); // Allow time for layout adjustment
    
    // Verify navigation controls are still visible and usable in portrait
    await expect(navigationControls).toBeVisible();
    await expect(page.locator('[data-testid="daily-schedule-grid"]')).toBeVisible();
    
    // Verify all navigation buttons are still accessible
    await expect(page.locator('[data-testid="daily-view-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="weekly-view-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="monthly-view-button"]')).toBeVisible();
  });
});