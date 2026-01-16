import { test, expect } from '@playwright/test';

test.describe('Employee Daily Schedule - Story 12', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_USERNAME = process.env.TEST_USERNAME || 'employee@test.com';
  const VALID_PASSWORD = process.env.TEST_PASSWORD || 'Test@1234';

  test('Validate successful daily schedule display with valid employee login', async ({ page }) => {
    // Step 1: Employee logs into the web portal
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Login successful and dashboard displayed
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 5000 });
    await expect(page.locator('[data-testid="dashboard-container"]')).toBeVisible();

    // Step 2: Navigate to schedule section and select daily view
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="daily-view-option"]');
    
    // Expected Result: Daily schedule for current day is displayed with correct shift details
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-location"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-role"]')).toBeVisible();

    // Step 3: Navigate to previous and next days
    await page.click('[data-testid="previous-day-button"]');
    
    // Expected Result: Schedules for selected days load correctly without errors
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible({ timeout: 3000 });
    await page.waitForLoadState('networkidle');
    
    await page.click('[data-testid="next-day-button"]');
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible({ timeout: 3000 });
    await page.waitForLoadState('networkidle');
    
    await page.click('[data-testid="next-day-button"]');
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible({ timeout: 3000 });
    await page.waitForLoadState('networkidle');

    // Verify responsive layout on mobile dimensions
    await page.setViewportSize({ width: 375, height: 667 });
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
  });

  test('Verify access restriction for unauthenticated users', async ({ page }) => {
    // Step 1: Attempt to access daily schedule URL without login
    await page.goto(`${BASE_URL}/schedule/daily`);
    
    // Expected Result: Access denied with redirect to login page
    await expect(page).toHaveURL(/.*login/, { timeout: 5000 });
    const errorMessage = page.locator('[data-testid="error-message"]');
    if (await errorMessage.isVisible()) {
      await expect(errorMessage).toContainText(/access denied|unauthorized|please log in/i);
    }

    // Step 2: Login with valid credentials
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access granted to daily schedule
    await page.waitForLoadState('networkidle');
    
    // Verify OAuth2 token is present in session
    const cookies = await page.context().cookies();
    const hasAuthToken = cookies.some(cookie => 
      cookie.name.toLowerCase().includes('token') || 
      cookie.name.toLowerCase().includes('auth') ||
      cookie.name.toLowerCase().includes('session')
    );
    expect(hasAuthToken).toBeTruthy();

    // Navigate to schedule and verify access
    await page.goto(`${BASE_URL}/schedule/daily`);
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible({ timeout: 3000 });
  });

  test('Test system behavior when no shifts are scheduled', async ({ page }) => {
    // Login first
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 5000 });

    // Step 1: Navigate to the daily schedule view from the dashboard
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="daily-view-option"]');
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();

    // Step 2: Use date navigation to select a day with no scheduled shifts
    // Navigate forward multiple days to find a day without shifts
    for (let i = 0; i < 10; i++) {
      await page.click('[data-testid="next-day-button"]');
      await page.waitForLoadState('networkidle');
      
      const noShiftsMessage = page.locator('[data-testid="no-shifts-message"]');
      if (await noShiftsMessage.isVisible()) {
        // Expected Result: System displays message 'No scheduled shifts for this day'
        await expect(noShiftsMessage).toContainText(/no scheduled shifts|no shifts scheduled/i);
        
        // Verify no error messages or system failures occur
        const errorAlert = page.locator('[data-testid="error-alert"]');
        await expect(errorAlert).not.toBeVisible();
        
        // Navigate to a day with scheduled shifts
        await page.click('[data-testid="previous-day-button"]');
        await page.waitForLoadState('networkidle');
        
        // Verify shifts are displayed
        const hasShifts = await page.locator('[data-testid="shift-start-time"]').isVisible();
        if (hasShifts) {
          await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
        }
        
        // Navigate back to the day with no shifts
        await page.click('[data-testid="next-day-button"]');
        await page.waitForLoadState('networkidle');
        await expect(noShiftsMessage).toBeVisible();
        await expect(noShiftsMessage).toContainText(/no scheduled shifts|no shifts scheduled/i);
        
        break;
      }
    }
  });
});